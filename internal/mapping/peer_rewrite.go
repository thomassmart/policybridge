package mapping

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// PeerRewriteStats reports how peers were normalised after synthesis.
type PeerRewriteStats struct {
	AnyPeersOmitted           int
	NamespaceSelectorsStripped int
}

// knownNamespaces builds the set of synthesised segment namespaces, remapped
// targets, and "default" (vmware-analyzer includes default in ANY expansions).
func knownNamespaces(segments []SegmentEntry) map[string]bool {
	known := map[string]bool{"default": true}
	for _, e := range segments {
		from := SynthesizedNamespace(e.SegmentName)
		if from != "" {
			known[from] = true
		}
		to := strings.TrimSpace(e.TargetName)
		if to == "" {
			continue
		}
		to = SynthesizedNamespace(to)
		if to != "" {
			known[to] = true
		}
	}
	return known
}

// RewriteNetworkPolicyPeers normalises NetworkPolicy peers under dir so NSX
// ANY/segment peers match OpenShift intent: omit ANY from/to, and prefer
// same-namespace podSelector for tag peers when all members map to one project.
func RewriteNetworkPolicyPeers(dir string, segments []SegmentEntry) (PeerRewriteStats, error) {
	var stats PeerRewriteStats
	if dir == "" {
		return stats, nil
	}
	known := knownNamespaces(segments)
	if len(known) == 0 {
		return stats, nil
	}
	singleProject := PreferredPatchNamespace(segments)
	renames := NamespaceRenameMap(segments)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return stats, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(dir, name)
		fileStats, err := rewritePeersInFile(path, known, renames, singleProject)
		if err != nil {
			return stats, fmt.Errorf("%s: %w", name, err)
		}
		stats.AnyPeersOmitted += fileStats.AnyPeersOmitted
		stats.NamespaceSelectorsStripped += fileStats.NamespaceSelectorsStripped
	}
	return stats, nil
}

func rewritePeersInFile(path string, known map[string]bool, renames map[string]string, singleProject string) (PeerRewriteStats, error) {
	var stats PeerRewriteStats
	data, err := os.ReadFile(path)
	if err != nil {
		return stats, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	wrote := 0
	changed := false
	for {
		var obj map[string]any
		err := dec.Decode(&obj)
		if err == io.EOF {
			break
		}
		if err != nil {
			return stats, err
		}
		if obj == nil {
			continue
		}
		if kindOf(obj) == "NetworkPolicy" {
			s := rewriteNetworkPolicyPeers(obj, known, renames, singleProject)
			stats.AnyPeersOmitted += s.AnyPeersOmitted
			stats.NamespaceSelectorsStripped += s.NamespaceSelectorsStripped
			if s.AnyPeersOmitted > 0 || s.NamespaceSelectorsStripped > 0 {
				changed = true
			}
		}
		if err := enc.Encode(obj); err != nil {
			return stats, err
		}
		wrote++
	}
	if err := enc.Close(); err != nil {
		return stats, err
	}
	if wrote == 0 || !changed {
		return stats, nil
	}
	return stats, os.WriteFile(path, out.Bytes(), 0600)
}

func rewriteNetworkPolicyPeers(obj map[string]any, known map[string]bool, renames map[string]string, singleProject string) PeerRewriteStats {
	var stats PeerRewriteStats
	spec, ok := obj["spec"].(map[string]any)
	if !ok {
		return stats
	}
	policyNS := ""
	if meta, ok := obj["metadata"].(map[string]any); ok {
		policyNS, _ = meta["namespace"].(string)
	}
	for _, key := range []string{"ingress", "egress"} {
		rules, ok := spec[key].([]any)
		if !ok {
			continue
		}
		peerKey := "from"
		if key == "egress" {
			peerKey = "to"
		}
		for _, raw := range rules {
			rule, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			s := rewriteRulePeers(rule, peerKey, known, renames, singleProject, policyNS)
			stats.AnyPeersOmitted += s.AnyPeersOmitted
			stats.NamespaceSelectorsStripped += s.NamespaceSelectorsStripped
		}
	}
	return stats
}

func rewriteRulePeers(rule map[string]any, peerKey string, known map[string]bool, renames map[string]string, singleProject, policyNS string) PeerRewriteStats {
	var stats PeerRewriteStats
	peers, ok := rule[peerKey].([]any)
	if !ok {
		return stats
	}
	kept := make([]any, 0, len(peers))
	for _, raw := range peers {
		peer, ok := raw.(map[string]any)
		if !ok {
			kept = append(kept, raw)
			continue
		}
		if isTautologyIPBlock(peer) {
			stats.AnyPeersOmitted++
			continue
		}
		if isAnyLikeNamespacePeer(peer, known) {
			stats.AnyPeersOmitted++
			continue
		}
		if stripSameNamespaceSelector(peer, known, renames, singleProject, policyNS) {
			stats.NamespaceSelectorsStripped++
		}
		kept = append(kept, peer)
	}
	if len(kept) == 0 {
		delete(rule, peerKey)
	} else {
		rule[peerKey] = kept
	}
	return stats
}

func isTautologyIPBlock(peer map[string]any) bool {
	block, ok := peer["ipBlock"].(map[string]any)
	if !ok {
		return false
	}
	cidr, _ := block["cidr"].(string)
	if cidr != "0.0.0.0/0" && cidr != "::/0" {
		return false
	}
	if except, ok := block["except"]; ok {
		if list, ok := except.([]any); ok && len(list) > 0 {
			return false
		}
	}
	// Pure tautology peer: only ipBlock (no pod/namespace selectors).
	_, hasPod := peer["podSelector"]
	_, hasNS := peer["namespaceSelector"]
	return !hasPod && !hasNS
}

func isAnyLikeNamespacePeer(peer map[string]any, known map[string]bool) bool {
	if _, hasIP := peer["ipBlock"]; hasIP {
		return false
	}
	if !isEmptyPodSelector(peer) {
		return false
	}
	vals := namespaceSelectorValues(peer["namespaceSelector"])
	if len(vals) == 0 {
		// Empty namespaceSelector {} with empty podSelector also means all peers.
		if raw, ok := peer["namespaceSelector"]; ok {
			if sel, ok := raw.(map[string]any); ok && len(sel) == 0 {
				return true
			}
		}
		return false
	}
	for _, v := range vals {
		if !known[v] {
			return false
		}
	}
	return true
}

func isEmptyPodSelector(peer map[string]any) bool {
	raw, ok := peer["podSelector"]
	if !ok {
		return true
	}
	sel, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	if len(sel) == 0 {
		return true
	}
	ml, hasML := sel["matchLabels"].(map[string]any)
	exprs, hasExpr := sel["matchExpressions"].([]any)
	if hasML && len(ml) > 0 {
		return false
	}
	if hasExpr && len(exprs) > 0 {
		return false
	}
	// Only empty matchLabels/matchExpressions keys.
	return (!hasML || len(ml) == 0) && (!hasExpr || len(exprs) == 0) && len(sel) <= 2
}

func stripSameNamespaceSelector(peer map[string]any, known map[string]bool, renames map[string]string, singleProject, policyNS string) bool {
	if _, hasIP := peer["ipBlock"]; hasIP {
		return false
	}
	if isEmptyPodSelector(peer) {
		return false
	}
	raw, ok := peer["namespaceSelector"]
	if !ok {
		return false
	}
	vals := namespaceSelectorValues(raw)
	if len(vals) == 0 {
		return false
	}
	for _, v := range vals {
		if !known[v] {
			return false
		}
	}
	if !shouldStripNamespaceSelector(vals, renames, singleProject, policyNS) {
		return false
	}
	delete(peer, "namespaceSelector")
	return true
}

func shouldStripNamespaceSelector(vals []string, renames map[string]string, singleProject, policyNS string) bool {
	if singleProject != "" {
		return true
	}
	if policyNS == "" {
		return false
	}
	for _, v := range vals {
		resolved := v
		if next, hit := renames[v]; hit {
			resolved = next
		}
		if resolved != policyNS {
			return false
		}
	}
	return true
}

func namespaceSelectorValues(node any) []string {
	sel, ok := node.(map[string]any)
	if !ok {
		return nil
	}
	var out []string
	if ml, ok := sel["matchLabels"].(map[string]any); ok {
		if v, ok := ml["kubernetes.io/metadata.name"].(string); ok && v != "" {
			out = append(out, v)
		}
	}
	exprs, _ := sel["matchExpressions"].([]any)
	for _, raw := range exprs {
		expr, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		key, _ := expr["key"].(string)
		if key != "kubernetes.io/metadata.name" {
			continue
		}
		op, _ := expr["operator"].(string)
		if op != "" && op != "In" {
			continue
		}
		vals, ok := expr["values"].([]any)
		if !ok {
			continue
		}
		for _, val := range vals {
			if s, ok := val.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}
