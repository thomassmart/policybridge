package mapping

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Matches np-guard/vmware-analyzer ToLegalK8SString: strip chars outside [-A-Za-z0-9_.].
var k8sLegalChars = regexp.MustCompile(`[^-A-Za-z0-9_.]`)

// SynthesizedNamespace returns the namespace name vmware-analyzer emits for an NSX segment.
func SynthesizedNamespace(segmentName string) string {
	return k8sLegalChars.ReplaceAllString(segmentName, "")
}

// NamespaceRenameMap builds old→new namespace renames from segment TargetName edits.
// Keys are the namespaces synthesis writes (segment-derived); values are user TargetName.
func NamespaceRenameMap(segments []SegmentEntry) map[string]string {
	out := make(map[string]string)
	for _, e := range segments {
		from := SynthesizedNamespace(e.SegmentName)
		to := strings.TrimSpace(e.TargetName)
		if to == "" {
			continue
		}
		to = SynthesizedNamespace(to)
		if from == "" || to == "" || from == to {
			continue
		}
		out[from] = to
	}
	return out
}

// RewriteGeneratedNamespaces rewrites namespaces in synthesised YAML under dir.
// vmware-analyzer hard-codes namespace = NSX segment name; this applies Mapping TargetName.
func RewriteGeneratedNamespaces(dir string, renames map[string]string) error {
	if len(renames) == 0 {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
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
		if err := rewriteYAMLFile(path, renames); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func rewriteYAMLFile(path string, renames map[string]string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	wrote := 0
	seenNamespaces := make(map[string]bool)
	for {
		var obj map[string]any
		err := dec.Decode(&obj)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if obj == nil {
			continue
		}
		rewriteObject(obj, renames)
		if kindOf(obj) == "Namespace" {
			nsName := metadataName(obj)
			if nsName != "" && seenNamespaces[nsName] {
				continue
			}
			if nsName != "" {
				seenNamespaces[nsName] = true
			}
		}
		if err := enc.Encode(obj); err != nil {
			return err
		}
		wrote++
	}
	if err := enc.Close(); err != nil {
		return err
	}
	if wrote == 0 {
		return nil
	}
	return os.WriteFile(path, out.Bytes(), 0600)
}

func rewriteObject(obj map[string]any, renames map[string]string) {
	kind := kindOf(obj)
	meta, _ := obj["metadata"].(map[string]any)
	if meta == nil {
		return
	}

	if ns, ok := meta["namespace"].(string); ok {
		if next, hit := renames[ns]; hit {
			meta["namespace"] = next
		}
	}

	if name, ok := meta["name"].(string); ok {
		if kind == "Namespace" {
			if next, hit := renames[name]; hit {
				meta["name"] = next
				setLabel(meta, "kubernetes.io/metadata.name", next)
			}
		} else {
			meta["name"] = rewritePrefixedName(name, renames)
		}
	}

	if labels, ok := meta["labels"].(map[string]any); ok {
		if v, ok := labels["kubernetes.io/metadata.name"].(string); ok {
			if next, hit := renames[v]; hit {
				labels["kubernetes.io/metadata.name"] = next
			}
		}
	}

	if annotations, ok := meta["annotations"].(map[string]any); ok {
		for k, v := range annotations {
			if s, ok := v.(string); ok {
				annotations[k] = rewriteStringMentions(s, renames)
			}
		}
	}

	rewriteNamespaceSelectors(obj["spec"], renames)
}

func rewritePrefixedName(name string, renames map[string]string) string {
	prefixes := []string{"udn-", "default-deny-for-", "dns-policy-"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			rest := strings.TrimPrefix(name, prefix)
			if next, hit := renames[rest]; hit {
				return prefix + next
			}
		}
	}
	return name
}

func rewriteStringMentions(s string, renames map[string]string) string {
	out := s
	for from, to := range renames {
		out = strings.ReplaceAll(out, from, to)
	}
	return out
}

func rewriteNamespaceSelectors(node any, renames map[string]string) {
	switch v := node.(type) {
	case map[string]any:
		if raw, ok := v["namespaceSelector"]; ok {
			rewriteLabelSelector(raw, renames)
		}
		for _, child := range v {
			rewriteNamespaceSelectors(child, renames)
		}
	case []any:
		for _, child := range v {
			rewriteNamespaceSelectors(child, renames)
		}
	}
}

func rewriteLabelSelector(node any, renames map[string]string) {
	sel, ok := node.(map[string]any)
	if !ok {
		return
	}
	if ml, ok := sel["matchLabels"].(map[string]any); ok {
		if v, ok := ml["kubernetes.io/metadata.name"].(string); ok {
			if next, hit := renames[v]; hit {
				ml["kubernetes.io/metadata.name"] = next
			}
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
		vals, ok := expr["values"].([]any)
		if !ok {
			continue
		}
		for i, val := range vals {
			s, ok := val.(string)
			if !ok {
				continue
			}
			if next, hit := renames[s]; hit {
				vals[i] = next
			}
		}
	}
}

func kindOf(obj map[string]any) string {
	k, _ := obj["kind"].(string)
	return k
}

func metadataName(obj map[string]any) string {
	meta, _ := obj["metadata"].(map[string]any)
	if meta == nil {
		return ""
	}
	name, _ := meta["name"].(string)
	return name
}

func setLabel(meta map[string]any, key, value string) {
	labels, _ := meta["labels"].(map[string]any)
	if labels == nil {
		labels = map[string]any{}
		meta["labels"] = labels
	}
	labels[key] = value
}

// PreferredPatchNamespace picks a default namespace for workload label-patch export.
// Prefers a single remapped TargetName when all segment rows agree; otherwise empty.
func PreferredPatchNamespace(segments []SegmentEntry) string {
	var chosen string
	for _, e := range segments {
		to := strings.TrimSpace(e.TargetName)
		if to == "" {
			continue
		}
		to = SynthesizedNamespace(to)
		if to == "" {
			continue
		}
		if chosen == "" {
			chosen = to
			continue
		}
		if chosen != to {
			return ""
		}
	}
	return chosen
}
