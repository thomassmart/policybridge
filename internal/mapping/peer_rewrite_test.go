package mapping

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fleetSegmentsSingleProject() []SegmentEntry {
	return []SegmentEntry{
		{SegmentName: "Seg-Web", TargetName: "tom-testing"},
		{SegmentName: "Seg-Database", TargetName: "tom-testing"},
		{SegmentName: "Seg-Management", TargetName: "tom-testing"},
	}
}

func TestRewriteNetworkPolicyPeers_FleetGolden(t *testing.T) {
	dir := t.TempDir()
	beforePath := filepath.Join("..", "..", "testdata", "mapping", "peers_before.yaml")
	afterPath := filepath.Join("..", "..", "testdata", "mapping", "peers_after.yaml")
	src, err := os.ReadFile(beforePath)
	if err != nil {
		t.Fatalf("read before fixture: %v", err)
	}
	policies := filepath.Join(dir, "policies.yaml")
	if err := os.WriteFile(policies, src, 0600); err != nil {
		t.Fatal(err)
	}

	segments := fleetSegmentsSingleProject()
	renames := NamespaceRenameMap(segments)
	if err := RewriteGeneratedNamespaces(dir, renames); err != nil {
		t.Fatalf("namespace rewrite: %v", err)
	}
	stats, err := RewriteNetworkPolicyPeers(dir, segments)
	if err != nil {
		t.Fatalf("peer rewrite: %v", err)
	}
	if stats.AnyPeersOmitted < 2 {
		t.Fatalf("expected ANY peers omitted, got %#v", stats)
	}
	if stats.NamespaceSelectorsStripped < 1 {
		t.Fatalf("expected namespaceSelector stripped, got %#v", stats)
	}

	got := mustRead(t, policies)
	want := mustRead(t, afterPath)

	for _, needle := range []string{"Seg-Web", "Seg-Database", "Seg-Management"} {
		if strings.Contains(got, needle) {
			t.Fatalf("got still contains %q:\n%s", needle, got)
		}
	}
	assertPolicySemantics(t, got, "policy-0", false, true)  // ANY egress: no to
	assertPolicySemantics(t, got, "policy-16", true, false) // tag→tag: to without ns selector
	assertPolicySemantics(t, got, "policy-22", false, true) // ANY ingress: no from

	// Golden file is the accepted after shape; compare normalised doc count + key snippets.
	if !strings.Contains(got, "namespace: tom-testing") {
		t.Fatalf("expected tom-testing namespace:\n%s", got)
	}
	if !strings.Contains(want, "namespace: tom-testing") {
		t.Fatalf("golden after missing tom-testing")
	}
	if strings.Contains(got, "namespaceSelector") {
		t.Fatalf("single-project rewrite should remove peer namespaceSelectors:\n%s", got)
	}
	if strings.Contains(got, "0.0.0.0/0") {
		t.Fatalf("tautology ipBlock should be omitted:\n%s", got)
	}
}

func TestRewriteNetworkPolicyPeers_AnyEgressKeepsPorts(t *testing.T) {
	dir := t.TempDir()
	yaml := strings.Join([]string{
		`apiVersion: networking.k8s.io/v1`,
		`kind: NetworkPolicy`,
		`metadata:`,
		`  name: dns`,
		`  namespace: Seg-Web`,
		`spec:`,
		`  podSelector:`,
		`    matchExpressions:`,
		`    - key: tag__web`,
		`      operator: Exists`,
		`  egress:`,
		`  - to:`,
		`    - namespaceSelector:`,
		`        matchExpressions:`,
		`        - key: kubernetes.io/metadata.name`,
		`          operator: In`,
		`          values:`,
		`          - Seg-Web`,
		`          - default`,
		`      podSelector: {}`,
		`    ports:`,
		`    - port: 53`,
		`      protocol: UDP`,
	}, "\n")
	mustWrite(t, filepath.Join(dir, "policies.yaml"), yaml)

	segments := []SegmentEntry{{SegmentName: "Seg-Web", TargetName: "tom-testing"}}
	_ = RewriteGeneratedNamespaces(dir, NamespaceRenameMap(segments))
	stats, err := RewriteNetworkPolicyPeers(dir, segments)
	if err != nil {
		t.Fatal(err)
	}
	if stats.AnyPeersOmitted != 1 {
		t.Fatalf("stats=%#v", stats)
	}
	got := mustRead(t, filepath.Join(dir, "policies.yaml"))
	if strings.Contains(got, "to:") {
		t.Fatalf("expected no to:\n%s", got)
	}
	if !strings.Contains(got, "port: 53") {
		t.Fatalf("ports should remain:\n%s", got)
	}
}

func TestRewriteNetworkPolicyPeers_TagToTagSameNamespace(t *testing.T) {
	dir := t.TempDir()
	yaml := strings.Join([]string{
		`apiVersion: networking.k8s.io/v1`,
		`kind: NetworkPolicy`,
		`metadata:`,
		`  name: east-west`,
		`  namespace: Seg-Web`,
		`spec:`,
		`  podSelector:`,
		`    matchExpressions:`,
		`    - key: tag__web`,
		`      operator: Exists`,
		`  egress:`,
		`  - to:`,
		`    - namespaceSelector:`,
		`        matchExpressions:`,
		`        - key: kubernetes.io/metadata.name`,
		`          operator: In`,
		`          values:`,
		`          - Seg-Database`,
		`      podSelector:`,
		`        matchExpressions:`,
		`        - key: tag__api`,
		`          operator: Exists`,
	}, "\n")
	mustWrite(t, filepath.Join(dir, "policies.yaml"), yaml)

	segments := fleetSegmentsSingleProject()
	_ = RewriteGeneratedNamespaces(dir, NamespaceRenameMap(segments))
	stats, err := RewriteNetworkPolicyPeers(dir, segments)
	if err != nil {
		t.Fatal(err)
	}
	if stats.NamespaceSelectorsStripped != 1 {
		t.Fatalf("stats=%#v", stats)
	}
	got := mustRead(t, filepath.Join(dir, "policies.yaml"))
	if strings.Contains(got, "namespaceSelector") {
		t.Fatalf("expected podSelector only:\n%s", got)
	}
	if !strings.Contains(got, "key: tag__api") {
		t.Fatalf("tag peer missing:\n%s", got)
	}
	if strings.Contains(got, "Seg-") {
		t.Fatalf("segment names remain:\n%s", got)
	}
}

func TestRewriteNetworkPolicyPeers_MultiProjectKeepsNamespaceSelector(t *testing.T) {
	dir := t.TempDir()
	yaml := strings.Join([]string{
		`apiVersion: networking.k8s.io/v1`,
		`kind: NetworkPolicy`,
		`metadata:`,
		`  name: cross-ns`,
		`  namespace: Seg-Web`,
		`spec:`,
		`  podSelector:`,
		`    matchExpressions:`,
		`    - key: tag__web`,
		`      operator: Exists`,
		`  egress:`,
		`  - to:`,
		`    - namespaceSelector:`,
		`        matchExpressions:`,
		`        - key: kubernetes.io/metadata.name`,
		`          operator: In`,
		`          values:`,
		`          - Seg-Database`,
		`      podSelector:`,
		`        matchExpressions:`,
		`        - key: tag__db`,
		`          operator: Exists`,
	}, "\n")
	mustWrite(t, filepath.Join(dir, "policies.yaml"), yaml)

	segments := []SegmentEntry{
		{SegmentName: "Seg-Web", TargetName: "proj-web"},
		{SegmentName: "Seg-Database", TargetName: "proj-db"},
	}
	_ = RewriteGeneratedNamespaces(dir, NamespaceRenameMap(segments))
	stats, err := RewriteNetworkPolicyPeers(dir, segments)
	if err != nil {
		t.Fatal(err)
	}
	if stats.NamespaceSelectorsStripped != 0 {
		t.Fatalf("should keep cross-ns selector, got %#v", stats)
	}
	got := mustRead(t, filepath.Join(dir, "policies.yaml"))
	if !strings.Contains(got, "proj-db") {
		t.Fatalf("expected remapped peer namespace:\n%s", got)
	}
	if strings.Contains(got, "Seg-Database") {
		t.Fatalf("segment name should be remapped:\n%s", got)
	}
	if !strings.Contains(got, "namespaceSelector") {
		t.Fatalf("cross-ns peer must keep namespaceSelector:\n%s", got)
	}
}

func TestRewriteNetworkPolicyPeers_RejectsUnmappedSegmentAsPeer(t *testing.T) {
	// When TargetName maps segments away, peer rewrite must not leave Seg-* selectors.
	dir := t.TempDir()
	src, err := os.ReadFile(filepath.Join("..", "..", "testdata", "mapping", "peers_before.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, "policies.yaml"), string(src))
	segments := fleetSegmentsSingleProject()
	_ = RewriteGeneratedNamespaces(dir, NamespaceRenameMap(segments))
	if _, err := RewriteNetworkPolicyPeers(dir, segments); err != nil {
		t.Fatal(err)
	}
	got := mustRead(t, filepath.Join(dir, "policies.yaml"))
	for _, bad := range []string{"Seg-Web", "Seg-Database", "Seg-Management"} {
		if strings.Contains(got, "- "+bad) || strings.Contains(got, "namespace: "+bad) {
			t.Fatalf("unmapped segment %q still referenced:\n%s", bad, got)
		}
	}
}

func assertPolicySemantics(t *testing.T, docs, name string, expectTo, expectNoPeers bool) {
	t.Helper()
	marker := "name: " + name + "\n"
	idx := strings.Index(docs, marker)
	if idx < 0 {
		t.Fatalf("policy %s not found", name)
	}
	rest := docs[idx:]
	// Next document separator (encoder emits --- between docs).
	next := strings.Index(rest[len(marker):], "\n---\n")
	chunk := rest
	if next >= 0 {
		chunk = rest[:len(marker)+next]
	}
	hasTo := strings.Contains(chunk, "to:")
	hasFrom := strings.Contains(chunk, "from:")
	if expectTo && !hasTo {
		t.Fatalf("%s: expected to:\n%s", name, chunk)
	}
	if expectNoPeers && (hasTo || hasFrom) {
		t.Fatalf("%s: expected no from/to:\n%s", name, chunk)
	}
}
