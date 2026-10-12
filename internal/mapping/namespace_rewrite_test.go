package mapping

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSynthesizedNamespaceMatchesNpGuard(t *testing.T) {
	cases := map[string]string{
		"Seg-Web":         "Seg-Web",
		"App Segment/01":  "AppSegment01",
		"telco_lab.web":   "telco_lab.web",
	}
	for in, want := range cases {
		if got := SynthesizedNamespace(in); got != want {
			t.Fatalf("SynthesizedNamespace(%q)=%q want %q", in, got, want)
		}
	}
}

func TestNamespaceRenameMap(t *testing.T) {
	m := NamespaceRenameMap([]SegmentEntry{
		{SegmentName: "Seg-Web", TargetName: "tom-testing"},
		{SegmentName: "Seg-Database", TargetName: "Seg-Database"},
		{SegmentName: "Seg-Management", TargetName: "  "},
	})
	if len(m) != 1 || m["Seg-Web"] != "tom-testing" {
		t.Fatalf("unexpected renames: %#v", m)
	}
}

func TestRewriteGeneratedNamespaces(t *testing.T) {
	dir := t.TempDir()
	policies := strings.Join([]string{
		`apiVersion: networking.k8s.io/v1`,
		`kind: NetworkPolicy`,
		`metadata:`,
		`  name: policy-4`,
		`  namespace: Seg-Web`,
		`  annotations:`,
		`    description: default deny policy for namespace Seg-Web`,
		`spec:`,
		`  podSelector: {}`,
		`  ingress:`,
		`  - from:`,
		`    - namespaceSelector:`,
		`        matchExpressions:`,
		`        - key: kubernetes.io/metadata.name`,
		`          operator: In`,
		`          values:`,
		`          - Seg-Web`,
		`---`,
		`apiVersion: networking.k8s.io/v1`,
		`kind: NetworkPolicy`,
		`metadata:`,
		`  name: default-deny-for-Seg-Web`,
		`  namespace: Seg-Web`,
		`spec:`,
		`  podSelector: {}`,
	}, "\n")
	namespaces := strings.Join([]string{
		`apiVersion: v1`,
		`kind: Namespace`,
		`metadata:`,
		`  name: Seg-Web`,
		`  labels:`,
		`    kubernetes.io/metadata.name: Seg-Web`,
	}, "\n")
	udns := strings.Join([]string{
		`apiVersion: k8s.ovn.org/v1`,
		`kind: UserDefinedNetwork`,
		`metadata:`,
		`  name: udn-Seg-Web`,
		`  namespace: Seg-Web`,
	}, "\n")

	mustWrite(t, filepath.Join(dir, "policies.yaml"), policies)
	mustWrite(t, filepath.Join(dir, "namespaces.yaml"), namespaces)
	mustWrite(t, filepath.Join(dir, "udns.yaml"), udns)

	if err := RewriteGeneratedNamespaces(dir, map[string]string{"Seg-Web": "tom-testing"}); err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	gotPolicies := mustRead(t, filepath.Join(dir, "policies.yaml"))
	for _, want := range []string{
		"namespace: tom-testing",
		"name: default-deny-for-tom-testing",
		"- tom-testing",
		"description: default deny policy for namespace tom-testing",
	} {
		if !strings.Contains(gotPolicies, want) {
			t.Fatalf("policies missing %q:\n%s", want, gotPolicies)
		}
	}
	if strings.Contains(gotPolicies, "Seg-Web") {
		t.Fatalf("policies still contain Seg-Web:\n%s", gotPolicies)
	}

	gotNS := mustRead(t, filepath.Join(dir, "namespaces.yaml"))
	if !strings.Contains(gotNS, "name: tom-testing") {
		t.Fatalf("namespace not renamed:\n%s", gotNS)
	}
	if strings.Contains(gotNS, "Seg-Web") {
		t.Fatalf("namespaces still contain Seg-Web:\n%s", gotNS)
	}

	gotUDN := mustRead(t, filepath.Join(dir, "udns.yaml"))
	for _, want := range []string{"name: udn-tom-testing", "namespace: tom-testing"} {
		if !strings.Contains(gotUDN, want) {
			t.Fatalf("udn missing %q:\n%s", want, gotUDN)
		}
	}
}

func TestRewriteGeneratedNamespaces_DedupesCollapsedNamespaces(t *testing.T) {
	dir := t.TempDir()
	namespaces := strings.Join([]string{
		`apiVersion: v1`,
		`kind: Namespace`,
		`metadata:`,
		`  name: Seg-Web`,
		`---`,
		`apiVersion: v1`,
		`kind: Namespace`,
		`metadata:`,
		`  name: Seg-Database`,
	}, "\n")
	mustWrite(t, filepath.Join(dir, "namespaces.yaml"), namespaces)

	renames := map[string]string{
		"Seg-Web":      "tom-testing",
		"Seg-Database": "tom-testing",
	}
	if err := RewriteGeneratedNamespaces(dir, renames); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	got := mustRead(t, filepath.Join(dir, "namespaces.yaml"))
	if strings.Count(got, "kind: Namespace") != 1 {
		t.Fatalf("expected one Namespace after collapse:\n%s", got)
	}
	if !strings.Contains(got, "name: tom-testing") {
		t.Fatalf("expected tom-testing:\n%s", got)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
