package export

import (
	"archive/zip"
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestValidateZipPath_RejectsTraversal(t *testing.T) {
	cases := []string{
		"../etc/passwd",
		"/etc/passwd",
		"foo/../../bar",
	}
	for _, c := range cases {
		if err := validateZipPath(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestValidateZipPath_AllowsValid(t *testing.T) {
	cases := []string{
		"policybridge-export/base/kustomization.yaml",
		"policybridge-export/overlays/dev/kustomization.yaml",
	}
	for _, c := range cases {
		if err := validateZipPath(c); err != nil {
			t.Errorf("unexpected error for %q: %v", c, err)
		}
	}
}

func TestKustomizeExport_Structure(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/policies.yaml", []byte("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/namespaces.yaml", []byte("apiVersion: v1\nkind: Namespace\n"), 0600); err != nil {
		t.Fatal(err)
	}

	meta := ExportMetadata{
		PolicyBridgeVersion:   "0.1.0",
		VMwareAnalyzerVersion: "v0.2.1",
		NetpolAnalyzerVersion: "v1.4.4",
	}

	data, err := KustomizeExport(dir, nil, meta)
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("read zip: %v", err)
	}

	expected := []string{
		"policybridge-export/README.md",
		"policybridge-export/base/kustomization.yaml",
		"policybridge-export/base/policies/kustomization.yaml",
		"policybridge-export/base/policies/policies.yaml",
		"policybridge-export/base/networking/kustomization.yaml",
		"policybridge-export/base/networking/namespaces.yaml",
		"policybridge-export/overlays/development/kustomization.yaml",
		"policybridge-export/overlays/test/kustomization.yaml",
		"policybridge-export/overlays/production/kustomization.yaml",
		"policybridge-export/reports/migration-summary.md",
	}

	found := make(map[string]bool)
	for _, f := range zr.File {
		found[f.Name] = true
		if err := validateZipPath(f.Name); err != nil {
			t.Errorf("zip slip in %s: %v", f.Name, err)
		}
	}

	for _, e := range expected {
		if !found[e] {
			t.Errorf("missing zip entry: %s", e)
		}
	}
}

func TestYAMLExport_Order(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/policies.yaml", []byte("kind: NetworkPolicy\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/namespaces.yaml", []byte("kind: Namespace\n"), 0600); err != nil {
		t.Fatal(err)
	}

	data, err := YAMLExport(dir, ExportMetadata{PolicyBridgeVersion: "0.1.0"})
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	content := string(data)
	nsIdx := strings.Index(content, "kind: Namespace")
	npIdx := strings.Index(content, "kind: NetworkPolicy")
	if nsIdx < 0 || npIdx < 0 {
		t.Fatal("missing expected kinds")
	}
	if nsIdx > npIdx {
		t.Error("namespaces should appear before network policies")
	}
}
