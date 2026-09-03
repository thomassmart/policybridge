package export

import (
	"archive/zip"
	"bytes"
	"os"
	"testing"
)

func TestKustomizeExport_GoldenStructure(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"policies.yaml":      "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: test\n",
		"adminPolicies.yaml": "apiVersion: policy.networking.k8s.io/v1alpha1\nkind: AdminNetworkPolicy\nmetadata:\n  name: admin\n",
		"namespaces.yaml":    "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: test-ns\n",
		"udns.yaml":          "apiVersion: k8s.ovn.org/v1\nkind: UserDefinedNetwork\nmetadata:\n  name: udn\n",
		"vms.yaml":           "apiVersion: kubevirt.io/v1\nkind: VirtualMachine\nmetadata:\n  name: vm\n",
		"pods.yaml":          "apiVersion: v1\nkind: Pod\nmetadata:\n  name: pod\n",
	}
	for name, content := range files {
		if err := os.WriteFile(dir+"/"+name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}

	meta := ExportMetadata{
		PolicyBridgeVersion:   "0.1.0",
		VMwareAnalyzerVersion: "v0.2.1",
		NetpolAnalyzerVersion: "v1.4.4",
	}

	data, err := KustomizeExport(dir, []byte(`{"exact":1}`), meta)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}

	requiredPrefixes := []string{
		"policybridge-export/README.md",
		"policybridge-export/base/kustomization.yaml",
		"policybridge-export/overlays/development/kustomization.yaml",
		"policybridge-export/reports/migration-summary.md",
		"policybridge-export/reports/connectivity-comparison.json",
	}

	names := make(map[string]bool)
	for _, f := range zr.File {
		names[f.Name] = true
	}
	for _, req := range requiredPrefixes {
		if !names[req] {
			t.Errorf("missing required entry: %s", req)
		}
	}
}
