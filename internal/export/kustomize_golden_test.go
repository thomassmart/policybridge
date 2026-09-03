package export

import (
	"archive/zip"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestKustomizeExport_BuildGoldens(t *testing.T) {
	build := kustomizeBuildCmd()
	if build == nil {
		t.Skip("kustomize/kubectl not installed")
	}

	dir := t.TempDir()
	files := map[string]string{
		"policies.yaml":      "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: test\nspec:\n  podSelector: {}\n  policyTypes:\n  - Ingress\n",
		"adminPolicies.yaml": "apiVersion: policy.networking.k8s.io/v1alpha1\nkind: AdminNetworkPolicy\nmetadata:\n  name: admin\nspec:\n  priority: 10\n  subject:\n    namespaces: {}\n  ingress: []\n  egress: []\n",
		"namespaces.yaml":    "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: test-ns\n",
		"udns.yaml":          "apiVersion: k8s.ovn.org/v1\nkind: UserDefinedNetwork\nmetadata:\n  name: udn\nspec:\n  topology: Layer3\n  subnets:\n  - cidr: 10.0.0.0/24\n",
		"vms.yaml":           "apiVersion: kubevirt.io/v1\nkind: VirtualMachine\nmetadata:\n  name: vm\nspec:\n  running: false\n  template:\n    spec:\n      domain:\n        devices: {}\n",
		"pods.yaml":          "apiVersion: v1\nkind: Pod\nmetadata:\n  name: pod\nspec:\n  containers:\n  - name: app\n    image: example.com/app:latest\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}

	meta := ExportMetadata{
		PolicyBridgeVersion:   "0.1.0",
		VMwareAnalyzerVersion: "v0.2.1",
		NetpolAnalyzerVersion: "v1.4.4",
	}

	data, err := KustomizeExport(dir, nil, meta)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	extractDir := t.TempDir()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if err := validateZipPath(f.Name); err != nil {
			t.Fatalf("zip slip: %v", err)
		}
		dest := filepath.Join(extractDir, f.Name)
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			t.Fatal(err)
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		out, err := os.Create(dest)
		if err != nil {
			rc.Close()
			t.Fatal(err)
		}
		_, err = out.ReadFrom(rc)
		rc.Close()
		out.Close()
		if err != nil {
			t.Fatal(err)
		}
	}

	overlays := []string{
		"policybridge-export/base",
		"policybridge-export/overlays/development",
		"policybridge-export/overlays/test",
		"policybridge-export/overlays/production",
	}
	for _, overlay := range overlays {
		cmd := build(filepath.Join(extractDir, overlay))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("kustomize build %s: %v\n%s", overlay, err, out)
		}
		if len(out) == 0 {
			t.Fatalf("kustomize build %s produced empty output", overlay)
		}
	}
}

func kustomizeBuildCmd() func(dir string) *exec.Cmd {
	if _, err := exec.LookPath("kustomize"); err == nil {
		return func(dir string) *exec.Cmd {
			return exec.Command("kustomize", "build", dir)
		}
	}
	if _, err := exec.LookPath("kubectl"); err == nil {
		return func(dir string) *exec.Cmd {
			return exec.Command("kubectl", "kustomize", dir)
		}
	}
	return nil
}
