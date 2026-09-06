package nsx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratePreparedDump_EmitsHTTPSPort(t *testing.T) {
	dump := []byte(`{
  "services": [],
  "virtual_machines": [
    {"display_name": "frontend-01", "external_id": "vm-1"},
    {"display_name": "backend-01", "external_id": "vm-2"}
  ],
  "virtual_network_interface": [],
  "segments": [],
  "domains": [{
    "id": "default",
    "display_name": "default",
    "resources": {
      "security_policies": [{
        "display_name": "app-policy",
        "category": "Application",
        "scope": ["ANY"],
        "rules": [{
          "display_name": "allow-https",
          "rule_id": 7,
          "action": "ALLOW",
          "direction": "IN_OUT",
          "scope": ["ANY"],
          "services": ["/infra/services/HTTPS"],
          "source_groups": ["/infra/domains/default/groups/frontend"],
          "destination_groups": ["/infra/domains/default/groups/backend"]
        }]
      }],
      "groups": [
        {
          "display_name": "frontend",
          "id": "frontend",
          "path": "/infra/domains/default/groups/frontend",
          "vm_members": [{"display_name": "frontend-01"}]
        },
        {
          "display_name": "backend",
          "id": "backend",
          "path": "/infra/domains/default/groups/backend",
          "vm_members": [{"display_name": "backend-01"}]
        }
      ]
    }
  }]
}`)
	resources, err := ValidateDump(dump)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	prepared, err := PrepareDumpForGeneration(resources, []int{7}, DefaultRuleSpec{Mode: DefaultRuleNewDrop})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}

	dir := t.TempDir()
	dumpPath := filepath.Join(dir, "dump.json")
	if err := WriteDump(prepared, dumpPath); err != nil {
		t.Fatalf("write dump: %v", err)
	}
	genDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(genDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	adapter := New()
	_, stdout, err := adapter.Run(GenerateOptions(dumpPath, genDir, DefaultGenerationConfig())...)
	if err != nil {
		t.Fatalf("generate: %v\n%s", err, stdout)
	}

	yamlPath := filepath.Join(genDir, "k8s_resources", "policies.yaml")
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		alt := filepath.Join(genDir, "policies.yaml")
		data, err = os.ReadFile(alt)
		if err != nil {
			t.Fatalf("read policies.yaml: %v\nstdout:\n%s", err, stdout)
		}
		yamlPath = alt
	}
	text := string(data)
	if !strings.Contains(text, "443") {
		t.Fatalf("expected TCP/443 in %s, got:\n%s\nstdout:\n%s", yamlPath, text, stdout)
	}
	if strings.Count(text, "kind: NetworkPolicy") < 2 {
		t.Fatalf("expected allow NetworkPolicies besides default deny in %s, got:\n%s", yamlPath, text)
	}
}

func TestGeneratePreparedDump_ExpressionGroupsEmitHTTPSPort(t *testing.T) {
	dump := []byte(`{
  "services": [],
  "virtual_machines": [
    {"display_name": "frontend-01", "external_id": "vm-1"},
    {"display_name": "backend-01", "external_id": "vm-2"}
  ],
  "virtual_network_interface": [],
  "segments": [],
  "domains": [{
    "id": "default",
    "display_name": "default",
    "resources": {
      "security_policies": [{
        "display_name": "app-policy",
        "category": "Application",
        "scope": ["ANY"],
        "rules": [{
          "display_name": "allow-https",
          "rule_id": 7,
          "action": "ALLOW",
          "direction": "IN_OUT",
          "scope": ["ANY"],
          "services": ["/infra/services/HTTPS"],
          "source_groups": ["/infra/domains/default/groups/frontend"],
          "destination_groups": ["/infra/domains/default/groups/backend"]
        }]
      }],
      "groups": [
        {
          "display_name": "frontend",
          "id": "frontend",
          "path": "/infra/domains/default/groups/frontend",
          "expression": [{
            "resource_type": "Condition",
            "member_type": "VirtualMachine",
            "key": "Name",
            "operator": "EQUALS",
            "value": "frontend-01"
          }]
        },
        {
          "display_name": "backend",
          "id": "backend",
          "path": "/infra/domains/default/groups/backend",
          "expression": [{
            "resource_type": "Condition",
            "member_type": "VirtualMachine",
            "key": "Name",
            "operator": "EQUALS",
            "value": "backend-01"
          }]
        }
      ]
    }
  }]
}`)
	resources, err := ValidateDump(dump)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	prepared, err := PrepareDumpForGeneration(resources, []int{7}, DefaultRuleSpec{Mode: DefaultRuleNewDrop})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	dir := t.TempDir()
	dumpPath := filepath.Join(dir, "dump.json")
	if err := WriteDump(prepared, dumpPath); err != nil {
		t.Fatalf("write dump: %v", err)
	}
	genDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(genDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	adapter := New()
	_, stdout, err := adapter.Run(GenerateOptions(dumpPath, genDir, DefaultGenerationConfig())...)
	if err != nil {
		t.Fatalf("generate: %v\n%s", err, stdout)
	}
	yamlPath := filepath.Join(genDir, "k8s_resources", "policies.yaml")
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("read policies.yaml: %v\n%s", err, stdout)
	}
	text := string(data)
	if !strings.Contains(text, "443") || strings.Count(text, "kind: NetworkPolicy") < 2 {
		t.Fatalf("expected allow policies with TCP/443 from expression groups, got:\n%s\nstdout:\n%s", text, stdout)
	}
}

func TestGeneratePreparedDump_UntaggedGrpPrefixGroupsEmitHTTPSPort(t *testing.T) {
	dump := []byte(`{
  "services": [],
  "virtual_machines": [
    {"display_name": "fleet-web", "external_id": "vm-web"},
    {"display_name": "fleet-db", "external_id": "vm-db"}
  ],
  "virtual_network_interface": [],
  "segments": [],
  "domains": [{
    "id": "default",
    "display_name": "default",
    "resources": {
      "security_policies": [{
        "display_name": "Fleet-Management-App-Policies",
        "category": "Application",
        "scope": ["ANY"],
        "rules": [{
          "display_name": "allow-https",
          "rule_id": 1036,
          "action": "ALLOW",
          "direction": "IN_OUT",
          "scope": ["ANY"],
          "services": ["/infra/services/HTTPS"],
          "source_groups": ["/infra/domains/default/groups/grp-fleet-web"],
          "destination_groups": ["/infra/domains/default/groups/grp-fleet-db"]
        }]
      }],
      "groups": [
        {
          "display_name": "grp-fleet-web",
          "id": "grp-fleet-web",
          "path": "/infra/domains/default/groups/grp-fleet-web",
          "expression": [{
            "resource_type": "Condition",
            "member_type": "VirtualMachine",
            "key": "Tag",
            "operator": "EQUALS",
            "scope_operator": "EQUALS",
            "value": "telco-lab|fleet-web"
          }]
        },
        {
          "display_name": "grp-fleet-db",
          "id": "grp-fleet-db",
          "path": "/infra/domains/default/groups/grp-fleet-db",
          "expression": [{
            "resource_type": "Condition",
            "member_type": "VirtualMachine",
            "key": "Tag",
            "operator": "EQUALS",
            "scope_operator": "EQUALS",
            "value": "telco-lab|fleet-db"
          }]
        }
      ]
    }
  }]
}`)
	resources, err := ValidateDump(dump)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	prepared, err := PrepareDumpForGeneration(resources, []int{1036}, DefaultRuleSpec{Mode: DefaultRuleNewDrop})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	dir := t.TempDir()
	dumpPath := filepath.Join(dir, "dump.json")
	if err := WriteDump(prepared, dumpPath); err != nil {
		t.Fatalf("write dump: %v", err)
	}
	genDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(genDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	adapter := New()
	_, stdout, err := adapter.Run(GenerateOptions(dumpPath, genDir, DefaultGenerationConfig())...)
	if err != nil {
		t.Fatalf("generate: %v\n%s", err, stdout)
	}
	yamlPath := filepath.Join(genDir, "k8s_resources", "policies.yaml")
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("read policies.yaml: %v\n%s", err, stdout)
	}
	text := string(data)
	if !strings.Contains(text, "443") || strings.Count(text, "kind: NetworkPolicy") < 2 {
		t.Fatalf("expected allow policies with TCP/443 from grp- prefix groups, got:\n%s\nstdout:\n%s", text, stdout)
	}
}

func TestGeneratePreparedDump_ScopePipeTagsEmitHTTPSPort(t *testing.T) {
	dump := []byte(`{
  "services": [],
  "virtual_machines": [
    {"display_name": "workload-320", "external_id": "vm-web", "tags": [{"scope": "workzone", "tag": "web"}]},
    {"display_name": "jumphost", "external_id": "vm-mgmt", "tags": [{"scope": "workzone", "tag": "mgmt"}]}
  ],
  "virtual_network_interface": [],
  "segments": [],
  "domains": [{
    "id": "default",
    "display_name": "default",
    "resources": {
      "security_policies": [{
        "display_name": "app-policy",
        "category": "Application",
        "scope": ["ANY"],
        "rules": [{
          "display_name": "allow-https",
          "rule_id": 7,
          "action": "ALLOW",
          "direction": "IN_OUT",
          "scope": ["ANY"],
          "services": ["/infra/services/HTTPS"],
          "source_groups": ["/infra/domains/default/groups/Grp-Mgmt-Hosts"],
          "destination_groups": ["/infra/domains/default/groups/Grp-Web-Servers"]
        }]
      }],
      "groups": [
        {
          "display_name": "Grp-Web-Servers",
          "id": "Grp-Web-Servers",
          "path": "/infra/domains/default/groups/Grp-Web-Servers",
          "expression": [{
            "resource_type": "Condition",
            "member_type": "VirtualMachine",
            "key": "Tag",
            "operator": "EQUALS",
            "scope_operator": "EQUALS",
            "value": "workzone|web"
          }]
        },
        {
          "display_name": "Grp-Mgmt-Hosts",
          "id": "Grp-Mgmt-Hosts",
          "path": "/infra/domains/default/groups/Grp-Mgmt-Hosts",
          "expression": [{
            "resource_type": "Condition",
            "member_type": "VirtualMachine",
            "key": "Tag",
            "operator": "EQUALS",
            "scope_operator": "EQUALS",
            "value": "workzone|mgmt"
          }]
        }
      ]
    }
  }]
}`)
	resources, err := ValidateDump(dump)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	prepared, err := PrepareDumpForGeneration(resources, []int{7}, DefaultRuleSpec{Mode: DefaultRuleNewDrop})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	dir := t.TempDir()
	dumpPath := filepath.Join(dir, "dump.json")
	if err := WriteDump(prepared, dumpPath); err != nil {
		t.Fatalf("write dump: %v", err)
	}
	genDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(genDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	adapter := New()
	_, stdout, err := adapter.Run(GenerateOptions(dumpPath, genDir, DefaultGenerationConfig())...)
	if err != nil {
		t.Fatalf("generate: %v\n%s", err, stdout)
	}
	yamlPath := filepath.Join(genDir, "k8s_resources", "policies.yaml")
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("read policies.yaml: %v\n%s", err, stdout)
	}
	text := string(data)
	if !strings.Contains(text, "443") || strings.Count(text, "kind: NetworkPolicy") < 2 {
		t.Fatalf("expected allow policies with TCP/443 from scope|tag groups, got:\n%s\nstdout:\n%s", text, stdout)
	}
}
