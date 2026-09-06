package nsx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/policybridge/policybridge/internal/fixtures"
)

func TestExtractDFWRules_FromFixture(t *testing.T) {
	data := fixtures.LoadFixture("one_redundant_covered_by_2_rules.json")
	resources, err := ValidateDump(data)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	rules := ExtractDFWRules(resources)
	if len(rules) == 0 {
		t.Fatal("expected DFW rules")
	}
	found := false
	for _, r := range rules {
		if r.Name == "allowRule" && len(r.Services) > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected allowRule with services, got %#v", rules)
	}
}

func TestFilterDumpByRuleIDs(t *testing.T) {
	data := fixtures.LoadFixture("one_redundant_covered_by_2_rules.json")
	resources, err := ValidateDump(data)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	all := ExtractDFWRules(resources)
	if len(all) < 2 {
		t.Fatalf("fixture should have multiple rules, got %d", len(all))
	}

	keepID := all[0].ID
	filtered, err := FilterDumpByRuleIDs(resources, []int{keepID})
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	kept := ExtractDFWRules(filtered)
	found := false
	for _, r := range kept {
		if r.ID == keepID {
			found = true
		}
		if r.Action == "ALLOW" && r.ID != keepID {
			t.Fatalf("unselected allow rule should be dropped, got %#v", r)
		}
	}
	if !found {
		t.Fatalf("expected selected rule %d to remain, got %#v", keepID, kept)
	}
}

func TestFilterDumpByRuleIDs_InjectsCatchAllDeny(t *testing.T) {
	resources, err := ValidateDump(fixtures.MinimalNSXDump())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	rules := ExtractDFWRules(resources)
	if len(rules) == 0 {
		t.Fatal("expected rules")
	}
	filtered, err := FilterDumpByRuleIDs(resources, []int{rules[0].ID})
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	kept := ExtractDFWRules(filtered)
	foundDeny := false
	for _, r := range kept {
		if r.Action == "DROP" {
			foundDeny = true
			break
		}
	}
	if !foundDeny {
		t.Fatalf("expected a catch-all deny after filtering, got %#v", kept)
	}
}

func TestPrepareDumpForGeneration_NewAllow(t *testing.T) {
	resources, err := ValidateDump(fixtures.MinimalNSXDump())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	rules := ExtractDFWRules(resources)
	filtered, err := PrepareDumpForGeneration(resources, []int{rules[0].ID}, DefaultRuleSpec{Mode: DefaultRuleNewAllow})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	foundAllow := false
	for _, r := range ExtractDFWRules(filtered) {
		if r.Name == "policybridge-default-allow" && r.Action == "ALLOW" {
			foundAllow = true
		}
	}
	if !foundAllow {
		t.Fatalf("expected a catch-all allow, got %#v", ExtractDFWRules(filtered))
	}
}

func TestPrepareDumpForGeneration_NewAllowReplacesExistingDrop(t *testing.T) {
	data := fixtures.LoadFixture("one_redundant_covered_by_2_rules.json")
	resources, err := ValidateDump(data)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	filtered, err := PrepareDumpForGeneration(resources, nil, DefaultRuleSpec{Mode: DefaultRuleNewAllow})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	foundAllow := false
	for _, r := range ExtractDFWRules(filtered) {
		if r.Action == "DROP" && (len(r.Sources) == 0 || r.Sources[0] == "Any" || r.Sources[0] == "ANY") &&
			(len(r.Destinations) == 0 || r.Destinations[0] == "Any" || r.Destinations[0] == "ANY") {
			t.Fatalf("expected existing catch-all drop to be replaced, got %#v", r)
		}
		if r.Name == "policybridge-default-allow" && r.Action == "ALLOW" {
			foundAllow = true
		}
	}
	if !foundAllow {
		t.Fatalf("expected a catch-all allow, got %#v", ExtractDFWRules(filtered))
	}
}

func TestPrepareDumpForGeneration_ExistingRule(t *testing.T) {
	resources, err := ValidateDump(fixtures.MinimalNSXDump())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	rules := ExtractDFWRules(resources)
	keep := rules[0].ID
	filtered, err := PrepareDumpForGeneration(resources, []int{keep}, DefaultRuleSpec{Mode: DefaultRuleExisting, RuleID: keep})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	foundKeep, foundDefault := false, false
	for _, r := range ExtractDFWRules(filtered) {
		if r.ID == keep {
			foundKeep = true
		}
		if r.Name == "policybridge-default-allow" && r.Action == "ALLOW" {
			foundDefault = true
		}
	}
	if !foundKeep {
		t.Fatal("expected existing rule to remain")
	}
	if !foundDefault {
		t.Fatal("expected a global catch-all using the existing rule action")
	}
}

func TestPrepareDumpForGeneration_ExistingRuleKeptWhenUnselected(t *testing.T) {
	data := fixtures.LoadFixture("one_redundant_covered_by_2_rules.json")
	resources, err := ValidateDump(data)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	all := ExtractDFWRules(resources)
	if len(all) < 2 {
		t.Fatal("fixture should have multiple rules")
	}
	keep := all[0].ID
	def := all[len(all)-1].ID
	filtered, err := PrepareDumpForGeneration(resources, []int{keep}, DefaultRuleSpec{Mode: DefaultRuleExisting, RuleID: def})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	foundKeep, foundDef := false, false
	for _, r := range ExtractDFWRules(filtered) {
		if r.ID == keep {
			foundKeep = true
		}
		if r.ID == def {
			foundDef = true
		}
		if r.Name == "policybridge-default-deny" || r.Name == "policybridge-default-allow" {
			t.Fatalf("did not expect a synthetic default, got %#v", r)
		}
	}
	if !foundKeep || !foundDef {
		t.Fatalf("expected selected rule %d and default rule %d, got %#v", keep, def, ExtractDFWRules(filtered))
	}
}

func TestParseDefaultRule(t *testing.T) {
	drop, err := ParseDefaultRule("")
	if err != nil || drop.Mode != DefaultRuleNewDrop {
		t.Fatalf("expected new-drop, got %#v %v", drop, err)
	}
	allow, err := ParseDefaultRule("new-allow")
	if err != nil || allow.Mode != DefaultRuleNewAllow {
		t.Fatalf("expected new-allow, got %#v %v", allow, err)
	}
	existing, err := ParseDefaultRule("1004")
	if err != nil || existing.Mode != DefaultRuleExisting || existing.RuleID != 1004 {
		t.Fatalf("expected existing 1004, got %#v %v", existing, err)
	}
}

func TestNormalizeSelectedRuleIDs(t *testing.T) {
	data := fixtures.LoadFixture("one_redundant_covered_by_2_rules.json")
	resources, err := ValidateDump(data)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	allIDs := AllDFWRuleIDs(resources)
	if len(allIDs) < 2 {
		t.Fatalf("fixture should have multiple rules")
	}
	if got := NormalizeSelectedRuleIDs(resources, allIDs); got != nil {
		t.Fatalf("expected nil for full selection, got %#v", got)
	}
	if got := NormalizeSelectedRuleIDs(resources, allIDs[:1]); got == nil {
		t.Fatal("expected partial selection to be preserved")
	}
}

func TestBuildRuleSelectionView_DefaultAllSelected(t *testing.T) {
	resources, err := ValidateDump(fixtures.MinimalNSXDump())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	view := BuildRuleSelectionView(resources, nil)
	if len(view.Rules) == 0 {
		t.Fatal("expected rules")
	}
	for _, row := range view.Rules {
		if !row.Selected {
			t.Fatalf("expected all selected by default, rule %d", row.ID)
		}
	}
}

func TestPrepareDumpForGeneration_DefaultPolicyIsUnscoped(t *testing.T) {
	dump := []byte(`{
  "virtual_machines": [
    {"display_name": "frontend-01", "external_id": "vm-1"},
    {"display_name": "backend-01", "external_id": "vm-2"}
  ],
  "domains": [{
    "id": "default",
    "display_name": "default",
    "resources": {
      "security_policies": [{
        "display_name": "fleet-policy",
        "id": "pol-fleet",
        "category": "Application",
        "scope": ["/infra/domains/default/groups/frontend"],
        "rules": [{
          "display_name": "allow-http",
          "rule_id": 42,
          "action": "ALLOW",
          "services": ["/infra/services/HTTP"],
          "source_groups": ["/infra/domains/default/groups/frontend"],
          "destination_groups": ["/infra/domains/default/groups/backend"],
          "scope": ["/infra/domains/default/groups/frontend"]
        }]
      }],
      "groups": [
        {"display_name": "frontend", "id": "grp-frontend", "path": "/infra/domains/default/groups/frontend"},
        {"display_name": "backend", "id": "grp-backend", "path": "/infra/domains/default/groups/backend"}
      ]
    }
  }]
}`)
	resources, err := ValidateDump(dump)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	filtered, err := PrepareDumpForGeneration(resources, []int{42}, DefaultRuleSpec{Mode: DefaultRuleNewDrop})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}

	var foundDefault bool
	for di := range filtered.DomainList {
		for pi := range filtered.DomainList[di].Resources.SecurityPolicyList {
			p := filtered.DomainList[di].Resources.SecurityPolicyList[pi]
			if p.Id != nil && *p.Id == "policybridge-default" {
				foundDefault = true
				if p.Category == nil || *p.Category != "Application" {
					t.Fatalf("expected Application category, got %#v", p.Category)
				}
				if len(p.Scope) != 1 || p.Scope[0] != "ANY" {
					t.Fatalf("expected ANY scope, got %#v", p.Scope)
				}
			}
			if p.Id != nil && *p.Id == "pol-fleet" {
				for _, rule := range p.Rules {
					if ptrInt(rule.RuleId) == 1_000_000_000 {
						t.Fatal("default catch-all must not be attached to the scoped application policy")
					}
				}
			}
		}
	}
	if !foundDefault {
		t.Fatal("expected an unscoped Application default policy")
	}
}

func TestExtractDFWRules_ServicePortsFromEntries(t *testing.T) {
	dump := []byte(`{
  "services": [
    {
      "display_name": "HTTPS",
      "id": "HTTPS",
      "path": "/infra/services/HTTPS",
      "service_entries": [{
        "resource_type": "L4PortSetServiceEntry",
        "l4_protocol": "TCP",
        "destination_ports": ["443"]
      }]
    },
    {
      "display_name": "DNS",
      "id": "DNS",
      "path": "/infra/services/DNS",
      "service_entries": [
        {"resource_type": "L4PortSetServiceEntry", "l4_protocol": "UDP", "destination_ports": ["53"]},
        {"resource_type": "L4PortSetServiceEntry", "l4_protocol": "TCP", "destination_ports": ["53"]}
      ]
    },
    {
      "display_name": "Web",
      "id": "Web",
      "path": "/infra/services/Web",
      "service_entries": [{
        "resource_type": "NestedServiceServiceEntry",
        "nested_service_path": "/infra/services/HTTPS"
      }]
    }
  ],
  "virtual_machines": [
    {"display_name": "frontend-01", "external_id": "vm-1"}
  ],
  "domains": [{
    "id": "default",
    "display_name": "default",
    "resources": {
      "security_policies": [{
        "display_name": "app-policy",
        "id": "pol-1",
        "category": "Application",
        "rules": [
          {
            "display_name": "allow-https",
            "rule_id": 1,
            "action": "ALLOW",
            "services": ["/infra/services/HTTPS"],
            "source_groups": ["ANY"],
            "destination_groups": ["ANY"]
          },
          {
            "display_name": "allow-dns",
            "rule_id": 2,
            "action": "ALLOW",
            "services": ["/infra/services/DNS"],
            "source_groups": ["ANY"],
            "destination_groups": ["ANY"]
          },
          {
            "display_name": "allow-web",
            "rule_id": 3,
            "action": "ALLOW",
            "services": ["/infra/services/Web"],
            "source_groups": ["ANY"],
            "destination_groups": ["ANY"]
          }
        ]
      }],
      "groups": []
    }
  }]
}`)
	resources, err := ValidateDump(dump)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	rules := ExtractDFWRules(resources)
	byName := map[string]DFWRuleView{}
	for _, r := range rules {
		byName[r.Name] = r
	}

	https := byName["allow-https"]
	if len(https.ServicePorts) != 1 || https.ServicePorts[0].Name != "HTTPS" ||
		https.ServicePorts[0].Protocol != "TCP" || https.ServicePorts[0].Ports != "443" {
		t.Fatalf("HTTPS ports: %#v", https.ServicePorts)
	}

	dns := byName["allow-dns"]
	if len(dns.ServicePorts) != 2 {
		t.Fatalf("DNS ports: %#v", dns.ServicePorts)
	}

	web := byName["allow-web"]
	if len(web.ServicePorts) != 1 || web.ServicePorts[0].Protocol != "TCP" || web.ServicePorts[0].Ports != "443" {
		t.Fatalf("nested Web should expand to HTTPS TCP/443, got %#v", web.ServicePorts)
	}
}

func TestPrepareDumpForGeneration_InlinesNamedServiceEntries(t *testing.T) {
	dump := []byte(`{
  "services": [{
    "display_name": "HTTPS",
    "id": "HTTPS",
    "path": "/infra/services/HTTPS",
    "service_entries": [{
      "resource_type": "L4PortSetServiceEntry",
      "l4_protocol": "TCP",
      "destination_ports": ["443"]
    }]
  }],
  "virtual_machines": [{"display_name": "web", "external_id": "vm-1"}],
  "domains": [{
    "id": "default",
    "resources": {
      "security_policies": [{
        "display_name": "app",
        "rules": [{
          "display_name": "allow-https",
          "rule_id": 7,
          "action": "ALLOW",
          "services": ["/infra/services/HTTPS"],
          "source_groups": ["ANY"],
          "destination_groups": ["ANY"]
        }]
      }],
      "groups": []
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

	rule := findRuleByID(prepared, 7)
	if rule == nil {
		t.Fatal("expected rule 7")
	}
	if !ruleHasTCPPort(rule, "443") {
		t.Fatalf("expected inlined TCP/443 service entry, got %#v", rule.ServiceEntries)
	}

	prepared.ServiceList = nil
	ports := ExtractDFWRules(prepared)
	found := false
	for _, r := range ports {
		if r.ID != 7 {
			continue
		}
		for _, sp := range r.ServicePorts {
			if sp.Protocol == "TCP" && sp.Ports == "443" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("inlined entries should still resolve after ServiceList is cleared, got %#v", ports)
	}
}

func TestPrepareDumpForGeneration_ResolvesGroupExpressionMembers(t *testing.T) {
	dump := []byte(`{
  "services": [],
  "virtual_machines": [
    {"display_name": "frontend-01", "external_id": "vm-1"},
    {"display_name": "backend-01", "external_id": "vm-2"}
  ],
  "domains": [{
    "id": "default",
    "resources": {
      "security_policies": [{
        "display_name": "app",
        "category": "Application",
        "rules": [{
          "display_name": "allow-https",
          "rule_id": 7,
          "action": "ALLOW",
          "direction": "IN_OUT",
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
            "operator": "CONTAINS",
            "value": "backend"
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
	frontend := findGroupByName(prepared, "frontend")
	if frontend == nil || len(frontend.VMMembers) == 0 || stringOr(frontend.VMMembers[0].Id, nil) != "vm-1" {
		t.Fatalf("expected frontend expression to resolve vm-1, got %#v", frontend)
	}
	backend := findGroupByName(prepared, "backend")
	if backend == nil || len(backend.VMMembers) == 0 || stringOr(backend.VMMembers[0].Id, nil) != "vm-2" {
		t.Fatalf("expected backend expression to resolve vm-2, got %#v", backend)
	}
}

func TestPrepareDumpForGeneration_ResolvesScopePipeTags(t *testing.T) {
	dump := []byte(`{
  "services": [],
  "virtual_machines": [
    {"display_name": "workload-320", "external_id": "vm-web", "tags": [{"scope": "workzone", "tag": "web"}]},
    {"display_name": "jumphost", "external_id": "vm-mgmt", "tags": [{"scope": "workzone", "tag": "mgmt"}]}
  ],
  "domains": [{
    "id": "default",
    "resources": {
      "security_policies": [{
        "display_name": "app",
        "category": "Application",
        "rules": [{
          "display_name": "allow-https",
          "rule_id": 7,
          "action": "ALLOW",
          "direction": "IN_OUT",
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
	web := findGroupByName(prepared, "Grp-Web-Servers")
	if web == nil || !groupHasMemberID(web, "vm-web") {
		t.Fatalf("expected workzone|web to resolve workload-320, got %#v", web)
	}
	mgmt := findGroupByName(prepared, "Grp-Mgmt-Hosts")
	if mgmt == nil || !groupHasMemberID(mgmt, "vm-mgmt") {
		t.Fatalf("expected workzone|mgmt to resolve jumphost, got %#v", mgmt)
	}
}

func TestPrepareDumpForGeneration_AttachesUntaggedVMFromGrpPrefix(t *testing.T) {
	dump := []byte(`{
  "services": [],
  "virtual_machines": [
    {"display_name": "fleet-web", "external_id": "50143950-1821-bf5f-562b-991cb2add3e1"},
    {"display_name": "fleet-db", "external_id": "vm-db"}
  ],
  "domains": [{
    "id": "default",
    "resources": {
      "security_policies": [{
        "display_name": "Fleet-Management-App-Policies",
        "category": "Application",
        "scope": ["/infra/domains/default/groups/grp-fleet-web", "/infra/domains/default/groups/grp-fleet-db"],
        "rules": [{
          "display_name": "allow-https",
          "rule_id": 1036,
          "action": "ALLOW",
          "direction": "IN_OUT",
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
	web := findGroupByName(prepared, "grp-fleet-web")
	if web == nil || !groupHasMemberID(web, "50143950-1821-bf5f-562b-991cb2add3e1") {
		t.Fatalf("expected grp-fleet-web to attach untagged fleet-web VM, got %#v", web)
	}
	db := findGroupByName(prepared, "grp-fleet-db")
	if db == nil || !groupHasMemberID(db, "vm-db") {
		t.Fatalf("expected grp-fleet-db to attach untagged fleet-db VM, got %#v", db)
	}
	if vm := findVMByName(prepared, "fleet-web"); vm == nil || !vmHasTagLiteral(vm, "telco-lab|fleet-web") {
		t.Fatalf("expected fleet-web to carry analyzer tag telco-lab|fleet-web, got %#v", vm)
	}
	if vm := findVMByName(prepared, "fleet-db"); vm == nil || !vmHasTagLiteral(vm, "telco-lab|fleet-db") {
		t.Fatalf("expected fleet-db to carry analyzer tag telco-lab|fleet-db, got %#v", vm)
	}
}

func TestPrepareDumpForGeneration_LiveFleetDump(t *testing.T) {
	const dumpPath = "/tmp/pb-session/policybridge-c4568a46-060f-4483-bd64-9e6066132d93/dump.json"
	data, err := os.ReadFile(dumpPath)
	if err != nil {
		t.Skip("live session dump not present")
	}
	resources, err := ValidateDump(data)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	prepared, err := PrepareDumpForGeneration(resources, []int{1034, 1036, 1043}, DefaultRuleSpec{Mode: DefaultRuleNewDrop})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	web := findGroupByName(prepared, "grp-fleet-web")
	if web == nil || !groupHasMemberID(web, "50143950-1821-bf5f-562b-991cb2add3e1") {
		t.Fatalf("expected grp-fleet-web to include fleet-web, got %#v", web)
	}
	db := findGroupByName(prepared, "grp-fleet-db")
	if db == nil || len(db.VMMembers) == 0 {
		t.Fatalf("expected grp-fleet-db to include fleet-db, got %#v", db)
	}

	dir := t.TempDir()
	outDump := filepath.Join(dir, "dump.json")
	if err := WriteDump(prepared, outDump); err != nil {
		t.Fatalf("write dump: %v", err)
	}
	genDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(genDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	adapter := New()
	_, stdout, err := adapter.Run(GenerateOptions(outDump, genDir, DefaultGenerationConfig())...)
	if err != nil {
		t.Fatalf("generate: %v\n%s", err, stdout)
	}
	yamlPath := filepath.Join(genDir, "k8s_resources", "policies.yaml")
	yaml, err := os.ReadFile(yamlPath)
	if err != nil {
		t.Fatalf("read policies.yaml: %v\n%s", err, stdout)
	}
	text := string(yaml)
	for _, want := range []string{"443", "80", "5432"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected port %s in generated policies, got:\n%s\nstdout:\n%s", want, text, stdout)
		}
	}
}

func groupHasMemberID(group *collector.Group, id string) bool {
	if group == nil {
		return false
	}
	for _, member := range group.VMMembers {
		if stringOr(member.Id, member.DisplayName) == id {
			return true
		}
	}
	return false
}

func TestPrepareDumpForGeneration_WellKnownHTTPSWhenServiceMissing(t *testing.T) {
	resources, err := ValidateDump(fixtures.MinimalNSXDump())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	rules := ExtractDFWRules(resources)
	if len(rules) == 0 {
		t.Fatal("expected rules")
	}
	prepared, err := PrepareDumpForGeneration(resources, []int{rules[0].ID}, DefaultRuleSpec{Mode: DefaultRuleNewDrop})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	rule := findRuleByID(prepared, rules[0].ID)
	if rule == nil || !ruleHasTCPPort(rule, "80") {
		t.Fatalf("expected well-known HTTP TCP/80 when dump has no service catalog, got %#v", rule)
	}
}

func findRuleByID(resources *collector.ResourcesContainerModel, id int) *collector.Rule {
	for di := range resources.DomainList {
		for pi := range resources.DomainList[di].Resources.SecurityPolicyList {
			for ri := range resources.DomainList[di].Resources.SecurityPolicyList[pi].Rules {
				rule := &resources.DomainList[di].Resources.SecurityPolicyList[pi].Rules[ri]
				if ptrInt(rule.RuleId) == id {
					return rule
				}
			}
		}
	}
	return nil
}

func ruleHasTCPPort(rule *collector.Rule, port string) bool {
	for _, entry := range rule.ServiceEntries {
		l4, ok := entry.(*collector.L4PortSetServiceEntry)
		if !ok || l4.L4Protocol == nil || string(*l4.L4Protocol) != "TCP" {
			continue
		}
		for _, p := range l4.DestinationPorts {
			if string(p) == port {
				return true
			}
		}
	}
	return false
}

func TestBuildAnalysisInsights_AllConnectionsWarning(t *testing.T) {
	resources, err := ValidateDump(fixtures.MinimalNSXDump())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	connJSON := `[{"src":"a","dst":"b","conn":"All Connections"}]`
	insights := BuildAnalysisInsights(resources, connJSON)
	if insights.ConnectivitySummary.TotalEdges != 1 || insights.ConnectivitySummary.AllConnectionsEdges != 1 {
		t.Fatalf("unexpected summary: %#v", insights.ConnectivitySummary)
	}
}

func TestPrepareDumpForGeneration_FillsGroupMemberIDsAndPaths(t *testing.T) {
	dump := []byte(`{
  "services": [],
  "virtual_machines": [
    {"display_name": "frontend-01", "external_id": "vm-1"},
    {"display_name": "backend-01", "external_id": "vm-2"}
  ],
  "domains": [{
    "id": "default",
    "resources": {
      "security_policies": [{
        "display_name": "app",
        "category": "Application",
        "rules": [{
          "display_name": "allow-https",
          "rule_id": 7,
          "action": "ALLOW",
          "direction": "IN_OUT",
          "services": ["/infra/services/HTTPS"],
          "source_groups": ["frontend"],
          "destination_groups": ["/infra/domains/default/groups/backend"]
        }]
      }],
      "groups": [
        {"display_name": "frontend", "id": "frontend", "vm_members": [{"display_name": "frontend-01"}]},
        {"display_name": "backend", "id": "backend", "path": "/infra/domains/default/groups/backend", "vm_members": [{"display_name": "backend-01"}]}
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

	frontend := findGroupByName(prepared, "frontend")
	if frontend == nil || frontend.Path == nil || *frontend.Path == "" {
		t.Fatalf("expected frontend group path, got %#v", frontend)
	}
	if len(frontend.VMMembers) == 0 || frontend.VMMembers[0].Id == nil || *frontend.VMMembers[0].Id != "vm-1" {
		t.Fatalf("expected frontend vm member id vm-1, got %#v", frontend)
	}

	if prepared.GetService("/infra/services/HTTPS") == nil {
		t.Fatal("expected HTTPS service to be injected with the rule path")
	}

	dir := t.TempDir()
	dumpPath := filepath.Join(dir, "dump.json")
	if err := WriteDump(prepared, dumpPath); err != nil {
		t.Fatalf("write: %v", err)
	}
	raw, err := os.ReadFile(dumpPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(raw), `"443"`) {
		t.Fatalf("expected persisted TCP/443 service entries, got %s", truncate(string(raw), 800))
	}
	reloaded, err := ValidateDump(raw)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.GetService("/infra/services/HTTPS") == nil {
		t.Fatal("HTTPS service missing after WriteDump round-trip")
	}
	rule := findRuleByID(reloaded, 7)
	if rule == nil || !ruleHasTCPPort(rule, "443") {
		t.Fatalf("inlined HTTPS entries missing after round-trip, got %#v", rule)
	}
}

func findGroupByName(resources *collector.ResourcesContainerModel, name string) *collector.Group {
	for di := range resources.DomainList {
		for gi := range resources.DomainList[di].Resources.GroupList {
			group := &resources.DomainList[di].Resources.GroupList[gi]
			if stringOr(group.DisplayName, group.Id) == name {
				return group
			}
		}
	}
	return nil
}

func findVMByName(resources *collector.ResourcesContainerModel, name string) *collector.VirtualMachine {
	for i := range resources.VirtualMachineList {
		vm := &resources.VirtualMachineList[i]
		if stringOr(vm.DisplayName, vm.ExternalId) == name {
			return vm
		}
	}
	return nil
}
