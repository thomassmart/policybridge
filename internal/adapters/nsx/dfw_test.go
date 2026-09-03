package nsx

import (
	"testing"

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
