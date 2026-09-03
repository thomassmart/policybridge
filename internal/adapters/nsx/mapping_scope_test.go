package nsx

import (
	"strings"
	"testing"

	"github.com/policybridge/policybridge/internal/fixtures"
	"github.com/policybridge/policybridge/internal/mapping"
)

func TestMappingScopeFromSelection_OmitsUnusedGroups(t *testing.T) {
	resources, err := ValidateDump(scopedMappingDump())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}

	all := MappingScopeFromSelection(resources, nil)
	assertNames(t, all.Groups, "backend", "frontend", "mgmt")
	if containsName(all.Groups, "DefaultMaliciousIpGroup") {
		t.Fatalf("unused inventory group should be omitted: %#v", all.Groups)
	}
	assertNames(t, all.VMs, "backend-01", "frontend-01", "mgmt-01")

	selected := MappingScopeFromSelection(resources, []int{101})
	assertNames(t, selected.Groups, "backend", "frontend")
	if containsName(selected.Groups, "mgmt") {
		t.Fatalf("unselected rule group should be omitted: %#v", selected.Groups)
	}
	assertNames(t, selected.VMs, "backend-01", "frontend-01")
	if !selected.LimitSegments {
		t.Fatal("expected segment membership to limit segment rows")
	}
	if !containsName(selected.SegmentKeys, "seg-1") {
		t.Fatalf("expected seg-1 from group membership, got %#v", selected.SegmentKeys)
	}

	cfg := mapping.DefaultConfigForScope(resources, selected)
	if len(cfg.Segments) != 1 || cfg.Segments[0].SegmentID != "seg-1" {
		t.Fatalf("expected only seg-1, got %#v", cfg.Segments)
	}
	gotGroups := identityNames(cfg.LabelMappings, mapping.IdentityGroup)
	assertNames(t, gotGroups, "backend", "frontend")
}

func TestMappingScopeFromSelection_UnresolvedGroupStillMapped(t *testing.T) {
	resources, err := ValidateDump([]byte(`{
  "virtual_machines": [],
  "segments": [],
  "domains": [{
    "id": "default",
    "resources": {
      "security_policies": [{
        "display_name": "app-policy",
        "rules": [{
          "display_name": "allow",
          "rule_id": 7,
          "action": "ALLOW",
          "source_groups": ["/infra/domains/default/groups/ghost"],
          "destination_groups": ["ANY"]
        }]
      }],
      "groups": []
    }
  }]
}`))
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	scope := MappingScopeFromSelection(resources, nil)
	assertNames(t, scope.Groups, "ghost")
}

func TestDefaultConfigForSelection_UsedByMappingAPI(t *testing.T) {
	resources, err := ValidateDump(fixtures.MinimalNSXDump())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	scope := MappingScopeFromSelection(resources, nil)
	assertNames(t, scope.Groups, "frontend", "backend")
}

func scopedMappingDump() []byte {
	return []byte(`{
  "services": [],
  "virtual_machines": [
    {"display_name": "frontend-01", "external_id": "vm-1"},
    {"display_name": "backend-01", "external_id": "vm-2"},
    {"display_name": "mgmt-01", "external_id": "vm-3"},
    {"display_name": "unused-01", "external_id": "vm-4"}
  ],
  "virtual_network_interface": [],
  "segments": [
    {"display_name": "seg-1", "id": "seg-1", "path": "/infra/segments/seg-1"},
    {"display_name": "seg-unused", "id": "seg-unused", "path": "/infra/segments/seg-unused"}
  ],
  "tier0": [],
  "tier1": [],
  "domains": [{
    "id": "default",
    "display_name": "default",
    "resources": {
      "security_policies": [{
        "display_name": "app-policy",
        "id": "pol-1",
        "rules": [
          {
            "display_name": "allow-http",
            "id": "rule-1",
            "rule_id": 101,
            "action": "ALLOW",
            "services": ["/infra/services/HTTP"],
            "source_groups": ["/infra/domains/default/groups/frontend"],
            "destination_groups": ["/infra/domains/default/groups/backend"]
          },
          {
            "display_name": "allow-ssh",
            "id": "rule-2",
            "rule_id": 102,
            "action": "ALLOW",
            "services": ["/infra/services/SSH"],
            "source_groups": ["/infra/domains/default/groups/mgmt"],
            "destination_groups": ["/infra/domains/default/groups/backend"]
          }
        ]
      }],
      "gateway_policies": [],
      "redirection_policies": [],
      "groups": [
        {
          "display_name": "frontend",
          "id": "grp-frontend",
          "path": "/infra/domains/default/groups/frontend",
          "vm_members": [{"display_name": "frontend-01", "id": "vm-1"}],
          "segment_members": [{"display_name": "seg-1", "id": "seg-1", "path": "/infra/segments/seg-1"}]
        },
        {
          "display_name": "backend",
          "id": "grp-backend",
          "path": "/infra/domains/default/groups/backend",
          "vm_members": [{"display_name": "backend-01", "external_id": "vm-2"}]
        },
        {
          "display_name": "mgmt",
          "id": "grp-mgmt",
          "path": "/infra/domains/default/groups/mgmt",
          "vm_members": [{"display_name": "mgmt-01", "external_id": "vm-3"}]
        },
        {
          "display_name": "DefaultMaliciousIpGroup",
          "id": "DefaultMaliciousIpGroup",
          "path": "/infra/domains/default/groups/DefaultMaliciousIpGroup"
        }
      ]
    }
  }]
}`)
}

func assertNames(t *testing.T, got []string, want ...string) {
	t.Helper()
	for _, name := range want {
		if !containsName(got, name) {
			t.Fatalf("expected %q in %#v", name, got)
		}
	}
}

func containsName(got []string, name string) bool {
	for _, g := range got {
		if g == name {
			return true
		}
	}
	return false
}

func identityNames(entries []mapping.LabelEntry, kind mapping.IdentityKind) []string {
	var names []string
	for _, e := range entries {
		if e.Kind == kind {
			names = append(names, e.NSXIdentity)
		}
	}
	return names
}

func TestShortenPathKeepsSegmentPaths(t *testing.T) {
	if got := shortenPath("/infra/domains/default/groups/frontend"); got != "frontend" {
		t.Fatalf("unexpected shorten: %q", got)
	}
	if got := shortenPath("/infra/segments/seg-1"); !strings.Contains(got, "seg-1") {
		t.Fatalf("unexpected shorten: %q", got)
	}
}
