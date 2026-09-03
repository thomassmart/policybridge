package mapping

import (
	"strings"
	"testing"
)

func TestLabelPatchScript(t *testing.T) {
	entries := []LabelEntry{
		{NSXIdentity: "fleet-web", Kind: IdentityVM, LabelKey: "app.kubernetes.io/name", LabelValue: "fleet-web"},
		{NSXIdentity: "fleet-db", Kind: IdentityVM, LabelKey: "app.kubernetes.io/name", LabelValue: "fleet-db"},
		{NSXIdentity: "grp-fleet-web", Kind: IdentityGroup, LabelKey: "network.microseg/group", LabelValue: "fleet-web"},
	}
	script := LabelPatchScript(entries, DefaultPatchOptions())
	if !strings.Contains(script, "fleet-web") {
		t.Fatalf("expected fleet-web in script: %s", script)
	}
	if !strings.Contains(script, "app.kubernetes.io/name") {
		t.Fatalf("expected label key in script")
	}
	if strings.Contains(script, "grp-fleet-web") {
		t.Fatalf("group mappings should not appear in workload patch script")
	}
}

func TestLabelPatchJSON(t *testing.T) {
	data, err := LabelPatchJSON([]LabelEntry{
		{NSXIdentity: "fleet-web", Kind: IdentityVM, LabelKey: "app", LabelValue: "fleet-web"},
	}, DefaultPatchOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "fleet-web") {
		t.Fatalf("unexpected json: %s", string(data))
	}
}

func TestToIdentityMapGroupsOnly(t *testing.T) {
	entries := []LabelEntry{
		{NSXIdentity: "fleet-web", Kind: IdentityVM, LabelKey: "app", LabelValue: "fleet-web"},
		{NSXIdentity: "grp-fleet-web", Kind: IdentityGroup, LabelKey: "network.microseg/group", LabelValue: "fleet-web"},
	}
	m := ToIdentityMap(entries)
	if _, ok := m["fleet-web"]; ok {
		t.Fatalf("VM entries should not be in group-only identity map")
	}
	if m["grp-fleet-web"] != "network.microseg/group=fleet-web" {
		t.Fatalf("unexpected group map: %#v", m)
	}
}

func TestToIdentityMapWithWorkloads(t *testing.T) {
	entries := []LabelEntry{
		{NSXIdentity: "fleet-web", Kind: IdentityVM, LabelKey: "app", LabelValue: "fleet-web-new"},
	}
	m := ToIdentityMapWithWorkloads(entries)
	if m["fleet-web"] != "app=fleet-web-new" {
		t.Fatalf("unexpected map: %#v", m)
	}
}
