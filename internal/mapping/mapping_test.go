package mapping

import "testing"

func TestMergePreservesUserEdits(t *testing.T) {
	defaults := Config{Segments: []SegmentEntry{{
		SegmentID: "a", SegmentName: "seg-a", TargetKind: TargetUDN, TargetName: "seg-a",
	}}}
	existing := Config{Segments: []SegmentEntry{{
		SegmentID: "a", SegmentName: "seg-a", TargetKind: TargetNAD, TargetName: "nad-a",
	}}}
	merged := Merge(existing, defaults)
	if merged.Segments[0].TargetKind != TargetNAD {
		t.Fatalf("expected NAD to be preserved")
	}
}

func TestMergePreservesLabelMappings(t *testing.T) {
	defaults := Config{LabelMappings: []LabelEntry{{
		NSXIdentity: "fleet-web", Kind: IdentityVM, LabelKey: "policybridge.io/nsx-vm", LabelValue: "fleet-web",
	}}}
	existing := Config{LabelMappings: []LabelEntry{{
		NSXIdentity: "fleet-web", Kind: IdentityVM, LabelKey: "app", LabelValue: "fleet-web-new",
	}}}
	merged := Merge(existing, defaults)
	if merged.LabelMappings[0].LabelKey != "app" || merged.LabelMappings[0].LabelValue != "fleet-web-new" {
		t.Fatalf("expected label mapping to be preserved, got %#v", merged.LabelMappings[0])
	}
}

func TestToIdentityMap(t *testing.T) {
	m := ToIdentityMap([]LabelEntry{{
		NSXIdentity: "fleet-web", Kind: IdentityGroup, LabelKey: "app", LabelValue: "fleet-web-new",
	}})
	if m["fleet-web"] != "app=fleet-web-new" {
		t.Fatalf("unexpected map: %#v", m)
	}
}

func TestSanitizeName(t *testing.T) {
	if got := sanitizeName("App Segment/01"); got != "App-Segment-01" {
		t.Fatalf("unexpected sanitize: %q", got)
	}
}

func TestMergeDropsIdentitiesMissingFromDefaults(t *testing.T) {
	defaults := Config{LabelMappings: []LabelEntry{{
		NSXIdentity: "frontend", Kind: IdentityGroup, LabelKey: DefaultGroupLabelKey, LabelValue: "frontend",
	}}}
	existing := Config{LabelMappings: []LabelEntry{
		{NSXIdentity: "frontend", Kind: IdentityGroup, LabelKey: "app", LabelValue: "web"},
		{NSXIdentity: "DefaultMaliciousIpGroup", Kind: IdentityGroup, LabelKey: DefaultGroupLabelKey, LabelValue: "DefaultMaliciousIpGroup"},
	}}
	merged := Merge(existing, defaults)
	if len(merged.LabelMappings) != 1 {
		t.Fatalf("expected unused group to be dropped, got %#v", merged.LabelMappings)
	}
	if merged.LabelMappings[0].NSXIdentity != "frontend" || merged.LabelMappings[0].LabelValue != "web" {
		t.Fatalf("expected frontend edit to be preserved, got %#v", merged.LabelMappings[0])
	}
}

func TestDefaultConfigForScopeLimitsRows(t *testing.T) {
	cfg := DefaultConfigForScope(nil, Scope{
		Groups:        []string{"frontend", "backend"},
		VMs:           []string{"web-01"},
		SegmentKeys:   []string{"seg-web"},
		LimitSegments: true,
	})
	if cfg.Segments != nil && len(cfg.Segments) != 0 {
		t.Fatalf("expected no segments without inventory, got %#v", cfg.Segments)
	}
	if len(cfg.LabelMappings) != 3 {
		t.Fatalf("expected 3 label rows, got %#v", cfg.LabelMappings)
	}
}
