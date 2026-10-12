package mapping

import (
	"sort"
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
)

// Scope lists NSX identities that should appear in default mapping rows.
// Groups and VMs are always limited to the provided names. Segments are limited
// only when LimitSegments is true; otherwise every collected segment is included.
type Scope struct {
	Groups        []string
	VMs           []string
	SegmentKeys   []string
	LimitSegments bool
}

// SegmentTargetKind is the Kubernetes networking target for an NSX segment.
type SegmentTargetKind string

const (
	TargetUDN        SegmentTargetKind = "udn"
	TargetNAD        SegmentTargetKind = "nad"
	TargetPodNetwork SegmentTargetKind = "pod-network"
)

// IdentityKind classifies an NSX identity for label mapping.
type IdentityKind string

const (
	IdentityVM    IdentityKind = "vm"
	IdentityGroup IdentityKind = "group"
)

// Default label keys — cluster-neutral, no PolicyBridge or NSX branding.
const (
	DefaultWorkloadLabelKey = "app.kubernetes.io/name"
	DefaultGroupLabelKey    = "network.microseg/group"
)

// SegmentEntry maps one NSX segment to a Kubernetes networking construct.
type SegmentEntry struct {
	SegmentID   string            `json:"segmentId"`
	SegmentName string            `json:"segmentName"`
	TargetKind  SegmentTargetKind `json:"targetKind"`
	TargetName  string            `json:"targetName"`
	Labels      map[string]string `json:"labels,omitempty"` // deprecated; use LabelMappings
}

// LabelEntry maps an NSX VM or group to target Kubernetes labels.
type LabelEntry struct {
	NSXIdentity string       `json:"nsxIdentity"`
	Kind        IdentityKind `json:"kind"`
	LabelKey    string       `json:"labelKey"`
	LabelValue  string       `json:"labelValue"`
}

// Config holds user-defined segment and label mappings for a session.
type Config struct {
	Segments      []SegmentEntry `json:"segments"`
	LabelMappings []LabelEntry   `json:"labelMappings,omitempty"`
}

// DefaultConfig builds mapping rows from every collected NSX identity.
func DefaultConfig(resources *collector.ResourcesContainerModel) Config {
	return DefaultConfigForScope(resources, inventoryScope(resources))
}

// DefaultConfigForScope builds mapping rows limited to identities in scope.
func DefaultConfigForScope(resources *collector.ResourcesContainerModel, scope Scope) Config {
	return Config{
		Segments:      scopedSegments(resources, scope),
		LabelMappings: append(labelEntries(IdentityVM, scope.VMs, DefaultWorkloadLabelKey), labelEntries(IdentityGroup, scope.Groups, DefaultGroupLabelKey)...),
	}
}

// Merge preserves user edits when refreshing from dump.
func Merge(existing, defaults Config) Config {
	out := Config{
		Segments:      mergeSegments(existing.Segments, defaults.Segments),
		LabelMappings: mergeLabels(existing.LabelMappings, defaults.LabelMappings),
	}
	return out
}

// ToIdentityMap maps NSX identities to comparison identities for validation.
// When label key and value are set, the mapped identity is "key=value".
func ToIdentityMap(entries []LabelEntry) map[string]string {
	return toIdentityMapFrom(GroupLabelEntries(entries))
}

// ToIdentityMapWithWorkloads includes VM patch mappings for validation against migrated workloads.
func ToIdentityMapWithWorkloads(entries []LabelEntry) map[string]string {
	return toIdentityMapFrom(append(GroupLabelEntries(entries), WorkloadPatchEntries(entries)...))
}

func toIdentityMapFrom(entries []LabelEntry) map[string]string {
	m := make(map[string]string, len(entries))
	for _, e := range entries {
		if e.NSXIdentity == "" {
			continue
		}
		switch {
		case e.LabelKey != "" && e.LabelValue != "":
			m[e.NSXIdentity] = e.LabelKey + "=" + e.LabelValue
		case e.LabelValue != "":
			m[e.NSXIdentity] = e.LabelValue
		default:
			m[e.NSXIdentity] = e.NSXIdentity
		}
	}
	return m
}

func mergeSegments(existing, defaults []SegmentEntry) []SegmentEntry {
	if len(existing) == 0 {
		return defaults
	}
	byID := make(map[string]SegmentEntry, len(existing))
	for _, e := range existing {
		byID[e.SegmentID] = e
	}
	out := make([]SegmentEntry, 0, len(defaults))
	for _, d := range defaults {
		if e, ok := byID[d.SegmentID]; ok {
			if e.TargetName == "" {
				e.TargetName = d.TargetName
			}
			out = append(out, e)
			continue
		}
		out = append(out, d)
	}
	return out
}

func mergeLabels(existing, defaults []LabelEntry) []LabelEntry {
	if len(existing) == 0 {
		return defaults
	}
	key := func(e LabelEntry) string { return string(e.Kind) + "\x00" + e.NSXIdentity }
	byKey := make(map[string]LabelEntry, len(existing))
	for _, e := range existing {
		byKey[key(e)] = e
	}
	out := make([]LabelEntry, 0, len(defaults)+len(existing))
	seen := make(map[string]bool, len(defaults))
	for _, d := range defaults {
		k := key(d)
		seen[k] = true
		if e, ok := byKey[k]; ok {
			if e.LabelKey == "" {
				e.LabelKey = d.LabelKey
			}
			if e.LabelValue == "" {
				e.LabelValue = d.LabelValue
			}
			out = append(out, e)
			continue
		}
		out = append(out, d)
	}
	// Keep client-supplied VM workload patches even when the VM is outside the
	// current rule scope (groups may not list VM members in the dump).
	for _, e := range existing {
		k := key(e)
		if seen[k] || e.Kind != IdentityVM {
			continue
		}
		out = append(out, e)
	}
	return out
}

func inventoryScope(resources *collector.ResourcesContainerModel) Scope {
	scope := Scope{VMs: make([]string, 0, len(resources.VirtualMachineList))}
	for _, vm := range resources.VirtualMachineList {
		if name := vmName(&vm); name != "" {
			scope.VMs = append(scope.VMs, name)
		}
	}
	for _, domain := range resources.DomainList {
		for _, group := range domain.Resources.GroupList {
			if name := groupName(&group); name != "" {
				scope.Groups = append(scope.Groups, name)
			}
		}
	}
	return scope
}

func scopedSegments(resources *collector.ResourcesContainerModel, scope Scope) []SegmentEntry {
	if resources == nil {
		return nil
	}
	allowed := make(map[string]struct{}, len(scope.SegmentKeys))
	for _, key := range scope.SegmentKeys {
		if key != "" {
			allowed[key] = struct{}{}
		}
	}
	out := make([]SegmentEntry, 0, len(resources.SegmentList))
	for _, seg := range resources.SegmentList {
		if scope.LimitSegments && !segmentAllowed(&seg, allowed) {
			continue
		}
		name := segmentName(&seg)
		id := segmentID(&seg)
		out = append(out, SegmentEntry{
			SegmentID:   id,
			SegmentName: name,
			TargetKind:  TargetUDN,
			// Default to the namespace vmware-analyzer synthesises so unchanged rows are no-ops.
			TargetName: SynthesizedNamespace(name),
		})
	}
	return out
}

func segmentAllowed(seg *collector.Segment, allowed map[string]struct{}) bool {
	for _, key := range []string{segmentID(seg), segmentName(seg)} {
		if _, ok := allowed[key]; ok {
			return true
		}
	}
	if seg.Path != nil {
		path := *seg.Path
		if _, ok := allowed[path]; ok {
			return true
		}
		if strings.HasPrefix(path, "/infra/segments/") {
			if _, ok := allowed[strings.TrimPrefix(path, "/infra/segments/")]; ok {
				return true
			}
		}
	}
	return false
}

func labelEntries(kind IdentityKind, names []string, key string) []LabelEntry {
	seen := make(map[string]bool, len(names))
	var entries []LabelEntry
	for _, name := range names {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		entries = append(entries, LabelEntry{
			NSXIdentity: name,
			Kind:        kind,
			LabelKey:    key,
			LabelValue:  sanitizeName(name),
		})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].NSXIdentity < entries[j].NSXIdentity
	})
	return entries
}

func vmName(vm *collector.VirtualMachine) string {
	if vm.DisplayName != nil && *vm.DisplayName != "" {
		return *vm.DisplayName
	}
	if vm.ExternalId != nil && *vm.ExternalId != "" {
		return *vm.ExternalId
	}
	return ""
}

func groupName(group *collector.Group) string {
	if group.DisplayName != nil && *group.DisplayName != "" {
		return *group.DisplayName
	}
	if group.Id != nil && *group.Id != "" {
		return *group.Id
	}
	return ""
}

func segmentName(seg *collector.Segment) string {
	if seg.DisplayName != nil && *seg.DisplayName != "" {
		return *seg.DisplayName
	}
	if seg.Id != nil {
		return *seg.Id
	}
	return "segment"
}

func segmentID(seg *collector.Segment) string {
	if seg.Id != nil {
		return *seg.Id
	}
	return segmentName(seg)
}

func sanitizeName(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			out = append(out, r)
		case r == '-' || r == '.':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "segment"
	}
	return string(out)
}
