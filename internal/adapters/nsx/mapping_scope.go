package nsx

import (
	"sort"
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsxgen "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/policybridge/policybridge/internal/mapping"
)

// MappingScopeFromSelection returns mapping identities required by selected DFW rules.
// When selectedIDs is nil, every DFW rule is considered. Groups that are not referenced
// by those rules are omitted even if they exist in inventory.
func MappingScopeFromSelection(resources *collector.ResourcesContainerModel, selectedIDs []int) mapping.Scope {
	scope := mapping.Scope{}
	if resources == nil {
		return scope
	}

	selected := make(map[int]struct{}, len(selectedIDs))
	limitRules := selectedIDs != nil
	for _, id := range selectedIDs {
		selected[id] = struct{}{}
	}

	index := buildGroupIndex(resources)
	groups := make(map[string]struct{})
	vms := make(map[string]struct{})
	segments := make(map[string]struct{})

	for _, domain := range resources.DomainList {
		for _, policy := range domain.Resources.SecurityPolicyList {
			for _, rule := range policy.Rules {
				if limitRules {
					if _, ok := selected[ptrInt(rule.RuleId)]; !ok {
						continue
					}
				}
				refs := append(append([]string{}, rule.SourceGroups...), rule.DestinationGroups...)
				for _, ref := range refs {
					if isAnyEndpoint(ref) {
						continue
					}
					group, ok := lookupGroup(index, ref)
					if !ok {
						groups[shortenPath(ref)] = struct{}{}
						continue
					}
					if name := groupDisplayName(group); name != "" {
						groups[name] = struct{}{}
					}
					addGroupMembers(group, vms, segments)
				}
			}
		}
	}

	scope.Groups = sortedKeys(groups)
	scope.VMs = sortedKeys(vms)
	scope.SegmentKeys = sortedKeys(segments)
	scope.LimitSegments = len(segments) > 0
	return scope
}

func lookupGroup(index map[string]collector.Group, ref string) (collector.Group, bool) {
	if group, ok := index[ref]; ok {
		return group, true
	}
	if group, ok := index[shortenPath(ref)]; ok {
		return group, true
	}
	return collector.Group{}, false
}

func groupDisplayName(group collector.Group) string {
	return stringOr(group.DisplayName, group.Id)
}

func addGroupMembers(group collector.Group, vms, segments map[string]struct{}) {
	for i := range group.VMMembers {
		if name := realizedVMName(&group.VMMembers[i]); name != "" {
			vms[name] = struct{}{}
		}
	}
	for i := range group.Segments {
		addMemberKeys(group.Segments[i], segments)
	}
	for i := range group.SegmentPorts {
		addMemberKeys(group.SegmentPorts[i], segments)
		addSegmentParentFromPort(group.SegmentPorts[i], segments)
	}
}

func realizedVMName(vm *collector.RealizedVirtualMachine) string {
	return stringOr(vm.DisplayName, vm.Id)
}

func addMemberKeys(member nsxgen.PolicyGroupMemberDetails, dest map[string]struct{}) {
	if name := stringOr(member.DisplayName, member.Id); name != "" {
		dest[name] = struct{}{}
	}
	if member.Path == nil || *member.Path == "" {
		return
	}
	path := *member.Path
	dest[path] = struct{}{}
	dest[shortenPath(path)] = struct{}{}
	if strings.HasPrefix(path, "/infra/segments/") {
		dest[strings.TrimPrefix(path, "/infra/segments/")] = struct{}{}
	}
}

func addSegmentParentFromPort(member nsxgen.PolicyGroupMemberDetails, dest map[string]struct{}) {
	if member.Path == nil {
		return
	}
	path := *member.Path
	i := strings.Index(path, "/ports/")
	if i <= 0 {
		return
	}
	parent := path[:i]
	dest[parent] = struct{}{}
	if strings.HasPrefix(parent, "/infra/segments/") {
		dest[strings.TrimPrefix(parent, "/infra/segments/")] = struct{}{}
	}
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
