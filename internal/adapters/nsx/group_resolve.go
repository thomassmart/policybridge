package nsx

import (
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsxgen "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
)

// ensureRuleDefaults fills NSX fields the UI treats as defaults but vmware-analyzer
// skips or mis-parses when omitted (nil action, empty direction, mixed-case ANY).
func ensureRuleDefaults(resources *collector.ResourcesContainerModel) {
	if resources == nil {
		return
	}
	allow := nsxgen.RuleActionALLOW
	inout := nsxgen.RuleDirectionINOUT
	for di := range resources.DomainList {
		policies := resources.DomainList[di].Resources.SecurityPolicyList
		for pi := range policies {
			for ri := range policies[pi].Rules {
				rule := &policies[pi].Rules[ri]
				if rule.Action == nil {
					rule.Action = &allow
				}
				if rule.Direction == "" {
					rule.Direction = inout
				}
				rule.Services = normalizeAnyPaths(rule.Services)
				rule.SourceGroups = normalizeAnyPaths(rule.SourceGroups)
				rule.DestinationGroups = normalizeAnyPaths(rule.DestinationGroups)
				rule.Scope = normalizeAnyPaths(rule.Scope)
			}
		}
	}
}

func normalizeAnyPaths(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := make([]string, len(values))
	for i, v := range values {
		if isAnyEndpoint(v) || isAnyService(v) {
			out[i] = "ANY"
			continue
		}
		out[i] = v
	}
	return out
}

// ensureResolvableGroups makes DFW group references visible to GetGroup (exact path)
// and fills vm_member ids so groupToVMsList can match VirtualMachine.external_id.
func ensureResolvableGroups(resources *collector.ResourcesContainerModel) {
	if resources == nil {
		return
	}
	ensureGroupPaths(resources)
	copyTagsFromGroupMembers(resources)
	populateGroupMembersFromExpressions(resources)
	fillGroupMemberIDs(resources)
	attachSingletonVMsToEmptyGroups(resources)
	applyGroupTagExpressionsToMembers(resources)
	aliasGroupsForRulePaths(resources)
}

var groupNamePrefixes = []string{"grp-", "group-", "gs-"}

func copyTagsFromGroupMembers(resources *collector.ResourcesContainerModel) {
	vmsByExt := map[string]*collector.VirtualMachine{}
	vmsByName := map[string]*collector.VirtualMachine{}
	for i := range resources.VirtualMachineList {
		vm := &resources.VirtualMachineList[i]
		if vm.ExternalId != nil && *vm.ExternalId != "" {
			vmsByExt[*vm.ExternalId] = vm
		}
		if name := stringOr(vm.DisplayName, vm.ExternalId); name != "" {
			vmsByName[strings.ToLower(name)] = vm
		}
	}
	for di := range resources.DomainList {
		for _, group := range resources.DomainList[di].Resources.GroupList {
			for _, member := range group.VMMembers {
				if len(member.Tags) == 0 {
					continue
				}
				vm := lookupInventoryVM(member, vmsByExt, vmsByName)
				if vm == nil || len(vm.Tags) > 0 {
					continue
				}
				vm.Tags = append([]nsxgen.Tag{}, member.Tags...)
			}
		}
	}
}

func lookupInventoryVM(member collector.RealizedVirtualMachine, byExt, byName map[string]*collector.VirtualMachine) *collector.VirtualMachine {
	if member.Id != nil && *member.Id != "" {
		if vm := byExt[*member.Id]; vm != nil {
			return vm
		}
	}
	name := stringOr(member.DisplayName, member.Id)
	if name == "" {
		return nil
	}
	if vm := byName[strings.ToLower(name)]; vm != nil {
		return vm
	}
	return byExt[name]
}

func ensureGroupPaths(resources *collector.ResourcesContainerModel) {
	for di := range resources.DomainList {
		domain := &resources.DomainList[di]
		prefix := groupPathPrefix(domain)
		for gi := range domain.Resources.GroupList {
			group := &domain.Resources.GroupList[gi]
			if group.Path != nil && *group.Path != "" {
				continue
			}
			name := stringOr(group.Id, group.DisplayName)
			if name == "" {
				continue
			}
			path := prefix + name
			group.Path = &path
		}
	}
}

func groupPathPrefix(domain *collector.Domain) string {
	if domain == nil {
		return "/infra/domains/default/groups/"
	}
	if domain.Path != nil && strings.Contains(*domain.Path, "/domains/") {
		return strings.TrimSuffix(*domain.Path, "/") + "/groups/"
	}
	id := stringOr(domain.Id, domain.DisplayName)
	if id == "" {
		id = "default"
	}
	return "/infra/domains/" + id + "/groups/"
}

func fillGroupMemberIDs(resources *collector.ResourcesContainerModel) {
	vmsByName := map[string]*collector.VirtualMachine{}
	vmsByExt := map[string]*collector.VirtualMachine{}
	for i := range resources.VirtualMachineList {
		vm := &resources.VirtualMachineList[i]
		if name := stringOr(vm.DisplayName, vm.ExternalId); name != "" {
			vmsByName[name] = vm
		}
		if vm.ExternalId != nil && *vm.ExternalId != "" {
			vmsByExt[*vm.ExternalId] = vm
		}
	}

	for di := range resources.DomainList {
		for gi := range resources.DomainList[di].Resources.GroupList {
			group := &resources.DomainList[di].Resources.GroupList[gi]
			for mi := range group.VMMembers {
				member := &group.VMMembers[mi]
				if member.Id != nil && *member.Id != "" {
					if _, ok := vmsByExt[*member.Id]; ok {
						continue
					}
				}
				name := stringOr(member.DisplayName, member.Id)
				vm := vmsByName[name]
				if vm == nil {
					vm = vmsByExt[name]
				}
				if vm == nil || vm.ExternalId == nil || *vm.ExternalId == "" {
					continue
				}
				member.Id = vm.ExternalId
				if member.DisplayName == nil {
					member.DisplayName = vm.DisplayName
				}
			}
		}
	}
}

func attachSingletonVMsToEmptyGroups(resources *collector.ResourcesContainerModel) {
	vmsByName := map[string]*collector.VirtualMachine{}
	for i := range resources.VirtualMachineList {
		vm := &resources.VirtualMachineList[i]
		if name := stringOr(vm.DisplayName, vm.ExternalId); name != "" {
			vmsByName[name] = vm
		}
	}

	for di := range resources.DomainList {
		for gi := range resources.DomainList[di].Resources.GroupList {
			group := &resources.DomainList[di].Resources.GroupList[gi]
			if groupHasRealizedMembers(*group) {
				continue
			}
			vm := uniqueVMForEmptyGroup(group, vmsByName)
			if vm == nil || vm.ExternalId == nil {
				continue
			}
			group.VMMembers = []collector.RealizedVirtualMachine{{
				RealizedVirtualMachine: nsxgen.RealizedVirtualMachine{
					DisplayName: vm.DisplayName,
					Id:          vm.ExternalId,
				},
			}}
		}
	}
}

func aliasGroupsForRulePaths(resources *collector.ResourcesContainerModel) {
	index := buildGroupIndex(resources)
	have := map[string]bool{}
	for di := range resources.DomainList {
		for _, group := range resources.DomainList[di].Resources.GroupList {
			if group.Path != nil {
				have[*group.Path] = true
			}
		}
	}

	for di := range resources.DomainList {
		domain := &resources.DomainList[di]
		var aliases []collector.Group
		for _, policy := range domain.Resources.SecurityPolicyList {
			for _, rule := range policy.Rules {
				refs := append(append([]string{}, rule.SourceGroups...), rule.DestinationGroups...)
				refs = append(refs, rule.Scope...)
				for _, path := range refs {
					if isAnyEndpoint(path) || have[path] {
						continue
					}
					group, ok := lookupGroup(index, path)
					if !ok {
						continue
					}
					clone := group
					p := path
					clone.Path = &p
					aliases = append(aliases, clone)
					have[path] = true
				}
			}
		}
		domain.Resources.GroupList = append(domain.Resources.GroupList, aliases...)
	}
}

func uniqueVMForEmptyGroup(group *collector.Group, vmsByName map[string]*collector.VirtualMachine) *collector.VirtualMachine {
	if group == nil {
		return nil
	}
	seen := map[string]*collector.VirtualMachine{}
	for _, candidate := range groupNameCandidates(group) {
		vm := uniqueVMForGroupName(candidate, vmsByName)
		if vm == nil || vm.ExternalId == nil || *vm.ExternalId == "" {
			continue
		}
		seen[*vm.ExternalId] = vm
	}
	if len(seen) != 1 {
		return nil
	}
	for _, vm := range seen {
		return vm
	}
	return nil
}

func groupNameCandidates(group *collector.Group) []string {
	raw := []string{stringOr(group.DisplayName, group.Id)}
	if group.Path != nil {
		raw = append(raw, shortenPath(*group.Path))
	}
	for _, elem := range group.Expression {
		cond, ok := elem.(*collector.Condition)
		if !ok || cond.Value == nil || *cond.Value == "" {
			continue
		}
		if cond.Key != nil && *cond.Key != nsxgen.ConditionKeyName && *cond.Key != nsxgen.ConditionKeyTag {
			continue
		}
		raw = append(raw, *cond.Value)
		if _, tag, found := strings.Cut(*cond.Value, "|"); found {
			raw = append(raw, tag)
		}
	}
	var out []string
	seen := map[string]bool{}
	push := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		key := strings.ToLower(s)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, s)
	}
	for _, s := range raw {
		push(s)
		lower := strings.ToLower(s)
		for _, prefix := range groupNamePrefixes {
			if strings.HasPrefix(lower, prefix) {
				push(s[len(prefix):])
			}
		}
	}
	return out
}

func uniqueVMForGroupName(name string, vmsByName map[string]*collector.VirtualMachine) *collector.VirtualMachine {
	if name == "" {
		return nil
	}
	seen := map[string]*collector.VirtualMachine{}
	for _, candidate := range expandGroupName(name) {
		vm := lookupUniqueVM(candidate, vmsByName)
		if vm == nil || vm.ExternalId == nil || *vm.ExternalId == "" {
			continue
		}
		seen[*vm.ExternalId] = vm
	}
	if len(seen) != 1 {
		return nil
	}
	for _, vm := range seen {
		return vm
	}
	return nil
}

func expandGroupName(name string) []string {
	out := []string{name}
	lower := strings.ToLower(name)
	for _, prefix := range groupNamePrefixes {
		if strings.HasPrefix(lower, prefix) {
			out = append(out, name[len(prefix):])
		}
	}
	return out
}

func lookupUniqueVM(name string, vmsByName map[string]*collector.VirtualMachine) *collector.VirtualMachine {
	if name == "" {
		return nil
	}
	if vm := vmsByName[name]; vm != nil {
		return vm
	}
	lower := strings.ToLower(name)
	var matches []*collector.VirtualMachine
	for vmName, vm := range vmsByName {
		nl := strings.ToLower(vmName)
		if nl == lower || strings.HasPrefix(nl, lower+"-") || strings.HasPrefix(lower, nl+"-") {
			matches = append(matches, vm)
		}
	}
	if len(matches) == 1 {
		return matches[0]
	}
	return nil
}

// applyGroupTagExpressionsToMembers copies each group's Tag condition value onto
// its realized VMs. vmware-analyzer synthesizes tag groups as labels of the raw
// expression value (including "scope|tag"), while the parser only reads Tag.Tag
// and ignores Scope. Untagged dump VMs and live NSX tags stored as Scope+Tag
// therefore produce empty namespace selectors and default-deny-only YAML.
func applyGroupTagExpressionsToMembers(resources *collector.ResourcesContainerModel) {
	if resources == nil {
		return
	}
	vmsByExt := map[string]*collector.VirtualMachine{}
	vmsByName := map[string]*collector.VirtualMachine{}
	for i := range resources.VirtualMachineList {
		vm := &resources.VirtualMachineList[i]
		if vm.ExternalId != nil && *vm.ExternalId != "" {
			vmsByExt[*vm.ExternalId] = vm
		}
		if name := stringOr(vm.DisplayName, vm.ExternalId); name != "" {
			vmsByName[strings.ToLower(name)] = vm
		}
	}
	for di := range resources.DomainList {
		for _, group := range resources.DomainList[di].Resources.GroupList {
			tagValues := tagValuesFromExpression(group.Expression)
			if len(tagValues) == 0 {
				continue
			}
			for _, member := range group.VMMembers {
				vm := lookupInventoryVM(member, vmsByExt, vmsByName)
				if vm == nil {
					continue
				}
				for _, value := range tagValues {
					ensureVMHasAnalyzerTag(vm, value)
				}
			}
		}
	}
}

func tagValuesFromExpression(expr collector.Expression) []string {
	var out []string
	seen := map[string]bool{}
	var walk func(collector.Expression)
	walk = func(items collector.Expression) {
		for _, elem := range items {
			switch v := elem.(type) {
			case *collector.Condition:
				if v == nil || v.Value == nil || *v.Value == "" {
					continue
				}
				if v.Key == nil || *v.Key != nsxgen.ConditionKeyTag {
					continue
				}
				if seen[*v.Value] {
					continue
				}
				seen[*v.Value] = true
				out = append(out, *v.Value)
			case *collector.NestedExpression:
				walk(v.Expressions)
			}
		}
	}
	walk(expr)
	return out
}

func ensureVMHasAnalyzerTag(vm *collector.VirtualMachine, value string) {
	if vm == nil || value == "" {
		return
	}
	if !vmHasTagLiteral(vm, value) {
		vm.Tags = append(vm.Tags, nsxgen.Tag{Tag: value})
	}
	scope, tag, scoped := strings.Cut(value, "|")
	if !scoped || tag == "" {
		return
	}
	if vmHasScopedTag(vm, scope, tag) {
		return
	}
	vm.Tags = append(vm.Tags, nsxgen.Tag{Scope: scope, Tag: tag})
}

func vmHasTagLiteral(vm *collector.VirtualMachine, value string) bool {
	for _, tag := range vm.Tags {
		if strings.EqualFold(tag.Tag, value) {
			return true
		}
	}
	return false
}

func vmHasScopedTag(vm *collector.VirtualMachine, scope, tag string) bool {
	for _, existing := range vm.Tags {
		if strings.EqualFold(existing.Scope, scope) && strings.EqualFold(existing.Tag, tag) {
			return true
		}
	}
	return false
}

func populateGroupMembersFromExpressions(resources *collector.ResourcesContainerModel) {
	if resources == nil {
		return
	}
	for round := 0; round < 8; round++ {
		changed := false
		for di := range resources.DomainList {
			for gi := range resources.DomainList[di].Resources.GroupList {
				group := &resources.DomainList[di].Resources.GroupList[gi]
				if groupHasRealizedMembers(*group) || len(group.Expression) == 0 {
					continue
				}
				members := vmsMatchingExpression(resources, group.Expression)
				if len(members) == 0 {
					continue
				}
				group.VMMembers = append(group.VMMembers, members...)
				changed = true
			}
		}
		if !changed {
			return
		}
	}
}

func vmsMatchingExpression(resources *collector.ResourcesContainerModel, expr collector.Expression) []collector.RealizedVirtualMachine {
	if len(expr) == 0 {
		return nil
	}
	current := vmsMatchingElement(resources, expr[0])
	for i := 1; i+1 < len(expr); i += 2 {
		conj, ok := expr[i].(*collector.ConjunctionOperator)
		if !ok || conj.ConjunctionOperator.ConjunctionOperator == nil {
			continue
		}
		next := vmsMatchingElement(resources, expr[i+1])
		if *conj.ConjunctionOperator.ConjunctionOperator == nsxgen.ConjunctionOperatorConjunctionOperatorOR {
			current = unionVMMembers(current, next)
			continue
		}
		current = intersectVMMembers(current, next)
	}
	return current
}

func vmsMatchingElement(resources *collector.ResourcesContainerModel, elem collector.ExpressionElement) []collector.RealizedVirtualMachine {
	switch v := elem.(type) {
	case *collector.Condition:
		return vmsMatchingCondition(resources, v)
	case *collector.NestedExpression:
		return vmsMatchingExpression(resources, v.Expressions)
	case *collector.PathExpression:
		return vmsMatchingPaths(resources, v.Paths)
	case *collector.ExternalIDExpression:
		return vmsMatchingExternalIDs(resources, v.ExternalIds)
	default:
		return nil
	}
}

func vmsMatchingCondition(resources *collector.ResourcesContainerModel, cond *collector.Condition) []collector.RealizedVirtualMachine {
	if cond == nil || cond.Value == nil || *cond.Value == "" {
		return nil
	}
	key := nsxgen.ConditionKeyName
	if cond.Key != nil {
		key = *cond.Key
	}
	op := nsxgen.ConditionOperatorEQUALS
	if cond.Operator != nil {
		op = *cond.Operator
	}
	want := *cond.Value
	var out []collector.RealizedVirtualMachine
	for i := range resources.VirtualMachineList {
		vm := &resources.VirtualMachineList[i]
		if vm.ExternalId == nil {
			continue
		}
		if vmMatchesCondition(vm, key, op, want, cond.ScopeOperator) {
			out = append(out, realizedVM(vm))
		}
	}
	if len(out) == 0 && key == nsxgen.ConditionKeyTag {
		out = vmsMatchingTagNameFallback(resources, want, op)
	}
	return out
}

func vmsMatchingTagNameFallback(resources *collector.ResourcesContainerModel, want string, op nsxgen.ConditionOperator) []collector.RealizedVirtualMachine {
	if op != nsxgen.ConditionOperatorEQUALS && op != nsxgen.ConditionOperatorCONTAINS && op != nsxgen.ConditionOperatorSTARTSWITH && op != nsxgen.ConditionOperatorENDSWITH {
		return nil
	}
	tagWant := want
	if _, suffix, found := strings.Cut(want, "|"); found {
		tagWant = suffix
	}
	if tagWant == "" {
		return nil
	}
	var out []collector.RealizedVirtualMachine
	for i := range resources.VirtualMachineList {
		vm := &resources.VirtualMachineList[i]
		if vm.ExternalId == nil {
			continue
		}
		name := stringOr(vm.DisplayName, vm.ExternalId)
		if compareExpr(name, tagWant, op) {
			out = append(out, realizedVM(vm))
		}
	}
	return out
}

func vmMatchesCondition(vm *collector.VirtualMachine, key nsxgen.ConditionKey, op nsxgen.ConditionOperator, want string, scopeOp *nsxgen.ConditionScopeOperator) bool {
	switch key {
	case nsxgen.ConditionKeyName:
		return compareExpr(stringOr(vm.DisplayName, vm.ExternalId), want, op)
	case nsxgen.ConditionKeyTag:
		return vmMatchesTagCondition(vm, want, op, scopeOp)
	default:
		return false
	}
}

func vmMatchesTagCondition(vm *collector.VirtualMachine, want string, op nsxgen.ConditionOperator, scopeOp *nsxgen.ConditionScopeOperator) bool {
	negate := op == nsxgen.ConditionOperatorNOTEQUALS || op == nsxgen.ConditionOperatorNOTIN
	positive := op
	if negate {
		positive = nsxgen.ConditionOperatorEQUALS
		if op == nsxgen.ConditionOperatorNOTIN {
			positive = nsxgen.ConditionOperatorIN
		}
	}
	matched := false
	for _, tag := range vm.Tags {
		if tagSatisfies(tag, want, positive, scopeOp) {
			matched = true
			break
		}
	}
	if negate {
		return !matched
	}
	return matched
}

func tagSatisfies(tag nsxgen.Tag, want string, op nsxgen.ConditionOperator, scopeOp *nsxgen.ConditionScopeOperator) bool {
	if op == nsxgen.ConditionOperatorIN {
		for _, part := range strings.Split(want, ",") {
			if tagSatisfies(tag, strings.TrimSpace(part), nsxgen.ConditionOperatorEQUALS, scopeOp) {
				return true
			}
		}
		return false
	}
	scopeWant, tagWant, scoped := strings.Cut(want, "|")
	if !scoped {
		return compareExpr(tag.Tag, want, op) ||
			compareExpr(tag.Scope, want, op) ||
			compareExpr(tagComposite(tag), want, op)
	}
	if !compareExpr(tag.Tag, tagWant, op) {
		return false
	}
	if scopeWant == "" {
		return true
	}
	scopeMatch := strings.EqualFold(tag.Scope, scopeWant)
	if scopeOp != nil && *scopeOp == nsxgen.ConditionScopeOperatorNOTEQUALS {
		return !scopeMatch
	}
	return scopeMatch
}

func tagComposite(tag nsxgen.Tag) string {
	if tag.Scope == "" {
		return tag.Tag
	}
	return tag.Scope + "|" + tag.Tag
}

func compareExpr(have, want string, op nsxgen.ConditionOperator) bool {
	h, w := strings.ToLower(have), strings.ToLower(want)
	switch op {
	case nsxgen.ConditionOperatorCONTAINS:
		return strings.Contains(h, w)
	case nsxgen.ConditionOperatorSTARTSWITH:
		return strings.HasPrefix(h, w)
	case nsxgen.ConditionOperatorENDSWITH:
		return strings.HasSuffix(h, w)
	case nsxgen.ConditionOperatorNOTEQUALS, nsxgen.ConditionOperatorNOTIN:
		return h != w
	default:
		return h == w
	}
}

func vmsMatchingExternalIDs(resources *collector.ResourcesContainerModel, ids []string) []collector.RealizedVirtualMachine {
	want := map[string]bool{}
	for _, id := range ids {
		if id != "" {
			want[id] = true
		}
	}
	var out []collector.RealizedVirtualMachine
	for i := range resources.VirtualMachineList {
		vm := &resources.VirtualMachineList[i]
		if vm.ExternalId != nil && want[*vm.ExternalId] {
			out = append(out, realizedVM(vm))
		}
	}
	return out
}

func vmsMatchingPaths(resources *collector.ResourcesContainerModel, paths []string) []collector.RealizedVirtualMachine {
	var out []collector.RealizedVirtualMachine
	seen := map[string]bool{}
	index := buildGroupIndex(resources)
	for _, path := range paths {
		if group, ok := lookupGroup(index, path); ok {
			for i := range group.VMMembers {
				id := stringOr(group.VMMembers[i].Id, group.VMMembers[i].DisplayName)
				if id == "" || seen[id] {
					continue
				}
				seen[id] = true
				out = append(out, group.VMMembers[i])
			}
			continue
		}
		var seg *collector.Segment
		func() {
			defer func() { recover() }()
			seg = resources.GetSegment(path)
		}()
		if seg != nil {
			for _, vm := range safeVMsOfSegment(resources, seg) {
				id := stringOr(vm.ExternalId, vm.DisplayName)
				if id == "" || seen[id] {
					continue
				}
				seen[id] = true
				out = append(out, realizedVM(vm))
			}
		}
	}
	return out
}

func safeVMsOfSegment(resources *collector.ResourcesContainerModel, seg *collector.Segment) []*collector.VirtualMachine {
	if resources == nil || seg == nil {
		return nil
	}
	var out []*collector.VirtualMachine
	defer func() { recover() }()
	for _, vm := range resources.GetVMsOfSegment(seg) {
		if vm != nil {
			out = append(out, vm)
		}
	}
	return out
}

func realizedVM(vm *collector.VirtualMachine) collector.RealizedVirtualMachine {
	return collector.RealizedVirtualMachine{
		RealizedVirtualMachine: nsxgen.RealizedVirtualMachine{
			DisplayName: vm.DisplayName,
			Id:          vm.ExternalId,
		},
	}
}

func unionVMMembers(a, b []collector.RealizedVirtualMachine) []collector.RealizedVirtualMachine {
	seen := map[string]bool{}
	var out []collector.RealizedVirtualMachine
	for _, list := range [][]collector.RealizedVirtualMachine{a, b} {
		for _, m := range list {
			id := stringOr(m.Id, m.DisplayName)
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, m)
		}
	}
	return out
}

func intersectVMMembers(a, b []collector.RealizedVirtualMachine) []collector.RealizedVirtualMachine {
	inB := map[string]bool{}
	for _, m := range b {
		if id := stringOr(m.Id, m.DisplayName); id != "" {
			inB[id] = true
		}
	}
	var out []collector.RealizedVirtualMachine
	seen := map[string]bool{}
	for _, m := range a {
		id := stringOr(m.Id, m.DisplayName)
		if id == "" || !inB[id] || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, m)
	}
	return out
}
