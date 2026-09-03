package nsx

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsxgen "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
	"github.com/policybridge/policybridge/internal/mapping"
)

const (
	DefaultRuleNewDrop  = "new-drop"
	DefaultRuleNewAllow = "new-allow"
	DefaultRuleExisting = "existing"
)

// DefaultRuleSpec is the last-resort DFW rule used during synthesis.
type DefaultRuleSpec struct {
	Mode   string
	RuleID int
}

// ParseDefaultRule parses a generation-settings value: "new-drop", "new-allow", or a rule id.
func ParseDefaultRule(value string) (DefaultRuleSpec, error) {
	value = strings.TrimSpace(value)
	switch value {
	case "", DefaultRuleNewDrop:
		return DefaultRuleSpec{Mode: DefaultRuleNewDrop}, nil
	case DefaultRuleNewAllow:
		return DefaultRuleSpec{Mode: DefaultRuleNewAllow}, nil
	}
	id, err := strconv.Atoi(value)
	if err != nil || id == 0 {
		return DefaultRuleSpec{}, fmt.Errorf("invalid default rule %q", value)
	}
	return DefaultRuleSpec{Mode: DefaultRuleExisting, RuleID: id}, nil
}

func (s DefaultRuleSpec) normalized() DefaultRuleSpec {
	switch s.Mode {
	case DefaultRuleNewAllow, DefaultRuleExisting:
		return s
	default:
		s.Mode = DefaultRuleNewDrop
		return s
	}
}

// FilterDumpByRuleIDs returns a copy of the dump containing only DFW rules whose IDs
// appear in selectedIDs, plus a new DROP catch-all if none remains.
// When selectedIDs is nil, the original resources are returned.
func FilterDumpByRuleIDs(resources *collector.ResourcesContainerModel, selectedIDs []int) (*collector.ResourcesContainerModel, error) {
	if resources == nil || selectedIDs == nil {
		return resources, nil
	}
	return PrepareDumpForGeneration(resources, selectedIDs, DefaultRuleSpec{Mode: DefaultRuleNewDrop})
}

// PrepareDumpForGeneration clones the dump, optionally keeps a subset of DFW rules,
// applies the chosen default rule, and limits VMs to those referenced by the kept rules.
func PrepareDumpForGeneration(resources *collector.ResourcesContainerModel, selectedIDs []int, spec DefaultRuleSpec) (*collector.ResourcesContainerModel, error) {
	if resources == nil {
		return nil, fmt.Errorf("no NSX configuration loaded")
	}
	spec = spec.normalized()

	data, err := json.Marshal(resources)
	if err != nil {
		return nil, err
	}
	var filtered collector.ResourcesContainerModel
	if err := json.Unmarshal(data, &filtered); err != nil {
		return nil, err
	}

	if selectedIDs != nil {
		if err := keepSelectedRules(&filtered, selectedIDs, spec); err != nil {
			return nil, err
		}
		scopeIDs := selectedIDs
		if spec.Mode == DefaultRuleExisting {
			scopeIDs = append(append([]int{}, selectedIDs...), spec.RuleID)
		}
		restrictVMsToScope(&filtered, MappingScopeFromSelection(resources, scopeIDs))
	}

	if err := applyDefaultRule(&filtered, spec); err != nil {
		return nil, err
	}
	return &filtered, nil
}

func keepSelectedRules(resources *collector.ResourcesContainerModel, selectedIDs []int, spec DefaultRuleSpec) error {
	selected := make(map[int]struct{}, len(selectedIDs)+1)
	for _, id := range selectedIDs {
		selected[id] = struct{}{}
	}
	if spec.Mode == DefaultRuleExisting {
		selected[spec.RuleID] = struct{}{}
	}

	foundExisting := spec.Mode != DefaultRuleExisting
	for di := range resources.DomainList {
		policies := resources.DomainList[di].Resources.SecurityPolicyList
		for pi := range policies {
			var kept []collector.Rule
			for _, rule := range policies[pi].Rules {
				id := ptrInt(rule.RuleId)
				if _, ok := selected[id]; !ok {
					continue
				}
				kept = append(kept, rule)
				if spec.Mode == DefaultRuleExisting && id == spec.RuleID {
					foundExisting = true
				}
			}
			policies[pi].Rules = kept
			if len(kept) == 0 {
				clearPolicyDefault(resources, di, pi)
			}
		}
	}
	if !foundExisting {
		return fmt.Errorf("default rule %d was not found in the NSX configuration", spec.RuleID)
	}
	return nil
}

func applyDefaultRule(resources *collector.ResourcesContainerModel, spec DefaultRuleSpec) error {
	action := nsxgen.RuleActionDROP
	name := "policybridge-default-deny"
	pref := nsxgen.SecurityPolicyConnectivityPreferenceALLOWLIST
	switch spec.Mode {
	case DefaultRuleExisting:
		if !ruleIDPresent(resources, spec.RuleID) {
			return fmt.Errorf("default rule %d was not found in the NSX configuration", spec.RuleID)
		}
		if existingAction(resources, spec.RuleID) == "ALLOW" {
			action = nsxgen.RuleActionALLOW
			name = "policybridge-default-allow"
			pref = nsxgen.SecurityPolicyConnectivityPreferenceDENYLIST
		}
	case DefaultRuleNewAllow:
		action = nsxgen.RuleActionALLOW
		name = "policybridge-default-allow"
		pref = nsxgen.SecurityPolicyConnectivityPreferenceDENYLIST
	}
	opposite := "ALLOW"
	if action == nsxgen.RuleActionALLOW {
		opposite = "DROP"
	}
	removeGlobalCatchAll(resources, opposite)
	if hasGlobalCatchAll(resources, string(action)) {
		return nil
	}
	return appendGlobalDefault(resources, action, pref, name)
}

func ruleIDPresent(resources *collector.ResourcesContainerModel, id int) bool {
	for _, domain := range resources.DomainList {
		for _, policy := range domain.Resources.SecurityPolicyList {
			for _, rule := range policy.Rules {
				if ptrInt(rule.RuleId) == id {
					return true
				}
			}
		}
	}
	return false
}

func existingAction(resources *collector.ResourcesContainerModel, id int) string {
	for _, domain := range resources.DomainList {
		for _, policy := range domain.Resources.SecurityPolicyList {
			for _, rule := range policy.Rules {
				if ptrInt(rule.RuleId) == id {
					return ruleAction(rule.Action)
				}
			}
		}
	}
	return "DROP"
}

func hasGlobalCatchAll(resources *collector.ResourcesContainerModel, action string) bool {
	for _, domain := range resources.DomainList {
		for _, policy := range domain.Resources.SecurityPolicyList {
			if !policyIsUnscoped(policy) {
				continue
			}
			if policyDefaultAction(policy) == action {
				return true
			}
			for _, rule := range policy.Rules {
				if isGlobalCatchAll(rule, action) {
					return true
				}
			}
		}
	}
	return false
}

func removeGlobalCatchAll(resources *collector.ResourcesContainerModel, action string) {
	for di := range resources.DomainList {
		policies := resources.DomainList[di].Resources.SecurityPolicyList
		for pi := range policies {
			if !policyIsUnscoped(policies[pi]) {
				continue
			}
			if policyDefaultAction(policies[pi]) == action {
				clearPolicyDefault(resources, di, pi)
			}
			kept := policies[pi].Rules[:0]
			for _, rule := range policies[pi].Rules {
				if isGlobalCatchAll(rule, action) {
					continue
				}
				kept = append(kept, rule)
			}
			policies[pi].Rules = kept
		}
	}
}

func policyIsUnscoped(policy collector.SecurityPolicy) bool {
	return hasExplicitAny(policy.Scope)
}

func policyDefaultAction(policy collector.SecurityPolicy) string {
	if policy.DefaultRule == nil || policy.ConnectivityPreference == nil {
		return ""
	}
	switch *policy.ConnectivityPreference {
	case nsxgen.SecurityPolicyConnectivityPreferenceALLOWLIST, nsxgen.SecurityPolicyConnectivityPreferenceALLOWLISTENABLELOGGING:
		return "DROP"
	case nsxgen.SecurityPolicyConnectivityPreferenceDENYLIST, nsxgen.SecurityPolicyConnectivityPreferenceDENYLISTENABLELOGGING:
		return "ALLOW"
	default:
		return ""
	}
}

func clearPolicyDefault(resources *collector.ResourcesContainerModel, di, pi int) {
	none := nsxgen.SecurityPolicyConnectivityPreferenceNONE
	resources.DomainList[di].Resources.SecurityPolicyList[pi].DefaultRule = nil
	resources.DomainList[di].Resources.SecurityPolicyList[pi].DefaultRuleId = nil
	resources.DomainList[di].Resources.SecurityPolicyList[pi].ConnectivityPreference = &none
}

func isGlobalCatchAll(rule collector.Rule, action string) bool {
	return ruleAction(rule.Action) == action &&
		hasExplicitAny(rule.SourceGroups) &&
		hasExplicitAny(rule.DestinationGroups) &&
		allAnyEndpoints(rule.Services) &&
		hasExplicitAny(rule.Scope)
}

func appendGlobalDefault(resources *collector.ResourcesContainerModel, action nsxgen.RuleAction, pref nsxgen.SecurityPolicyConnectivityPreference, name string) error {
	if len(resources.DomainList) == 0 {
		return fmt.Errorf("no DFW domain available for a default rule")
	}
	di := len(resources.DomainList) - 1
	category := "Application"
	id := "policybridge-default"
	seq := 999_999
	ruleID := 1_000_000_000
	fwAction := nsxgen.FirewallRuleAction(action)
	fwID := fmt.Sprintf("%d", ruleID)
	fwDir := nsxgen.FirewallRuleDirectionINOUT
	policy := collector.SecurityPolicy{
		SecurityPolicy: nsxgen.SecurityPolicy{
			DisplayName:            &name,
			Id:                     &id,
			Category:               &category,
			Scope:                  []string{"ANY"},
			ConnectivityPreference: &pref,
			DefaultRuleId:          &ruleID,
			SequenceNumber:         &seq,
		},
		Rules: []collector.Rule{syntheticCatchAll(action, name)},
		DefaultRule: &collector.FirewallRule{
			FirewallRule: nsxgen.FirewallRule{
				DisplayName: &name,
				Id:          &fwID,
				Action:      &fwAction,
				Direction:   fwDir,
			},
		},
	}
	resources.DomainList[di].Resources.SecurityPolicyList = append(
		resources.DomainList[di].Resources.SecurityPolicyList, policy)
	return nil
}

func syntheticCatchAll(action nsxgen.RuleAction, name string) collector.Rule {
	dir := nsxgen.RuleDirectionINOUT
	id := 1_000_000_000
	seq := 999_999
	return collector.Rule{
		Rule: nsxgen.Rule{
			DisplayName:       &name,
			RuleId:            &id,
			Action:            &action,
			Direction:         dir,
			SourceGroups:      []string{"ANY"},
			DestinationGroups: []string{"ANY"},
			Services:          []string{"ANY"},
			Scope:             []string{"ANY"},
			SequenceNumber:    &seq,
		},
	}
}

func hasExplicitAny(values []string) bool {
	if len(values) == 0 {
		return false
	}
	return allAnyEndpoints(values)
}

func allAnyEndpoints(values []string) bool {
	if len(values) == 0 {
		return true
	}
	for _, v := range values {
		if !isAnyEndpoint(v) {
			return false
		}
	}
	return true
}

func restrictVMsToScope(resources *collector.ResourcesContainerModel, scope mapping.Scope) {
	if resources == nil || len(scope.VMs) == 0 {
		return
	}
	allowed := make(map[string]struct{}, len(scope.VMs))
	for _, name := range scope.VMs {
		allowed[name] = struct{}{}
	}
	kept := make([]collector.VirtualMachine, 0, len(scope.VMs))
	for _, vm := range resources.VirtualMachineList {
		name := stringOr(vm.DisplayName, vm.ExternalId)
		if _, ok := allowed[name]; ok {
			kept = append(kept, vm)
		}
	}
	if len(kept) > 0 {
		resources.VirtualMachineList = kept
	}
}

// SelectionIsComplete reports whether selectedIDs includes every DFW rule in the dump.
func SelectionIsComplete(resources *collector.ResourcesContainerModel, selectedIDs []int) bool {
	if selectedIDs == nil {
		return true
	}
	allIDs := AllDFWRuleIDs(resources)
	if len(selectedIDs) != len(allIDs) {
		return false
	}
	selected := make(map[int]struct{}, len(selectedIDs))
	for _, id := range selectedIDs {
		selected[id] = struct{}{}
	}
	for _, id := range allIDs {
		if _, ok := selected[id]; !ok {
			return false
		}
	}
	return true
}

// NormalizeSelectedRuleIDs returns nil when every rule is selected so callers can
// treat nil as "use the full dump".
func NormalizeSelectedRuleIDs(resources *collector.ResourcesContainerModel, selectedIDs []int) []int {
	if SelectionIsComplete(resources, selectedIDs) {
		return nil
	}
	return selectedIDs
}

// AllDFWRuleIDs returns every DFW rule ID in the collected configuration.
func AllDFWRuleIDs(resources *collector.ResourcesContainerModel) []int {
	rules := ExtractDFWRules(resources)
	ids := make([]int, 0, len(rules))
	for _, r := range rules {
		ids = append(ids, r.ID)
	}
	return ids
}

// RuleSelectionView is returned by the rules selection API.
type RuleSelectionView struct {
	Rules           []RuleSelectionRow `json:"rules"`
	SelectedRuleIDs []int              `json:"selectedRuleIds"`
}

// RuleSelectionRow is one DFW rule with its selection state.
type RuleSelectionRow struct {
	DFWRuleView
	Selected bool `json:"selected"`
}

// BuildRuleSelectionView builds the API response for rule selection.
// When selectedIDs is nil, every rule is marked selected.
func BuildRuleSelectionView(resources *collector.ResourcesContainerModel, selectedIDs []int) RuleSelectionView {
	rules := ExtractDFWRules(resources)
	selected := make(map[int]bool, len(rules))
	if selectedIDs == nil {
		for _, r := range rules {
			selected[r.ID] = true
		}
	} else {
		for _, id := range selectedIDs {
			selected[id] = true
		}
	}

	rows := make([]RuleSelectionRow, 0, len(rules))
	effectiveSelected := make([]int, 0, len(rules))
	for _, r := range rules {
		isSelected := selected[r.ID]
		rows = append(rows, RuleSelectionRow{DFWRuleView: r, Selected: isSelected})
		if isSelected {
			effectiveSelected = append(effectiveSelected, r.ID)
		}
	}

	return RuleSelectionView{
		Rules:           rows,
		SelectedRuleIDs: effectiveSelected,
	}
}
