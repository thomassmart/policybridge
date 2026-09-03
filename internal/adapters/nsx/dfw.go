package nsx

import (
	"encoding/json"
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsxgen "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
)

// DFWRuleView is a simplified DFW rule for the analysis UI.
type DFWRuleView struct {
	ID           int      `json:"id"`
	Name         string   `json:"name"`
	Policy       string   `json:"policy"`
	Category     string   `json:"category"`
	Action       string   `json:"action"`
	Sources      []string `json:"sources"`
	Destinations []string `json:"destinations"`
	Services     []string `json:"services"`
	Direction    string   `json:"direction,omitempty"`
}

// AnalysisInsights captures collection quality and connectivity sanity checks.
type AnalysisInsights struct {
	Warnings            []string            `json:"warnings,omitempty"`
	EmptyGroups         []string            `json:"emptyGroups,omitempty"`
	ConnectivitySummary ConnectivitySummary `json:"connectivitySummary"`
}

// ConnectivitySummary counts edge types in analyzed connectivity.
type ConnectivitySummary struct {
	TotalEdges          int `json:"totalEdges"`
	AllConnectionsEdges int `json:"allConnectionsEdges"`
}

// ExtractDFWRules returns DFW rules from a collected NSX dump.
func ExtractDFWRules(resources *collector.ResourcesContainerModel) []DFWRuleView {
	if resources == nil {
		return nil
	}
	serviceNames := buildServiceNameIndex(resources)
	var rules []DFWRuleView

	for _, domain := range resources.DomainList {
		for _, policy := range domain.Resources.SecurityPolicyList {
			policyName := stringOr(policy.DisplayName, policy.Id)
			category := stringOr(policy.Category, nil)
			for _, rule := range policy.Rules {
				rules = append(rules, ruleViewFromCollector(rule, policyName, category, serviceNames))
			}
		}
	}
	return rules
}

// BuildAnalysisInsights checks collection quality and connectivity sanity.
func BuildAnalysisInsights(resources *collector.ResourcesContainerModel, connectivityJSON string) AnalysisInsights {
	insights := AnalysisInsights{
		ConnectivitySummary: summarizeConnectivityJSON(connectivityJSON),
	}
	if resources == nil {
		return insights
	}

	referenced := referencedGroups(resources)
	for ref, group := range referenced {
		if groupMemberCount(group) == 0 {
			insights.EmptyGroups = append(insights.EmptyGroups, ref)
		}
	}
	if len(insights.EmptyGroups) > 0 {
		insights.Warnings = append(insights.Warnings,
			"Some DFW groups referenced by rules have no collected members. Connectivity analysis may show broader access than your NSX rules imply until group membership is collected.")
	}

	restrictiveRules := countRestrictiveDFWRules(resources)
	allConn := insights.ConnectivitySummary.AllConnectionsEdges
	total := insights.ConnectivitySummary.TotalEdges
	if restrictiveRules > 0 && total > 0 && allConn == total {
		insights.Warnings = append(insights.Warnings,
			"Analyzed connectivity shows only unrestricted (All Connections) flows, but the collected DFW rules define specific services. Review the DFW rules table below and verify group membership was collected from NSX.")
	} else if restrictiveRules > 0 && total > 0 && allConn > total/2 {
		insights.Warnings = append(insights.Warnings,
			"Many analyzed connections are unrestricted (All Connections) despite specific DFW service rules. This can happen when VMs share a segment with intra-segment allow, or when group membership is incomplete.")
	}

	return insights
}

func ruleViewFromCollector(rule collector.Rule, policyName, category string, serviceNames map[string]string) DFWRuleView {
	return DFWRuleView{
		ID:           ptrInt(rule.RuleId),
		Name:         stringOr(rule.DisplayName, rule.Id),
		Policy:       policyName,
		Category:     category,
		Action:       ruleAction(rule.Action),
		Sources:      resolveRuleEndpoints(rule.SourceGroups),
		Destinations: resolveRuleEndpoints(rule.DestinationGroups),
		Services:     resolveServices(rule.Services, serviceNames),
		Direction:    string(rule.Direction),
	}
}

func ruleAction(action *nsxgen.RuleAction) string {
	if action == nil {
		return "ALLOW"
	}
	return string(*action)
}

func summarizeConnectivityJSON(connectivityJSON string) ConnectivitySummary {
	var edges []struct {
		Conn string `json:"conn"`
	}
	if err := json.Unmarshal([]byte(connectivityJSON), &edges); err != nil {
		return ConnectivitySummary{}
	}
	summary := ConnectivitySummary{TotalEdges: len(edges)}
	for _, e := range edges {
		if isAllConnections(e.Conn) {
			summary.AllConnectionsEdges++
		}
	}
	return summary
}

func isAllConnections(conn string) bool {
	conn = strings.TrimSpace(conn)
	return conn == "" || strings.EqualFold(conn, "All Connections")
}

func countRestrictiveDFWRules(resources *collector.ResourcesContainerModel) int {
	count := 0
	for _, domain := range resources.DomainList {
		for _, policy := range domain.Resources.SecurityPolicyList {
			for _, rule := range policy.Rules {
				if len(rule.Services) > 0 && (hasSpecificGroup(rule.SourceGroups) || hasSpecificGroup(rule.DestinationGroups)) {
					count++
				}
			}
		}
	}
	return count
}

func hasSpecificGroup(groups []string) bool {
	for _, g := range groups {
		if !isAnyEndpoint(g) {
			return true
		}
	}
	return false
}

func isAnyEndpoint(v string) bool {
	v = strings.TrimSpace(strings.ToUpper(v))
	if v == "" || v == "ANY" {
		return true
	}
	return strings.HasSuffix(v, "/GROUPS/ANY")
}

func buildServiceNameIndex(resources *collector.ResourcesContainerModel) map[string]string {
	index := make(map[string]string)
	for _, svc := range resources.ServiceList {
		name := stringOr(svc.DisplayName, svc.Id)
		if svc.Path != nil {
			index[*svc.Path] = name
		}
		if svc.Id != nil {
			index[*svc.Id] = name
		}
		if svc.DisplayName != nil {
			index[*svc.DisplayName] = name
		}
	}
	return index
}

func buildGroupIndex(resources *collector.ResourcesContainerModel) map[string]collector.Group {
	index := make(map[string]collector.Group)
	for _, domain := range resources.DomainList {
		for _, group := range domain.Resources.GroupList {
			if group.DisplayName != nil {
				index[*group.DisplayName] = group
			}
			if group.Id != nil {
				index[*group.Id] = group
			}
			if group.Path != nil {
				index[*group.Path] = group
				index[strings.TrimPrefix(*group.Path, "/infra/domains/default/groups/")] = group
			}
		}
	}
	return index
}

func referencedGroups(resources *collector.ResourcesContainerModel) map[string]collector.Group {
	index := buildGroupIndex(resources)
	referenced := make(map[string]collector.Group)
	for _, domain := range resources.DomainList {
		for _, policy := range domain.Resources.SecurityPolicyList {
			for _, rule := range policy.Rules {
				for _, g := range append(append([]string{}, rule.SourceGroups...), rule.DestinationGroups...) {
					if isAnyEndpoint(g) {
						continue
					}
					if group, ok := index[g]; ok {
						referenced[g] = group
					} else if group, ok := index[strings.TrimPrefix(g, "/infra/domains/default/groups/")]; ok {
						referenced[g] = group
					}
				}
			}
		}
	}
	return referenced
}

func groupMemberCount(group collector.Group) int {
	n := len(group.VMMembers) + len(group.VIFMembers) + len(group.AddressMembers) +
		len(group.Segments) + len(group.SegmentPorts) + len(group.IPGroups) + len(group.TransportNodes)
	if group.Expression != nil {
		n += len(group.Expression)
	}
	return n
}

func resolveRuleEndpoints(groups []string) []string {
	if len(groups) == 0 {
		return []string{"Any"}
	}
	out := make([]string, len(groups))
	for i, g := range groups {
		out[i] = shortenPath(g)
	}
	return out
}

func resolveServices(paths []string, serviceNames map[string]string) []string {
	if len(paths) == 0 {
		return []string{"Any"}
	}
	out := make([]string, len(paths))
	for i, p := range paths {
		if name, ok := serviceNames[p]; ok {
			out[i] = name
			continue
		}
		out[i] = shortenPath(p)
	}
	return out
}

func shortenPath(path string) string {
	path = strings.TrimSpace(path)
	if strings.HasPrefix(path, "/infra/services/") {
		return strings.TrimPrefix(path, "/infra/services/")
	}
	if strings.HasPrefix(path, "/infra/domains/default/groups/") {
		return strings.TrimPrefix(path, "/infra/domains/default/groups/")
	}
	return path
}

func stringOr(values ...*string) string {
	for _, v := range values {
		if v != nil && *v != "" {
			return *v
		}
	}
	return ""
}

func ptrInt(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}
