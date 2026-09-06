package nsx

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsxgen "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
)

// ServicePortView is a named NSX service expanded to protocol and destination ports.
type ServicePortView struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol,omitempty"`
	Ports    string `json:"ports,omitempty"`
}

// DFWRuleView is a simplified DFW rule for the analysis UI.
type DFWRuleView struct {
	ID           int               `json:"id"`
	Name         string            `json:"name"`
	Policy       string            `json:"policy"`
	Category     string            `json:"category"`
	Action       string            `json:"action"`
	Sources      []string          `json:"sources"`
	Destinations []string          `json:"destinations"`
	Services     []string          `json:"services"`
	ServicePorts []ServicePortView `json:"servicePorts,omitempty"`
	Direction    string            `json:"direction,omitempty"`
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
	services := buildServiceIndex(resources)
	var rules []DFWRuleView

	for _, domain := range resources.DomainList {
		for _, policy := range domain.Resources.SecurityPolicyList {
			policyName := stringOr(policy.DisplayName, policy.Id)
			category := stringOr(policy.Category, nil)
			for _, rule := range policy.Rules {
				rules = append(rules, ruleViewFromCollector(rule, policyName, category, services))
			}
		}
	}
	return rules
}

// PrepareWarnings reports dump issues that cause vmware-analyzer to emit only default-deny policies.
func PrepareWarnings(resources *collector.ResourcesContainerModel) []string {
	if resources == nil {
		return nil
	}
	var warnings []string
	for ref, group := range referencedGroups(resources) {
		if groupHasRealizedMembers(group) {
			continue
		}
		warnings = append(warnings, "DFW group "+ref+" has no VM members; allow rules using it will not generate NetworkPolicies")
	}
	return warnings
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

func ruleViewFromCollector(rule collector.Rule, policyName, category string, services serviceIndex) DFWRuleView {
	names := resolveServices(rule.Services, services.names)
	return DFWRuleView{
		ID:           ptrInt(rule.RuleId),
		Name:         stringOr(rule.DisplayName, rule.Id),
		Policy:       policyName,
		Category:     category,
		Action:       ruleAction(rule.Action),
		Sources:      resolveRuleEndpoints(rule.SourceGroups),
		Destinations: resolveRuleEndpoints(rule.DestinationGroups),
		Services:     names,
		ServicePorts: resolveServicePorts(rule.Services, rule.ServiceEntries, services),
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

type serviceIndex struct {
	byKey map[string]*collector.Service
	names map[string]string
}

func buildServiceIndex(resources *collector.ResourcesContainerModel) serviceIndex {
	idx := serviceIndex{
		byKey: make(map[string]*collector.Service),
		names: make(map[string]string),
	}
	for i := range resources.ServiceList {
		svc := &resources.ServiceList[i]
		name := stringOr(svc.DisplayName, svc.Id)
		addServiceKey := func(key string) {
			if key == "" {
				return
			}
			idx.byKey[key] = svc
			if name != "" {
				idx.names[key] = name
			}
		}
		if svc.Path != nil {
			addServiceKey(*svc.Path)
			addServiceKey(shortenPath(*svc.Path))
		}
		if svc.Id != nil {
			addServiceKey(*svc.Id)
		}
		if svc.DisplayName != nil {
			addServiceKey(*svc.DisplayName)
		}
	}
	return idx
}

func (idx serviceIndex) lookup(key string) *collector.Service {
	if svc, ok := idx.byKey[key]; ok {
		return svc
	}
	if short := shortenPath(key); short != key {
		return idx.byKey[short]
	}
	return nil
}

func isAnyService(path string) bool {
	v := strings.TrimSpace(strings.ToUpper(path))
	if v == "" || v == "ANY" {
		return true
	}
	return strings.HasSuffix(v, "/SERVICES/ANY")
}

func resolveServicePorts(paths []string, inline collector.ServiceEntries, idx serviceIndex) []ServicePortView {
	var out []ServicePortView
	visiting := map[string]bool{}

	anyOnly := len(paths) == 0
	if !anyOnly {
		anyOnly = true
		for _, p := range paths {
			if !isAnyService(p) {
				anyOnly = false
				break
			}
		}
	}

	if !anyOnly {
		for _, p := range paths {
			if isAnyService(p) {
				out = append(out, ServicePortView{Name: "Any"})
				continue
			}
			svc := idx.lookup(p)
			name := ""
			if svc != nil {
				name = stringOr(svc.DisplayName, svc.Id)
			}
			if name == "" {
				name = shortenPath(p)
			}
			if svc != nil && len(svc.ServiceEntries) > 0 {
				if svc.Path != nil {
					visiting[*svc.Path] = true
				}
				out = append(out, expandServiceEntries(svc.ServiceEntries, name, idx, visiting)...)
				if svc.Path != nil {
					delete(visiting, *svc.Path)
				}
			} else {
				out = append(out, ServicePortView{Name: name})
			}
		}
	}

	if len(inline) > 0 {
		out = append(out, expandServiceEntries(inline, "", idx, visiting)...)
	}
	if len(out) == 0 {
		return []ServicePortView{{Name: "Any"}}
	}
	return mergeServicePorts(out)
}

func expandServiceEntries(entries collector.ServiceEntries, serviceName string, idx serviceIndex, visiting map[string]bool) []ServicePortView {
	var out []ServicePortView
	for _, entry := range entries {
		switch v := entry.(type) {
		case *collector.L4PortSetServiceEntry:
			name := entryDisplayName(v.DisplayName, serviceName)
			proto := ""
			if v.L4Protocol != nil {
				proto = string(*v.L4Protocol)
			}
			ports := joinPortElements(v.DestinationPorts)
			if ports == "" {
				ports = "*"
			}
			out = append(out, ServicePortView{Name: name, Protocol: proto, Ports: ports})
		case *collector.ICMPTypeServiceEntry:
			name := entryDisplayName(v.DisplayName, serviceName)
			proto, ports := icmpDetail(v)
			out = append(out, ServicePortView{Name: name, Protocol: proto, Ports: ports})
		case *collector.NestedServiceServiceEntry:
			if v.NestedServicePath == nil || *v.NestedServicePath == "" {
				continue
			}
			path := *v.NestedServicePath
			if visiting[path] {
				continue
			}
			nested := idx.lookup(path)
			nestedName := entryDisplayName(v.DisplayName, serviceName)
			if nested != nil {
				if n := stringOr(nested.DisplayName, nested.Id); n != "" {
					nestedName = n
				}
				visiting[path] = true
				out = append(out, expandServiceEntries(nested.ServiceEntries, nestedName, idx, visiting)...)
				delete(visiting, path)
			} else if nestedName != "" {
				out = append(out, ServicePortView{Name: nestedName})
			} else {
				out = append(out, ServicePortView{Name: shortenPath(path)})
			}
		default:
			if serviceName != "" {
				out = append(out, ServicePortView{Name: serviceName})
			}
		}
	}
	return out
}

func entryDisplayName(display *string, fallback string) string {
	if display != nil && *display != "" {
		return *display
	}
	if fallback != "" {
		return fallback
	}
	return "Service"
}

func joinPortElements(ports []nsxgen.PortElement) string {
	if len(ports) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		s := strings.TrimSpace(string(p))
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ",")
}

func icmpDetail(e *collector.ICMPTypeServiceEntry) (protocol, ports string) {
	protocol = "ICMP"
	if e.Protocol != nil && *e.Protocol == nsxgen.ICMPTypeServiceEntryProtocolICMPv6 {
		protocol = "ICMPv6"
	}
	switch {
	case e.IcmpType != nil && e.IcmpCode != nil:
		ports = fmt.Sprintf("%d/%d", *e.IcmpType, *e.IcmpCode)
	case e.IcmpType != nil:
		ports = fmt.Sprintf("type %d", *e.IcmpType)
	}
	return protocol, ports
}

func mergeServicePorts(in []ServicePortView) []ServicePortView {
	type key struct{ name, proto string }
	order := make([]key, 0, len(in))
	ports := make(map[key][]string, len(in))
	seen := make(map[key]map[string]bool, len(in))

	for _, sp := range in {
		k := key{name: sp.Name, proto: strings.ToUpper(sp.Protocol)}
		if _, ok := ports[k]; !ok {
			order = append(order, k)
			seen[k] = map[string]bool{}
			ports[k] = nil
		}
		if sp.Ports == "" {
			continue
		}
		for _, p := range strings.Split(sp.Ports, ",") {
			p = strings.TrimSpace(p)
			if p == "" || seen[k][p] {
				continue
			}
			seen[k][p] = true
			ports[k] = append(ports[k], p)
		}
	}

	out := make([]ServicePortView, 0, len(order))
	for _, k := range order {
		proto := k.proto
		if proto == "ICMPV6" {
			proto = "ICMPv6"
		} else if proto == "ICMPV4" {
			proto = "ICMP"
		}
		out = append(out, ServicePortView{
			Name:     k.name,
			Protocol: proto,
			Ports:    strings.Join(ports[k], ","),
		})
	}
	return out
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
	n := realizedGroupMemberCount(group)
	if group.Expression != nil {
		n += len(group.Expression)
	}
	return n
}

func groupHasRealizedMembers(group collector.Group) bool {
	return realizedGroupMemberCount(group) > 0
}

func realizedGroupMemberCount(group collector.Group) int {
	return len(group.VMMembers) + len(group.VIFMembers) + len(group.AddressMembers) +
		len(group.Segments) + len(group.SegmentPorts) + len(group.IPGroups) + len(group.TransportNodes)
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
