package compare

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
)

// Category classifies a comparison result.
type Category string

const (
	CategoryExact        Category = "exact"
	CategoryMissing      Category = "missing"
	CategoryAdditional   Category = "additional"
	CategoryUncomparable Category = "uncomparable"
)

// Severity indicates the importance of a comparison finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// ConnectivityFact is the normalised comparison unit.
type ConnectivityFact struct {
	SourceIdentity      string   `json:"sourceIdentity"`
	DestinationIdentity string   `json:"destinationIdentity"`
	Direction           string   `json:"direction"`
	Protocol            string   `json:"protocol"`
	PortRange           string   `json:"portRange"`
	Allowed             bool     `json:"allowed"`
	Category            Category `json:"category"`
	Severity            Severity `json:"severity"`
	MappingNotes        []string `json:"mappingNotes,omitempty"`
	NSXRuleIDs          []int    `json:"nsxRuleIds,omitempty"`
	PolicyResources     []string `json:"policyResources,omitempty"`
}

// Result holds the full comparison output.
type Result struct {
	Exact        []ConnectivityFact `json:"exact"`
	Missing      []ConnectivityFact `json:"missing"`
	Additional   []ConnectivityFact `json:"additional"`
	Uncomparable []ConnectivityFact `json:"uncomparable"`
	Summary      SummaryCounts      `json:"summary"`
	Limitations  []string           `json:"limitations"`
}

// SummaryCounts provides category totals.
type SummaryCounts struct {
	Exact        int `json:"exact"`
	Missing      int `json:"missing"`
	Additional   int `json:"additional"`
	Uncomparable int `json:"uncomparable"`
	Total        int `json:"total"`
}

// NSXConnection represents a normalised NSX connectivity entry.
type NSXConnection struct {
	Source      string
	Destination string
	Connections string
	RuleIDs     []int
}

// Compare normalises and compares NSX connectivity against K8s connlist results.
func Compare(nsxConns []NSXConnection, k8sConns []connlist.Peer2PeerConnection, labelMap map[string]string) *Result {
	result := &Result{
		Limitations: defaultLimitations(),
	}

	nsxNorm := normaliseNSX(nsxConns, labelMap)
	k8sNorm := normaliseK8s(k8sConns, labelMap)

	nsxKeys := make(map[string]ConnectivityFact)
	for _, f := range nsxNorm {
		key := factKey(f)
		nsxKeys[key] = f
	}

	k8sKeys := make(map[string]ConnectivityFact)
	for _, f := range k8sNorm {
		key := factKey(f)
		k8sKeys[key] = f
	}

	for key, nsxFact := range nsxKeys {
		if k8sFact, ok := k8sKeys[key]; ok {
			fact := nsxFact
			fact.Category = CategoryExact
			fact.Severity = SeverityInfo
			fact.PolicyResources = k8sFact.PolicyResources
			result.Exact = append(result.Exact, fact)
			delete(k8sKeys, key)
		} else {
			mapped := tryFuzzyMatch(nsxFact, k8sKeys, labelMap)
			if mapped != nil {
				mapped.Category = CategoryExact
				mapped.Severity = SeverityInfo
				result.Exact = append(result.Exact, *mapped)
				delete(k8sKeys, factKey(*mapped))
			} else if isUncomparable(nsxFact) {
				nsxFact.Category = CategoryUncomparable
				nsxFact.Severity = SeverityInfo
				result.Uncomparable = append(result.Uncomparable, nsxFact)
			} else {
				nsxFact.Category = CategoryMissing
				nsxFact.Severity = severityForMissing(nsxFact)
				result.Missing = append(result.Missing, nsxFact)
			}
		}
	}

	for _, k8sFact := range k8sKeys {
		if isUncomparable(k8sFact) {
			k8sFact.Category = CategoryUncomparable
			k8sFact.Severity = SeverityInfo
			result.Uncomparable = append(result.Uncomparable, k8sFact)
		} else {
			k8sFact.Category = CategoryAdditional
			k8sFact.Severity = SeverityMedium
			result.Additional = append(result.Additional, k8sFact)
		}
	}

	result.Summary = SummaryCounts{
		Exact:        len(result.Exact),
		Missing:      len(result.Missing),
		Additional:   len(result.Additional),
		Uncomparable: len(result.Uncomparable),
		Total:        len(result.Exact) + len(result.Missing) + len(result.Additional) + len(result.Uncomparable),
	}

	return result
}

func factKey(f ConnectivityFact) string {
	return fmt.Sprintf("%s->%s:%s:%s", f.SourceIdentity, f.DestinationIdentity, f.Protocol, f.PortRange)
}

func normaliseNSX(conns []NSXConnection, labelMap map[string]string) []ConnectivityFact {
	var facts []ConnectivityFact
	for _, c := range conns {
		proto, ports := parseConnectionString(c.Connections)
		src := mapIdentity(c.Source, labelMap)
		dst := mapIdentity(c.Destination, labelMap)

		for _, port := range ports {
			facts = append(facts, ConnectivityFact{
				SourceIdentity:      src,
				DestinationIdentity: dst,
				Direction:           "egress",
				Protocol:            proto,
				PortRange:           port,
				Allowed:             true,
				NSXRuleIDs:          c.RuleIDs,
				MappingNotes:        mappingNotes(c.Source, src, labelMap),
			})
		}
	}
	return facts
}

func normaliseK8s(conns []connlist.Peer2PeerConnection, labelMap map[string]string) []ConnectivityFact {
	var facts []ConnectivityFact
	for _, c := range conns {
		src := c.Src().String()
		dst := c.Dst().String()

		if c.AllProtocolsAndPorts() {
			facts = append(facts, ConnectivityFact{
				SourceIdentity:      src,
				DestinationIdentity: dst,
				Protocol:            "ALL",
				PortRange:           "all",
				Allowed:             true,
			})
			continue
		}

		for proto, portRanges := range c.ProtocolsAndPorts() {
			for _, pr := range portRanges {
				start := pr.Start()
				end := pr.End()
				portStr := fmt.Sprintf("%d", start)
				if end != start {
					portStr = fmt.Sprintf("%d-%d", start, end)
				}
				facts = append(facts, ConnectivityFact{
					SourceIdentity:      src,
					DestinationIdentity: dst,
					Protocol:            string(proto),
					PortRange:           portStr,
					Allowed:             true,
				})
			}
		}
	}
	return facts
}

func parseConnectionString(conn string) (string, []string) {
	conn = strings.TrimSpace(conn)
	if strings.EqualFold(conn, "All Connections") {
		return "ALL", []string{"all"}
	}

	upper := strings.ToUpper(conn)
	var proto string
	rest := conn

	for _, p := range []string{"TCP", "UDP", "ICMP", "SCTP"} {
		if strings.HasPrefix(upper, p) {
			proto = p
			rest = strings.TrimSpace(conn[len(p):])
			break
		}
	}
	if proto == "" {
		proto = "TCP"
	}

	rest = strings.TrimPrefix(rest, "dst-ports:")
	rest = strings.TrimSpace(rest)

	if rest == "" {
		return proto, []string{"all"}
	}

	var ports []string
	for _, part := range strings.Split(rest, ",") {
		ports = append(ports, strings.TrimSpace(part))
	}
	return proto, ports
}

func mapIdentity(name string, labelMap map[string]string) string {
	if mapped, ok := labelMap[name]; ok {
		return mapped
	}
	return name
}

func mappingNotes(original, mapped string, labelMap map[string]string) []string {
	if original == mapped {
		return nil
	}
	return []string{fmt.Sprintf("NSX identity %q mapped to %q", original, mapped)}
}

func tryFuzzyMatch(nsxFact ConnectivityFact, k8sKeys map[string]ConnectivityFact, labelMap map[string]string) *ConnectivityFact {
	for key, k8sFact := range k8sKeys {
		if strings.EqualFold(nsxFact.Protocol, k8sFact.Protocol) &&
			nsxFact.PortRange == k8sFact.PortRange {
			if labelsMatch(nsxFact.SourceIdentity, k8sFact.SourceIdentity, labelMap) &&
				labelsMatch(nsxFact.DestinationIdentity, k8sFact.DestinationIdentity, labelMap) {
				merged := nsxFact
				merged.SourceIdentity = k8sFact.SourceIdentity
				merged.DestinationIdentity = k8sFact.DestinationIdentity
				merged.PolicyResources = k8sFact.PolicyResources
				_ = key
				return &merged
			}
		}
	}
	return nil
}

func labelsMatch(nsxName, k8sName string, labelMap map[string]string) bool {
	if mapped, ok := labelMap[nsxName]; ok {
		return strings.Contains(k8sName, mapped) || strings.Contains(k8sName, nsxName)
	}
	return strings.Contains(k8sName, nsxName) || strings.Contains(nsxName, k8sName)
}

func isUncomparable(f ConnectivityFact) bool {
	if strings.EqualFold(f.Protocol, "ICMP") {
		return true
	}
	if strings.Contains(f.SourceIdentity, "ingress-controller") ||
		strings.Contains(f.DestinationIdentity, "ingress-controller") {
		return true
	}
	if strings.Contains(f.SourceIdentity, "entire-cluster") ||
		strings.Contains(f.DestinationIdentity, "entire-cluster") {
		return true
	}
	return false
}

func severityForMissing(f ConnectivityFact) Severity {
	if f.Protocol == "ALL" || f.PortRange == "all" {
		return SeverityCritical
	}
	return SeverityHigh
}

func defaultLimitations() []string {
	return []string{
		"Comparison validates connectivity overlap, not semantic policy equivalence",
		"ICMP connectivity cannot be expressed in Kubernetes NetworkPolicy",
		"IPv6 addresses are not supported by upstream analysis",
		"Identity mapping between NSX VMs and generated K8s workloads is best-effort",
		"Exposure analysis peers (entire-cluster, representative peers) are reported separately",
	}
}

// BuildLabelMap creates a VM-name to K8s-identity mapping from synthesis labels.
func BuildLabelMap(vmNames []string) map[string]string {
	m := make(map[string]string)
	for _, vm := range vmNames {
		m[vm] = vm
	}
	return m
}

// ParseNSXConnectivityJSON parses NSX connectivity JSON output into NSXConnection slice.
func ParseNSXConnectivityFromText(text string) []NSXConnection {
	var conns []NSXConnection
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Source") || strings.HasPrefix(line, "Analyzed") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}
		conns = append(conns, NSXConnection{
			Source:      strings.TrimSpace(parts[0]),
			Destination: strings.TrimSpace(parts[1]),
			Connections: strings.TrimSpace(parts[2]),
		})
	}
	return conns
}

// ParseNSXConnectivityJSON parses connectivity JSON from analysis observations.
func ParseNSXConnectivityJSON(data []byte) []NSXConnection {
	var edges []struct {
		Src         string `json:"src"`
		Dst         string `json:"dst"`
		Conn        string `json:"conn"`
		Connections string `json:"connections"`
	}
	if err := json.Unmarshal(data, &edges); err != nil {
		return nil
	}
	conns := make([]NSXConnection, 0, len(edges))
	for _, e := range edges {
		conn := e.Conn
		if conn == "" {
			conn = e.Connections
		}
		if e.Src == "" && e.Dst == "" {
			continue
		}
		conns = append(conns, NSXConnection{
			Source:      e.Src,
			Destination: e.Dst,
			Connections: conn,
		})
	}
	return conns
}

// PortHint is a DFW allow-rule used to expand unrestricted "All Connections" analysis rows.
type PortHint struct {
	Sources      []string
	Destinations []string
	Protocol     string
	Ports        string
	RuleID       int
}

// ExpandUnrestricted replaces All Connections rows with protocol/port facts from matching DFW hints.
func ExpandUnrestricted(conns []NSXConnection, hints []PortHint) []NSXConnection {
	if len(hints) == 0 {
		return conns
	}
	out := make([]NSXConnection, 0, len(conns))
	for _, c := range conns {
		if !isUnrestrictedConn(c.Connections) {
			out = append(out, c)
			continue
		}
		expanded := false
		for _, hint := range hints {
			if hint.Protocol == "" || strings.EqualFold(hint.Protocol, "ALL") {
				continue
			}
			if hint.Ports == "" || strings.EqualFold(hint.Ports, "all") {
				continue
			}
			if !endpointMatchesHint(hint.Sources, c.Source) || !endpointMatchesHint(hint.Destinations, c.Destination) {
				continue
			}
			out = append(out, NSXConnection{
				Source:      c.Source,
				Destination: c.Destination,
				Connections: fmt.Sprintf("%s dst-ports: %s", hint.Protocol, hint.Ports),
				RuleIDs:     []int{hint.RuleID},
			})
			expanded = true
		}
		if !expanded {
			out = append(out, c)
		}
	}
	return out
}

func isUnrestrictedConn(conn string) bool {
	conn = strings.TrimSpace(conn)
	return conn == "" || strings.EqualFold(conn, "All Connections")
}

func endpointMatchesHint(ruleEndpoints []string, name string) bool {
	if len(ruleEndpoints) == 0 {
		return true
	}
	for _, endpoint := range ruleEndpoints {
		if isAnyHint(endpoint) {
			return true
		}
		if namesCompatible(endpoint, name) {
			return true
		}
	}
	return false
}

func isAnyHint(v string) bool {
	v = strings.TrimSpace(strings.ToUpper(v))
	return v == "" || v == "ANY" || strings.HasSuffix(v, "/GROUPS/ANY")
}

func namesCompatible(ruleName, vmName string) bool {
	r := strings.ToLower(lastPathSegment(ruleName))
	v := strings.ToLower(strings.TrimSpace(vmName))
	if r == "" || v == "" {
		return false
	}
	if r == v {
		return true
	}
	return strings.HasPrefix(v, r+"-") || strings.HasPrefix(r, v+"-")
}

func lastPathSegment(path string) string {
	path = strings.TrimSpace(path)
	if i := strings.LastIndex(path, "/"); i >= 0 && i < len(path)-1 {
		return path[i+1:]
	}
	return path
}
