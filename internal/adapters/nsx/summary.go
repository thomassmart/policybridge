package nsx

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	vmrunner "github.com/np-guard/vmware-analyzer/pkg/runner"
	"github.com/policybridge/policybridge/internal/mapping"
)

// Summary provides a concise overview of collected NSX configuration.
type Summary struct {
	SourceType     string   `json:"sourceType"`
	NSXVersion     string   `json:"nsxVersion"`
	VMCount        int      `json:"vmCount"`
	GroupCount     int      `json:"groupCount"`
	SegmentCount   int      `json:"segmentCount"`
	DFWPolicyCount int      `json:"dfwPolicyCount"`
	DFWRuleCount   int      `json:"dfwRuleCount"`
	ServiceCount   int      `json:"serviceCount"`
	Warnings       []string `json:"warnings,omitempty"`
}

// ValidateDump checks that JSON bytes unmarshal to ResourcesContainerModel.
func ValidateDump(data []byte) (*collector.ResourcesContainerModel, error) {
	resources, err := collector.FromJSONString(data)
	if err != nil {
		return nil, fmt.Errorf("invalid NSX resource dump: %w", err)
	}
	if len(resources.VirtualMachineList) == 0 && len(resources.DomainList) == 0 {
		return nil, fmt.Errorf("dump contains no virtual machines or domains")
	}
	return resources, nil
}

// BuildSummary creates a summary from a resources container.
func BuildSummary(resources *collector.ResourcesContainerModel, sourceType string) Summary {
	s := Summary{
		SourceType:   sourceType,
		NSXVersion:   "not reported by the collector",
		VMCount:      len(resources.VirtualMachineList),
		SegmentCount: len(resources.SegmentList),
		ServiceCount: len(resources.ServiceList),
	}

	for _, domain := range resources.DomainList {
		s.GroupCount += len(domain.Resources.GroupList)
		s.DFWPolicyCount += len(domain.Resources.SecurityPolicyList)
		for _, pol := range domain.Resources.SecurityPolicyList {
			s.DFWRuleCount += len(pol.Rules)
			if pol.DefaultRule != nil {
				s.DFWRuleCount++
			}
		}
	}

	if len(resources.DomainList) > 1 {
		s.Warnings = append(s.Warnings, "Multiple NSX domains detected; only single-domain analysis is supported")
	}

	return s
}

// TestConnection validates NSX Manager connectivity.
func TestConnection(host, user, password string, disableInsecureSkipVerify bool) (string, error) {
	return collector.ValidateNSXConnection(host, user, password, disableInsecureSkipVerify)
}

// LintResult holds parsed lint findings.
type LintResult struct {
	ShadowedRules    []ShadowedRule    `json:"shadowedRules,omitempty"`
	IneffectiveRules []IneffectiveRule `json:"ineffectiveRules,omitempty"`
	RawReport        string            `json:"rawReport,omitempty"`
	Structured       bool              `json:"structured"`
}

type ShadowedRule struct {
	RuleID           string `json:"ruleId"`
	Category         string `json:"category"`
	Direction        string `json:"direction"`
	ShadowingRuleIDs string `json:"shadowingRuleIds"`
}

type IneffectiveRule struct {
	RuleID      string `json:"ruleId"`
	Description string `json:"description"`
}

// ParseLintReport attempts to parse the text lint report into structured findings.
func ParseLintReport(report string) LintResult {
	result := LintResult{RawReport: report, Structured: true}

	lines := strings.Split(report, "\n")
	inShadowed := false
	inIneffective := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "Potential shadowed") {
			inShadowed = true
			inIneffective = false
			continue
		}
		if strings.Contains(trimmed, "Ineffective DFW") {
			inShadowed = false
			inIneffective = true
			continue
		}
		if strings.Contains(trimmed, "rule ID") || strings.Contains(trimmed, "----") {
			continue
		}
		if strings.Contains(trimmed, "No redundant") {
			result.Structured = true
			return result
		}

		parts := strings.Split(trimmed, "|")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}

		if inShadowed && len(parts) >= 4 {
			result.ShadowedRules = append(result.ShadowedRules, ShadowedRule{
				RuleID:           parts[0],
				Category:         parts[1],
				Direction:        parts[2],
				ShadowingRuleIDs: parts[3],
			})
		}
		if inIneffective && len(parts) >= 2 {
			result.IneffectiveRules = append(result.IneffectiveRules, IneffectiveRule{
				RuleID:      parts[0],
				Description: parts[1],
			})
		}
	}

	if len(result.ShadowedRules) == 0 && len(result.IneffectiveRules) == 0 &&
		!strings.Contains(report, "No redundant") {
		result.Structured = false
	}
	return result
}

// WriteDump writes resources to a JSON file.
func WriteDump(resources *collector.ResourcesContainerModel, path string) error {
	jsonStr, err := resources.ToJSONString()
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(jsonStr), 0600)
}

// GenerationConfig holds synthesis options for the API.
type GenerationConfig struct {
	EndpointsMapping        string                 `json:"endpointsMapping"`
	SegmentsMapping         string                 `json:"segmentsMapping"`
	PolicyOptimizationLevel string                 `json:"policyOptimizationLevel"`
	SynthesizeAdminPolicies bool                   `json:"synthesizeAdminPolicies"`
	CreateDNSPolicy         bool                   `json:"createDNSPolicy"`
	DisjointHints           [][]string             `json:"disjointHints,omitempty"`
	HintsInference          bool                   `json:"hintsInference"`
	OutputFilter            []string               `json:"outputFilter,omitempty"`
	DefaultRule             string                 `json:"defaultRule,omitempty"`
	LabelMappings           []mapping.LabelEntry   `json:"labelMappings,omitempty"`
	SegmentMappings         []mapping.SegmentEntry `json:"segmentMappings,omitempty"`
}

// DefaultGenerationConfig returns safe defaults with documented rationale.
func DefaultGenerationConfig() GenerationConfig {
	return GenerationConfig{
		EndpointsMapping:        "both",
		SegmentsMapping:         "udns",
		PolicyOptimizationLevel: "max",
		SynthesizeAdminPolicies: false,
		CreateDNSPolicy:         false,
		HintsInference:          false,
		DefaultRule:             DefaultRuleNewDrop,
	}
}

// MarshalGenerationConfig serialises config for storage.
func MarshalGenerationConfig(cfg GenerationConfig) ([]byte, error) {
	return json.Marshal(cfg)
}

// ConnectivityJSONFromObservations extracts connectivity JSON from observations.
func ConnectivityJSONFromObservations(obs *vmrunner.Observations) (string, error) {
	if obs == nil {
		return "[]", nil
	}
	res, err := obs.ConfigAsJSON()
	if err != nil {
		return "", err
	}
	return res.Connectivity, nil
}

// LintViaRunner runs lint command via runner and returns stdout + parsed result.
func LintViaRunner(adapter *Adapter, dumpPath string) (LintResult, error) {
	_, stdout, err := adapter.Run(LintOptions(dumpPath)...)
	if err != nil {
		return LintResult{}, err
	}
	return ParseLintReport(stdout), nil
}

// ConfigFromDump parses configuration from a dump file path via runner analyze.
func ConfigFromDump(adapter *Adapter, dumpPath string) (*vmrunner.Observations, error) {
	obs, _, err := adapter.Run(AnalyzeOptions(dumpPath, "")...)
	return obs, err
}

// Observations re-export.
type Observations = vmrunner.Observations
