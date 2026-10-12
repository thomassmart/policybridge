package mapping

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// PatchOptions configures kubectl label patch script generation.
type PatchOptions struct {
	Namespace    string
	ResourceType string // deployment, statefulset, virtualmachine
}

// DefaultPatchOptions returns sensible kubectl defaults.
func DefaultPatchOptions() PatchOptions {
	return PatchOptions{
		Namespace:    "default",
		ResourceType: "deployment",
	}
}

// WorkloadPatchEntries returns VM-kind label mappings for patching existing workloads.
func WorkloadPatchEntries(entries []LabelEntry) []LabelEntry {
	var out []LabelEntry
	for _, e := range entries {
		if e.Kind != IdentityVM || e.NSXIdentity == "" {
			continue
		}
		if e.LabelKey == "" || e.LabelValue == "" {
			continue
		}
		out = append(out, e)
	}
	return out
}

// GroupLabelEntries returns group-kind mappings used for policy segmentation labels.
func GroupLabelEntries(entries []LabelEntry) []LabelEntry {
	var out []LabelEntry
	for _, e := range entries {
		if e.Kind != IdentityGroup || e.NSXIdentity == "" {
			continue
		}
		if e.LabelKey == "" || e.LabelValue == "" {
			continue
		}
		out = append(out, e)
	}
	return out
}

// LabelPatchDocument is a machine-readable patch manifest.
type LabelPatchDocument struct {
	Description string              `json:"description"`
	Options     PatchOptions          `json:"options"`
	Patches     []WorkloadLabelPatch  `json:"patches"`
}

// WorkloadLabelPatch labels one migrated workload matched by NSX VM name.
type WorkloadLabelPatch struct {
	WorkloadName string            `json:"workloadName"`
	NSXIdentity  string            `json:"nsxIdentity"`
	Labels       map[string]string `json:"labels"`
}

// LabelPatchJSON builds a JSON manifest for workload label patches.
func LabelPatchJSON(entries []LabelEntry, opts PatchOptions) ([]byte, error) {
	patches := buildWorkloadPatches(entries)
	doc := LabelPatchDocument{
		Description: "Apply labels to existing Kubernetes workloads matched by migrated VM name (NSX identity).",
		Options:     opts,
		Patches:     patches,
	}
	return json.MarshalIndent(doc, "", "  ")
}

// LabelPatchScript builds a shell script with kubectl label commands.
func LabelPatchScript(entries []LabelEntry, opts PatchOptions) string {
	patches := buildWorkloadPatches(entries)
	var buf bytes.Buffer
	buf.WriteString("#!/usr/bin/env bash\n")
	buf.WriteString("# PolicyBridge workload label patch\n")
	buf.WriteString("#\n")
	buf.WriteString("# Applies labels to workloads that already exist in the cluster.\n")
	buf.WriteString("# Workloads are matched by name to the NSX VM identity from your migration.\n")
	buf.WriteString("#\n")
	buf.WriteString("# Usage:\n")
	buf.WriteString("#   export NAMESPACE=your-namespace\n")
	buf.WriteString("#   export RESOURCE_TYPE=deployment   # deployment | statefulset | virtualmachine\n")
	buf.WriteString("#   bash label-patch.sh\n")
	buf.WriteString("#\n")
	buf.WriteString("# OpenShift Virtualization / KubeVirt:\n")
	buf.WriteString("#   kubectl label virtualmachine/... only patches VM object metadata.\n")
	buf.WriteString("#   NetworkPolicy podSelectors match the virt-launcher pod, so security\n")
	buf.WriteString("#   labels (e.g. tag__…) must be on spec.template.metadata.labels.\n")
	buf.WriteString("#   Prefer editing the VirtualMachine template (or a controller that syncs\n")
	buf.WriteString("#   template labels) rather than relying on this script alone for VMs.\n")
	buf.WriteString("#\n")
	buf.WriteString("set -euo pipefail\n\n")
	buf.WriteString("NAMESPACE=\"${NAMESPACE:-" + shellQuote(opts.Namespace) + "}\"\n")
	buf.WriteString("RESOURCE_TYPE=\"${RESOURCE_TYPE:-" + shellQuote(opts.ResourceType) + "}\"\n\n")
	buf.WriteString("apply_label() {\n")
	buf.WriteString("  local workload=\"$1\"\n")
	buf.WriteString("  local key=\"$2\"\n")
	buf.WriteString("  local value=\"$3\"\n")
	buf.WriteString("  kubectl label -n \"$NAMESPACE\" \"$RESOURCE_TYPE/$workload\" \"$key=$value\" --overwrite\n")
	buf.WriteString("}\n\n")

	if len(patches) == 0 {
		buf.WriteString("echo \"No workload label patches defined.\" >&2\n")
		buf.WriteString("exit 1\n")
		return buf.String()
	}

	for _, p := range patches {
		buf.WriteString(fmt.Sprintf("# NSX VM: %s\n", p.NSXIdentity))
		for _, pair := range sortedLabelPairs(p.Labels) {
			buf.WriteString(fmt.Sprintf("apply_label %s %s %s\n",
				shellQuote(p.WorkloadName), shellQuote(pair[0]), shellQuote(pair[1])))
		}
		buf.WriteString("\n")
	}
	return buf.String()
}

func buildWorkloadPatches(entries []LabelEntry) []WorkloadLabelPatch {
	byWorkload := make(map[string]map[string]string)
	for _, e := range WorkloadPatchEntries(entries) {
		name := strings.TrimSpace(e.NSXIdentity)
		if byWorkload[name] == nil {
			byWorkload[name] = make(map[string]string)
		}
		byWorkload[name][e.LabelKey] = e.LabelValue
	}
	out := make([]WorkloadLabelPatch, 0, len(byWorkload))
	for name, labels := range byWorkload {
		out = append(out, WorkloadLabelPatch{
			WorkloadName: name,
			NSXIdentity:  name,
			Labels:       labels,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].WorkloadName < out[j].WorkloadName })
	return out
}

func sortedLabelPairs(labels map[string]string) [][2]string {
	pairs := make([][2]string, 0, len(labels))
	for k, v := range labels {
		pairs = append(pairs, [2]string{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i][0] < pairs[j][0] })
	return pairs
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return r == ' ' || r == '\'' || r == '"' || r == '$' || r == '\\' || r == '\n' || r == '\t'
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
