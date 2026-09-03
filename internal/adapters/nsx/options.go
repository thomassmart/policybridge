package nsx

import (
	"reflect"

	vmrunner "github.com/np-guard/vmware-analyzer/pkg/runner"
)

// reflectRunnerOption bridges string values into vmware-analyzer option functions that
// accept internal enum types (common.Endpoints, common.Segments, common.OutFormat).
func reflectRunnerOption(fn any, value string) RunnerOption {
	fv := reflect.ValueOf(fn)
	argType := fv.Type().In(0)
	converted := reflect.ValueOf(value).Convert(argType)
	out := fv.Call([]reflect.Value{converted})
	return out[0].Interface().(RunnerOption)
}

// WithOutputFormatValue sets the runner output format from a string value.
func WithOutputFormatValue(format string) RunnerOption {
	return reflectRunnerOption(vmrunner.WithOutputFormat, format)
}

// WithEndpointsMappingValue sets endpoint synthesis mapping from a string value.
func WithEndpointsMappingValue(mapping string) RunnerOption {
	return reflectRunnerOption(vmrunner.WithEndpointsMapping, mapping)
}

// WithSegmentsMappingValue sets segment synthesis mapping from a string value.
func WithSegmentsMappingValue(mapping string) RunnerOption {
	return reflectRunnerOption(vmrunner.WithSegmentsMapping, mapping)
}

// AnalyzeOptions returns runner options for connectivity analysis.
func AnalyzeOptions(dumpPath, analysisOutput string) []RunnerOption {
	opts := []RunnerOption{
		WithResourcesInputFile(dumpPath),
		WithOutputFormatValue("txt"),
		WithAnalysisExplain(true),
		WithQuietVerbosity(true),
	}
	if analysisOutput != "" {
		opts = append(opts, WithAnalysisOutputFile(analysisOutput))
	}
	return opts
}

// LintOptions returns runner options for lint-only execution.
func LintOptions(dumpPath string) []RunnerOption {
	return []RunnerOption{
		WithResourcesInputFile(dumpPath),
		WithLint(true),
		WithSkipAnalysis(true),
		WithQuietVerbosity(true),
	}
}

// CollectOptions returns runner options for live NSX collection.
func CollectOptions(host, user, password, dumpPath string, disableInsecureSkipVerify, anonymize bool) []RunnerOption {
	opts := []RunnerOption{
		WithNSXURL(host),
		WithNSXUser(user),
		WithNSXPassword(password),
		WithDisableInsecureSkipVerify(disableInsecureSkipVerify),
		WithResourcesDumpFile(dumpPath),
		WithSkipAnalysis(true),
		WithHighVerbosity(true),
	}
	if anonymize {
		opts = append(opts, WithResourcesAnonymization(true))
	}
	return opts
}

// GenerateOptions returns runner options for policy synthesis.
func GenerateOptions(dumpPath, synthesisDir string, cfg GenerationConfig) []RunnerOption {
	opts := []RunnerOption{
		WithResourcesInputFile(dumpPath),
		WithSynthesisDir(synthesisDir),
		WithEndpointsMappingValue(cfg.EndpointsMapping),
		WithSegmentsMappingValue(cfg.SegmentsMapping),
		WithSynthAdminPolicies(cfg.SynthesizeAdminPolicies),
		WithSynthDNSPolicies(cfg.CreateDNSPolicy),
		WithInferHints(cfg.HintsInference),
		WithQuietVerbosity(true),
	}
	if len(cfg.OutputFilter) > 0 {
		opts = append(opts, WithAnalysisVMsFilter(cfg.OutputFilter))
	}
	for _, hint := range cfg.DisjointHints {
		opts = append(opts, WithSynthesisHints([]string{joinHint(hint)}))
	}
	return opts
}

func joinHint(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += "," + parts[i]
	}
	return result
}
