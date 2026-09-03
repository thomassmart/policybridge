package nsx

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	vmrunner "github.com/np-guard/vmware-analyzer/pkg/runner"
)

var mu sync.Mutex

// Adapter wraps vmware-analyzer Runner with serialised access and
// credential-safe configuration.
type Adapter struct{}

// New creates a new NSX adapter.
func New() *Adapter {
	return &Adapter{}
}

// RunnerOption is re-exported for callers.
type RunnerOption = vmrunner.RunnerOption

// Re-export runner options for convenience.
var (
	WithNSXURL                    = vmrunner.WithNSXURL
	WithNSXUser                   = vmrunner.WithNSXUser
	WithNSXPassword               = vmrunner.WithNSXPassword
	WithResourcesInputFile        = vmrunner.WithResourcesInputFile
	WithResourcesAnonymization    = vmrunner.WithResourcesAnonymization
	WithResourcesDumpFile         = vmrunner.WithResourcesDumpFile
	WithDisableInsecureSkipVerify = vmrunner.WithDisableInsecureSkipVerify
	WithAnalysisExplain           = vmrunner.WithAnalysisExplain
	WithAnalysisOutputFile        = vmrunner.WithAnalysisOutputFile
	WithAnalysisVMsFilter         = vmrunner.WithAnalysisVMsFilter
	WithSynthesisDir              = vmrunner.WithSynthesisDir
	WithSynthesisHints            = vmrunner.WithSynthesisHints
	WithSynthAdminPolicies        = vmrunner.WithSynthAdminPolicies
	WithSynthDNSPolicies          = vmrunner.WithSynthDNSPolicies
	WithInferHints                = vmrunner.WithInferHints
	WithHighVerbosity             = vmrunner.WithHighVerbosity
	WithQuietVerbosity            = vmrunner.WithQuietVerbosity
	WithLint                      = vmrunner.WithLint
	WithSkipAnalysis              = vmrunner.WithSkipAnalysis
)

// Run executes a Runner with stdout captured and serialised access.
func (a *Adapter) Run(opts ...RunnerOption) (*vmrunner.Observations, string, error) {
	return a.run(opts, nil)
}

// RunVerbose executes a Runner and streams each stdout/stderr line to onLine while running.
func (a *Adapter) RunVerbose(onLine func(string), opts ...RunnerOption) (*vmrunner.Observations, string, error) {
	return a.run(opts, onLine)
}

func (a *Adapter) run(opts []RunnerOption, onLine func(string)) (*vmrunner.Observations, string, error) {
	mu.Lock()
	defer mu.Unlock()

	oldStdout := os.Stdout
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		return nil, "", fmt.Errorf("capture output: %w", err)
	}
	os.Stdout = w
	os.Stderr = w

	var output strings.Builder
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(r)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			output.WriteString(line)
			output.WriteByte('\n')
			if onLine != nil {
				onLine(line)
			}
		}
	}()

	runner, err := vmrunner.NewRunnerWithOptionsList(opts...)
	if err != nil {
		w.Close()
		wg.Wait()
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		return nil, "", err
	}

	var obs *vmrunner.Observations
	var runErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				runErr = fmt.Errorf("%v", r)
			}
		}()
		obs, runErr = runner.Run()
	}()

	w.Close()
	wg.Wait()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	return obs, output.String(), runErr
}

// NewRunner creates a runner without executing (for inspection).
func (a *Adapter) NewRunner(opts ...RunnerOption) (*vmrunner.Runner, error) {
	mu.Lock()
	defer mu.Unlock()
	return vmrunner.NewRunnerWithOptionsList(opts...)
}
