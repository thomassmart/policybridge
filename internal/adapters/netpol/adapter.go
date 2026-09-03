package netpol

import (
	"fmt"
	"sync"

	"github.com/np-guard/netpol-analyzer/pkg/netpol/connlist"
	"github.com/np-guard/netpol-analyzer/pkg/logger"
)

var mu sync.Mutex

// Adapter wraps netpol-analyzer ConnlistAnalyzer.
type Adapter struct{}

// New creates a new netpol adapter.
func New() *Adapter {
	return &Adapter{}
}

// AnalysisResult holds connlist analysis output.
type AnalysisResult struct {
	Connections []connlist.Peer2PeerConnection
	Peers       []connlist.Peer
	JSONOutput  string
	ExplainText string
	Exposures   []connlist.ExposedPeer
	Errors      []string
}

// AnalyzeDir runs connectivity analysis on a directory of YAML manifests.
func (a *Adapter) AnalyzeDir(dirPath string) (*AnalysisResult, error) {
	mu.Lock()
	defer mu.Unlock()

	ca := connlist.NewConnlistAnalyzer(
		connlist.WithLogger(logger.NewDefaultLogger()),
		connlist.WithExposureAnalysis(),
		connlist.WithOutputFormat("json"),
		connlist.WithMuteErrsAndWarns(),
	)

	conns, peers, err := ca.ConnlistFromDirPath(dirPath)
	if err != nil {
		return nil, fmt.Errorf("connlist analysis: %w", err)
	}

	jsonOut, err := ca.ConnectionsListToString(conns)
	if err != nil {
		return nil, fmt.Errorf("format connections: %w", err)
	}

	result := &AnalysisResult{
		Connections: conns,
		Peers:       peers,
		JSONOutput:  jsonOut,
		Exposures:   ca.ExposedPeers(),
	}

	for _, e := range ca.Errors() {
		if e != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%v", e))
		}
	}

	return result, nil
}

// AnalyzeDirWithExplain runs analysis with explainability (txt format).
func (a *Adapter) AnalyzeDirWithExplain(dirPath string) (*AnalysisResult, error) {
	mu.Lock()
	defer mu.Unlock()

	ca := connlist.NewConnlistAnalyzer(
		connlist.WithLogger(logger.NewDefaultLogger()),
		connlist.WithExplanation(),
		connlist.WithExposureAnalysis(),
		connlist.WithOutputFormat("txt"),
		connlist.WithMuteErrsAndWarns(),
	)

	conns, peers, err := ca.ConnlistFromDirPath(dirPath)
	if err != nil {
		return nil, fmt.Errorf("connlist analysis: %w", err)
	}

	txtOut, err := ca.ConnectionsListToString(conns)
	if err != nil {
		return nil, fmt.Errorf("format connections: %w", err)
	}

	result := &AnalysisResult{
		Connections: conns,
		Peers:       peers,
		ExplainText: txtOut,
		Exposures:   ca.ExposedPeers(),
	}

	for _, e := range ca.Errors() {
		if e != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%v", e))
		}
	}

	return result, nil
}
