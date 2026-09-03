package nsx

import (
	"strings"
	"testing"

	"github.com/policybridge/policybridge/internal/fixtures"
)

func TestAnalyzeExample2_HasGranularConnectivity(t *testing.T) {
	dump := fixtures.FixturePath("Example2.json")
	adapter := New()
	obs, stdout, err := adapter.Run(AnalyzeOptions(dump, "")...)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	connJSON, err := ConnectivityJSONFromObservations(obs)
	if err != nil {
		t.Fatalf("connectivity json: %v", err)
	}
	if strings.Contains(connJSON, "All Connections") && !strings.Contains(connJSON, "TCP") {
		t.Fatalf("expected granular TCP connectivity in JSON, got: %s", truncate(connJSON, 500))
	}
	if !strings.Contains(stdout, "TCP") {
		t.Fatalf("expected TCP in stdout, got: %s", truncate(stdout, 500))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
