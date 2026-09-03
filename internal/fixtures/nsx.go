// Package fixtures provides mocked NSX integration and test data.
package fixtures

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
)

// MinimalNSXDump returns a minimal valid ResourcesContainerModel JSON.
func MinimalNSXDump() []byte {
	return []byte(`{
  "services": [],
  "virtual_machines": [
    {"display_name": "frontend-01", "external_id": "vm-1"},
    {"display_name": "backend-01", "external_id": "vm-2"}
  ],
  "virtual_network_interface": [],
  "segments": [{"display_name": "seg-1", "id": "seg-1", "path": "/infra/segments/seg-1"}],
  "tier0": [],
  "tier1": [],
  "domains": [{
    "id": "default",
    "display_name": "default",
    "resources": {
      "security_policies": [{
        "display_name": "app-policy",
        "id": "pol-1",
        "rules": [{
          "display_name": "allow-http",
          "id": "rule-1",
          "action": "ALLOW",
          "services": ["/infra/services/HTTP"],
          "source_groups": ["/infra/domains/default/groups/frontend"],
          "destination_groups": ["/infra/domains/default/groups/backend"]
        }]
      }],
      "gateway_policies": [],
      "redirection_policies": [],
      "groups": [
        {"display_name": "frontend", "id": "grp-frontend", "path": "/infra/domains/default/groups/frontend"},
        {"display_name": "backend", "id": "grp-backend", "path": "/infra/domains/default/groups/backend"}
      ]
    }
  }]
}`)
}

// MockNSXServer returns an httptest server that mimics basic NSX API responses.
func MockNSXServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/fabric/virtual-machines":
			json.NewEncoder(w).Encode(map[string]any{
				"results": []map[string]string{
					{"display_name": "frontend-01", "external_id": "vm-1"},
					{"display_name": "backend-01", "external_id": "vm-2"},
				},
				"result_count": 2,
			})
		default:
			json.NewEncoder(w).Encode(map[string]any{
				"results":      []any{},
				"result_count": 0,
			})
		}
	}))
}

// FixturePath returns the path to a test fixture file.
func FixturePath(name string) string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "nsx", name)
}

// LoadFixture reads a test fixture file, returning minimal dump if not found.
func LoadFixture(name string) []byte {
	path := FixturePath(name)
	data, err := os.ReadFile(path)
	if err != nil {
		return MinimalNSXDump()
	}
	return data
}
