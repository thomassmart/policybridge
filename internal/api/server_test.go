package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/policybridge/policybridge/internal/fixtures"
	"github.com/policybridge/policybridge/internal/mapping"
	"github.com/policybridge/policybridge/internal/session"
)

func TestHealthEndpoint(t *testing.T) {
	store := session.NewStore(t.TempDir(), session.DefaultIdleTimeout)
	srv := NewServer(store, "127.0.0.1:0")

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAboutEndpoint(t *testing.T) {
	store := session.NewStore(t.TempDir(), session.DefaultIdleTimeout)
	srv := NewServer(store, "127.0.0.1:0")

	req := httptest.NewRequest("GET", "/api/v1/about", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["vmwareAnalyzer"] != "v0.2.1" {
		t.Fatalf("unexpected vmware version: %v", resp["vmwareAnalyzer"])
	}
}

func TestCreateSession(t *testing.T) {
	store := session.NewStore(t.TempDir(), session.DefaultIdleTimeout)
	srv := NewServer(store, "127.0.0.1:0")

	req := httptest.NewRequest("POST", "/api/v1/sessions", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUploadDump(t *testing.T) {
	store := session.NewStore(t.TempDir(), session.DefaultIdleTimeout)
	srv := NewServer(store, "127.0.0.1:0")

	// Create session
	req := httptest.NewRequest("POST", "/api/v1/sessions", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var sessResp map[string]string
	json.NewDecoder(w.Body).Decode(&sessResp)
	sessID := sessResp["id"]

	// Upload dump
	dump := fixtures.MinimalNSXDump()
	req = httptest.NewRequest("POST", "/api/v1/sessions/"+sessID+"/source/upload", bytes.NewReader(dump))
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var summary map[string]any
	json.NewDecoder(w.Body).Decode(&summary)
	if summary["vmCount"] == nil {
		t.Fatal("expected vmCount in summary")
	}

	req = httptest.NewRequest("GET", "/api/v1/sessions/"+sessID+"/export/dump", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("export dump: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Content-Disposition") == "" {
		t.Fatal("expected Content-Disposition header")
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("virtual_machines")) {
		t.Fatal("expected dump JSON body")
	}
}

func TestGetMapping_OmitsUnusedGroups(t *testing.T) {
	store := session.NewStore(t.TempDir(), session.DefaultIdleTimeout)
	srv := NewServer(store, "127.0.0.1:0")

	req := httptest.NewRequest("POST", "/api/v1/sessions", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var sessResp map[string]string
	json.NewDecoder(w.Body).Decode(&sessResp)
	sessID := sessResp["id"]

	dump := fixtures.MinimalNSXDump()
	req = httptest.NewRequest("POST", "/api/v1/sessions/"+sessID+"/source/upload", bytes.NewReader(dump))
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}

	stale := mapping.Config{
		LabelMappings: []mapping.LabelEntry{
			{NSXIdentity: "frontend", Kind: mapping.IdentityGroup, LabelKey: mapping.DefaultGroupLabelKey, LabelValue: "web"},
			{NSXIdentity: "DefaultMaliciousIpGroup", Kind: mapping.IdentityGroup, LabelKey: mapping.DefaultGroupLabelKey, LabelValue: "bad"},
		},
	}
	body, _ := json.Marshal(stale)
	req = httptest.NewRequest("PUT", "/api/v1/sessions/"+sessID+"/mapping", bytes.NewReader(body))
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("put mapping: %d %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest("GET", "/api/v1/sessions/"+sessID+"/mapping", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get mapping: %d %s", w.Code, w.Body.String())
	}
	var cfg mapping.Config
	if err := json.NewDecoder(w.Body).Decode(&cfg); err != nil {
		t.Fatalf("decode mapping: %v", err)
	}
	got := map[string]string{}
	for _, e := range cfg.LabelMappings {
		if e.Kind == mapping.IdentityGroup {
			got[e.NSXIdentity] = e.LabelValue
		}
	}
	if got["frontend"] != "web" {
		t.Fatalf("expected frontend edit preserved, got %#v", cfg.LabelMappings)
	}
	if _, ok := got["DefaultMaliciousIpGroup"]; ok {
		t.Fatalf("unused group should be dropped, got %#v", cfg.LabelMappings)
	}
	if _, ok := got["backend"]; !ok {
		t.Fatalf("expected backend from selected rules, got %#v", cfg.LabelMappings)
	}
}

func TestExportLabelPatch(t *testing.T) {
	store := session.NewStore(t.TempDir(), session.DefaultIdleTimeout)
	srv := NewServer(store, "127.0.0.1:0")

	req := httptest.NewRequest("POST", "/api/v1/sessions", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var sessResp map[string]string
	json.NewDecoder(w.Body).Decode(&sessResp)
	sessID := sessResp["id"]

	dump := fixtures.MinimalNSXDump()
	req = httptest.NewRequest("POST", "/api/v1/sessions/"+sessID+"/source/upload", bytes.NewReader(dump))
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}

	cfg := mapping.Config{
		LabelMappings: []mapping.LabelEntry{{
			NSXIdentity: "frontend-01",
			Kind:        mapping.IdentityVM,
			LabelKey:    "app.kubernetes.io/name",
			LabelValue:  "frontend",
		}},
	}
	body, _ := json.Marshal(cfg)
	req = httptest.NewRequest("PUT", "/api/v1/sessions/"+sessID+"/mapping", bytes.NewReader(body))
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("put mapping: %d %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest("GET", "/api/v1/sessions/"+sessID+"/export/label-patch", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("export label patch: %d %s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("kubectl label")) {
		t.Fatalf("expected kubectl label script, got: %s", w.Body.Bytes())
	}
}

func TestUploadDump_InvalidJSON(t *testing.T) {
	store := session.NewStore(t.TempDir(), session.DefaultIdleTimeout)
	srv := NewServer(store, "127.0.0.1:0")

	req := httptest.NewRequest("POST", "/api/v1/sessions", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var sessResp map[string]string
	json.NewDecoder(w.Body).Decode(&sessResp)

	req = httptest.NewRequest("POST", "/api/v1/sessions/"+sessResp["id"]+"/source/upload",
		bytes.NewReader([]byte(`{"invalid": true}`)))
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestExportYAML_NoPolicies(t *testing.T) {
	store := session.NewStore(t.TempDir(), session.DefaultIdleTimeout)
	srv := NewServer(store, "127.0.0.1:0")

	req := httptest.NewRequest("POST", "/api/v1/sessions", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var sessResp map[string]string
	json.NewDecoder(w.Body).Decode(&sessResp)

	req = httptest.NewRequest("POST", "/api/v1/sessions/"+sessResp["id"]+"/export/yaml", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without policies, got %d", w.Code)
	}
}

func TestPathTraversalRejected(t *testing.T) {
	sess, _ := session.NewStore(t.TempDir(), session.DefaultIdleTimeout).Create()
	_, err := sess.SafePath("../etc/passwd")
	if err == nil {
		t.Fatal("expected path traversal rejection")
	}
}

func TestConnectionPersistence(t *testing.T) {
	store := session.NewStore(t.TempDir(), session.DefaultIdleTimeout)
	srv := NewServer(store, "127.0.0.1:0")
	handler := srv.Handler()

	req := httptest.NewRequest("POST", "/api/v1/sessions", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	var sessResp map[string]string
	json.NewDecoder(w.Body).Decode(&sessResp)

	body := []byte(`{"host":"https://nsx.example.com","username":"admin","password":"secret123","insecureSkipVerify":true}`)
	req = httptest.NewRequest("POST", "/api/v1/sessions/"+sessResp["id"]+"/source/test", bytes.NewReader(body))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway && w.Code != http.StatusOK {
		t.Fatalf("test connection: expected 200 or 502, got %d %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest("GET", "/api/v1/sessions/"+sessResp["id"]+"/source/connection", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get connection: %d %s", w.Code, w.Body.String())
	}
	var conn map[string]any
	json.NewDecoder(w.Body).Decode(&conn)
	if conn["configured"] != true {
		t.Fatalf("expected configured connection: %+v", conn)
	}
	if conn["host"] != "https://nsx.example.com" {
		t.Fatalf("unexpected host: %v", conn["host"])
	}
	if conn["hasPassword"] != true {
		t.Fatal("expected hasPassword true")
	}

	// Partial update should keep password in session memory
	req = httptest.NewRequest("POST", "/api/v1/sessions/"+sessResp["id"]+"/source/test",
		bytes.NewReader([]byte(`{"host":"https://nsx2.example.com","username":"admin"}`)))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code == http.StatusBadRequest {
		t.Fatalf("partial update should succeed: %s", w.Body.String())
	}

	req = httptest.NewRequest("GET", "/api/v1/sessions/"+sessResp["id"]+"/source/connection", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	json.NewDecoder(w.Body).Decode(&conn)
	if conn["host"] != "https://nsx2.example.com" {
		t.Fatalf("expected updated host, got %v", conn["host"])
	}
}

func TestCredentialRedaction(t *testing.T) {
	store := session.NewStore(t.TempDir(), session.DefaultIdleTimeout)
	srv := NewServer(store, "127.0.0.1:0")

	req := httptest.NewRequest("POST", "/api/v1/sessions", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var sessResp map[string]string
	json.NewDecoder(w.Body).Decode(&sessResp)

	req = httptest.NewRequest("POST", "/api/v1/sessions/"+sessResp["id"]+"/source/test",
		bytes.NewReader([]byte(`{"host":"https://bad.example.com","username":"admin","password":"secret123"}`)))
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	body := w.Body.String()
	if bytes.Contains([]byte(body), []byte("secret123")) {
		t.Fatal("password leaked in response")
	}
}

func TestWarnIfExposed(t *testing.T) {
	// Should not panic
	WarnIfExposed("127.0.0.1:8080")
	WarnIfExposed("0.0.0.0:8080")
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
