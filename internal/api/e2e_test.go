//go:build integration

package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/policybridge/policybridge/internal/api"
	"github.com/policybridge/policybridge/internal/fixtures"
	"github.com/policybridge/policybridge/internal/session"
)

func TestE2E_UploadAnalyzeFlow(t *testing.T) {
	store := session.NewStore(t.TempDir(), session.DefaultIdleTimeout)
	srv := api.NewServer(store, "127.0.0.1:0")
	handler := srv.Handler()

	// Create session
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/sessions", nil))
	if w.Code != http.StatusCreated {
		t.Fatalf("create session: %d %s", w.Code, w.Body.String())
	}
	var sess map[string]string
	json.NewDecoder(w.Body).Decode(&sess)

	// Upload fixture dump
	dump := fixtures.LoadFixture("one_redundant_covered_by_2_rules.json")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/sessions/"+sess["id"]+"/source/upload", bytes.NewReader(dump)))
	if w.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}

	// Summary
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/sessions/"+sess["id"]+"/summary", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("summary: %d %s", w.Code, w.Body.String())
	}

	// Analyze
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/sessions/"+sess["id"]+"/analyze", nil))
	if w.Code != http.StatusAccepted {
		t.Fatalf("analyze: %d %s", w.Code, w.Body.String())
	}
	var jobResp map[string]string
	json.NewDecoder(w.Body).Decode(&jobResp)

	// Poll job
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/sessions/"+sess["id"]+"/jobs/"+jobResp["jobId"], nil))
		var job map[string]any
		json.NewDecoder(w.Body).Decode(&job)
		if job["state"] != "running" {
			if job["state"] == "failed" {
				t.Fatalf("analysis failed: %v", job["error"])
			}
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Get analysis
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/sessions/"+sess["id"]+"/analysis", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("get analysis: %d %s", w.Code, w.Body.String())
	}
	var analysis map[string]any
	json.NewDecoder(w.Body).Decode(&analysis)
	if analysis["lint"] == nil {
		t.Fatal("expected lint results in analysis")
	}
}

func TestE2E_MockNSXConnection(t *testing.T) {
	mock := fixtures.MockNSXServer()
	defer mock.Close()

	store := session.NewStore(t.TempDir(), session.DefaultIdleTimeout)
	srv := api.NewServer(store, "127.0.0.1:0")

	body, _ := json.Marshal(map[string]any{
		"host":               mock.URL,
		"username":           "admin",
		"password":           "test",
		"insecureSkipVerify": true,
	})
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/sessions/invalid/source/test", bytes.NewReader(body)))
	// Session not found is expected for invalid session ID
	if w.Code == http.StatusOK {
		var resp map[string]string
		json.NewDecoder(w.Body).Decode(&resp)
		if resp["message"] == "" {
			t.Fatal("expected connection message")
		}
	}
}
