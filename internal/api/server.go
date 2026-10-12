package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	"github.com/policybridge/policybridge/internal/adapters/netpol"
	nsxadapter "github.com/policybridge/policybridge/internal/adapters/nsx"
	"github.com/policybridge/policybridge/internal/compare"
	"github.com/policybridge/policybridge/internal/export"
	"github.com/policybridge/policybridge/internal/mapping"
	"github.com/policybridge/policybridge/internal/redact"
	"github.com/policybridge/policybridge/internal/session"
	"github.com/policybridge/policybridge/internal/version"
)

const (
	maxUploadBytes = 100 * 1024 * 1024 // 100 MB
	cookieMaxAge   = 7200              // 2 hours
)

// Server is the HTTP API server.
type Server struct {
	store      *session.Store
	nsx        *nsxadapter.Adapter
	netpol     *netpol.Adapter
	mux        *http.ServeMux
	logger     *slog.Logger
	listenAddr string
}

// NewServer creates an API server.
func NewServer(store *session.Store, listenAddr string) *Server {
	s := &Server{
		store:      store,
		nsx:        nsxadapter.New(),
		netpol:     netpol.New(),
		mux:        http.NewServeMux(),
		logger:     slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
		listenAddr: listenAddr,
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/about", s.handleAbout)
	s.mux.HandleFunc("POST /api/v1/sessions", s.handleCreateSession)
	s.mux.HandleFunc("GET /api/v1/sessions/current", s.handleCurrentSession)
	s.mux.HandleFunc("POST /api/v1/sessions/{id}/source/upload", s.handleUpload)
	s.mux.HandleFunc("POST /api/v1/sessions/{id}/source/connect", s.handleConnect)
	s.mux.HandleFunc("GET /api/v1/sessions/{id}/source/connection", s.handleGetConnection)
	s.mux.HandleFunc("POST /api/v1/sessions/{id}/source/test", s.handleTestConnection)
	s.mux.HandleFunc("GET /api/v1/sessions/{id}/summary", s.handleSummary)
	s.mux.HandleFunc("GET /api/v1/sessions/{id}/export/dump", s.handleExportDump)
	s.mux.HandleFunc("GET /api/v1/sessions/{id}/export/label-patch", s.handleExportLabelPatch)
	s.mux.HandleFunc("POST /api/v1/sessions/{id}/analyze", s.handleAnalyze)
	s.mux.HandleFunc("GET /api/v1/sessions/{id}/analysis", s.handleGetAnalysis)
	s.mux.HandleFunc("GET /api/v1/sessions/{id}/mapping", s.handleGetMapping)
	s.mux.HandleFunc("PUT /api/v1/sessions/{id}/mapping", s.handlePutMapping)
	s.mux.HandleFunc("GET /api/v1/sessions/{id}/rules/selection", s.handleGetRuleSelection)
	s.mux.HandleFunc("PUT /api/v1/sessions/{id}/rules/selection", s.handlePutRuleSelection)
	s.mux.HandleFunc("POST /api/v1/sessions/{id}/generate", s.handleGenerate)
	s.mux.HandleFunc("GET /api/v1/sessions/{id}/policies", s.handleGetPolicies)
	s.mux.HandleFunc("POST /api/v1/sessions/{id}/validate", s.handleValidate)
	s.mux.HandleFunc("GET /api/v1/sessions/{id}/validation", s.handleGetValidation)
	s.mux.HandleFunc("POST /api/v1/sessions/{id}/export/yaml", s.handleExportYAML)
	s.mux.HandleFunc("POST /api/v1/sessions/{id}/export/kustomize", s.handleExportKustomize)
	s.mux.HandleFunc("GET /api/v1/sessions/{id}/jobs/{jobId}", s.handleGetJob)
	s.mux.HandleFunc("POST /api/v1/sessions/{id}/jobs/cancel", s.handleCancelJob)
}

// Handler returns the HTTP handler with middleware.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		s.mux.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAbout(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version":            version.Version,
		"vmwareAnalyzer":     version.VMwareAnalyzer,
		"netpolAnalyzer":     version.NetpolAnalyzer,
		"license":            "Apache-2.0",
		"independenceNotice": "PolicyBridge is an independent project and is not endorsed by NP-Guard, VMware, Broadcom, Red Hat, or IBM.",
	})
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	sess, err := s.store.Create()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     session.CookieName,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   cookieMaxAge,
	})
	writeJSON(w, http.StatusCreated, map[string]string{"id": sess.ID})
}

func (s *Server) handleCurrentSession(w http.ResponseWriter, r *http.Request) {
	sess := s.getSession(w, r)
	if sess == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":         sess.ID,
		"sourceType": sess.SourceType,
		"anonymized": sess.Anonymized,
		"createdAt":  sess.CreatedAt,
		"currentJob": sess.CurrentJob,
		"connection": sess.ConnectionView(),
	})
}

func (s *Server) handleGetConnection(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	writeJSON(w, http.StatusOK, sess.ConnectionView())
}

func decodeConnectionRequest(r *http.Request) (session.ConnectionInput, bool, error) {
	var req struct {
		Host               string `json:"host"`
		Username           string `json:"username"`
		Password           string `json:"password"`
		InsecureSkipVerify bool   `json:"insecureSkipVerify"`
		Anonymize          bool   `json:"anonymize"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return session.ConnectionInput{}, false, err
	}
	return session.ConnectionInput{
		Host:               strings.TrimSpace(req.Host),
		Username:           req.Username,
		Password:           req.Password,
		InsecureSkipVerify: req.InsecureSkipVerify,
	}, req.Anonymize, nil
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	if sess.IsJobRunning() {
		writeError(w, http.StatusConflict, fmt.Errorf("operation in progress"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("upload too large or read error"))
		return
	}

	resources, err := nsxadapter.ValidateDump(data)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	dumpPath, err := sess.SafePath("dump.json")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := nsxadapter.WriteDump(resources, dumpPath); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	sess.DumpPath = dumpPath
	sess.SourceType = session.SourceUpload
	writeJSON(w, http.StatusOK, nsxadapter.BuildSummary(resources, string(session.SourceUpload)))
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}

	in, anonymize, err := decodeConnectionRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if err := sess.StoreCredentials(in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	job, ctx, err := sess.StartJob("collect")
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}

	go s.runCollect(ctx, sess, job, anonymize)
	writeJSON(w, http.StatusAccepted, map[string]string{"jobId": job.ID})
}

func (s *Server) handleTestConnection(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}

	in, _, err := decodeConnectionRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if err := sess.StoreCredentials(in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	creds, err := sess.ResolvedCredentials()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	disableSkip := !creds.InsecureSkipVerify
	msg, err := nsxadapter.TestConnection(creds.Host, creds.Username, creds.Password, disableSkip)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("%s", redact.Message(err.Error(), creds.Password)))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message":    msg,
		"connection": sess.ConnectionView(),
	})
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	if sess.DumpPath == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("no NSX configuration loaded"))
		return
	}

	data, err := os.ReadFile(sess.DumpPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	resources, err := nsxadapter.ValidateDump(data)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, nsxadapter.BuildSummary(resources, string(sess.SourceType)))
}

func (s *Server) handleExportDump(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	if sess.DumpPath == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("no NSX configuration loaded"))
		return
	}

	data, err := os.ReadFile(sess.DumpPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if _, err := nsxadapter.ValidateDump(data); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("stored dump is invalid: %w", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="nsx-resources.json"`)
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (s *Server) handleExportLabelPatch(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	if sess.Mapping == nil || len(sess.Mapping.LabelMappings) == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("no label mappings configured"))
		return
	}
	entries := mapping.WorkloadPatchEntries(sess.Mapping.LabelMappings)
	if len(entries) == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("no workload (VM) label mappings defined for patch export"))
		return
	}

	opts := mapping.DefaultPatchOptions()
	if ns := r.URL.Query().Get("namespace"); ns != "" {
		opts.Namespace = ns
	} else if sess.Mapping != nil {
		if mapped := mapping.PreferredPatchNamespace(sess.Mapping.Segments); mapped != "" {
			opts.Namespace = mapped
		}
	}
	if rt := r.URL.Query().Get("resourceType"); rt != "" {
		opts.ResourceType = rt
	}

	format := r.URL.Query().Get("format")
	if format == "json" {
		data, err := mapping.LabelPatchJSON(entries, opts)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=label-patch.json")
		w.WriteHeader(http.StatusOK)
		w.Write(data)
		return
	}

	script := mapping.LabelPatchScript(entries, opts)
	w.Header().Set("Content-Type", "application/x-sh")
	w.Header().Set("Content-Disposition", "attachment; filename=label-patch.sh")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(script))
}

func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	if sess.DumpPath == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("no NSX configuration loaded"))
		return
	}

	job, ctx, err := sess.StartJob("analyze")
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}

	go s.runAnalyze(ctx, sess, job)
	writeJSON(w, http.StatusAccepted, map[string]string{"jobId": job.ID})
}

func (s *Server) handleGetAnalysis(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	if sess.AnalysisPath == "" {
		writeError(w, http.StatusNotFound, fmt.Errorf("analysis not yet run"))
		return
	}

	data, err := os.ReadFile(sess.AnalysisPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (s *Server) handleGetMapping(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	if sess.DumpPath == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("no NSX configuration loaded"))
		return
	}

	data, err := os.ReadFile(sess.DumpPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	resources, err := nsxadapter.ValidateDump(data)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, mappingForSession(sess, resources))
}

func mappingForSession(sess *session.Session, resources *collector.ResourcesContainerModel) mapping.Config {
	defaults := mapping.DefaultConfigForScope(resources, nsxadapter.MappingScopeFromSelection(resources, sess.SelectedRuleIDs))
	if sess.Mapping == nil {
		return defaults
	}
	return mapping.Merge(*sess.Mapping, defaults)
}

func (s *Server) handlePutMapping(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	if sess.DumpPath == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("no NSX configuration loaded"))
		return
	}

	var cfg mapping.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	data, err := os.ReadFile(sess.DumpPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	resources, err := nsxadapter.ValidateDump(data)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Merge with scope defaults so a partial/empty PUT cannot drop segment rows
	// (e.g. Seg-Web) that still exist in the selected-rule mapping scope.
	defaults := mapping.DefaultConfigForScope(resources, nsxadapter.MappingScopeFromSelection(resources, sess.SelectedRuleIDs))
	merged := mapping.Merge(cfg, defaults)
	sess.Mapping = &merged
	writeJSON(w, http.StatusOK, merged)
}

func (s *Server) handleGetRuleSelection(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	if sess.DumpPath == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("no NSX configuration loaded"))
		return
	}
	data, err := os.ReadFile(sess.DumpPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	resources, err := nsxadapter.ValidateDump(data)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, nsxadapter.BuildRuleSelectionView(resources, sess.SelectedRuleIDs))
}

func (s *Server) handlePutRuleSelection(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	if sess.DumpPath == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("no NSX configuration loaded"))
		return
	}
	var req struct {
		SelectedRuleIDs []int `json:"selectedRuleIds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	data, err := os.ReadFile(sess.DumpPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	resources, err := nsxadapter.ValidateDump(data)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	allIDs := nsxadapter.AllDFWRuleIDs(resources)
	valid := make(map[int]struct{}, len(allIDs))
	for _, id := range allIDs {
		valid[id] = struct{}{}
	}
	for _, id := range req.SelectedRuleIDs {
		if _, ok := valid[id]; !ok {
			writeError(w, http.StatusBadRequest, fmt.Errorf("unknown rule id: %d", id))
			return
		}
	}
	if len(req.SelectedRuleIDs) == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("at least one DFW rule must be selected"))
		return
	}
	sess.SelectedRuleIDs = nsxadapter.NormalizeSelectedRuleIDs(resources, req.SelectedRuleIDs)
	sess.GenerationPath = ""
	sess.ValidationPath = ""
	writeJSON(w, http.StatusOK, nsxadapter.BuildRuleSelectionView(resources, sess.SelectedRuleIDs))
}

func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	if sess.DumpPath == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("no NSX configuration loaded"))
		return
	}

	var cfg nsxadapter.GenerationConfig
	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	} else {
		cfg = nsxadapter.DefaultGenerationConfig()
	}
	if len(cfg.SegmentMappings) > 0 || len(cfg.LabelMappings) > 0 {
		sess.Mapping = &mapping.Config{
			Segments:      cfg.SegmentMappings,
			LabelMappings: cfg.LabelMappings,
		}
		if len(cfg.SegmentMappings) > 0 {
			cfg.SegmentsMapping = deriveSegmentsMapping(cfg.SegmentMappings)
		}
		cfg.LabelMappings = mapping.GroupLabelEntries(cfg.LabelMappings)
	} else if sess.Mapping != nil && len(sess.Mapping.Segments) > 0 {
		cfg.SegmentMappings = sess.Mapping.Segments
		cfg.LabelMappings = mapping.GroupLabelEntries(sess.Mapping.LabelMappings)
		cfg.SegmentsMapping = deriveSegmentsMapping(sess.Mapping.Segments)
	}

	job, ctx, err := sess.StartJob("generate")
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}

	go s.runGenerate(ctx, sess, job, cfg)
	writeJSON(w, http.StatusAccepted, map[string]string{"jobId": job.ID})
}

func (s *Server) handleGetPolicies(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	if sess.GenerationPath == "" {
		writeError(w, http.StatusNotFound, fmt.Errorf("policies not yet generated"))
		return
	}

	counts, files, err := export.ListResources(sess.GenerationPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	filename := r.URL.Query().Get("file")
	if filename != "" {
		data, err := export.ReadResourceFile(sess.GenerationPath, filename)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"filename": filename, "content": string(data)})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"resourceCounts": counts,
		"files":          files,
	})
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	if sess.GenerationPath == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("policies not yet generated"))
		return
	}

	job, ctx, err := sess.StartJob("validate")
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}

	go s.runValidate(ctx, sess, job)
	writeJSON(w, http.StatusAccepted, map[string]string{"jobId": job.ID})
}

func (s *Server) handleGetValidation(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	if sess.ValidationPath == "" {
		writeError(w, http.StatusNotFound, fmt.Errorf("validation not yet run"))
		return
	}

	data, err := os.ReadFile(sess.ValidationPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (s *Server) handleExportYAML(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	if sess.GenerationPath == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("policies not yet generated"))
		return
	}

	meta := export.ExportMetadata{
		PolicyBridgeVersion:   version.Version,
		VMwareAnalyzerVersion: version.VMwareAnalyzer,
		NetpolAnalyzerVersion: version.NetpolAnalyzer,
	}

	data, err := export.YAMLExport(sess.GenerationPath, meta)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", "attachment; filename=policybridge-export.yaml")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (s *Server) handleExportKustomize(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	if sess.GenerationPath == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("policies not yet generated"))
		return
	}

	var comparisonJSON []byte
	if sess.ValidationPath != "" {
		comparisonJSON, _ = os.ReadFile(sess.ValidationPath)
	}

	meta := export.ExportMetadata{
		PolicyBridgeVersion:   version.Version,
		VMwareAnalyzerVersion: version.VMwareAnalyzer,
		NetpolAnalyzerVersion: version.NetpolAnalyzer,
	}

	data, err := export.KustomizeExport(sess.GenerationPath, comparisonJSON, meta)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=policybridge-export.zip")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	jobID := r.PathValue("jobId")
	job := sess.GetJob(jobID)
	if job == nil {
		writeError(w, http.StatusNotFound, fmt.Errorf("job not found"))
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	sess := s.getSessionByID(w, r)
	if sess == nil {
		return
	}
	sess.CancelJob()
	writeJSON(w, http.StatusOK, map[string]string{"status": "cancelled"})
}

// Background job runners

func (s *Server) runCollect(ctx context.Context, sess *session.Session, job *session.Job, anonymize bool) {
	defer func() {
		if r := recover(); r != nil {
			job.SetError(fmt.Sprintf("collection panic: %v", r))
		}
	}()

	creds := sess.Credentials
	if creds == nil {
		job.SetError("no credentials")
		return
	}

	job.SetProgress(5, "Preparing NSX collection")
	disableSkip := !creds.InsecureSkipVerify
	dumpPath, err := sess.SafePath("dump.json")
	if err != nil {
		job.SetError(err.Error())
		return
	}

	job.SetProgress(10, fmt.Sprintf("Connecting to %s", creds.Host))
	opts := nsxadapter.CollectOptions(
		creds.Host,
		creds.Username,
		creds.Password,
		dumpPath,
		disableSkip,
		anonymize,
	)

	select {
	case <-ctx.Done():
		job.SetState(session.JobCancelled, "cancelled")
		return
	default:
	}

	job.SetProgress(20, "Collecting NSX resources (verbose — see activity console for live API progress)")

	err = runWithHeartbeat(ctx, job, 20, 95, "Collecting NSX resources", func() error {
		_, _, runErr := s.nsx.RunVerbose(func(line string) {
			job.AppendLog(redact.Message(line, creds.Password))
		}, opts...)
		return runErr
	})
	if err != nil {
		if err == context.Canceled {
			job.SetState(session.JobCancelled, "cancelled")
			return
		}
		job.SetError(redact.Message(err.Error(), creds.Password))
		return
	}

	sess.DumpPath = dumpPath
	sess.SourceType = session.SourceConnect
	sess.Anonymized = anonymize
	job.SetProgress(100, "collection complete")
	job.SetState(session.JobCompleted, "collection complete")
}

func (s *Server) runAnalyze(ctx context.Context, sess *session.Session, job *session.Job) {
	analysisPath, err := sess.SafePath("analysis.json")
	if err != nil {
		job.SetError(err.Error())
		return
	}

	job.SetProgress(10, "Running connectivity analysis")

	select {
	case <-ctx.Done():
		job.SetState(session.JobCancelled, "cancelled")
		return
	default:
	}

	job.SetProgress(40, "Analysing NSX connectivity with vmware-analyzer")

	var obs *nsxadapter.Observations
	var stdout string
	err = runWithHeartbeat(ctx, job, 40, 75, "Running connectivity analysis", func() error {
		var runErr error
		obs, stdout, runErr = s.nsx.Run(nsxadapter.AnalyzeOptions(sess.DumpPath, analysisPath)...)
		return runErr
	})
	if err != nil {
		if err == context.Canceled {
			job.SetState(session.JobCancelled, "cancelled")
			return
		}
		job.SetError(redact.Message(err.Error()))
		return
	}

	lintResult, _ := nsxadapter.LintViaRunner(s.nsx, sess.DumpPath)

	job.SetProgress(80, "Parsing DFW lint findings")

	result := map[string]any{
		"lint":   lintResult,
		"stdout": stdout,
	}

	var connJSON string
	if extracted, err := nsxadapter.ConnectivityJSONFromObservations(obs); err == nil {
		connJSON = extracted
		result["connectivityJson"] = json.RawMessage(connJSON)
	}

	dumpData, _ := os.ReadFile(sess.DumpPath)
	if resources, err := nsxadapter.ValidateDump(dumpData); err == nil {
		result["dfwRules"] = nsxadapter.ExtractDFWRules(resources)
		if connJSON != "" {
			result["insights"] = nsxadapter.BuildAnalysisInsights(resources, connJSON)
		}
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	_ = os.WriteFile(analysisPath, data, 0600)
	sess.AnalysisPath = analysisPath
	job.SetProgress(100, "analysis complete")
	job.SetState(session.JobCompleted, "analysis complete")
}

func (s *Server) runGenerate(ctx context.Context, sess *session.Session, job *session.Job, cfg nsxadapter.GenerationConfig) {
	genDir, err := sess.SafePath("k8s_resources")
	if err != nil {
		job.SetError(err.Error())
		return
	}
	_ = os.MkdirAll(genDir, 0700)

	job.SetProgress(10, "Preparing policy synthesis options")

	dumpData, readErr := os.ReadFile(sess.DumpPath)
	if readErr != nil {
		job.SetError(readErr.Error())
		return
	}
	resources, valErr := nsxadapter.ValidateDump(dumpData)
	if valErr != nil {
		job.SetError(valErr.Error())
		return
	}
	spec, specErr := nsxadapter.ParseDefaultRule(cfg.DefaultRule)
	if specErr != nil {
		job.SetError(specErr.Error())
		return
	}
	prepared, prepErr := nsxadapter.PrepareDumpForGeneration(resources, sess.SelectedRuleIDs, spec)
	if prepErr != nil {
		job.SetError(prepErr.Error())
		return
	}
	filteredPath, pathErr := sess.SafePath("filtered-dump.json")
	if pathErr != nil {
		job.SetError(pathErr.Error())
		return
	}
	if writeErr := nsxadapter.WriteDump(prepared, filteredPath); writeErr != nil {
		job.SetError(writeErr.Error())
		return
	}
	for _, warning := range nsxadapter.PrepareWarnings(prepared) {
		job.AppendLog(warning)
	}
	dumpPath := filteredPath

	opts := nsxadapter.GenerateOptions(dumpPath, genDir, cfg)

	select {
	case <-ctx.Done():
		job.SetState(session.JobCancelled, "cancelled")
		return
	default:
	}

	job.SetProgress(30, "Generating Kubernetes resources with vmware-analyzer")
	err = runWithHeartbeat(ctx, job, 30, 95, "Generating Kubernetes resources", func() error {
		_, _, runErr := s.nsx.RunVerbose(func(line string) {
			job.AppendLog(redact.Message(line))
		}, opts...)
		return runErr
	})
	if err != nil {
		if err == context.Canceled {
			job.SetState(session.JobCancelled, "cancelled")
			return
		}
		job.SetError(generationErrorMessage(err))
		return
	}

	actualDir := filepath.Join(genDir, "k8s_resources")
	if _, err := os.Stat(actualDir); err == nil {
		sess.GenerationPath = actualDir
	} else {
		sess.GenerationPath = genDir
	}
	if sess.Mapping != nil {
		renames := mapping.NamespaceRenameMap(sess.Mapping.Segments)
		if len(renames) > 0 {
			job.SetProgress(96, "Applying target namespace mappings")
			if rewriteErr := mapping.RewriteGeneratedNamespaces(sess.GenerationPath, renames); rewriteErr != nil {
				job.SetError("namespace rewrite failed: " + rewriteErr.Error())
				return
			}
			for from, to := range renames {
				job.AppendLog(fmt.Sprintf("namespace mapping: %s -> %s", from, to))
			}
		}
		job.SetProgress(97, "Normalising NetworkPolicy peers")
		peerStats, peerErr := mapping.RewriteNetworkPolicyPeers(sess.GenerationPath, sess.Mapping.Segments)
		if peerErr != nil {
			job.SetError("peer rewrite failed: " + peerErr.Error())
			return
		}
		if peerStats.AnyPeersOmitted > 0 || peerStats.NamespaceSelectorsStripped > 0 {
			job.AppendLog(fmt.Sprintf(
				"peer rewrite: omitted %d ANY-like peer(s), stripped %d same-namespace selector(s)",
				peerStats.AnyPeersOmitted, peerStats.NamespaceSelectorsStripped,
			))
		}
		if data, err := json.MarshalIndent(sess.Mapping, "", "  "); err == nil {
			// Keep mapping.json out of the generated manifests directory. netpol-analyzer
			// tries to decode every file there as a Kubernetes object.
			if mappingPath, pathErr := sess.SafePath("mapping.json"); pathErr == nil {
				_ = os.WriteFile(mappingPath, data, 0600)
			}
		}
	}
	job.SetProgress(100, "generation complete")
	job.SetState(session.JobCompleted, "generation complete")
}

func (s *Server) runValidate(ctx context.Context, sess *session.Session, job *session.Job) {
	job.SetProgress(5, "Starting validation")
	select {
	case <-ctx.Done():
		job.SetState(session.JobCancelled, "cancelled")
		return
	default:
	}

	job.SetProgress(20, "Analysing generated policies with netpol-analyzer")

	npResult, err := s.netpol.AnalyzeDir(sess.GenerationPath)
	if err != nil {
		job.SetError(redact.Message(err.Error()))
		return
	}

	var nsxConns []compare.NSXConnection
	if sess.AnalysisPath != "" {
		analysisData, _ := os.ReadFile(sess.AnalysisPath)
		var analysis map[string]any
		if json.Unmarshal(analysisData, &analysis) == nil {
			nsxConns = nsxConnectionsFromAnalysis(analysis)
		}
	}
	if dumpData, readErr := os.ReadFile(sess.DumpPath); readErr == nil {
		if resources, valErr := nsxadapter.ValidateDump(dumpData); valErr == nil {
			nsxConns = compare.ExpandUnrestricted(nsxConns, dfwPortHints(nsxadapter.ExtractDFWRules(resources)))
		}
	}

	var labelMap map[string]string
	if sess.Mapping != nil && len(sess.Mapping.LabelMappings) > 0 {
		labelMap = mapping.ToIdentityMapWithWorkloads(sess.Mapping.LabelMappings)
	} else {
		labelMap = compare.BuildLabelMap(nil)
	}
	job.SetProgress(70, "Comparing NSX intent with generated policy connectivity")
	cmpResult := compare.Compare(nsxConns, npResult.Connections, labelMap)

	validationResult := map[string]any{
		"netpolAnalysis": npResult.JSONOutput,
		"comparison":     cmpResult,
		"exposures":      len(npResult.Exposures),
		"errors":         npResult.Errors,
	}

	validationPath, err := sess.SafePath("validation.json")
	if err != nil {
		job.SetError(err.Error())
		return
	}
	data, _ := json.MarshalIndent(validationResult, "", "  ")
	_ = os.WriteFile(validationPath, data, 0600)
	sess.ValidationPath = validationPath
	job.SetProgress(100, "validation complete")
	job.SetState(session.JobCompleted, "validation complete")
}

// Helpers

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) *session.Session {
	cookie, err := r.Cookie(session.CookieName)
	if err != nil {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("no session"))
		return nil
	}
	sess, ok := s.store.Get(cookie.Value)
	if !ok {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("session expired"))
		return nil
	}
	return sess
}

func (s *Server) getSessionByID(w http.ResponseWriter, r *http.Request) *session.Session {
	id := r.PathValue("id")
	sess, ok := s.store.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("session not found"))
		return nil
	}
	return sess
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// WarnIfExposed logs a warning if not bound to loopback.
func WarnIfExposed(addr string) {
	if !strings.HasPrefix(addr, "127.0.0.1") && !strings.HasPrefix(addr, "[::1]") && addr != "localhost" {
		slog.Warn("SECURITY WARNING: PolicyBridge is listening on a non-loopback address. This application has no authentication.",
			"address", addr)
	}
}

// WaitForShutdown blocks until context is cancelled, then cleans up.
func (s *Server) WaitForShutdown(ctx context.Context) {
	<-ctx.Done()
	s.store.Shutdown()
}

func generationErrorMessage(err error) string {
	msg := redact.Message(err.Error())
	if strings.Contains(msg, "no default rule") {
		return "vmware-analyzer could not determine remaining connectivity between some workloads (no default DFW rule). Choose New - Drop, New - Allow, or an existing ANY/ANY default on Generation settings."
	}
	return msg
}

func nsxConnectionsFromAnalysis(analysis map[string]any) []compare.NSXConnection {
	if raw, ok := analysis["connectivityJson"]; ok {
		switch v := raw.(type) {
		case []any:
			if data, err := json.Marshal(v); err == nil {
				if conns := compare.ParseNSXConnectivityJSON(data); len(conns) > 0 {
					return conns
				}
			}
		case string:
			if conns := compare.ParseNSXConnectivityJSON([]byte(v)); len(conns) > 0 {
				return conns
			}
		}
	}
	if stdout, ok := analysis["stdout"].(string); ok {
		return compare.ParseNSXConnectivityFromText(stdout)
	}
	return nil
}

func dfwPortHints(rules []nsxadapter.DFWRuleView) []compare.PortHint {
	var hints []compare.PortHint
	for _, rule := range rules {
		if !strings.EqualFold(rule.Action, "ALLOW") {
			continue
		}
		for _, sp := range rule.ServicePorts {
			if sp.Protocol == "" || strings.EqualFold(sp.Protocol, "ALL") {
				continue
			}
			if sp.Ports == "" || strings.EqualFold(sp.Ports, "all") {
				continue
			}
			hints = append(hints, compare.PortHint{
				Sources:      rule.Sources,
				Destinations: rule.Destinations,
				Protocol:     sp.Protocol,
				Ports:        sp.Ports,
				RuleID:       rule.ID,
			})
		}
	}
	return hints
}

func deriveSegmentsMapping(entries []mapping.SegmentEntry) string {
	if len(entries) == 0 {
		return "udns"
	}
	podOnly := true
	for _, e := range entries {
		if e.TargetKind != mapping.TargetPodNetwork {
			podOnly = false
			break
		}
	}
	if podOnly {
		return "pod-network"
	}
	return "udns"
}

// PollJob waits for a job to complete (for testing).
func PollJob(sess *session.Session, jobID string, timeout time.Duration) *session.Job {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		job := sess.GetJob(jobID)
		if job != nil && job.State != session.JobRunning {
			return job
		}
		time.Sleep(100 * time.Millisecond)
	}
	return sess.GetJob(jobID)
}
