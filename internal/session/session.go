package session

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/policybridge/policybridge/internal/mapping"
)

const (
	DefaultIdleTimeout = 2 * time.Hour
	CookieName         = "policybridge_session"
)

// Credentials holds NSX connection credentials in memory only.
type Credentials struct {
	Host                    string
	Username                string
	Password                string
	InsecureSkipVerify      bool
}

// Wipe zeroes credential fields.
func (c *Credentials) Wipe() {
	if c == nil {
		return
	}
	c.Host = ""
	c.Username = ""
	c.Password = ""
}

// SourceType identifies how NSX configuration was obtained.
type SourceType string

const (
	SourceUpload  SourceType = "upload"
	SourceConnect SourceType = "connect"
)

// JobState tracks background operation status.
type JobState string

const (
	JobIdle      JobState = "idle"
	JobRunning   JobState = "running"
	JobCompleted JobState = "completed"
	JobFailed    JobState = "failed"
	JobCancelled JobState = "cancelled"
)

// Job represents a cancellable background operation.
type Job struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	State     JobState  `json:"state"`
	Progress  int       `json:"progress"`
	Message   string    `json:"message,omitempty"`
	Logs      []string  `json:"logs,omitempty"`
	Error     string    `json:"error,omitempty"`
	StartedAt time.Time `json:"startedAt,omitempty"`
	DoneAt    time.Time `json:"doneAt,omitempty"`

	cancel context.CancelFunc
	mu     sync.Mutex
}

func (j *Job) SetState(state JobState, msg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.State = state
	j.Message = msg
	if state == JobCompleted || state == JobFailed || state == JobCancelled {
		j.DoneAt = time.Now()
	}
}

func (j *Job) SetError(err string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.State = JobFailed
	j.Error = err
	j.DoneAt = time.Now()
}

// SetProgress updates running job progress without changing terminal state.
func (j *Job) SetProgress(progress int, msg string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if progress > 0 {
		j.Progress = progress
	}
	if msg != "" {
		j.Message = msg
	}
}

// AppendLog records a verbose progress line for polling clients.
func (j *Job) AppendLog(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	const maxLogs = 500
	if len(j.Logs) >= maxLogs {
		j.Logs = j.Logs[len(j.Logs)-maxLogs+1:]
	}
	j.Logs = append(j.Logs, line)
	j.Message = line
}

// Session holds all state for a single analysis workflow.
type Session struct {
	ID          string       `json:"id"`
	CreatedAt   time.Time    `json:"createdAt"`
	LastAccess  time.Time    `json:"lastAccess"`
	SourceType  SourceType   `json:"sourceType,omitempty"`
	Anonymized  bool         `json:"anonymized"`
	TempDir     string       `json:"-"`
	Credentials *Credentials `json:"-"`

	// Cached results (paths within TempDir or serialised JSON)
	DumpPath       string `json:"-"`
	AnalysisPath   string `json:"-"`
	GenerationPath string `json:"-"`
	ValidationPath string `json:"-"`
	Mapping        *mapping.Config `json:"-"`
	SelectedRuleIDs []int          `json:"-"` // nil = all rules; non-nil = explicit subset

	CurrentJob *Job   `json:"currentJob,omitempty"`
	jobs       map[string]*Job

	mu sync.Mutex
}

// Touch updates last access time.
func (s *Session) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastAccess = time.Now()
}

// IsJobRunning returns true if a job is currently running.
func (s *Session) IsJobRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.CurrentJob != nil && s.CurrentJob.State == JobRunning
}

// StartJob creates and registers a new job, cancelling any conflicting operation.
func (s *Session) StartJob(jobType string) (*Job, context.Context, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.CurrentJob != nil && s.CurrentJob.State == JobRunning {
		return nil, nil, fmt.Errorf("a %s operation is already running", s.CurrentJob.Type)
	}

	ctx, cancel := context.WithCancel(context.Background())
	job := &Job{
		ID:        uuid.New().String(),
		Type:      jobType,
		State:     JobRunning,
		Message:   "starting",
		StartedAt: time.Now(),
		cancel:    cancel,
	}
	s.CurrentJob = job
	if s.jobs == nil {
		s.jobs = make(map[string]*Job)
	}
	s.jobs[job.ID] = job
	return job, ctx, nil
}

// GetJob returns a job by ID.
func (s *Session) GetJob(id string) *Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jobs[id]
}

// CancelJob cancels the current running job.
func (s *Session) CancelJob() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.CurrentJob != nil && s.CurrentJob.State == JobRunning {
		if s.CurrentJob.cancel != nil {
			s.CurrentJob.cancel()
		}
		s.CurrentJob.State = JobCancelled
		s.CurrentJob.DoneAt = time.Now()
	}
}

// Cleanup removes temp directory and wipes credentials.
func (s *Session) Cleanup() {
	s.Credentials.Wipe()
	if s.TempDir != "" {
		_ = os.RemoveAll(s.TempDir)
	}
}

// Store manages in-memory sessions.
type Store struct {
	sessions    map[string]*Session
	idleTimeout time.Duration
	tempRoot    string
	mu          sync.RWMutex
}

// NewStore creates a session store.
func NewStore(tempRoot string, idleTimeout time.Duration) *Store {
	if idleTimeout == 0 {
		idleTimeout = DefaultIdleTimeout
	}
	return &Store{
		sessions:    make(map[string]*Session),
		idleTimeout: idleTimeout,
		tempRoot:    tempRoot,
	}
}

// Create creates a new session with an isolated temp directory.
func (st *Store) Create() (*Session, error) {
	id := uuid.New().String()
	dir := filepath.Join(st.tempRoot, "policybridge-"+id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create session directory: %w", err)
	}

	s := &Session{
		ID:         id,
		CreatedAt:  time.Now(),
		LastAccess: time.Now(),
		TempDir:    dir,
		jobs:       make(map[string]*Job),
	}

	st.mu.Lock()
	st.sessions[id] = s
	st.mu.Unlock()
	return s, nil
}

// Get returns a session by ID.
func (st *Store) Get(id string) (*Session, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	s, ok := st.sessions[id]
	if ok {
		s.Touch()
	}
	return s, ok
}

// Delete removes and cleans up a session.
func (st *Store) Delete(id string) {
	st.mu.Lock()
	s, ok := st.sessions[id]
	if ok {
		delete(st.sessions, id)
	}
	st.mu.Unlock()
	if ok {
		s.Cleanup()
	}
}

// StartCleanup runs a background goroutine that expires idle sessions.
func (st *Store) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			st.expireIdle()
		}
	}
}

func (st *Store) expireIdle() {
	now := time.Now()
	var expired []string
	st.mu.RLock()
	for id, s := range st.sessions {
		if now.Sub(s.LastAccess) > st.idleTimeout {
			expired = append(expired, id)
		}
	}
	st.mu.RUnlock()
	for _, id := range expired {
		st.Delete(id)
	}
}

// Shutdown cleans up all sessions.
func (st *Store) Shutdown() {
	st.mu.Lock()
	ids := make([]string, 0, len(st.sessions))
	for id := range st.sessions {
		ids = append(ids, id)
	}
	st.mu.Unlock()
	for _, id := range ids {
		st.Delete(id)
	}
}

// SafePath resolves a relative path within the session temp directory,
// rejecting path traversal attempts.
func (s *Session) SafePath(rel string) (string, error) {
	clean := filepath.Clean(rel)
	if filepath.IsAbs(clean) || clean == ".." || len(clean) >= 3 && clean[:3] == "../" {
		return "", fmt.Errorf("path traversal rejected: %s", rel)
	}
	full := filepath.Join(s.TempDir, clean)
	absBase, err := filepath.Abs(s.TempDir)
	if err != nil {
		return "", err
	}
	absFull, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	if absFull != absBase && (len(absFull) <= len(absBase) || !strings.HasPrefix(absFull, absBase+string(filepath.Separator))) {
		return "", fmt.Errorf("path outside session directory: %s", rel)
	}
	return full, nil
}
