package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafePath_RejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	s := &Session{TempDir: dir}

	_, err := s.SafePath("../etc/passwd")
	if err == nil {
		t.Fatal("expected error for path traversal")
	}

	_, err = s.SafePath("/etc/passwd")
	if err == nil {
		t.Fatal("expected error for absolute path")
	}
}

func TestSafePath_AllowsValidPath(t *testing.T) {
	dir := t.TempDir()
	s := &Session{TempDir: dir}

	p, err := s.SafePath("dump.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(p, dir) {
		t.Fatalf("path %s not under %s", p, dir)
	}
}

func TestStore_CreateAndDelete(t *testing.T) {
	root := t.TempDir()
	st := NewStore(root, DefaultIdleTimeout)

	s, err := st.Create()
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	got, ok := st.Get(s.ID)
	if !ok || got.ID != s.ID {
		t.Fatal("session not found after create")
	}

	dumpPath := filepath.Join(s.TempDir, "test.txt")
	if err := os.WriteFile(dumpPath, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}

	st.Delete(s.ID)
	if _, ok := st.Get(s.ID); ok {
		t.Fatal("session still exists after delete")
	}
	if _, err := os.Stat(dumpPath); !os.IsNotExist(err) {
		t.Fatal("temp dir not cleaned up")
	}
}

func TestCredentials_Wipe(t *testing.T) {
	c := &Credentials{Host: "h", Username: "u", Password: "p"}
	c.Wipe()
	if c.Password != "" || c.Host != "" {
		t.Fatal("credentials not wiped")
	}
}

func TestSession_ConcurrentJobGuard(t *testing.T) {
	s := &Session{jobs: make(map[string]*Job)}
	_, _, err := s.StartJob("analyze")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s.StartJob("generate")
	if err == nil {
		t.Fatal("expected error for concurrent job")
	}
}
