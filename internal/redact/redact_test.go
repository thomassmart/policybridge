package redact

import "testing"

func TestMessage_RedactsPassword(t *testing.T) {
	input := "connection failed: password=supersecret123"
	got := Message(input)
	if stringsContains(got, "supersecret123") {
		t.Errorf("expected password to be redacted, got: %s", got)
	}
	if !stringsContains(got, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in output, got: %s", got)
	}
}

func TestMessage_RedactsCustomSecret(t *testing.T) {
	input := "auth failed for user admin with key abc123xyz"
	got := Message(input, "abc123xyz")
	if stringsContains(got, "abc123xyz") {
		t.Errorf("expected custom secret to be redacted, got: %s", got)
	}
}

func TestMessage_RedactsBasicAuth(t *testing.T) {
	input := "connecting to https://admin:pass@nsx.example.com/api"
	got := Message(input)
	if stringsContains(got, "admin:pass") {
		t.Errorf("expected basic auth to be redacted, got: %s", got)
	}
}

func stringsContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstr(s, substr)))
}

func findSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
