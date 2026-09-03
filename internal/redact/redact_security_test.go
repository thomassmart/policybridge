package redact

import "testing"

func TestMessage_NoSecretsInOutput(t *testing.T) {
	password := "my-super-secret-password"
	input := "failed to connect: password=" + password
	got := Message(input, password)
	if contains(got, password) {
		t.Errorf("password not redacted: %s", got)
	}
}

func TestMessage_PreservesNonSecretContent(t *testing.T) {
	input := "connection refused to nsx.example.com"
	got := Message(input)
	if got != input {
		t.Errorf("unexpected modification: %s", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && search(s, sub)
}

func search(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
