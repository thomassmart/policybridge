package session

import "testing"

func TestStoreCredentials_MergesWithExisting(t *testing.T) {
	s := &Session{}
	if err := s.StoreCredentials(ConnectionInput{
		Host:     "https://nsx.example.com",
		Username: "admin",
		Password: "secret",
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.StoreCredentials(ConnectionInput{
		Host: "https://nsx2.example.com",
	}); err != nil {
		t.Fatal(err)
	}

	creds, err := s.ResolvedCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if creds.Host != "https://nsx2.example.com" {
		t.Fatalf("expected updated host, got %q", creds.Host)
	}
	if creds.Password != "secret" {
		t.Fatal("expected password to persist from prior store")
	}
}

func TestStoreCredentials_RequiresHost(t *testing.T) {
	s := &Session{}
	if err := s.StoreCredentials(ConnectionInput{}); err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestConnectionView_OmitsPassword(t *testing.T) {
	s := &Session{
		Credentials: &Credentials{
			Host:     "https://nsx.example.com",
			Username: "admin",
			Password: "secret",
		},
	}
	view := s.ConnectionView()
	if !view.Configured || !view.HasPassword {
		t.Fatalf("unexpected view: %+v", view)
	}
	if view.Host != "https://nsx.example.com" {
		t.Fatalf("unexpected host: %q", view.Host)
	}
}
