package session

import "fmt"

// ConnectionView exposes stored NSX connection details without returning the password.
type ConnectionView struct {
	Configured         bool   `json:"configured"`
	Host               string `json:"host,omitempty"`
	Username           string `json:"username,omitempty"`
	HasPassword        bool   `json:"hasPassword"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

// ConnectionInput is the API payload for NSX connection details.
type ConnectionInput struct {
	Host               string
	Username           string
	Password           string
	InsecureSkipVerify bool
}

// StoreCredentials merges input with any existing session credentials and saves in memory.
func (s *Session) StoreCredentials(in ConnectionInput) error {
	host := in.Host
	username := in.Username
	password := in.Password
	insecure := in.InsecureSkipVerify

	if s.Credentials != nil {
		if host == "" {
			host = s.Credentials.Host
		}
		if username == "" {
			username = s.Credentials.Username
		}
		if password == "" {
			password = s.Credentials.Password
		}
	}

	if host == "" {
		return fmt.Errorf("NSX Manager URL is required")
	}
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if password == "" {
		return fmt.Errorf("password is required")
	}

	s.Credentials = &Credentials{
		Host:               host,
		Username:           username,
		Password:           password,
		InsecureSkipVerify: insecure,
	}
	s.SourceType = SourceConnect
	return nil
}

// ConnectionView returns non-secret connection details for the session.
func (s *Session) ConnectionView() ConnectionView {
	if s.Credentials == nil || s.Credentials.Host == "" {
		return ConnectionView{}
	}
	return ConnectionView{
		Configured:         true,
		Host:               s.Credentials.Host,
		Username:           s.Credentials.Username,
		HasPassword:        s.Credentials.Password != "",
		InsecureSkipVerify: s.Credentials.InsecureSkipVerify,
	}
}

// ResolvedCredentials returns stored credentials or an error if incomplete.
func (s *Session) ResolvedCredentials() (*Credentials, error) {
	if s.Credentials == nil || s.Credentials.Host == "" {
		return nil, fmt.Errorf("NSX connection details are not configured for this session")
	}
	if s.Credentials.Password == "" {
		return nil, fmt.Errorf("password is required")
	}
	return s.Credentials, nil
}
