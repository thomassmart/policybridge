package redact

import (
	"regexp"
	"strings"
)

var (
	passwordPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|credential)\s*[:=]\s*\S+`),
		regexp.MustCompile(`(?i)NSX_PASSWORD=\S+`),
		regexp.MustCompile(`(?i)--password\s+\S+`),
	}
	basicAuthPattern = regexp.MustCompile(`://[^:]+:[^@]+@`)
)

// Message sanitises a string by redacting known credential patterns.
func Message(msg string, secrets ...string) string {
	result := msg
	for _, p := range passwordPatterns {
		result = p.ReplaceAllString(result, "$1=[REDACTED]")
	}
	result = basicAuthPattern.ReplaceAllString(result, "://[REDACTED]@[REDACTED]@")
	for _, s := range secrets {
		if s != "" {
			result = strings.ReplaceAll(result, s, "[REDACTED]")
		}
	}
	return result
}
