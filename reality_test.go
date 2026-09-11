package reality

import (
	"bytes"
	"testing"
)

func TestWildcardMatching(t *testing.T) {
	cfg := &Config{
		ServerNames: map[string]bool{
			"*.example.com": true,
			"direct.com":    true,
		},
	}
	cfg.CompileServerNamePatterns()

	testCases := []struct {
		sni      string
		expected bool
	}{
		{"test.example.com", true},
		{"sub.sub.example.com", false}, // RFC 6125: *.example.com only matches single-level
		{"example.com", false},
		{"direct.com", true},
		{"other.com", false},
	}

	for _, tc := range testCases {
		if got := cfg.MatchServerName(tc.sni); got != tc.expected {
			t.Errorf("MatchServerName(%q) = %v; want %v", tc.sni, got, tc.expected)
		}
	}
}

func TestGetConcreteDomain(t *testing.T) {
	d := GetConcreteDomain("*.example.com")
	if len(d) == 0 || !bytes.HasSuffix([]byte(d), []byte(".example.com")) {
		t.Fatalf("GetConcreteDomain returned unexpected: %s", d)
	}
}
