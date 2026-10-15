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

func TestGetProbeSNI(t *testing.T) {
	cfg := &Config{
		Dest: "www.example.com:443",
		ServerNames: map[string]bool{
			"*.example.com": true,
			"*":             true,
		},
	}
	cfg.CompileServerNamePatterns()

	if got := GetProbeSNI(cfg, "*.example.com"); got != "www.example.com" {
		t.Fatalf("GetProbeSNI(*.example.com) = %q, want www.example.com", got)
	}
	if got := GetProbeSNI(cfg, "*"); got != "www.example.com" {
		t.Fatalf("GetProbeSNI(*) = %q, want www.example.com", got)
	}
}
