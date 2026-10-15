package reality

import (
	"bytes"
	"sync"
	"testing"
)

func TestWildcardMatching(t *testing.T) {
	cfg := &Config{
		ServerNames: map[string]bool{
			"*.example.com":  true,
			"direct.com":     true,
			"*.disabled.com": false,
			"*":              true,
		},
	}
	cfg.CompileServerNamePatterns()

	testCases := []struct {
		sni             string
		expectedMatch   bool
		expectedPattern string
	}{
		{"test.example.com", true, "*.example.com"},
		{"sub.sub.example.com", true, "*"}, // Falls through single-level *.example.com to catch-all *
		{"example.com", true, "*"},
		{"direct.com", true, "direct.com"},
		{"a.disabled.com", true, "*"}, // Disabled pattern ignored, matched by *
		{"", false, ""},               // Empty SNI must not match *
	}

	for _, tc := range testCases {
		if got := cfg.MatchServerName(tc.sni); got != tc.expectedMatch {
			t.Errorf("MatchServerName(%q) = %v; want %v", tc.sni, got, tc.expectedMatch)
		}
		if gotPattern := cfg.GetMatchedPattern(tc.sni); gotPattern != tc.expectedPattern {
			t.Errorf("GetMatchedPattern(%q) = %q; want %q", tc.sni, gotPattern, tc.expectedPattern)
		}
	}
}

func TestLazyAndConcurrentPatternCompilation(t *testing.T) {
	cfg := &Config{
		ServerNames: map[string]bool{
			"*.example.com":     true,
			"*.sub.example.com": true,
			"*":                 true,
		},
	}
	// Do not call CompileServerNamePatterns upfront; verify lazy compilation and thread-safety
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg.CompileServerNamePatterns()
			if got := cfg.GetMatchedPattern("a.sub.example.com"); got != "*.sub.example.com" {
				t.Errorf("expected *.sub.example.com, got %q", got)
			}
			if got := cfg.GetMatchedPattern("a.example.com"); got != "*.example.com" {
				t.Errorf("expected *.example.com, got %q", got)
			}
		}()
	}
	wg.Wait()
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

	// When Dest is an IP address and a concrete sibling matches the wildcard pattern,
	// GetProbeSNI should select the concrete sibling rather than synthesizing a random subdomain.
	cfgIP := &Config{
		Dest: "1.1.1.1:443",
		ServerNames: map[string]bool{
			"*.example.com":  true,
			"www.example.com": true,
			"*":              true,
		},
	}
	if got := GetProbeSNI(cfgIP, "*.example.com"); got != "www.example.com" {
		t.Fatalf("GetProbeSNI(IP Dest, *.example.com) = %q, want www.example.com", got)
	}
	if got := GetProbeSNI(cfgIP, "*"); got != "www.example.com" {
		t.Fatalf("GetProbeSNI(IP Dest, *) = %q, want www.example.com", got)
	}
}
