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
			"*.example.com":   true,
			"www.example.com": true,
			"*":               true,
		},
	}
	if got := GetProbeSNI(cfgIP, "*.example.com"); got != "www.example.com" {
		t.Fatalf("GetProbeSNI(IP Dest, *.example.com) = %q, want www.example.com", got)
	}
	if got := GetProbeSNI(cfgIP, "*"); got != "www.example.com" {
		t.Fatalf("GetProbeSNI(IP Dest, *) = %q, want www.example.com", got)
	}
}

func TestConfigCloneConcurrency(t *testing.T) {
	cfg := &Config{
		Dest: "www.example.com:443",
		ServerNames: map[string]bool{
			"*.example.com": true,
			"*":             true,
		},
		ShortIds: map[[8]byte]bool{
			{1, 2, 3}: true,
		},
	}
	cfg.CompileServerNamePatterns()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			clone := cfg.Clone()
			_ = clone.MatchServerName("test.example.com")
		}()
	}
	wg.Wait()
}

func TestValueVersionEncoding(t *testing.T) {
	if got, want := VersionValue(26, 7, 11), (26<<16)|(7<<8)|11; got != want {
		t.Fatalf("VersionValue(26,7,11) = %d, want %d", got, want)
	}
	if got, want := VersionValue(26, 7), (26<<16)|(7<<8); got != want {
		t.Fatalf("VersionValue(26,7) = %d, want %d", got, want)
	}
	if got, want := VersionValue(26), 26<<16; got != want {
		t.Fatalf("VersionValue(26) = %d, want %d", got, want)
	}
	if got := VersionValue(); got != 0 {
		t.Fatalf("VersionValue() = %d, want 0", got)
	}
}

func TestValueBigEndian(t *testing.T) {
	if got, want := Value(0x03, 0x03), 0x0303; got != want {
		t.Fatalf("Value(0x03, 0x03) = %x, want %x", got, want)
	}
	if got, want := Value(0x12, 0x34), 0x1234; got != want {
		t.Fatalf("Value(0x12, 0x34) = %x, want %x", got, want)
	}
	if got, want := Value(0x01, 0x02, 0x03), 0x010203; got != want {
		t.Fatalf("Value(0x01, 0x02, 0x03) = %x, want %x", got, want)
	}
}

func TestFallbackReadDeadlineConstant(t *testing.T) {
	if DefaultFallbackReadDeadline <= 0 {
		t.Fatalf("expected positive DefaultFallbackReadDeadline, got %v", DefaultFallbackReadDeadline)
	}
}

func TestS2CBufPoolPreservesCapacityOnReslice(t *testing.T) {
	bufPtr := realityS2CBufPool.Get().(*[]byte)
	origCap := cap(*bufPtr)
	if origCap < DefaultRealityServerBufSize {
		t.Fatalf("expected initial capacity >= %d, got %d", DefaultRealityServerBufSize, origCap)
	}
	s2cSaved := (*bufPtr)[:0]
	s2cSaved = append(s2cSaved, make([]byte, 2048)...)
	// Simulate consuming records by reslicing forward
	s2cSaved = s2cSaved[1200:]
	s2cSaved = s2cSaved[848:]
	realityS2CBufPool.Put(bufPtr)

	bufPtr2 := realityS2CBufPool.Get().(*[]byte)
	defer realityS2CBufPool.Put(bufPtr2)
	if cap(*bufPtr2) < DefaultRealityServerBufSize {
		t.Fatalf("pooled buffer lost capacity after reslicing: got %d, want >= %d", cap(*bufPtr2), DefaultRealityServerBufSize)
	}
}

func TestReleaseHandshakeBuffers(t *testing.T) {
	c := &Conn{}
	hb := c.handBuf()
	hb.Write(make([]byte, 2048))
	rb := rawInputPool.Get().(*bytes.Buffer)
	rb.Grow(4096)
	rb.Write(make([]byte, 2048))
	c.rawInput = rb
	c.smallInput = new(bytes.Buffer)
	c.out.handshakeBuf = make([]byte, 1024)

	// Non-forced release when buffers still have unread data should retain them
	c.releaseHandshakeBuffers(false)
	if c.hand == nil || c.rawInput == nil {
		t.Fatal("expected non-empty buffers to be retained when force=false")
	}

	// Forced release (e.g., on fallback or failed handshake) must recycle and clear all buffers
	c.releaseHandshakeBuffers(true)
	if c.hand != nil || c.rawInput != nil || c.smallInput != nil || c.out.handshakeBuf != nil {
		t.Fatal("expected all handshake buffers to be released and nilled when force=true")
	}
}
