package reality

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pires/go-proxyproto"
	utls "github.com/refraction-networking/utls"
)

var GlobalPostHandshakeRecordsLens sync.Map
var GlobalMaxCSSMsgCount sync.Map

func GetConcreteDomain(pattern string) string {
	if !strings.Contains(pattern, "*") {
		return pattern
	}
	// Generate a random 5-character lowercase alphanumeric prefix
	var rndBytes [5]byte
	if _, err := rand.Read(rndBytes[:]); err != nil {
		// Fallback to time-nanosecond pseudo-random bytes if crypto/rand fails
		seed := uint64(time.Now().UnixNano())
		for i := range rndBytes {
			rndBytes[i] = byte(seed >> (i * 8))
		}
	}
	for i, b := range rndBytes {
		rndBytes[i] = "abcdefghijklmnopqrstuvwxyz0123456789"[b%36]
	}
	randomPrefix := string(rndBytes[:])

	if strings.HasPrefix(pattern, "*.") {
		return randomPrefix + "." + pattern[2:]
	}
	return strings.ReplaceAll(pattern, "*", randomPrefix)
}

func GetProbeSNI(config *Config, pattern string) string {
	if pattern != "" && !strings.Contains(pattern, "*") {
		return pattern
	}
	if config == nil {
		if pattern != "" && pattern != "*" {
			return GetConcreteDomain(pattern)
		}
		return ""
	}
	// Prefer host from config.Dest when it is a valid domain name (not an IP),
	// so active probes present a real hostname covered by the target's certificate
	// rather than a random synthesized subdomain that may fail TLS verification.
	host, _, err := net.SplitHostPort(config.Dest)
	if err != nil {
		host = config.Dest
	}
	if net.ParseIP(host) == nil && host != "" {
		if pattern == "" || pattern == "*" || matchWildcardPattern(pattern, host) || config.MatchServerName(host) {
			return host
		}
	}
	// Collect enabled concrete sibling domains in deterministic order.
	var concreteSiblings []string
	for sn, enabled := range config.ServerNames {
		if enabled && sn != "" && !strings.Contains(sn, "*") {
			concreteSiblings = append(concreteSiblings, sn)
		}
	}
	slices.Sort(concreteSiblings)

	if pattern != "" && pattern != "*" {
		for _, sn := range concreteSiblings {
			if matchWildcardPattern(pattern, sn) {
				return sn
			}
		}
		concrete := GetConcreteDomain(pattern)
		if concrete != "" {
			return concrete
		}
	}
	if net.ParseIP(host) == nil && host != "" {
		return host
	}
	// Fallback: Concrete sibling domain before wildcard synthesis (useful when Dest is an IP and pattern is "*")
	if len(concreteSiblings) > 0 {
		return concreteSiblings[0]
	}
	var wildcardSiblings []string
	for sn, enabled := range config.ServerNames {
		if enabled && sn != "" && sn != "*" && strings.Contains(sn, "*") {
			wildcardSiblings = append(wildcardSiblings, sn)
		}
	}
	slices.Sort(wildcardSiblings)
	for _, sn := range wildcardSiblings {
		c := GetConcreteDomain(sn)
		if c != "" {
			return c
		}
	}
	return ""
}

func storeRecordsLensForKeys(keys []string, val any) {
	for _, k := range keys {
		GlobalPostHandshakeRecordsLens.Store(k, val)
	}
}

func storeMaxCCSForKeys(keys []string, val any) {
	for _, k := range keys {
		GlobalMaxCSSMsgCount.Store(k, val)
	}
}

func DetectPostHandshakeRecordsLens(config *Config) {
	if config == nil {
		return
	}
	config.CompileServerNamePatterns()
	sniToPatterns := make(map[string][]string)
	for pattern, enabled := range config.ServerNames {
		if !enabled {
			continue
		}
		probeSNI := GetProbeSNI(config, pattern)
		if probeSNI == "" {
			continue
		}
		sniToPatterns[probeSNI] = append(sniToPatterns[probeSNI], pattern)
	}

	for probeSNI, patterns := range sniToPatterns {
		probeSNI := probeSNI
		patterns := patterns
		for alpn := range 3 { // 0, 1, 2
			alpn := alpn
			alpnStr := strconv.Itoa(alpn)
			probeKey := config.Dest + " " + probeSNI + " " + alpnStr
			keys := make([]string, 0, len(patterns)+1)
			keys = append(keys, probeKey)
			for _, p := range patterns {
				pk := config.Dest + " " + p + " " + alpnStr
				if pk != probeKey {
					keys = append(keys, pk)
				}
			}

			alreadyLoaded := true
			for _, k := range keys {
				if _, loaded := GlobalPostHandshakeRecordsLens.LoadOrStore(k, false); !loaded {
					alreadyLoaded = false
				}
			}
			if !alreadyLoaded {
				go func() {
					defer func() {
						for _, k := range keys {
							val, _ := GlobalPostHandshakeRecordsLens.Load(k)
							if _, ok := val.(bool); ok {
								GlobalPostHandshakeRecordsLens.Store(k, []int{})
							}
						}
					}()
					target, err := net.DialTimeout(config.Type, config.Dest, 5*time.Second)
					if err != nil {
						return
					}
					defer target.Close()
					if config.Xver == 1 || config.Xver == 2 {
						if _, err = proxyproto.HeaderProxyFromAddrs(config.Xver, target.LocalAddr(), target.RemoteAddr()).WriteTo(target); err != nil {
							return
						}
					}
					detectConn := &PostHandshakeRecordDetectConn{
						Conn: target,
						Key:  probeKey,
						Keys: keys,
					}
					fingerprint := utls.HelloChrome_Auto
					nextProtos := []string{"h2", "http/1.1"}
					if alpn != 2 {
						fingerprint = utls.HelloGolang
					}
					if alpn == 1 {
						nextProtos = []string{"http/1.1"}
					}
					if alpn == 0 {
						nextProtos = nil
					}
					uConn := utls.UClient(detectConn, &utls.Config{
						ServerName: probeSNI,
						NextProtos: nextProtos,
					}, fingerprint)
					uConn.SetDeadline(time.Now().Add(5 * time.Second))
					if err = uConn.Handshake(); err != nil {
						return
					}
					io.Copy(io.Discard, uConn)
				}()
				go func() {
					target, err := net.DialTimeout(config.Type, config.Dest, 5*time.Second)
					if err != nil {
						return
					}
					defer target.Close()
					if config.Xver == 1 || config.Xver == 2 {
						if _, err = proxyproto.HeaderProxyFromAddrs(config.Xver, target.LocalAddr(), target.RemoteAddr()).WriteTo(target); err != nil {
							return
						}
					}
					fingerprint := utls.HelloChrome_Auto
					nextProtos := []string{"h2", "http/1.1"}
					if alpn != 2 {
						fingerprint = utls.HelloGolang
					}
					if alpn == 1 {
						nextProtos = []string{"http/1.1"}
					}
					if alpn == 0 {
						nextProtos = nil
					}
					conn := &CCSDetectConn{
						Conn: target,
						Key:  probeKey,
						Keys: keys,
					}
					uConn := utls.UClient(conn, &utls.Config{
						ServerName: probeSNI,
						NextProtos: nextProtos,
					}, fingerprint)
					uConn.SetDeadline(time.Now().Add(5 * time.Second))
					if err = uConn.Handshake(); err != nil {
						return
					}
				}()
			}
		}
	}
}

type PostHandshakeRecordDetectConn struct {
	net.Conn
	Key     string
	Keys    []string
	CcsSent bool
}

func (c *PostHandshakeRecordDetectConn) storeResult(lens []int) {
	if len(c.Keys) > 0 {
		storeRecordsLensForKeys(c.Keys, lens)
	} else if c.Key != "" {
		GlobalPostHandshakeRecordsLens.Store(c.Key, lens)
	}
}

func (c *PostHandshakeRecordDetectConn) Write(b []byte) (n int, err error) {
	if len(b) >= 3 && bytes.Equal(b[:3], []byte{20, 3, 3}) {
		c.CcsSent = true
	}
	return c.Conn.Write(b)
}

func (c *PostHandshakeRecordDetectConn) Read(b []byte) (n int, err error) {
	if !c.CcsSent {
		return c.Conn.Read(b)
	}
	c.Conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	data, _ := io.ReadAll(c.Conn)
	var postHandshakeRecordsLens []int
	for {
		if len(data) >= 5 && bytes.Equal(data[:3], []byte{23, 3, 3}) {
			length := int(binary.BigEndian.Uint16(data[3:5])) + 5
			if length > len(data) {
				break
			}
			postHandshakeRecordsLens = append(postHandshakeRecordsLens, length)
			data = data[length:]
		} else {
			break
		}
	}
	c.storeResult(postHandshakeRecordsLens)
	return 0, io.EOF
}

var CCSMsg = []byte{0x14, 0x3, 0x3, 0x0, 0x1, 0x1}

type CCSDetectConn struct {
	net.Conn
	Key     string
	Keys    []string
	ccsOnce sync.Once
}

func (c *CCSDetectConn) storeResult(maxCount int) {
	if len(c.Keys) > 0 {
		storeMaxCCSForKeys(c.Keys, maxCount)
	} else if c.Key != "" {
		GlobalMaxCSSMsgCount.Store(c.Key, maxCount)
	}
}

func (c *CCSDetectConn) Write(b []byte) (n int, err error) {
	if len(b) >= 3 && bytes.Equal(b[:3], []byte{20, 3, 3}) {
		ran := false
		c.ccsOnce.Do(func() { ran = true })
		if !ran {
			return c.Conn.Write(b)
		}
		var hasAlert atomic.Bool
		go func() {
			defer hasAlert.Store(true)
			buf := make([]byte, 512)
			for {
				_, readErr := c.Conn.Read(buf)
				if readErr != nil {
					return
				}
				if buf[0] == 0x15 {
					return
				}
			}
		}()
		sendProbePayload := func(count int) bool {
			msg := bytes.Repeat(CCSMsg, count)
			c.Conn.Write(msg)
			time.Sleep(1 * time.Second)
			if hasAlert.Load() {
				return true
			}
			return false
		}
		if sendProbePayload(2) {
			c.storeResult(1)
			return c.Conn.Write(b)
		}
		if sendProbePayload(15) {
			c.storeResult(16)
			return c.Conn.Write(b)
		}
		if sendProbePayload(16) {
			c.storeResult(32)
			return c.Conn.Write(b)
		}
		c.storeResult(math.MaxInt)
		return c.Conn.Write(b)
	}
	return c.Conn.Write(b)
}
