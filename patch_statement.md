# Codebase Change Statement: REALITY

**Current Codebase:** `zhfreal/REALITY` (`reality-wildcard-patches`, Tag: `v1.26.9-patch10` / `v1.26.9+patch10`)  
**Original Upstream Baseline:** `XTLS/REALITY` (Commit `83f621788ca88b83179810b12baa7ae518aacb83`)  
**Repository Location:** `./reality-mine`  
**Status:** Production-Ready, Race-Verified (`go test -race ./...` passing 100%)

---

## 1. Executive Summary

This document specifies the complete architectural, functional, performance, and security delta between the current codebase (`zhfreal/REALITY @ reality-wildcard-patches`) and the original upstream baseline (`XTLS/REALITY @ 83f621788ca88b83179810b12baa7ae518aacb83`).

The modifications against the original upstream codebase are organized into two principal categories:
1. **Type 1: New Features & Cryptographic Capabilities**: Zero-allocation wildcard domain pattern pre-compilation, anti-DPI active probing with synthesized 5-character subdomain prefixes, half-close connection propagation, exported zero-copy ECH parsers, and user-tunable handshake/probe/fallback timeouts backed by named protocol constants.
2. **Type 2: Bug Fixes, Concurrency, Memory Leak & Resource Usage Remediations**: Listener panic and leak elimination on shutdown (`send on closed channel`), active probe connection burst deduplication, `sync.RWMutex` recursive read-lock avoidance, `CLOSE_WAIT` socket leak fixes, handshake buffer aliasing elimination, `handPool` / `rawInputPool` / `realityServerBufPool` / `realityS2CBufPool` memory pooling and reclamation across normal, fallback, and failed handshakes, lazy certificate initialization, alert inspection bounds guards, and strict peer certificate verification.

---

## 2. New Features

### 2.1 Zero-Allocation Wildcard SNI Pattern Matching & Pre-compilation (`common.go`, `tls.go`)
* **Thread-Safe Pattern Pre-compilation**:
  - Added `ServerNamePatterns []*regexp.Regexp` and `ServerNamePatternStrings []string` to `Config`.
  - Implemented `CompileServerNamePatterns()` to compile wildcard patterns once at startup, caching compiled regular expressions in `globalServerNameRegexCache` (`sync.Map`) keyed directly by the raw wildcard pattern string so cache hits incur zero heap allocations.
  - Added lazy compilation in `GetMatchedPattern()` under double-checked locking if callers execute handshakes without calling `CompileServerNamePatterns()` first.
* **Deterministic Specificity Sorting & Empty SNI Rejection**:
  - Filtered out disabled `ServerNames` entries (`!enabled`).
  - Sorted compiled patterns by specificity: explicit subdomains (`*.sub.example.com`) take precedence over broader wildcards (`*.example.com`), which take precedence over catch-all (`*`).
  - Enforced strict rejection of empty ClientHello SNI (`""`) against catch-all wildcard `*`.
* **Multi-Level Wildcard Regex Compilation**:
  - Compiled catch-all `"*"` to `^.+$` (matching multi-level fully qualified domain names) and single-label wildcards (`*.example.com`) to `^[^.]+\.example\.com$`.
* **Handshake SNI Matching**:
  - Replaced strict map lookup `!config.ServerNames[hs.clientHello.serverName]` in `Server()` with `!config.MatchServerName(hs.clientHello.serverName)`.
  - Resolved `matchedPattern := config.GetMatchedPattern(hs.clientHello.serverName)` for post-handshake record length and ChangeCipherSpec limit lookups so wildcard matches hit pre-computed detection caches.

### 2.2 Anti-DPI Active Probing with Synthesized Random 5-Character Subdomain Prefixes (`record_detect.go`)
* **Random 5-Character Alphanumeric Prefixing**:
  - Added `GetConcreteDomain(pattern string) string` to synthesize random `DefaultRandomSubdomainLen` (5-character) lowercase alphanumeric prefixes for wildcard subdomains using `crypto/rand` (with nanosecond timestamp fallback).
* **Destination Hostname & Sibling Domain Selection**:
  - Added `GetProbeSNI(config *Config, pattern string) string`, prioritizing `config.Dest`'s domain hostname when `config.Dest` is a domain name so active probes present a hostname covered by the target's certificate.
  - When `config.Dest` is an IP literal, `GetProbeSNI` selects deterministically sorted enabled concrete sibling domains from `config.ServerNames` before falling back to wildcard synthesis.

### 2.3 Half-Close Connection Support (`CloseWrite`) (`tls.go`)
* **Safe Underlying Transport Delegation**:
  - Replaced unconditional type assertion `raw.(CloseWriteConn)` with safe comma-ok checks (`if cw, ok := underlying.(CloseWriteConn); ok { _ = cw.CloseWrite() }`), preserving half-close semantics on TCP/Unix sockets without panicking when the underlying transport is a custom `net.Conn` wrapper or `net.Pipe`.

### 2.4 Exported Zero-Copy ECH Configuration & Extension Decoders (`ech.go`)
* **Exported Public Parsers**:
  - Exported `ParseECHConfig` and `ParseECHExt` wrappers around `parseECHConfig` and `parseECHExt` to allow external consumers (such as Xray-core) to decode and inspect Encrypted Client Hello configurations and extensions directly.
* **Zero-Copy Extension & Single-Allocation AAD Parsing**:
  - Removed the intermediate heap slice copy `data := make([]byte, len(ext)); copy(data, ext)` in `parseECHExt`, parsing directly via `cryptobyte.String(ext)`.
  - Replaced `bytes.Replace(hello[4:], payload, make([]byte, len(payload)), 1)` in `decryptECHPayload` with `outerAAD := bytes.Clone(hello[4:])` and in-place `clear(outerAAD[idx : idx+len(payload)])`, eliminating the temporary zero-slice heap allocation and adding a `len(hello) < 4` bounds check.

### 2.5 User-Tunable Timeouts & Named Protocol Constants (`common.go`, `record_detect.go`, `tls.go`, `handshake_server_tls13.go`)
* **Configurable Timeout Fields**:
  - Added `ProbeTimeout`, `MaxPostHandshakeWait`, `HandshakeTimeout`, and `FallbackReadDeadline` to `Config` (and preserved them in `Config.Clone()`).
* **Named Protocol Constants**:
  - Defined named constants in `common.go` and `tls.go` (`DefaultProbeTimeout`, `DefaultDetectReadDeadline`, `DefaultPostHandshakeWaitTimeout`, `PostHandshakePollInterval`, `MaxPostHandshakeWaitAttempts`, `DefaultHandshakeTimeout`, `DefaultFallbackReadDeadline`, `DefaultRealityServerBufSize`, `RecordMinAEADTagLen`, `RecordHeaderLen`, `RecordMinEncryptedLen`, `Mldsa65CertSignatureOffset`, `DefaultRandomSubdomainLen`, `MaxDetectRecordBufferSize`, `AlertInspectionBufferSize`, `CCSProbeWaitDuration`, `CCSProbeStage1Count`..`CCSProbeStage3MaxResult`, `RecordTypeChangeCipherSpec`, `RecordTypeAlert`, `RecordTypeHandshake`, `RecordTypeApplicationData`, `TLS12RecordVersionMajor`, `TLS12RecordVersionMinor`, `realityIndexServerHello`..`realityIndexNewSessionTicket`, `realityChangeCipherSpecRecordLen`, `realityChangeCipherSpecPayloadByte`, `realityEncryptedExtensionsMinLen`, `realityX25519KeyLen`, `realitySessionIDLen`, `realityAuthKeyHKDFSaltLen`, `realityAuthKeyLen`, `realityProbeBufLen`, `realityClientTimeOffset`, `realityClientShortIDOffset`).

---

## 3. Bug Fixes, Memory Leak & Resource Usage Remediations

### 3.1 Listener Panic & Connection Leak Elimination on Shutdown (`tls.go`)
* **Elimination of `panic: send on closed channel` & In-Flight Handshake Cancellation**:
  - Upstream `NewListener` closed `l.conns` when `l.Listener.Accept()` returned an error, causing concurrent handshake goroutines executing `l.conns <- c` to panic with `send on closed channel`.
  - Added a listener lifecycle context (`ctx`, `cancel`), a `done chan struct{}` closed via `closeOnce sync.Once`, and `errMu sync.Mutex` protecting `l.err`.
  - Handshake workers pass `l.ctx` to `Server(l.ctx, conn, l.config)` and deliver established connections via `select { case l.conns <- tlsConn: case <-l.done: _ = tlsConn.Close() }`.
  - Added panic recovery cleanup so any panic during `Server()` closes `tlsConn` or raw `conn` rather than leaking the file descriptor.
  - Added `listener.Close()` to cancel `l.ctx`, close `l.done`, and drain/close any queued connections in `l.conns`.

### 3.2 Active Probing Deduplication, Deadlock Prevention & Socket Leak Fixes (`record_detect.go`)
* **Probe Connection Burst Deduplication**:
  - Upstream `DetectPostHandshakeRecordsLens` dialed 6 outbound connections per entry in `config.ServerNames`.
  - Grouped enabled patterns by resolved `probeSNI` (`sniToPatterns`) and fanned out probe results across all associated cache keys (`storeRecordsLensForKeys`, `storeMaxCCSForKeys`).
* **Avoidance of Recursive `sync.RWMutex.RLock()`**:
  - Snapshotted `enabledPatterns` under `config.mutex.RLock()` and released `RUnlock()` before calling `GetProbeSNI`, avoiding recursive `RLock()` acquisition on the same goroutine.
* **Socket Leak, PROXY Header Timeout & CCS Probe Deadline Hardening**:
  - Defaulted empty `config.Type` to `"tcp"`, dialed targets via `net.DialTimeout(network, config.Dest, probeTimeout)`, and set `target.SetDeadline(time.Now().Add(probeTimeout))` immediately before writing any PROXY protocol header so stalled targets cannot hang probe goroutines.
  - Added `defer uConn.Close()` in both probe goroutines to ensure TLS and TCP resources are closed on exit.
  - Extended the connection deadline at the start of `CCSDetectConn.Write` (`time.Duration(CCSProbeStageCount)*CCSProbeWaitDuration + DefaultProbeTimeout`) so the 3-second staged ChangeCipherSpec sleep probe does not falsely trigger a read timeout from an earlier handshake deadline.
  - Bounded `PostHandshakeRecordDetectConn.Read` with `io.LimitReader(c.Conn, MaxDetectRecordBufferSize)` (64 KiB) and `DefaultDetectReadDeadline` (1s) to prevent unbounded memory growth.
  - Guarded alert byte inspection in `CCSDetectConn.Write` with `nRead > 0 && buf[0] == RecordTypeAlert`, guarded CCS probing with `ccsOnce sync.Once`, and ensured `GlobalMaxCSSMsgCount` stores `0` on failed probes.

### 3.3 Handshake Buffer Pooling, Aliasing Elimination & Pooled Buffer Reclamation (`tls.go`, `handshake_server_tls13.go`)
* **Lazy Self-Signed Certificate Initialization (`handshake_server_tls13.go`)**:
  - Replaced package `init()` certificate generation with `ensureRealityCerts()` guarded by `realityCertOnce sync.Once` using a stack-allocated `mldsaPlaceholder [3309]byte`, avoiding startup CPU overhead and heap allocations in processes that do not run a REALITY server.
* **Dedicated `handshakeBuf` Allocation & Safe Target Drain (`tls.go`)**:
  - Upstream aliased `hs.c.out.handshakeBuf = buf[:0]` to the shared `target.Read(buf)` scratch slice, risking memory corruption if `target.Read` continued concurrently. Allocated `make([]byte, 0, handshakeLen)` for `handshakeBuf` and passed `remaining := handshakeLen - len(s2cSaved)` by value to the drain goroutine using `io.CopyN(io.Discard, target, int64(remaining))` and a stack `probeBuf [1]byte`.
* **Scratch & Server-to-Client Buffer Pooling (`tls.go`)**:
  - Pooled the 17 KiB target read buffer via `realityServerBufPool` and the 17 KiB server-to-client accumulation buffer via `realityS2CBufPool`.
  - Kept the pooled `s2cBufPtr` slice header untouched (`s2cSaved := (*s2cBufPtr)[:0]` with `defer realityS2CBufPool.Put(s2cBufPtr)`) so forward reslicing (`s2cSaved = s2cSaved[handshakeLen:]`) during record parsing never shrinks the pooled slice's capacity or escapes a new slice header to the heap.
* **Immediate Reclamation of `handPool` and `rawInputPool` Buffers (`tls.go`)**:
  - Added `(*Conn).releaseHandshakeBuffers(force bool)` in `tls.go`.
  - When `Server()` falls back (`hs.c.conn != conn`), `hs.c.releaseHandshakeBuffers(true)` immediately returns `hs.c.hand` to `handPool` and `hs.c.rawInput` to `rawInputPool` before entering the long-lived fallback `io.Copy`, preventing fallback connections from pinning ~4 KiB of TLS handshake buffers for the lifetime of the proxy session and leaking them on exit.
  - When `Server()` completes a valid REALITY handshake, `hs.c.releaseHandshakeBuffers(false)` returns empty `hand` and `rawInput` buffers to their pools (matching `handshakeContext` in `conn.go`); when `Server()` fails, `hs.c.releaseHandshakeBuffers(true)` recycles all buffers before closing `conn`.
* **Stack-Allocated SessionID Buffers, Fast-Filter & Fallback Restoration (`tls.go`)**:
  - Added `len(hs.clientHello.sessionId) == realitySessionIDLen` (32 bytes) pre-check before running X25519 ECDH, HKDF, and AES-GCM.
  - Replaced heap-allocated `make([]byte, 32)` slices with stack-allocated `var ciphertext, plainText [realitySessionIDLen]byte`, and restored `copy(hs.clientHello.sessionId, ciphertext[:])` unconditionally before checking `openErr` so `hs.clientHello.original` is never left zeroed on authentication failure.
* **Semantic Version Comparison Alignment (`tls.go`)**:
  - Added `VersionValue(vals ...byte)` to align 1-, 2-, and 3-byte version slices `[major, minor, patch]` to fixed bit positions `(major << 16) | (minor << 8) | patch` when comparing `ClientVer` against `MinClientVer` / `MaxClientVer`, while keeping `Value(vals ...byte)` as the big-endian integer decoder for TLS record headers. Checked `len(config.MinClientVer) == 0` and `len(config.MaxClientVer) == 0` so non-nil empty version slices do not reject clients.

### 3.4 Active Handshake Deadlines, Bounded Post-Handshake Polling & Fallback Teardown (`tls.go`)
* **Context Watchdog & Handshake Deadlines**:
  - Propagated caller `ctx` into `hs.ctx`, `readClientHello(ctx)`, and a `context.AfterFunc` cancellation watchdog, and applied `HandshakeTimeout` (default `10s`) to both `conn` and `target` during the handshake, clearing deadlines once the handshake or fallback transition completes.
* **Symmetrical Fallback Half-Close Read Deadlines**:
  - Applied `FallbackReadDeadline` (default `5s`) via `SetReadDeadline` on the peer socket after `CloseWrite()` in both fallback directions (`underlying -> target` and `target -> underlying`), preventing half-open peers from pinning fallback goroutines and file descriptors indefinitely.
* **Bounded Post-Handshake Record Polling with Reusable Timer**:
  - Replaced upstream's unbounded `for { time.Sleep(5 * time.Second) }` loop with a bounded polling loop (`MaxPostHandshakeWait`, default `5s` in `500ms` intervals) using a single reusable `*time.Timer` and `<-ctx.Done()` cancellation, and guarded record synthesis with `if length < RecordMinEncryptedLen { continue }`.

### 3.5 Server TLS 1.3 Cryptographic Error & Bounds Hardening (`handshake_server_tls13.go`)
* **Validation of Key Shares, Cipher Suite & ML-DSA-65 Signatures**:
  - Added explicit checks for `hs.suite == nil`, `peerData == nil`, `X25519MLKEM768` peer key share length, and `hs.hello.serverShare.data` capacity.
  - Checked errors from `generateECDHEKey`, `NewPublicKey`, `key.ECDH`, and `mlkem.NewEncapsulationKey768`.
  - Replaced `copy(hs.hello.serverShare.data, append(ciphertext, hs.hello.serverShare.data[:32]...))` with two direct `copy()` calls to avoid a 1,120-byte intermediate heap allocation.
  - Added `if len(cert) < Mldsa65CertSignatureOffset+len(sig)` bounds check before copying the ML-DSA-65 signature into the certificate template.
  - Removed unreachable post-flight dead code below `return nil` in `hs.handshake()`.

### 3.6 Strict Peer Certificate Verification & Deep Config Cloning (`handshake_client.go`, `common.go`)
* **Rejection of Unverified `InsecureSkipVerify` (`handshake_client.go`)**:
  - Updated `verifyServerCertificate` to return a `CertificateVerificationError` when `InsecureSkipVerify` is true without a custom `VerifyPeerCertificate` or `VerifyConnection` callback.
* **Deep Configuration Cloning (`common.go`)**:
  - Updated `Config.Clone()` to deep-clone `ServerNames`, `ShortIds`, `ServerNamePatterns`, `ServerNamePatternStrings`, `MinClientVer`, and `MaxClientVer` using `maps.Clone`, `slices.Clone`, and `bytes.Clone`.

---

## 4. File Modification & Addition Matrix

| File Path | Status | Change Category | Description of Delta Relative to Upstream Baseline (`83f62178`) |
| :--- | :--- | :--- | :--- |
| `common.go` | **Modified** | **Features & Concurrency** | Wildcard regex compilation and zero-alloc `sync.Map` caching, specificity sorting, multi-level `*` support, `MatchServerName`, `GetMatchedPattern`, deep `Config.Clone()`, user-tunable `ProbeTimeout`, `MaxPostHandshakeWait`, `HandshakeTimeout`, and `FallbackReadDeadline` fields, and named protocol constants. |
| `record_detect.go` | **Modified** | **Features & Bugfixes** | Synthesized 5-character random subdomain prefixes (`GetConcreteDomain`), destination hostname/sibling selection (`GetProbeSNI`), active probe deduplication, `RLock` snapshot deadlock avoidance, socket leak fixes (`defer uConn.Close()`), early socket deadlines before PROXY headers, extended `CCSDetectConn` probe deadline, 64 KiB `LimitReader`, and alert bounds guards. |
| `tls.go` | **Modified** | **Performance, Memory & Concurrency** | Listener shutdown panic/leak elimination (`done` channel, `closeOnce`, `ctx` cancellation, panic socket cleanup), `realityServerBufPool` and capacity-preserving `realityS2CBufPool` (17 KiB), `releaseHandshakeBuffers` returning `handPool`/`rawInputPool` buffers on handshake completion, fallback, and error, dedicated `handshakeBuf`, stack `[32]byte` buffers, `VersionValue` semver encoding, handshake/fallback deadlines, and bounded reusable-timer post-handshake polling. |
| `handshake_server_tls13.go` | **Modified** | **Security, Memory & Bounds** | Lazy `sync.Once` certificate initialization (`ensureRealityCerts`), nil/bounds/error checks on TLS 1.3 ECDHE and ML-KEM-768 key exchange, zero-alloc server key share copy, `Mldsa65CertSignatureOffset` bounds check, and unreachable dead code removal. |
| `handshake_client.go` | **Modified** | **Security** | Strict peer certificate verification rejecting `InsecureSkipVerify` when both `VerifyPeerCertificate` and `VerifyConnection` are nil. |
| `ech.go` | **Modified** | **Features & Performance** | Exported zero-copy `ParseECHConfig` and `ParseECHExt` decoders, and single-allocation in-place `clear()` AAD reconstruction in `decryptECHPayload`. |
| `reality_test.go` | **Added** | **Testing** | Unit tests covering wildcard matching, concurrent lazy compilation, domain synthesis, probe SNI selection, `Config.Clone()` concurrency, `Value`/`VersionValue` encoding, `realityS2CBufPool` capacity preservation, and `releaseHandshakeBuffers`. |
| `go.mod` / `go.sum` | **Modified** | **Dependencies** | Switched uTLS dependency to `github.com/metacubex/utls`. |
