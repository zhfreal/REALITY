# Codebase Change Statement: REALITY

**Current Codebase:** `zhfreal/REALITY` (`reality-wildcard-patches`)  
**Original Upstream Baseline:** `XTLS/REALITY` (Commit `83f621788ca88b83179810b12baa7ae518aacb83`, baseline used in Xray-core v26.10.21)  
**Repository Location:** `./reality-mine`  
**Status:** Production-Ready, Race-Verified (`go test -race ./...` passing 100%)

---

## 1. Executive Summary

This document specifies the complete architectural, functional, and security delta between the current codebase (`zhfreal/REALITY @ reality-wildcard-patches`) and the original upstream baseline (`XTLS/REALITY @ 83f621788ca88b83179810b12baa7ae518aacb83`, the dependency in Xray-core `v26.10.21`).

The modifications against original upstream are organized into two principal categories:
1. **Type 1: New Features & Cryptographic Capabilities**: Zero-allocation wildcard domain pattern pre-compilation, anti-DPI active probing with synthesized 5-character subdomain prefixes, and half-close connection propagation.
2. **Type 2: Bug Fixes, Concurrency & Security Remediations**: Listener panic elimination on shutdown (`send on closed channel`), active probe connection burst deduplication and `CLOSE_WAIT` socket leak fixes, handshake memory aliasing elimination, alert inspection index bounds guards, scratch buffer memory pooling, and strict peer verification.

---

## 2. Type 1: New Features & Protocol Enhancements

### 2.1 Zero-Allocation Wildcard SNI Pattern Matching & Pre-compilation (`common.go`, `tls.go`)
* **Thread-Safe Pattern Pre-compilation**:
  - Added `ServerNamePatterns []*regexp.Regexp` and `ServerNamePatternStrings []string` to `Config`.
  - Implemented `CompileServerNamePatterns()` to compile wildcard patterns once at startup, caching compiled regular expressions in `globalServerNameRegexCache` (`sync.Map`) with zero runtime heap allocations during handshakes.
  - Added lazy compilation in `GetMatchedPattern()` if callers execute handshakes without calling `CompileServerNamePatterns()` first.
* **Deterministic Specificity Sorting & Empty SNI Rejection**:
  - Filtered out disabled `ServerNames` entries (`!enabled`).
  - Sorted compiled patterns by specificity: explicit subdomains (`*.sub.example.com`) take precedence over broader wildcards (`*.example.com`), which take precedence over catch-all (`*`).
  - Enforced strict rejection of empty ClientHello SNI (`""`) against catch-all wildcard `*`.
* **Multi-Level Wildcard Regex Compilation**:
  - Compiled catch-all `"*"` to `^.+$` (matching multi-level fully qualified domain names) rather than `^[^.]+$` (which only matched dotless hostnames).
* **Handshake SNI Matching**:
  - Replaced strict map lookup `!config.ServerNames[hs.clientHello.serverName]` in `Server()` with `!config.MatchServerName(hs.clientHello.serverName)`.
  - Cached and propagated `matchedPattern` for post-handshake record length caching so wildcard matches accurately hit pre-computed detection caches.

### 2.2 Anti-DPI Active Probing with Synthesized Random 5-Character Subdomain Prefixes (`record_detect.go`)
* **Random 5-Character Alphanumeric Prefixing**:
  - In `GetConcreteDomain(pattern string) string`, synthesized random 5-character lowercase alphanumeric prefixes for wildcard subdomains using `crypto/rand` (with system timestamp entropy fallbacks).
  - Ensures every active probe exercises unique domain paths, preventing middlebox routing cache bypass.
* **Destination Hostname & Sibling Domain Fallback**:
  - Prioritized `config.Dest`'s domain hostname in `GetProbeSNI` when the pattern is a wildcard, avoiding certificate verification failures against targets that reject synthesized subdomains.
  - If `config.Dest` is an IP literal, `GetProbeSNI` dynamically extracts enabled concrete sibling domains defined in `config.ServerNames`.

### 2.3 Half-Close Connection Support (`CloseWrite`) (`tls.go`)
* **Underlying Transport Delegation**:
  - Added safe comma-ok delegation for `CloseWriteConn`:
    ```go
    if cw, ok := underlying.(CloseWriteConn); ok {
        cw.CloseWrite()
    }
    ```
  - Preserves half-close semantics across wrapped TCP streams without panicking when underlying transport is an arbitrary `net.Conn` (e.g. `net.PipeConn`).

---

## 3. Type 2: Bug Fixes, Concurrency & Security Remediations

### 3.1 Listener Panic Elimination on Shutdown (`tls.go`)
* **Elimination of `panic: send on closed channel`**:
  - In upstream, `listener.Accept()` closed `l.conns` on the first accept error. Concurrent background handshake worker goroutines executing `l.conns <- tlsConn` then panicked with unrecoverable `send on closed channel`.
  - Replaced raw channel closure with a `done chan struct{}` closed once via `closeOnce sync.Once`. Handshake workers now select on:
    ```go
    select {
    case l.conns <- tlsConn:
    case <-l.done:
        _ = tlsConn.Close()
    }
    ```
* **Graceful Connection Drainage**:
  - On `listener.Close()`, any remaining connections buffered in `l.conns` are drained and closed cleanly, preventing file descriptor leaks.

### 3.2 Active Probing Connection Burst Deduplication & Socket Leak Fix (`record_detect.go`)
* **Probe Connection Burst Deduplication**:
  - In upstream, `DetectPostHandshakeRecordsLens` initiated independent outbound TLS handshakes for every configured server name, creating hundreds of simultaneous TCP connections on startup for extensive wildcard lists.
  - Deduplicated probes by unique `(config.Dest, probeSNI, alpn)` tuples and fanned out detected post-handshake record lengths and ChangeCipherSpec counts across all matching pattern cache keys.
* **Socket Leak & Timeout Prevention**:
  - Added `defer uConn.Close()` to both active probing goroutines in `DetectPostHandshakeRecordsLens`, eliminating sockets lingering in `CLOSE_WAIT`.
  - Added 5-second dial timeouts (`net.DialTimeout`) and handshake deadlines (`uConn.SetDeadline`).
* **Unbounded Memory Protection**:
  - Bounded `PostHandshakeRecordDetectConn.Read` with `io.LimitReader(c.Conn, 65536)`.
* **Thread-Safe Configuration Access**:
  - Protected `ServerNames` reads in `DetectPostHandshakeRecordsLens` and `GetProbeSNI` with `config.mutex.RLock()`.

### 3.3 Handshake Buffer Aliasing & Memory Corruption Elimination (`tls.go`)
* **Dedicated Handshake Backing Buffer**:
  - In upstream, `hs.c.out.handshakeBuf` was set to `buf[:0]`, where `buf` was the shared backing buffer used by `target.Read(buf)`. If fallback or background reading occurred, `buf` and `handshakeBuf` shared the same underlying memory, corrupting outbound TLS records.
  - Allocated a dedicated backing slice `make([]byte, 0, handshakeLen)` for `handshakeBuf`.
* **Target Drain Goroutine Concurrency**:
  - Passed `remaining := handshakeLen - len(s2cSaved)` by value to the post-handshake probe goroutine and used a stack-allocated `probeBuf [1]byte` instead of reusing shared `buf`.

### 3.4 Alert Inspection Index Panic Guard (`record_detect.go`)
* **Safe Alert Byte Verification**:
  - In `CCSDetectConn.Write`: Guarded alert inspection with `nRead > 0 && buf[0] == 0x15` after checking error, preventing index-out-of-range panics on zero-byte reads or immediate EOF.
  - Added `ccsOnce sync.Once` guard to prevent duplicate probe triggers on repeated CCS frames.
  - Ensured `GlobalMaxCSSMsgCount` keys are initialized to 0 if probing fails.

### 3.5 Memory Reduction & Buffer Pooling (`tls.go`)
* **17 KiB Connection Scratch Buffer Pool**:
  - Upstream `Server()` allocated a 17 KiB scratch buffer (`buf := make([]byte, size)`) on every incoming connection for reading target ServerHello responses. Under high concurrency, this generated excessive heap churn.
  - Introduced `realityServerBufPool sync.Pool` with `defer realityServerBufPool.Put(bufPtr)` in the server handshake loop, eliminating per-connection heap allocations for ServerHello buffering.
* **Stack Memory Allocations**:
  - Replaced heap allocations `make([]byte, 32)` for `ciphertext` and `plainText` in `Server()` with stack-allocated `var ciphertext, plainText [32]byte`.
* **Reduced Initial Buffering**:
  - Reduced initial `s2cSaved` slice allocation from 17 KiB to 4 KiB (growing dynamically only if required).
* **Defensive Nil Pointer Checks**:
  - Guarded `conn.RemoteAddr()` against nil before calling `.String()`.
  - Added defensive check `if target == nil` after `config.DialContext` in `Server()`, preventing nil pointer panics if custom dialers return a nil connection.
* **Idiomatic Control Flow in Client Authentication**:
  - Replaced anti-pattern single-iteration `for peerPub != nil && config.PrivateKey != nil { ... break }` with an idiomatic early-return closure `func() { ... }()`, eliminating static analyzer warnings regarding unconditionally terminated loops while preserving flat early-exit control flow.
* **Elimination of Impossible Key Share Check**:
  - In `Server()`, the loop over ClientHello key shares terminated immediately with `break` upon encountering the first `X25519` key share to enforce that `X25519MLKEM768` preceded `X25519`.
  - The check `if peerPub != nil` inside this branch was statically unreachable (`nil != nil`) because `peerPub` initialized to `nil` and the branch broke out on the first occurrence. Removed the redundant check, satisfying static analysis without altering validation behavior.

### 3.6 Strict Peer Certificate Verification (`handshake_client.go`)
* **Rejection of Unverified Insecure Bypasses**:
  - Updated `verifyServerCertificate` to reject `InsecureSkipVerify == true` whenever both `VerifyPeerCertificate == nil` and `VerifyConnection == nil`, preventing accidental transmission of unverified credentials.

### 3.7 Deep Configuration Cloning (`common.go`)
* **Deep Configuration Cloning (`Config.Clone`)**:
  - Deep-cloned maps (`ServerNames`, `ShortIds`) and slices (`ServerNamePatterns`, `ServerNamePatternStrings`, `MinClientVer`, `MaxClientVer`) using standard library `maps.Clone`, `slices.Clone`, and `bytes.Clone`.
  - Retained pointer references for immutable `*ecdh.PrivateKey` and `*mldsa.PrivateKey`.

### 3.8 ML-DSA-65 Certificate Buffer Bounds Check (`handshake_server_tls13.go`)
* **Signature Buffer Guard**:
  - Added bounds check `if len(cert) < 126+len(sig)` before copying the ML-DSA-65 signature into the synthesized certificate slice.

### 3.9 Dead Code Cleanup & Linter Warning Remediation (`handshake_server_tls13.go`)
* **Removal of Unreachable Post-Flight Handshake Code**:
  - In upstream commit `a7ae8b57`, an unconditional `return nil` was inserted into `hs.handshake()` immediately after `c.flush()` to allow target probing and `readClientFinished()` to be driven externally by `tls.go`.
  - Leftover standard TLS post-flight logic (`readClientCertificate()`, `readClientFinished()`, `c.isHandshakeComplete.Store(true)`) below this return triggered compiler and linter `unreachable code` warnings.
  - Removed the unreachable dead code block, ensuring clean compilation and passing `go vet ./...` without warnings.

### 3.10 Bounded Post-Handshake Record Mimicry, User Tunability & Context Cancellation (`tls.go`, `common.go`)
* **Elimination of Infinite Handshake Hangs & User Tunable Timeouts**:
  - In upstream, `Server()` looped indefinitely (`for { time.Sleep(5 * time.Second) }`) waiting for `GlobalPostHandshakeRecordsLens` if the target destination was unprobed or failed active probing, hanging server TLS handshakes forever.
  - Bounded active probe polling with `PostHandshakePollInterval` (500 ms) and `MaxPostHandshakeWaitAttempts` (10 attempts, 5-second total ceiling by default).
  - Exposed `MaxPostHandshakeWait` and `ProbeTimeout` in `Config` so users can tune handshake wait and active probing timeouts via configuration while retaining rock-solid defaults.
* **Context Cancellation & Goroutine Leak Elimination**:
  - Handled `<-ctx.Done()` within the handshake wait loop to abort promptly and close connections when clients terminate or time out, eliminating orphaned server handshake goroutines.
* **Malicious / Corrupt Record Length Guard & Named Constants**:
  - Added bounds validation (`length >= RecordMinEncryptedLen`) ensuring minimum 5-byte TLS record header + 16-byte AEAD authentication tag before slice allocation, preventing `makeslice: len out of range` runtime panics.
  - Replaced raw numbers and figures in comparisons with named constants (`RecordTypeChangeCipherSpec`, `RecordTypeApplicationData`, `RecordTypeAlert`, `TLS12RecordVersionMajor`, `TLS12RecordVersionMinor`, `RecordHeaderLen`, `RecordMinAEADTagLen`, `Mldsa65CertSignatureOffset`).

---

## 4. File Modification & Addition Matrix

| File Path | Status | Change Category | Description of Delta Relative to Upstream Baseline (`83f62178`) |
| :--- | :--- | :--- | :--- |
| `common.go` | **Modified** | **Features & Concurrency** | Wildcard regex compilation and caching (`sync.Map`), specificity sorting, multi-level `*` support, `MatchServerName`, `GetMatchedPattern`, deep `Clone` with `maps.Clone` and `slices.Clone`, user-tunable `ProbeTimeout` and `MaxPostHandshakeWait` configuration fields, and defined protocol constants. |
| `record_detect.go` | **Modified** | **Features & Bugfixes** | Synthesized 5-character random prefixes (`GetConcreteDomain`), destination hostname/sibling fallback (`GetProbeSNI`), active probe deduplication, socket leak fixes (`defer uConn.Close()`), dial/read timeouts respecting `ProbeTimeout`, bounds check on alert byte, and named protocol constants. |
| `tls.go` | **Modified** | **Performance & Concurrency** | Listener shutdown panic elimination (`done chan`, `closeOnce`), scratch buffer pooling (`realityServerBufPool sync.Pool`), dedicated `handshakeBuf` slice, stack-allocated `[32]byte` arrays, half-close `CloseWriteConn`, nil checks on `target` and `RemoteAddr()`, bounded post-handshake record polling with `MaxPostHandshakeWait` and `ctx.Done()` cancellation, and `RecordMinEncryptedLen` bounds guards. |
| `handshake_server_tls13.go` | **Modified** | **Security / Bounds** | Bounds check `len(cert) < Mldsa65CertSignatureOffset+len(sig)` before copying ML-DSA-65 signature with named constant `Mldsa65CertSignatureOffset`. |
| `handshake_client.go` | **Modified** | **Security** | Strict peer certificate verification (unverified `InsecureSkipVerify` rejected). |
| `reality_test.go` | **Added** | **Testing** | Comprehensive unit test suite covering wildcard matching, lazy compilation under concurrency, domain synthesis, probe SNI selection, and clone concurrency. |

