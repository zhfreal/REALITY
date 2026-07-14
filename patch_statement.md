# PATCH STATEMENT: Wildcard SNI Support, Target-Based Active Probing Cache Deduplication & CLOSE-WAIT Socket Fix

This document details the modifications applied to the custom `reality` module repository (`github.com/zhfreal/REALITY`). These changes optimize startup performance, resolve compiler and linter warnings, and add wildcard domain support.

---

## Repository Details
* **Base Upstream Repository**: `github.com/xtls/reality`
* **Base Upstream Commit**: `9234c772ba8f181f31c3e81dc2b4177322e5a9a9` (declaring support for `maxUselessRecords`)
* **Fork Repository**: `github.com/zhfreal/REALITY`
* **Development Branch**: `reality-wildcard-patches`
* **Latest Local Patch Commit**: `2461661bec6139d917840df985d889e8d849246d`

---

## Detailed Changes

### 1. Target & ALPN-based Active Probing Cache Deduplication (`record_detect.go` & `tls.go`)
* **Problem**: Previously, active probes were launched for every combination of `(target, SNI, ALPN)` on startup. In configurations with multiple SNIs/subdomains, this led to massive spikes in concurrent TCP connections at startup (often thousands of connections).
* **Solution**:
  - Rewrote active probing to query using a single concrete SNI per target host (`config.Dest`).
  - **Target Host Handling (`GetProbeSNI`)**:
    - If `config.Dest` is configured as `<domain>:<port>` (e.g., `yahoo.com:443`), the domain host name is parsed using `net.SplitHostPort` and directly used as the SNI for active probing.
    - If `config.Dest` is configured as `<ip>:<port>` (e.g., `1.1.1.1:443`), the host is recognized as an IP address. Since IP addresses are not valid TLS SNIs, the engine falls back to selecting the first concrete subdomain/domain from `config.ServerNames` (using `GetConcreteDomain` to translate any wildcard patterns like `*.example.com` to `www.example.com`).
  - Standardized the cache keys of `GlobalPostHandshakeRecordsLens` to use `config.Dest + " " + matchedPattern + " " + strconv.Itoa(alpn)` (matching on physical target, matched SNI pattern, and ALPN state).
  - Adjusted the TLS handshake loop in `tls.go` to construct cache lookup keys matching the new `(target, matchedPattern, ALPN)` format.
  - **Socket Closure Fix (`record_detect.go`)**: Added `defer target.Close()` immediately after successful `net.Dial` calls in both active probing goroutines. This ensures that the active probing sockets are closed immediately once the validation completes, completely resolving any lingering connection leaks in the `CLOSE-WAIT` state.
  - **Outcome**: Connection count at startup was reduced by **96.7%** (e.g., dropping from **1,446** to **48** concurrent connections), with zero leaked sockets.

### 2. Wildcard Domain Matching Support & Regex Caching (`common.go` & `tls.go`)
* **Problem**: REALITY originally checked incoming ClientHello SNIs against an exact lookup map of configured `ServerNames`, which prevented the use of wildcard patterns (like `*.example.com` or `*`). Additionally, when using many REALITY inbounds with the same wildcard SNI patterns, regex compilation was duplicated.
* **Solution**:
  - Extended `Config` struct in `common.go` to hold `ServerNamePatterns []*regexp.Regexp`.
  - Added `CompileServerNamePatterns()` method in `common.go` to compile wildcards (translating `*` to `[^.]+` regex to strictly match a single subdomain level) at setup time.
  - Implemented `globalServerNameRegexCache` (`sync.Map`) to cache compiled `*regexp.Regexp` objects globally, preventing duplicate compilation when multiple inbounds share wildcard server names.
  - Added `MatchServerName(name string)` and `GetMatchedPattern(name string)` in `common.go` to evaluate exact matches first, then match against compiled regex patterns. `GetMatchedPattern` returns the original wildcard pattern string (e.g. `*.example.com`) for use as the cache key component in `tls.go`.
  - Updated `record_detect.go` (`GetProbeSNI()`) to dynamically translate wildcard patterns to concrete hostnames (e.g. `*.example.com` -> `www.example.com`) to ensure that outbound probing TLS handshakes succeed.
  - Updated `tls.go` to check incoming connection SNIs using `config.MatchServerName(...)` rather than map lookups.

### 3. Warning Fixes & Code Refactoring (`handshake_server_tls13.go` & `tls.go`)
* **Problem**: Several code paths triggered linter warnings or static analysis failures.
* **Solution**:
  - **`handshake_server_tls13.go`**: Wrapped unreachable client certificate and finished reading routine logic (placed after an early `return nil`) in block comment delimiters (`/* ... */`).
  - **`tls.go`**: Replaced the faux `for peerPub != nil { ... break }` loop block with nested `if err == nil` statements. This maintains the clean step-by-step conditional flow without triggering the `surrounding loop is unconditionally terminated (SA4004)` linter warning. Removed the outer single-iteration `for` loop from the ClientHello processing goroutine.
