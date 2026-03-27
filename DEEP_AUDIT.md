# DEEP AUDIT: stealthreq v0.1.1

**Audit Date:** 2026-03-26  
**Auditor:** Kimi Code CLI  
**Scope:** Complete crate analysis — API design, implementation quality, standalone utility, and developer experience.

---

## Executive Summary

**Verdict: NOT RECOMMENDED for standalone use in its current form.**

`stealthreq` is a library that generates synthetic HTTP headers, timing jitter values, and TLS fingerprint metadata for "stealth" HTTP requests. It adopts a trait-based abstraction (`MutableRequest`) intended to decouple from specific HTTP clients.

**The core problem:** This crate provides *data* but performs *no action*. It doesn't make HTTP requests, doesn't sleep for jitter, doesn't configure TLS, and doesn't handle retries. The developer must implement the `MutableRequest` trait, manually extract timing values, and figure out TLS configuration themselves. The "trait abstraction" creates friction without delivering proportional value.

**DX Rating Justification (6/10):** The "6" is generous. The crate compiles and runs, but the API feels like a proof-of-concept rather than a production tool. Every integration requires boilerplate. The abstraction leaks immediately (TLS metadata without implementation). The "batteries included" claim in the README is misleading — this is a battery *specification*, not a battery.

---

## 1. The Existential Question: Why Does This Exist?

### What a Developer Actually Needs

A developer building a scraper needs:
1. **Rotating, coherent browser profiles** (headers that match a real browser)
2. **Actual TLS fingerprint spoofing** (not metadata — real JA3/JA4 configuration)
3. **Intelligent timing** (adaptive delays, retry backoff)
4. **Session management** (cookie jar, redirect handling)
5. **WAF evasion that works** (encoding, request sequencing)

### What stealthreq Provides

1. ✅ **Random header selection** — but incoherent (Chrome UA + Firefox headers)
2. ❌ **TLS metadata only** — returns cipher suites but doesn't configure TLS
3. ⚠️ **Uniform random delays** — just numbers, no actual sleeping
4. ❌ **No session management** — every request is isolated
5. ⚠️ **WAF detection** — static signatures, easily outdated

### The Competition

| Alternative | Standalone? | TLS Spoofing | Real Browser | Async | Verdict |
|-------------|-------------|--------------|--------------|-------|---------|
| `rquest` | ✅ Yes | ✅ Real JA3 | ❌ No | ✅ Yes | **Superior** |
| `playwright`/puppeteer | ✅ Yes | ✅ Real browser | ✅ Yes | ✅ Yes | **Heavier but works** |
| Manual headers + `reqwest` | ✅ Yes | ❌ No | ❌ No | ✅ Yes | **Same effort, more control** |
| `curl` | ✅ Yes | ⚠️ Partial | ❌ No | ❌ No | **CLI simplicity** |
| **stealthreq** | ❌ NO | ❌ Metadata only | ❌ No | ⚠️ Partial | **Loses on all axes** |

**Key Insight:** `stealthreq` is less useful than `rquest` (which actually spoofs TLS) AND requires more boilerplate than manual headers. It occupies a "worst of both worlds" position.

---

## 2. Critical Architectural Flaws

### 2.1 The `MutableRequest` Trait Abstraction Leak

```rust
// What stealthreq requires you to implement
pub trait MutableRequest {
    fn set_header(&mut self, name: &str, value: &str);
}
```

**Problems:**
- **Single method, massive burden:** You must wrap your HTTP client's request builder in a newtype, implement the trait, handle the `Option<builder>` dance (see `examples/reqwest.rs` lines 3-15), then unwrap it back.
- **No standard impls:** Despite claiming to work with "reqwest, hyper, ureq", there are zero blanket implementations. Every user writes the same adapter code.
- **Mutation-only:** Can't inspect what was set. Can't chain. The trait is a one-way street.

**Comparison — what `rquest` does:**
```rust
// Just use the client. No trait impl required.
let client = rquest::Client::builder()
    .impersonate(Impersonate::Chrome100)
    .build()?;
```

### 2.2 TLS Fingerprinting Theater

```rust
// src/tls.rs lines 21-28
pub fn as_header_hints(&self) -> Vec<(String, String)> {
    vec![
        ("Sec-CH-UA-Platform".to_string(), String::new()),
        ("X-TLS-Fingerprint".to_string(), self.ja3_hash.clone()), // WHAT?
    ]
}
```

**This is actively harmful.** Real browsers do NOT send an `X-TLS-Fingerprint` header. Adding this makes requests **MORE** fingerprintable, not less. It's a debug header that the library silently injects.

**The JA3 strings are fabricated:**
```rust
// src/tls.rs lines 73-86
("chrome-desktop-121", "770,4865-4866-4867,23-24,0-11-10-35-16-22,0-1"),
```

Real Chrome 121 JA3 is different. These strings appear to be simplified placeholders. Using them signals "I am a tool trying to look like Chrome" to sophisticated WAFs.

**Only 3 profiles:** Chrome desktop, Chrome mobile, Firefox. Missing: Edge, Safari, Opera, Brave, Arc, mobile Safari.

### 2.3 The Jitter Illusion

```rust
// README.md lines 72-78
let policy = StealthPolicy::default()
    .with_timing(TimingJitter::new(100, 500)); // 100-500ms delay

// The `AppliedRequestProfile` includes the sampled delay. Your code sleeps before sending.
```

The library returns a `Duration`. YOU must call `tokio::time::sleep()` or `std::thread::sleep()`. This is:
- **Error-prone:** Easy to forget the sleep
- **Async-unfriendly:** No built-in async integration
- **Context-losing:** The jitter isn't tied to the request lifecycle

```rust
// What you have to write
let profile = policy.apply(&mut req)?;
tokio::time::sleep(profile.jitter).await;  // Boilerplate every user writes
// Now send the request...
```

### 2.4 Incoherent Browser Simulation

```rust
// src/headers.rs lines 4-9 — ONLY 4 USER AGENTS
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Version/17.4 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
];
```

Headers are randomly selected from pools without coherence:
- You might get Chrome UA + Firefox Accept-Encoding
- No Sec-CH-UA headers that match the UA
- No correlation between mobile UAs and mobile-specific headers
- Hardcoded values from early 2024 — already outdated

**Real browsers send 15-25 headers in specific order.** This library sends 1-6 random headers.

---

## 3. API Rough Edges (The Paper Cuts)

### 3.1 Inconsistent Defaults

```rust
// src/config.rs lines 37-39 — Config default
fn default_header_budget() -> usize { 4 }

// src/policy.rs lines 51-60 — Policy default  
impl Default for StealthPolicy {
    fn default() -> Self {
        Self {
            header_budget: 6,  // DIFFERENT!
            // ...
        }
    }
}
```

Same concept, different defaults. Using TOML config vs. builder API gives different behavior.

### 3.2 The `header_budget` Anti-Pattern

```rust
// Maximum number of headers to include (why would you want FEWER for stealth?)
pub fn with_header_budget(mut self, header_budget: usize) -> Self
```

Stealth requires *complete* header sets that match real browsers. Sending only 4 random headers out of a possible 10 is a DETECTION signal, not evasion. Real Chrome sends ~20 headers.

The pruning logic is complex and buggy-prone:
```rust
// src/headers.rs lines 216-241 — 25 lines to randomly remove headers
// while preserving UA (which should never be removed anyway)
```

### 3.3 Nonsensical `burstiness()` Function

```rust
// src/timing.rs lines 26-29
pub fn burstiness(&self) -> bool {
    self.max_ms.saturating_sub(self.min_ms) % 2 == 0
}
```

This determines whether to add "burstiness headers" (DNT, Sec-Fetch-*). The logic: if `(max-min) % 2 == 0`, it's "bursty". This is cargo-cult programming — no statistical or browser-behavior basis.

### 3.4 WAF Detection Is Static and Fragile

```rust
// data/waf_signatures.toml — embedded TOML, parsed at runtime
// 12 signatures covering major WAFs
```

- **No updates:** Signatures are compiled in. New WAF = recompile.
- **Easily bypassed:** WAFs change their response patterns.
- **Detection only:** No actual evasion implementation — just encoding suggestions.
- **False confidence:** Returns `confidence: f64` based on arbitrary weights (0.25, 0.30, etc.) with no statistical validity.

### 3.5 Safety Module — Theater Security

```rust
// src/safety.rs lines 63-88 — Hardcoded dangerous endpoints
const DANGEROUS_ENDPOINTS: &[&str] = &[
    "/account/delete",
    "/logout",
    // ...
];
```

- **No URL normalization:** `/account/../delete` bypasses the check
- **POST allowed to dangerous endpoints:** Only DELETE/PATCH blocked
- **Query string confusion:** `/search?q=delete` is considered safe (correct) but `/delete?q=test` is blocked (correct) — yet the logic is fragile

---

## 4. Documentation Gaps

### 4.1 `#[allow(missing_docs)]` on the Entire Crate

```rust
// src/lib.rs line 1
#![allow(missing_docs)]
```

A library claiming to be for "security scanning" has no docs on public items.

### 4.2 README Examples Don't Show Real Usage

The README example (lines 5-31) shows implementing `MutableRequest` for a fake struct. It doesn't show:
- How to integrate with `reqwest`
- How to actually sleep for jitter
- How to configure TLS (because you can't with this crate)
- Error handling patterns

### 4.3 No Explanation of Key Concepts

- What is a "header budget" and why would I want to limit headers?
- What are the "Sec-Fetch-*" headers and when should they be sent?
- How do I rotate proxies? (Not supported)
- How do I handle CAPTCHAs? (Not supported)
- What's the difference between the 3 TLS profiles?

---

## 5. Implementation Quality Issues

### 5.1 Header Name Case Sensitivity Bug

```rust
// src/waf/helpers.rs lines 1-14
pub(crate) fn extract_cookies(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
    .filter(|(name, _)| name == "set-cookie" || name == "cookie")  // BUG!
```

HTTP header names are case-insensitive. `Set-Cookie` and `set-cookie` are the same. This code misses `SET-COOKIE`.

### 5.2 TOML Parsing at Runtime

```rust
// src/waf/signature.rs lines 8-16
static SIGNATURES: OnceLock<Vec<WafSignature>> = OnceLock::new();
SIGNATURES.get_or_init(|| {
    toml::from_str::<SignatureFile>(SIGNATURES_TOML)  // Parse on first use
        .map(|file| file.signatures)
        .unwrap_or_default()
})
```

WAF signatures are embedded TOML parsed at runtime. This could be:
- Compile-time generated (use `include!(concat!(env!("OUT_DIR"), "/signatures.rs"))`)
- At least use `lazy_static` with pre-parsed data

Current approach adds ~1ms cold-start latency for the first WAF check.

### 5.3 No Fuzzing or Property Tests

The "adversarial tests" (`src/adversarial_tests.rs`) are hand-written unit tests. No:
- `proptest` for randomized config generation
- Fuzzing for header parsing
- Chaos testing for concurrent policy use

### 5.4 Thread Safety Questions

```rust
// src/adversarial_tests.rs lines 351-375 — concurrent test
fn policy_concurrent_apply_with_same_seed() {
    let policy = Arc::new(StealthPolicy::default().with_seed(Some(42)));
    // Spawn 10 threads, all apply policy...
}
```

The test passes, but `StealthPolicy` contains `Vec<String>` and other non-atomic fields. The `apply` method mutates a passed RNG. This is technically safe (no shared state), but the API encourages cloning `StealthPolicy` across threads when it should be `Send + Sync` by design.

---

## 6. Missing Critical Features

### 6.1 No HTTP Client Integration

For a library claiming to work with "reqwest, hyper, ureq", there are zero adapter implementations. Users must write:

```rust
// Every. Single. Time.
struct ReqwestAdapter { builder: Option<reqwest::RequestBuilder> }
impl MutableRequest for ReqwestAdapter { /* ... */ }
```

### 6.2 No HTTP/2 Support

Modern browsers use HTTP/2. This crate has no:
- `:authority` pseudo-header generation
- Stream priority simulation
- Header compression (HPACK) considerations
- Connection coalescing logic

### 6.3 No Cookie Jar

Real browsers persist cookies. This crate has no cookie storage, parsing, or automatic Cookie header generation.

### 6.4 No Proxy Support

No proxy rotation, no proxy-specific headers (X-Forwarded-For simulation), no SOCKS integration.

### 6.5 No Adaptive Behavior

- Fixed random delays — doesn't adapt to rate limit responses
- Static header pools — doesn't learn from successful requests
- No retry logic with exponential backoff

### 6.6 No JavaScript Execution

Modern WAFs (Cloudflare, DataDome) require JavaScript challenges. This crate has zero JS support — not even detection that a challenge is required.

---

## 7. What Would Make This Useful?

To become a 9/10 DX crate, `stealthreq` needs:

### 7.1 Provide Actual HTTP Client Wrappers

```rust
// Hypothetical ideal API
use stealthreq::{Browser, Client};

let client = Client::builder()
    .browser(Browser::Chrome120)  // Complete, coherent profile
    .proxy_rotation(proxies)
    .build()?;

// Sends with correct headers, TLS, timing, cookies
let resp = client.get("https://example.com").send().await?;
```

### 7.2 Real TLS Integration

Integrate with `rustls` or `boring` to actually configure cipher suites and extensions. Return a `ClientConfig` that can be used with `hyper`.

### 7.3 Built-in Async Sleep

```rust
pub async fn apply(&self, request: &mut dyn MutableRequest) -> Result<AppliedProfile> {
    let jitter = self.sample_jitter();
    tokio::time::sleep(jitter).await;  // Do it for the user
    // ... rest of apply
}
```

### 7.4 Coherent Browser Profiles

```rust
// Instead of random pools:
pub struct BrowserProfile {
    pub user_agent: &'static str,
    pub accept: &'static str,
    pub accept_language: &'static str,
    pub sec_ch_ua: &'static str,  // Matches the UA!
    pub tls_config: TlsConfig,     // Real JA3
}

static CHROME_120: BrowserProfile = BrowserProfile { /* ... */ };
```

### 7.5 Feature Flags for Client Integration

```toml
[features]
default = []
reqwest = ["dep:reqwest"]
hyper = ["dep:hyper"]
ureq = ["dep:ureq"]
```

With blanket impls behind each flag.

---

## 8. The Final Verdict

### Should You Use This Crate?

| Scenario | Recommendation |
|----------|----------------|
| Production scraper | **NO** — Use `rquest` or Playwright |
| Learning project | **MAYBE** — Good for understanding concepts |
| Enterprise security scanning | **NO** — Missing critical features |
| Quick prototype | **NO** — Manual headers are faster |
| Building a higher-level crate | **MAYBE** — Could be a foundation if extended |

### Redeeming Qualities

1. **Good test coverage** — 467 lines of adversarial tests show thoughtfulness
2. **Deterministic seeding** — Useful for testing
3. **WAF signature format** — The TOML structure is extensible
4. **Safety module concept** — Endpoint blocklists are important for authenticated scanning
5. **Clean separation** — The trait design, while flawed, is decoupled

### Fatal Flaws

1. **No batteries included** — Trait abstraction without implementations
2. **TLS theater** — Metadata without mechanism, plus fake headers
3. **Incoherent profiles** — Random headers don't simulate browsers
4. **Manual everything** — User writes glue code for basic operations
5. **Missing modern features** — No HTTP/2, cookies, JS execution, proxy rotation

---

## 9. Actionable Recommendations (If Continuing Development)

### Immediate (v0.2.0)
1. Remove `X-TLS-Fingerprint` header from `as_header_hints()`
2. Add `reqwest` feature with built-in `MutableRequest` impl
3. Fix header budget defaults to be consistent
4. Add `#[deny(missing_docs)]` and document all public items
5. Implement coherent browser profiles (not random pools)

### Short-term (v0.3.0)
1. Integrate with `rustls` for actual TLS configuration
2. Add async sleep integration
3. Expand to 10+ browser profiles with real JA3 fingerprints
4. Add cookie jar implementation

### Long-term (v1.0.0)
1. Full HTTP client wrapper (not just trait)
2. HTTP/2 support
3. Proxy rotation
4. JavaScript challenge detection
5. Adaptive rate limiting

---

## Appendix: Code Smell Inventory

| Location | Smell | Severity |
|----------|-------|----------|
| `src/tls.rs:26` | Fake `X-TLS-Fingerprint` header | **Critical** |
| `src/timing.rs:28` | Nonsensical `burstiness()` logic | Medium |
| `src/headers.rs:37` | Inconsistent `header_budget` default | Medium |
| `src/waf/helpers.rs:4` | Case-sensitive header matching | Medium |
| `src/policy.rs:90` | `header_budget.max(1)` is silent clamping | Low |
| `src/safety.rs:117` | `glob_match` doesn't anchor patterns | Medium |
| `src/lib.rs:1` | `#![allow(missing_docs)]` | Medium |
| `Cargo.toml:32` | Empty features section | Low |

---

*End of Audit*
