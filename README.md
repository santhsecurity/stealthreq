# stealthreq

Generate human-like request behavior for scraping and security scanning. Applies realistic headers, timing jitter, and TLS fingerprint rotation to make automated requests resemble genuine browser traffic.

```rust
use stealthreq::{StealthPolicy, MutableRequest, AppliedRequestProfile};

// Implement MutableRequest for your HTTP client
struct MyRequest {
    headers: Vec<(String, String)>,
}

impl MutableRequest for MyRequest {
    fn set_header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }
}

fn main() -> stealthreq::Result<()> {
    let mut req = MyRequest::default();
    let policy = StealthPolicy::default();
    
    let applied: AppliedRequestProfile = policy.apply(&mut req)?;
    
    println!("User-Agent: {}", applied.user_agent);
    println!("Jitter: {:?}", applied.jitter);
    println!("TLS profile: {}", applied.tls_profile.name);
    
    Ok(())
}
```

## Why this exists

Scrapers and scanners get blocked by WAFs that look for automation signals. Missing Accept-Language headers. Static User-Agent strings. Perfectly consistent timing. Predictable TLS fingerprints.

stealthreq decouples the mutation logic from HTTP implementations. You implement a 1-method trait for your request type. The crate handles header selection, timing, and TLS profile rotation. Works with reqwest, hyper, ureq, or any other HTTP client.

## MutableRequest trait

Libraries integrate by implementing `MutableRequest`:

```rust
pub trait MutableRequest {
    fn set_header(&mut self, name: &str, value: &str);
    fn set_user_agent(&mut self, value: &str) {
        self.set_header("User-Agent", value);
    }
}
```

This minimal interface keeps the crate HTTP-agnostic.

## Header policies

`HeaderPolicy` manages pools of realistic browser values:

- 4 desktop and mobile User-Agent strings
- Accept-Language variants (en-US, en-GB, en-CA, fr-FR)
- Accept-Encoding preferences (gzip, deflate, br)
- Cache-Control directives
- Referer hosts
- Optional Pragma headers

The policy randomly selects headers up to a configurable budget, always preserving User-Agent.

## Timing jitter

`TimingJitter` generates random delays between requests:

```rust
use stealthreq::{StealthPolicy, TimingJitter};

let policy = StealthPolicy::default()
    .with_timing(TimingJitter::new(100, 500)); // 100-500ms delay
```

The `AppliedRequestProfile` includes the sampled delay. Your code sleeps before sending.

## TLS fingerprint rotation

`TlsRotationPolicy` provides browser-like JA3 fingerprints:

| Profile | Description |
|---------|-------------|
| chrome-desktop-121 | Chrome 121 on desktop |
| chrome-mobile-121 | Chrome 121 on mobile |
| firefox-desktop | Firefox desktop |

Each profile includes JA3 digest, ALPN order, cipher suites, and extension ordering. Bind these to your TLS stack configuration.

## Configuration via TOML

```rust
use stealthreq::StealthProfileConfig;

let config = StealthProfileConfig::from_toml(r#"
jitter_ms_min = 100
jitter_ms_max = 500
header_budget = 6
rotate_tls = true
seed = 42

[headers]
referer_hosts = ["https://google.com", "https://twitter.com"]
include_pragmas = true
"#)?;

let policy = config.build();
```

## Deterministic profiles

Set a seed for reproducible behavior in tests:

```rust
let policy = StealthPolicy::default().with_seed(Some(12345));

// Same seed produces same headers, timing, and TLS profile
let applied1 = policy.apply(&mut req1)?;
let applied2 = policy.apply(&mut req2)?;
assert_eq!(applied1.user_agent, applied2.user_agent);
```

## Contributing

Pull requests are welcome. There is no such thing as a perfect crate. If you find a bug, a better API, or just a rough edge, open a PR. We review quickly.

## License

MIT. Copyright 2026 CORUM COLLECTIVE LLC.

[![crates.io](https://img.shields.io/crates/v/stealthreq.svg)](https://crates.io/crates/stealthreq)
[![docs.rs](https://docs.rs/stealthreq/badge.svg)](https://docs.rs/stealthreq)
