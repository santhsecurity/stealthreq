#![warn(missing_docs)]
//! `stealthreq` generates human-like request behavior for scraping and crawler clients.
//!
//! It intentionally avoids hard-coupling to any single HTTP implementation.
//!
//! It exists for callers that need browser-like request shaping without giving up their own HTTP
//! stack, retry logic, or transport integration.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
// These lints are noisy for the crate's builder-style public API and trait adapters.
#![allow(clippy::must_use_candidate)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::return_self_not_must_use)]

mod config;
mod headers;
mod policy;
mod timing;
mod tls;
pub mod waf;

pub use crate::config::StealthProfileConfig;
pub use crate::headers::{HeaderPolicy, HeaderPolicyConfig};
pub use crate::policy::{AppliedRequestProfile, MutableRequest, RequestModifier, StealthPolicy};
pub use crate::timing::{TimingJitter, TimingJitterConfig};
pub use crate::tls::{TlsFingerprint, TlsRotationConfig, TlsRotationPolicy};

use thiserror::Error;

pub type Result<T> = std::result::Result<T, StealthError>;

/// Public error type.
#[derive(Debug, Error)]
pub enum StealthError {
    /// Invalid TOML/config input.
    #[error("stealth profile configuration error: {0}. Fix: validate the TOML keys and keep `jitter_ms_min <= jitter_ms_max` with `header_budget >= 1`.")]
    Config(String),
    /// Internal policy construction issue.
    #[error("stealth policy error: {0}. Fix: use a non-empty header policy and at least one TLS profile when rotation is enabled.")]
    Internal(&'static str),
}

#[cfg(test)]
mod adversarial_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::RequestModifier;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[derive(Default)]
    struct MockReq {
        headers: Vec<(String, String)>,
    }

    impl MutableRequest for MockReq {
        fn set_header(&mut self, name: &str, value: &str) {
            self.headers.push((name.to_string(), value.to_string()));
        }
    }

    #[test]
    fn toml_config_parse() {
        let toml = r#"
jitter_ms_min = 50
jitter_ms_max = 100
header_budget = 7
rotate_tls = true
seed = 123

[headers]
referer_hosts = ["https://example.com"]
include_pragmas = true

[tls]
enabled = true
"#;
        let cfg = StealthProfileConfig::from_toml(toml).unwrap();
        assert_eq!(cfg.jitter_ms_min, 50);
        assert_eq!(cfg.jitter_ms_max, 100);
        assert_eq!(cfg.header_budget, 7);
    }

    #[test]
    fn policy_runs_end_to_end() {
        let mut req = MockReq::default();
        let profile = StealthPolicy::default();
        let applied = profile.apply(&mut req).unwrap();
        assert!(!req.headers.is_empty());
        assert!(!applied.user_agent.is_empty());
        assert!(!applied.tls_profile.name.is_empty());
        assert!(applied.jitter > std::time::Duration::from_millis(0));
    }

    #[test]
    fn profile_with_seed_matches_applied_headers() {
        let mut req1 = MockReq::default();
        let mut req2 = MockReq::default();
        let mut rng1 = StdRng::seed_from_u64(100);
        let mut rng2 = StdRng::seed_from_u64(100);
        let policy = StealthPolicy::default().with_seed(Some(100));

        let a = policy.apply_with_rng(&mut req1, &mut rng1).unwrap();
        let b = policy.apply_with_rng(&mut req2, &mut rng2).unwrap();

        assert_eq!(a.user_agent, b.user_agent);
        assert_eq!(a.applied_headers, b.applied_headers);
        assert_eq!(a.tls_profile.name, b.tls_profile.name);
    }

    #[test]
    fn custom_config_build() {
        let cfg = StealthProfileConfig {
            jitter_ms_min: 10,
            jitter_ms_max: 20,
            header_budget: 3,
            seed: Some(44),
            rotate_tls: false,
            headers: HeaderPolicyConfig::default(),
            tls: TlsRotationConfig { enabled: false },
        };
        let policy = cfg.build();
        let mut req = MockReq::default();
        let applied = policy.apply(&mut req).unwrap();
        assert!(!applied.applied_headers.is_empty());
        assert!(!applied.user_agent.is_empty());
    }
}
