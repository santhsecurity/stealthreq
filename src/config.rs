use serde::{Deserialize, Serialize};

use crate::{HeaderPolicyConfig, TlsRotationConfig};
use crate::{TimingJitter, TlsRotationPolicy};

/// Configure a stealth profile via TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthProfileConfig {
    /// Minimum delay in milliseconds before sending a request.
    #[serde(default = "default_jitter_min")]
    pub jitter_ms_min: u64,
    /// Maximum delay in milliseconds before sending a request.
    #[serde(default = "default_jitter_max")]
    pub jitter_ms_max: u64,
    /// Number of random header families to include.
    #[serde(default = "default_header_budget")]
    pub header_budget: usize,
    /// Optional deterministic seed used for repeatable tests.
    pub seed: Option<u64>,
    /// Whether to rotate TLS fingerprints per request.
    #[serde(default = "default_rotate_tls")]
    pub rotate_tls: bool,
    /// Header preset section.
    #[serde(default)]
    pub headers: HeaderPolicyConfig,
    /// Optional custom TLS profile definitions.
    #[serde(default)]
    pub tls: TlsRotationConfig,
}

fn default_jitter_min() -> u64 {
    80
}
fn default_jitter_max() -> u64 {
    350
}
fn default_header_budget() -> usize {
    4
}
fn default_rotate_tls() -> bool {
    true
}

impl Default for StealthProfileConfig {
    fn default() -> Self {
        Self {
            jitter_ms_min: 80,
            jitter_ms_max: 350,
            header_budget: 4,
            seed: None,
            rotate_tls: true,
            headers: HeaderPolicyConfig::default(),
            tls: TlsRotationConfig::default(),
        }
    }
}

impl StealthProfileConfig {
    /// Parse this configuration from TOML text.
    pub fn from_toml(toml: &str) -> Result<Self, crate::StealthError> {
        let cfg: Self =
            toml::from_str(toml).map_err(|err| crate::StealthError::Config(err.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Build a concrete profile from this config.
    #[must_use]
    pub fn build(self) -> crate::StealthPolicy {
        let jitter = TimingJitter::new(self.jitter_ms_min, self.jitter_ms_max);
        let headers = self.headers.into_profile();
        let tls = TlsRotationPolicy::from_config(self.tls);

        crate::StealthPolicy::default()
            .with_seed(self.seed)
            .with_timing(jitter)
            .with_header_budget(self.header_budget)
            .with_headers(headers)
            .with_tls_rotation(tls)
            .with_rotate_tls(self.rotate_tls)
    }

    fn validate(&self) -> crate::Result<()> {
        if self.jitter_ms_min > self.jitter_ms_max {
            return Err(crate::StealthError::Config(
                "jitter_ms_min cannot exceed jitter_ms_max".to_string(),
            ));
        }
        if self.header_budget == 0 {
            return Err(crate::StealthError::Config(
                "header_budget must be >= 1".to_string(),
            ));
        }
        Ok(())
    }
}

impl TryFrom<&str> for StealthProfileConfig {
    type Error = crate::StealthError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_toml(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MutableRequest, RequestModifier};

    #[test]
    fn default_config_builds() {
        let config = StealthProfileConfig::default();
        assert!(config.rotate_tls);
        assert_eq!(config.header_budget, 4);
        let mut req = MockReq::default();
        let applied = config.build().apply(&mut req).unwrap();
        assert!(!applied.applied_headers.is_empty());
    }

    #[test]
    fn from_toml_minimal() {
        let config = StealthProfileConfig::from_toml("").unwrap();
        assert_eq!(config.jitter_ms_min, 80);
        assert_eq!(config.jitter_ms_max, 350);
        assert_eq!(config.header_budget, 4);
    }

    #[test]
    fn from_toml_full() {
        let config = StealthProfileConfig::from_toml(
            r"
            seed = 42
            jitter_ms_min = 100
            jitter_ms_max = 500
            [headers]
            include_pragmas = false
        ",
        )
        .unwrap();
        assert_eq!(config.seed, Some(42));
        assert_eq!(config.jitter_ms_min, 100);
        assert_eq!(config.jitter_ms_max, 500);
        assert!(!config.headers.include_pragmas);
    }

    #[test]
    fn from_toml_invalid_errors() {
        assert!(StealthProfileConfig::from_toml("{{invalid").is_err());
    }

    #[test]
    fn config_with_seed_deterministic() {
        let policy1 = StealthProfileConfig::from_toml("seed = 42")
            .unwrap()
            .build();
        let policy2 = StealthProfileConfig::from_toml("seed = 42")
            .unwrap()
            .build();

        // Same config with same seed should produce identical results
        let mut req1 = MockReq::default();
        let mut req2 = MockReq::default();
        let applied1 = policy1.apply(&mut req1).unwrap();
        let applied2 = policy2.apply(&mut req2).unwrap();

        // Verify deterministic behavior
        assert_eq!(applied1.user_agent, applied2.user_agent);
        assert_eq!(applied1.applied_headers, applied2.applied_headers);
        assert_eq!(applied1.tls_profile.name, applied2.tls_profile.name);
    }

    #[derive(Default)]
    struct MockReq {
        headers: Vec<(String, String)>,
    }

    impl MutableRequest for MockReq {
        fn set_header(&mut self, name: &str, value: &str) {
            self.headers.push((name.to_string(), value.to_string()));
        }
    }
}
