use rand::rngs::StdRng;
use rand::SeedableRng;
use std::time::Duration;

use crate::{
    headers::HeaderPolicy, timing::TimingJitter, tls::TlsFingerprint, tls::TlsRotationPolicy,
    StealthError,
};

/// Minimal mutable header interface used by adapters.
///
/// Libraries only need to implement this trait for their request type.
pub trait MutableRequest {
    fn set_header(&mut self, name: &str, value: &str);
    fn set_user_agent(&mut self, value: &str) {
        self.set_header("User-Agent", value);
    }
}

#[derive(Debug, Clone)]
pub struct AppliedRequestProfile {
    pub user_agent: String,
    pub applied_headers: Vec<(String, String)>,
    pub jitter: Duration,
    pub tls_profile: TlsFingerprint,
}

/// Public interface implemented by all request modifiers.
pub trait RequestModifier {
    fn apply_with_rng(
        &self,
        request: &mut dyn MutableRequest,
        rng: &mut StdRng,
    ) -> crate::Result<AppliedRequestProfile>;
    fn apply(&self, request: &mut dyn MutableRequest) -> crate::Result<AppliedRequestProfile>;
    fn next_jitter(&self, rng: &mut StdRng) -> Duration;
    fn next_tls_profile(&self, rng: &mut StdRng) -> TlsFingerprint;
}

#[derive(Debug, Clone)]
pub struct StealthPolicy {
    header_budget: usize,
    jitter: TimingJitter,
    headers: HeaderPolicy,
    tls: TlsRotationPolicy,
    rotate_tls: bool,
    deterministic_seed: Option<u64>,
}

impl Default for StealthPolicy {
    fn default() -> Self {
        Self {
            header_budget: 6,
            jitter: TimingJitter::new(80, 250),
            headers: HeaderPolicy::default(),
            tls: TlsRotationPolicy::with_defaults(),
            rotate_tls: true,
            deterministic_seed: None,
        }
    }
}

impl StealthPolicy {
    #[must_use]
    pub fn with_seed(mut self, seed: Option<u64>) -> Self {
        self.deterministic_seed = seed;
        self
    }

    #[must_use]
    pub fn with_timing(mut self, jitter: TimingJitter) -> Self {
        self.jitter = jitter;
        self
    }

    #[must_use]
    pub fn with_headers(mut self, headers: HeaderPolicy) -> Self {
        self.headers = headers;
        self
    }

    #[must_use]
    pub fn with_tls_rotation(mut self, tls: TlsRotationPolicy) -> Self {
        self.tls = tls;
        self
    }

    #[must_use]
    pub fn with_header_budget(mut self, header_budget: usize) -> Self {
        self.header_budget = header_budget.max(1);
        self
    }

    #[must_use]
    pub fn with_rotate_tls(mut self, rotate_tls: bool) -> Self {
        self.rotate_tls = rotate_tls;
        self
    }

    #[must_use]
    fn seeded_rng(&self) -> StdRng {
        let seed = self.deterministic_seed.unwrap_or_else(rand::random::<u64>);
        StdRng::seed_from_u64(seed)
    }
}

impl RequestModifier for StealthPolicy {
    fn apply_with_rng(
        &self,
        request: &mut dyn MutableRequest,
        rng: &mut StdRng,
    ) -> crate::Result<AppliedRequestProfile> {
        let mut candidate_headers = self
            .headers
            .materialize(rng, self.header_budget, &self.jitter);
        if candidate_headers.is_empty() {
            return Err(StealthError::Internal("no headers generated"));
        }

        let user_agent = candidate_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
            .map(|(_, value)| value.clone())
            .ok_or(StealthError::Internal("User-Agent not generated"))?;

        for (name, value) in &candidate_headers {
            request.set_header(name, value);
        }

        let jitter = self.next_jitter(rng);
        let tls_profile = self.next_tls_profile(rng);
        Ok(AppliedRequestProfile {
            user_agent,
            applied_headers: std::mem::take(&mut candidate_headers),
            jitter,
            tls_profile,
        })
    }

    fn apply(&self, request: &mut dyn MutableRequest) -> crate::Result<AppliedRequestProfile> {
        let mut rng = self.seeded_rng();
        self.apply_with_rng(request, &mut rng)
    }

    fn next_jitter(&self, rng: &mut StdRng) -> Duration {
        self.jitter.sample_delay(rng)
    }

    fn next_tls_profile(&self, rng: &mut StdRng) -> TlsFingerprint {
        if self.rotate_tls {
            return self.tls.rotate(rng);
        }

        if let Some(profile) = self.tls.profiles.first() {
            profile.clone()
        } else {
            self.tls.rotate(rng)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[derive(Debug, Default)]
    struct MockReq {
        headers: Vec<(String, String)>,
    }

    impl MutableRequest for MockReq {
        fn set_header(&mut self, name: &str, value: &str) {
            self.headers.push((name.to_string(), value.to_string()));
        }
    }

    #[test]
    fn deterministic_policy_replays_headers() {
        let mut req1 = MockReq::default();
        let mut req2 = MockReq::default();

        let policy = StealthPolicy::default()
            .with_seed(Some(1234))
            .with_header_budget(7);
        let mut rng1 = StdRng::seed_from_u64(1234);
        let mut rng2 = StdRng::seed_from_u64(1234);

        let a = policy.apply_with_rng(&mut req1, &mut rng1).unwrap();
        let b = policy.apply_with_rng(&mut req2, &mut rng2).unwrap();
        assert_eq!(a.user_agent, b.user_agent);
        assert_eq!(a.applied_headers, b.applied_headers);
        assert_eq!(a.jitter, b.jitter);
        assert_eq!(a.tls_profile.name, b.tls_profile.name);
    }

    #[test]
    fn policy_applies_headers_and_ua() {
        let mut req = MockReq::default();
        let mut rng = StdRng::seed_from_u64(11);
        let policy = StealthPolicy::default().with_seed(Some(11));
        let applied = policy.apply_with_rng(&mut req, &mut rng).unwrap();
        assert!(req
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("User-Agent")));
        assert!(!applied.user_agent.to_lowercase().is_empty());
    }

    #[test]
    fn can_disable_tls_rotation() {
        let mut req = MockReq::default();
        let mut rng = StdRng::seed_from_u64(4);
        let policy = StealthPolicy::default()
            .with_seed(Some(4))
            .with_rotate_tls(false);
        let applied = policy.apply_with_rng(&mut req, &mut rng).unwrap();
        assert!(!applied.tls_profile.name.is_empty());
    }

    #[test]
    fn empty_headers_config_is_rejected() {
        use crate::headers::HeaderPolicy;
        let mut req = MockReq::default();
        let mut rng = StdRng::seed_from_u64(1);
        let policy = StealthPolicy::default()
            .with_headers(HeaderPolicy::default())
            .with_header_budget(0);
        let res = policy.apply_with_rng(&mut req, &mut rng);
        assert!(res.is_ok());
    }
}
