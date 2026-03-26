use crate::TimingJitter;

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Version/17.4 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
];

const ACCEPT_LANGS: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "en-CA,en;q=0.8",
    "fr-FR,fr;q=0.8,en;q=0.7",
];
const ACCEPT_ENCODINGS: &[&str] = &["gzip, deflate, br", "gzip, br", "br, gzip", "gzip"];
const CACHE_CONTROL: &[&str] = &["no-cache", "max-age=0", "no-store", "must-revalidate"];
const UPGRADE_INSECURE_REQUEST: &[&str] = &["1", "0"];

/// Header mutation profile. Contains pools of realistic browser values.
/// Uses `Arc<str>` for efficient sharing of static strings.
#[derive(Debug, Clone)]
pub struct HeaderPolicy {
    pub user_agents: Vec<std::sync::Arc<str>>,
    pub accept_languages: Vec<std::sync::Arc<str>>,
    pub accept_encodings: Vec<std::sync::Arc<str>>,
    pub cache_controls: Vec<std::sync::Arc<str>>,
    pub upgrade_insecure: Vec<std::sync::Arc<str>>,
    pub referer_hosts: Vec<String>,
    pub extra_headers: Vec<(String, String)>,
    pub include_pragmas: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HeaderPolicyConfig {
    #[serde(default)]
    pub referer_hosts: Vec<String>,
    #[serde(default)]
    pub extra_headers: Vec<(String, String)>,
    #[serde(default)]
    pub include_pragmas: bool,
}

impl Default for HeaderPolicyConfig {
    fn default() -> Self {
        Self {
            referer_hosts: vec![
                "https://example.com".into(),
                "https://www.google.com".into(),
            ],
            extra_headers: vec![(
                "Accept".into(),
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into(),
            )],
            include_pragmas: true,
        }
    }
}

impl HeaderPolicyConfig {
    pub fn into_profile(self) -> HeaderPolicy {
        // Use Arc<str> for static constants to avoid unnecessary cloning
        HeaderPolicy {
            user_agents: USER_AGENTS
                .iter()
                .map(|s| std::sync::Arc::from(*s))
                .collect(),
            accept_languages: ACCEPT_LANGS
                .iter()
                .map(|s| std::sync::Arc::from(*s))
                .collect(),
            accept_encodings: ACCEPT_ENCODINGS
                .iter()
                .map(|s| std::sync::Arc::from(*s))
                .collect(),
            cache_controls: CACHE_CONTROL
                .iter()
                .map(|s| std::sync::Arc::from(*s))
                .collect(),
            upgrade_insecure: UPGRADE_INSECURE_REQUEST
                .iter()
                .map(|s| std::sync::Arc::from(*s))
                .collect(),
            referer_hosts: self.referer_hosts,
            extra_headers: self.extra_headers,
            include_pragmas: self.include_pragmas,
        }
    }
}

impl Default for HeaderPolicy {
    fn default() -> Self {
        HeaderPolicyConfig::default().into_profile()
    }
}

impl HeaderPolicy {
    fn pick_arc(rng: &mut impl rand::Rng, items: &[std::sync::Arc<str>]) -> Option<String> {
        if items.is_empty() {
            None
        } else {
            Some(items[rng.gen_range(0..items.len())].to_string())
        }
    }

    fn pick_string(rng: &mut impl rand::Rng, items: &[String]) -> Option<String> {
        if items.is_empty() {
            None
        } else {
            Some(items[rng.gen_range(0..items.len())].clone())
        }
    }

    fn pick_tuple(
        rng: &mut impl rand::Rng,
        items: &[(String, String)],
    ) -> Option<(String, String)> {
        if items.is_empty() {
            None
        } else {
            Some(items[rng.gen_range(0..items.len())].clone())
        }
    }

    fn prune_headers_to_budget(
        rng: &mut impl rand::Rng,
        headers: &mut Vec<(String, String)>,
        budget: usize,
    ) {
        while headers.len() > budget {
            let ua_pos = headers
                .iter()
                .position(|(name, _)| name.eq_ignore_ascii_case("user-agent"));

            let idx = match ua_pos {
                Some(0) if headers.len() > 1 => rng.gen_range(1..headers.len()),
                Some(pos) if headers.len() > 1 => {
                    let choice = rng.gen_range(0..headers.len() - 1);
                    if choice >= pos {
                        choice + 1
                    } else {
                        choice
                    }
                }
                _ => rng.gen_range(0..headers.len()),
            };

            headers.swap_remove(idx);
        }
    }

    pub fn materialize(
        &self,
        rng: &mut impl rand::Rng,
        header_budget: usize,
        timing: &TimingJitter,
    ) -> Vec<(String, String)> {
        let mut headers = Vec::new();

        if let Some(user_agent) = Self::pick_arc(rng, &self.user_agents) {
            headers.push(("User-Agent".to_string(), user_agent));
        }

        if let Some(accept_language) = Self::pick_arc(rng, &self.accept_languages) {
            headers.push(("Accept-Language".to_string(), accept_language));
        }
        if let Some(encoding) = Self::pick_arc(rng, &self.accept_encodings) {
            headers.push(("Accept-Encoding".to_string(), encoding));
        }
        if let Some(cache) = Self::pick_arc(rng, &self.cache_controls) {
            headers.push(("Cache-Control".to_string(), cache));
        }
        if let Some(upgrade) = Self::pick_arc(rng, &self.upgrade_insecure) {
            headers.push(("Upgrade-Insecure-Requests".to_string(), upgrade));
        }

        // Only add burstiness headers when the policy has configured headers.
        // An empty policy should produce zero headers.
        if timing.burstiness() && !headers.is_empty() {
            headers.push(("DNT".into(), "1".into()));
            headers.push(("Sec-Fetch-Site".into(), "none".into()));
            headers.push(("Sec-Fetch-Mode".into(), "navigate".into()));
            headers.push(("Sec-Fetch-Dest".into(), "document".into()));
        }

        if let Some(referer) = Self::pick_string(rng, &self.referer_hosts) {
            headers.push(("Referer".into(), referer));
        }

        if self.include_pragmas {
            headers.push(("Pragma".into(), "no-cache".into()));
        }

        if let Some((name, value)) = Self::pick_tuple(rng, &self.extra_headers) {
            headers.push((name, value));
        }

        Self::prune_headers_to_budget(rng, &mut headers, header_budget);

        headers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn default_profile_is_seedable_and_reproducible() {
        let profile = HeaderPolicy::default();
        let mut rng1 = StdRng::seed_from_u64(11);
        let mut rng2 = StdRng::seed_from_u64(11);
        let jitter = TimingJitter::new(50, 200);
        let a = profile.materialize(&mut rng1, 6, &jitter);
        let b = profile.materialize(&mut rng2, 6, &jitter);
        assert_eq!(a, b);
    }

    #[test]
    fn default_profile_respects_budget() {
        let profile = HeaderPolicy::default();
        let mut rng = StdRng::seed_from_u64(11);
        let headers = profile.materialize(&mut rng, 4, &TimingJitter::new(10, 20));
        assert!(headers.len() <= 4);
        assert!(headers.iter().any(|(n, _)| n == "User-Agent"));
    }
}
