/// Simulated TLS fingerprint profiles for request behavior rotation.
///
/// The crate does not perform TLS handshakes itself; this data lets clients
/// bind profiles to their own TLS stack (rustls/boring/native-tls, etc.).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TlsFingerprint {
    /// Human label for telemetry and observability.
    pub name: String,
    /// Raw JA3 string in `version,ciphers,extensions,elliptic_curves,point_formats` format.
    pub ja3: String,
    /// MD5 hash of the JA3 fingerprint string (computed as per JA3 spec).
    pub ja3_hash: String,
    /// ALPN order for this profile.
    pub alpn: Vec<String>,
    /// Cipher suite preference.
    pub cipher_suites: Vec<String>,
    /// Extension ordering.
    pub extensions: Vec<String>,
}

impl TlsFingerprint {
    #[must_use]
    pub fn as_header_hints(&self) -> Vec<(String, String)> {
        vec![
            ("Sec-CH-UA-Platform".to_string(), String::new()),
            ("X-TLS-Fingerprint".to_string(), self.ja3_hash.clone()),
        ]
    }

    /// Compute the MD5 hash of a JA3 string as per the JA3 specification.
    /// Returns a 32-character lowercase hex string (128-bit MD5 digest).
    fn compute_ja3_hash(ja3_str: &str) -> String {
        use md5::{Digest, Md5};
        let result = Md5::digest(ja3_str.as_bytes());
        format!("{result:032x}")
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TlsRotationPolicy {
    pub profiles: Vec<TlsFingerprint>,
    pub enable: bool,
    pub rotate: bool,
}

impl Default for TlsRotationPolicy {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl TlsRotationPolicy {
    #[must_use]
    pub fn from_config(cfg: TlsRotationConfig) -> Self {
        let mut policy = Self::with_defaults();
        policy.enable = cfg.enabled;
        policy.rotate = cfg.enabled;
        policy
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            profiles: Self::build_default_profiles(),
            enable: true,
            rotate: true,
        }
    }

    #[must_use]
    pub fn build_default_profiles() -> Vec<TlsFingerprint> {
        // JA3 strings are: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
        let profiles = vec![
            (
                "chrome-desktop-121",
                "770,4865-4866-4867,23-24,0-11-10-35-16-22,0-1",
            ),
            (
                "chrome-mobile-121",
                "771,4865-4867,23-24-25,0-11-10-35-16,0-1",
            ),
            (
                "firefox-desktop",
                "772,4867-4866-4865,23-24,0-10-11-16-35,0-1",
            ),
        ];

        profiles
            .into_iter()
            .map(|(name, ja3)| {
                let ja3_hash = TlsFingerprint::compute_ja3_hash(ja3);
                let cipher_suites = match name {
                    "chrome-desktop-121" => {
                        vec!["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]
                    }
                    "chrome-mobile-121" => {
                        vec!["TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"]
                    }
                    "firefox-desktop" => {
                        vec!["TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"]
                    }
                    _ => vec!["TLS_AES_128_GCM_SHA256"],
                };
                let extensions = match name {
                    "chrome-desktop-121" => {
                        vec!["server_name", "application_layer_protocol_negotiation"]
                    }
                    "chrome-mobile-121" => vec!["server_name", "extended_master_secret"],
                    "firefox-desktop" => vec!["server_name", "key_share"],
                    _ => vec!["server_name"],
                };
                TlsFingerprint {
                    name: name.to_string(),
                    ja3: ja3.to_string(),
                    ja3_hash,
                    alpn: vec!["h2".into(), "http/1.1".into()],
                    cipher_suites: cipher_suites.into_iter().map(String::from).collect(),
                    extensions: extensions.into_iter().map(String::from).collect(),
                }
            })
            .collect()
    }

    #[must_use]
    pub fn rotate(&self, rng: &mut impl rand::Rng) -> TlsFingerprint {
        if self.profiles.is_empty() {
            let ja3 = "771,4865,0,0,0".to_string();
            let ja3_hash = TlsFingerprint::compute_ja3_hash(&ja3);
            return TlsFingerprint {
                name: "fallback".to_string(),
                ja3,
                ja3_hash,
                alpn: vec!["h2".into()],
                cipher_suites: vec!["TLS_AES_128_GCM_SHA256".into()],
                extensions: vec!["server_name".into()],
            };
        }
        self.profiles[rng.gen_range(0..self.profiles.len())].clone()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TlsRotationConfig {
    pub enabled: bool,
}

impl Default for TlsRotationConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl From<TlsRotationConfig> for TlsRotationPolicy {
    fn from(value: TlsRotationConfig) -> Self {
        Self::from_config(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn default_profiles_are_stable() {
        let policy = TlsRotationPolicy::default();
        let mut rng = StdRng::seed_from_u64(99);
        let a = policy.rotate(&mut rng);
        let mut rng = StdRng::seed_from_u64(99);
        let b = policy.rotate(&mut rng);
        assert_eq!(a.name, b.name);
    }

    #[test]
    fn fallback_has_headers() {
        let profile = TlsRotationPolicy {
            profiles: vec![],
            enable: true,
            rotate: false,
        };
        let fp = profile.rotate(&mut StdRng::seed_from_u64(1));
        assert_eq!(fp.name, "fallback");
        assert_eq!(fp.as_header_hints()[1].0, "X-TLS-Fingerprint");
        assert_eq!(fp.ja3, "771,4865,0,0,0");
        assert_eq!(
            fp.ja3_hash.len(),
            32,
            "ja3_hash should be 32 hex characters (MD5)"
        );
    }

    #[test]
    fn ja3_hash_is_deterministic() {
        // Same JA3 string should produce same hash
        let policy = TlsRotationPolicy::default();
        assert!(!policy.profiles.is_empty());

        // All profiles should have valid hash format
        for profile in &policy.profiles {
            assert!(
                profile.ja3.split(',').count() == 5,
                "JA3 string should contain 5 comma-separated sections"
            );
            assert!(!profile.ja3_hash.is_empty(), "JA3 hash should not be empty");
            assert_eq!(
                profile.ja3_hash.len(),
                32,
                "JA3 hash should be 32 hex chars (MD5)"
            );
            assert_eq!(
                profile.ja3_hash,
                TlsFingerprint::compute_ja3_hash(&profile.ja3),
                "JA3 hash should match the raw JA3 string"
            );
            // Verify it's valid hex
            assert!(
                profile.ja3_hash.chars().all(|c| c.is_ascii_hexdigit()),
                "JA3 hash should be valid hexadecimal"
            );
        }
    }
}
