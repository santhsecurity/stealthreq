//! Request safety: endpoint blocklists, method classification, and safe-request guards.
//!
//! When security tools operate with real user credentials (cookies, tokens),
//! certain endpoints must never be accessed — account deletion, logout,
//! financial transfers. This module provides configurable safety guards
//! that prevent scanners from triggering destructive operations.
//!
//! # Quick Start
//!
//! ```rust
//! use stealthreq::safety::{SafetyConfig, is_safe_request};
//!
//! let config = SafetyConfig::default();
//!
//! // Blocked: dangerous endpoint
//! assert!(!is_safe_request("GET", "/account/delete", &config));
//!
//! // Allowed: normal endpoint
//! assert!(is_safe_request("GET", "/api/users", &config));
//!
//! // Blocked: destructive method
//! assert!(!is_safe_request("DELETE", "/api/users/1", &config));
//! ```

use std::collections::HashSet;
use std::time::Duration;

/// Safety configuration for authenticated scanning.
///
/// When scanning with real user sessions, stealth tools must avoid
/// endpoints that could modify or destroy the user's account.
#[derive(Debug, Clone)]
pub struct SafetyConfig {
    /// Whether safety checks are active.
    pub enabled: bool,
    /// Endpoints that must never be accessed (case-insensitive, URL-decoded).
    pub blocked_endpoints: HashSet<String>,
    /// HTTP methods that are always blocked regardless of endpoint.
    pub blocked_methods: HashSet<String>,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        let blocked_endpoints: HashSet<String> = DANGEROUS_ENDPOINTS
            .iter()
            .copied()
            .map(str::to_string)
            .collect();

        let blocked_methods: HashSet<String> =
            ["DELETE", "PATCH"].iter().copied().map(str::to_string).collect();

        Self {
            enabled: true,
            blocked_endpoints,
            blocked_methods,
        }
    }
}

/// Endpoints that must NEVER be accessed during authenticated scanning.
/// Accessing these could modify or destroy the user's account.
const DANGEROUS_ENDPOINTS: &[&str] = &[
    "/account/delete",
    "/account/deactivate",
    "/account/close",
    "/api/account/delete",
    "/api/v1/account/delete",
    "/api/v2/account/delete",
    "/settings/delete",
    "/user/delete",
    "/profile/delete",
    "/logout",
    "/signout",
    "/sign-out",
    "/auth/logout",
    "/api/auth/logout",
    "/api/logout",
    "/account/password/reset",
    "/api/account/password",
    "/transfer",
    "/api/transfer",
    "/payment/send",
    "/api/payment",
    "/withdraw",
    "/api/withdraw",
    "/order/cancel-all",
];

/// Check if a URL path is safe to access during stealth scanning.
///
/// Handles URL decoding and case-insensitive matching.
/// Glob-like patterns using `.*` in blocked endpoints are supported.
///
/// # Arguments
///
/// * `path` — The URL path (may include query string, URL encoding).
/// * `config` — Safety configuration with blocked endpoints.
///
/// # Example
///
/// ```rust
/// use stealthreq::safety::{SafetyConfig, is_safe_endpoint};
///
/// let config = SafetyConfig::default();
/// assert!(!is_safe_endpoint("/logout", &config));
/// assert!(is_safe_endpoint("/api/users", &config));
/// ```
pub fn is_safe_endpoint(path: &str, config: &SafetyConfig) -> bool {
    if !config.enabled {
        return true;
    }
    let decoded = urlencoding::decode(path).unwrap_or(std::borrow::Cow::Borrowed(path));
    let lower = decoded.to_lowercase();
    // Strip query string — only check path portion
    let path_only = lower.split('?').next().unwrap_or(&lower);
    !config.blocked_endpoints.iter().any(|blocked| {
        let blocked_lower = blocked.to_lowercase();
        if blocked_lower.contains(".*") {
            glob_match(path_only, &blocked_lower)
        } else {
            path_only.contains(&blocked_lower)
        }
    })
}

/// Check if an HTTP method is safe for stealth scanning (read-only).
///
/// Safe methods: GET, HEAD, OPTIONS.
/// Unsafe by default: POST, PUT, DELETE, PATCH.
///
/// # Example
///
/// ```rust
/// use stealthreq::safety::is_safe_method;
///
/// assert!(is_safe_method("GET"));
/// assert!(is_safe_method("HEAD"));
/// assert!(!is_safe_method("POST"));
/// assert!(!is_safe_method("DELETE"));
/// ```
pub fn is_safe_method(method: &str) -> bool {
    matches!(method.to_uppercase().as_str(), "GET" | "HEAD" | "OPTIONS")
}

/// Combined safety check: is this request safe for stealth scanning?
///
/// Checks both the HTTP method and endpoint path.
/// In stealth mode, DELETE and PATCH are always blocked.
/// POST and PUT are allowed on safe endpoints (search forms, etc.).
///
/// # Example
///
/// ```rust
/// use stealthreq::safety::{SafetyConfig, is_safe_request};
///
/// let config = SafetyConfig::default();
/// assert!(is_safe_request("GET", "/api/users", &config));
/// assert!(!is_safe_request("GET", "/logout", &config));
/// assert!(!is_safe_request("DELETE", "/api/users/1", &config));
/// ```
pub fn is_safe_request(method: &str, path: &str, config: &SafetyConfig) -> bool {
    if !config.enabled {
        return true;
    }
    if !is_safe_endpoint(path, config) {
        return false;
    }
    let upper = method.to_uppercase();
    !config.blocked_methods.contains(&upper)
}

/// Generate a Gaussian-distributed delay between min and max milliseconds.
///
/// Uses the Box-Muller transform for normal distribution, which produces
/// more human-like timing patterns than uniform random delays.
///
/// # Arguments
///
/// * `min_ms` — Minimum delay in milliseconds.
/// * `max_ms` — Maximum delay in milliseconds.
/// * `rng` — Random number generator for deterministic testing.
///
/// # Example
///
/// ```rust
/// use std::time::Duration;
/// use rand::{rngs::StdRng, SeedableRng};
/// use stealthreq::safety::gaussian_delay;
///
/// let mut rng = StdRng::seed_from_u64(42);
/// let delay = gaussian_delay(100, 500, &mut rng);
/// assert!(delay >= Duration::from_millis(100));
/// assert!(delay <= Duration::from_millis(500));
/// ```
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn gaussian_delay(min_ms: u64, max_ms: u64, rng: &mut impl rand::Rng) -> Duration {
    if max_ms == 0 {
        return Duration::ZERO;
    }
    let min = min_ms.min(max_ms);
    let max = min_ms.max(max_ms);
    if min == max {
        return Duration::from_millis(min);
    }

    let mean = (min + max) as f64 / 2.0;
    let stddev = (max - min) as f64 / 4.0;

    // Box-Muller transform
    let u1: f64 = rng.gen_range(0.001_f64..1.0);
    let u2: f64 = rng.gen_range(0.0_f64..std::f64::consts::TAU);
    let z = (-2.0 * u1.ln()).sqrt() * u2.cos();

    let delay_ms = (mean + z * stddev).clamp(min as f64, max as f64);
    Duration::from_millis(delay_ms as u64)
}

/// Simple glob-like matching for blocked endpoint patterns.
///
/// Supports `.*` as a wildcard that matches any sequence of characters.
fn glob_match(path: &str, pattern: &str) -> bool {
    let parts: Vec<&str> = pattern.split(".*").collect();
    let mut remaining = path;
    for part in &parts {
        if part.is_empty() {
            continue;
        }
        if let Some(pos) = remaining.find(part) {
            remaining = &remaining[pos + part.len()..];
        } else {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn dangerous_endpoints_blocked() {
        let config = SafetyConfig::default();
        assert!(!is_safe_endpoint("/account/delete", &config));
        assert!(!is_safe_endpoint("/api/auth/logout", &config));
        assert!(!is_safe_endpoint("/api/withdraw", &config));
        assert!(!is_safe_endpoint("/logout", &config));
    }

    #[test]
    fn normal_endpoints_allowed() {
        let config = SafetyConfig::default();
        assert!(is_safe_endpoint("/api/users", &config));
        assert!(is_safe_endpoint("/dashboard", &config));
        assert!(is_safe_endpoint("/search?q=test", &config));
        assert!(is_safe_endpoint("/api/v2/products", &config));
    }

    #[test]
    fn url_encoded_dangerous_path_blocked() {
        let config = SafetyConfig::default();
        assert!(!is_safe_endpoint("%2Flogout", &config));
    }

    #[test]
    fn case_variations_blocked() {
        let config = SafetyConfig::default();
        assert!(!is_safe_endpoint("/LOGOUT", &config));
        assert!(!is_safe_endpoint("/Logout", &config));
        assert!(!is_safe_endpoint("/LoGoUt", &config));
    }

    #[test]
    fn query_string_blocked_word_is_safe() {
        let config = SafetyConfig::default();
        // The blocked word "delete" is in query, not path
        assert!(is_safe_endpoint("/search?q=delete+account", &config));
    }

    #[test]
    fn safe_methods() {
        assert!(is_safe_method("GET"));
        assert!(is_safe_method("HEAD"));
        assert!(is_safe_method("OPTIONS"));
        assert!(!is_safe_method("POST"));
        assert!(!is_safe_method("DELETE"));
    }

    #[test]
    fn safe_request_combined() {
        let config = SafetyConfig::default();
        assert!(is_safe_request("GET", "/api/users", &config));
        assert!(!is_safe_request("GET", "/logout", &config));
        assert!(!is_safe_request("DELETE", "/api/users/1", &config));
        assert!(!is_safe_request("PATCH", "/api/users/1", &config));
    }

    #[test]
    fn glob_pattern_matching() {
        let mut config = SafetyConfig::default();
        config.blocked_endpoints.insert("/api/.*admin".to_string());
        assert!(!is_safe_endpoint("/api/users/admin", &config));
        assert!(!is_safe_endpoint("/api/settings/admin", &config));
    }

    #[test]
    fn gaussian_delay_within_range() {
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..100 {
            let delay = gaussian_delay(100, 500, &mut rng);
            assert!(delay >= Duration::from_millis(100));
            assert!(delay <= Duration::from_millis(500));
        }
    }

    #[test]
    fn gaussian_delay_zero_max() {
        let mut rng = StdRng::seed_from_u64(42);
        assert_eq!(gaussian_delay(0, 0, &mut rng), Duration::ZERO);
    }

    #[test]
    fn gaussian_delay_min_equals_max() {
        let mut rng = StdRng::seed_from_u64(42);
        assert_eq!(
            gaussian_delay(300, 300, &mut rng),
            Duration::from_millis(300)
        );
    }

    #[test]
    fn gaussian_delay_mean_is_centered() {
        let mut rng = StdRng::seed_from_u64(42);
        let expected_mean = 300.0;
        let mut sum = 0.0;
        let iterations = 5000;

        for _ in 0..iterations {
            sum += gaussian_delay(100, 500, &mut rng).as_secs_f64() * 1000.0;
        }

        let actual_mean = sum / f64::from(iterations);
        assert!(
            (actual_mean - expected_mean).abs() < 30.0,
            "mean {actual_mean} should be near {expected_mean}"
        );
    }

    #[test]
    fn disabled_config_allows_everything() {
        let config = SafetyConfig {
            enabled: false,
            ..SafetyConfig::default()
        };
        assert!(is_safe_endpoint("/logout", &config));
        assert!(is_safe_request("DELETE", "/account/delete", &config));
    }

    #[test]
    fn trailing_slash_still_blocked() {
        let config = SafetyConfig::default();
        assert!(!is_safe_endpoint("/logout/", &config));
        assert!(!is_safe_endpoint("/account/delete/", &config));
    }

    #[test]
    fn custom_blocked_endpoints() {
        let mut config = SafetyConfig::default();
        config.blocked_endpoints.insert("/custom/dangerous".to_string());
        assert!(!is_safe_endpoint("/custom/dangerous", &config));
    }
}
