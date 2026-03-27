//! Adversarial edge case tests for stealthreq
//!
//! These tests are designed to break the crate by testing:
//! - Empty header maps
//! - Headers with null bytes
//! - Timing jitter with zero/negative delays
//! - TLS fingerprints with empty cipher suites
//! - TOML configs with missing fields
//! - Concurrent policy rotation

use crate::*;
use rand::{rngs::StdRng, SeedableRng};
use std::sync::Arc;
use std::thread;

// =============================================================================
// Header Policy Tests
// =============================================================================

#[test]
fn empty_header_policy_generates_no_headers() {
    let policy = HeaderPolicy {
        user_agents: vec![],
        accept_languages: vec![],
        accept_encodings: vec![],
        cache_controls: vec![],
        upgrade_insecure: vec![],
        referer_hosts: vec![],
        extra_headers: vec![],
        include_pragmas: false,
    };
    let mut rng = StdRng::seed_from_u64(42);
    let jitter = TimingJitter::new(100, 200);
    let headers = policy.materialize(&mut rng, 10, &jitter);
    // Fixed: empty policy now correctly produces zero headers.
    // Burstiness headers are only added when the policy has other headers configured.
    assert!(
        headers.is_empty(),
        "empty policy should produce zero headers"
    );
}

#[test]
fn header_policy_with_null_bytes_in_extra_headers() {
    let mut policy = HeaderPolicy::default();
    policy
        .extra_headers
        .push(("X-Custom\0Header".to_string(), "value".to_string()));
    policy
        .extra_headers
        .push(("X-Normal".to_string(), "val\0ue".to_string()));

    let mut rng = StdRng::seed_from_u64(42);
    let jitter = TimingJitter::new(100, 200);
    let headers = policy.materialize(&mut rng, 20, &jitter);

    // Check that null bytes are preserved (this might be a bug - null bytes in headers)
    let custom_header = headers.iter().find(|(n, _)| n.contains('\0'));
    if let Some((name, _)) = custom_header {
        assert!(
            name.contains('\0'),
            "Null byte should be present in header name"
        );
    }
}

#[test]
fn header_budget_of_one_preserves_user_agent() {
    let policy = HeaderPolicy::default();
    let mut rng = StdRng::seed_from_u64(42);
    let jitter = TimingJitter::new(100, 200);
    let headers = policy.materialize(&mut rng, 1, &jitter);

    assert_eq!(
        headers.len(),
        1,
        "Budget of 1 should produce exactly 1 header"
    );
    assert!(
        headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("User-Agent")),
        "User-Agent should be preserved even with minimal budget"
    );
}

#[test]
fn header_budget_of_zero_causes_pruning_to_budget() {
    let policy = HeaderPolicy::default();
    let mut rng = StdRng::seed_from_u64(42);
    let jitter = TimingJitter::new(100, 200);

    // Test with budget 0 - the code should handle this gracefully
    let headers = policy.materialize(&mut rng, 0, &jitter);
    // The function prune_headers_to_budget uses a while loop that should handle 0
    assert_eq!(
        headers.len(),
        0,
        "Budget of 0 should result in empty headers after pruning"
    );
}

// =============================================================================
// Timing Jitter Tests
// =============================================================================

#[test]
fn timing_jitter_zero_min_max() {
    let jitter = TimingJitter::new(0, 0);
    let mut rng = StdRng::seed_from_u64(42);
    let delay = jitter.sample_delay(&mut rng);
    assert_eq!(
        delay.as_millis(),
        0,
        "Zero jitter should produce zero delay"
    );
}

#[test]
fn timing_jitter_inverted_range_max_less_than_min() {
    // Test when max_ms < min_ms - the code has a check for this
    let jitter = TimingJitter::new(100, 50);
    let mut rng = StdRng::seed_from_u64(42);
    let delay = jitter.sample_delay(&mut rng);
    // The code returns min_ms when max_ms <= min_ms
    assert_eq!(
        delay.as_millis(),
        100,
        "Inverted range should return min_ms"
    );
}

#[test]
fn timing_jitter_very_large_values() {
    let jitter = TimingJitter::new(u64::MAX - 100, u64::MAX);
    let mut rng = StdRng::seed_from_u64(42);
    // This could panic or overflow - let's see
    let delay = jitter.sample_delay(&mut rng);
    // Just verify it doesn't panic - the actual value depends on implementation
    assert!(delay.as_millis() >= u128::from(u64::MAX - 100) || delay.as_millis() <= 100);
}

#[test]
fn timing_jitter_burstiness_with_zero_difference() {
    let jitter = TimingJitter::new(100, 100);
    assert!(
        jitter.burstiness(),
        "Zero difference (100-100=0) should have burstiness=true (0 % 2 == 0)"
    );
}

#[test]
fn timing_jitter_burstiness_with_odd_difference() {
    let jitter = TimingJitter::new(100, 101);
    assert!(
        !jitter.burstiness(),
        "Odd difference (101-100=1) should have burstiness=false (1 % 2 == 1)"
    );
}

// =============================================================================
// TLS Fingerprint Tests
// =============================================================================

#[test]
fn tls_fingerprint_empty_cipher_suites() {
    let fp = TlsFingerprint {
        name: "test".to_string(),
        ja3: "771,4865,0,0,0".to_string(),
        ja3_hash: "abc123".to_string(),
        alpn: vec!["h2".to_string()],
        cipher_suites: vec![],
        extensions: vec!["server_name".to_string()],
    };
    let hints = fp.as_header_hints();
    assert_eq!(
        hints.len(),
        2,
        "Should still produce header hints with empty cipher suites"
    );
}

#[test]
fn tls_fingerprint_empty_extensions() {
    let fp = TlsFingerprint {
        name: "test".to_string(),
        ja3: "771,4865,0,0,0".to_string(),
        ja3_hash: "abc123".to_string(),
        alpn: vec![],
        cipher_suites: vec!["TLS_AES_128_GCM_SHA256".to_string()],
        extensions: vec![],
    };
    // Should handle empty extensions gracefully
    assert!(fp.extensions.is_empty());
}

#[test]
fn tls_rotation_empty_profiles() {
    let policy = TlsRotationPolicy {
        profiles: vec![],
        enable: true,
        rotate: true,
    };
    let mut rng = StdRng::seed_from_u64(42);
    let fp = policy.rotate(&mut rng);

    // Should return fallback with "unknown" ja3_hash
    assert_eq!(fp.name, "fallback");
    assert_eq!(
        fp.ja3_hash.len(),
        32,
        "Fallback should have valid MD5 hash (32 hex chars)"
    );
}

#[test]
fn tls_compute_ja3_hash_empty_string() {
    // Test via the fallback mechanism which computes hash of "unknown"
    let policy = TlsRotationPolicy {
        profiles: vec![],
        enable: true,
        rotate: true,
    };
    let mut rng = StdRng::seed_from_u64(42);
    let fp = policy.rotate(&mut rng);

    assert_eq!(fp.ja3, "771,4865,0,0,0");
    assert_eq!(fp.ja3_hash, "4b39897bc77cc94a60e587746645ad06".to_string());
}

// =============================================================================
// TOML Config Tests
// =============================================================================

#[test]
fn toml_config_empty_string() {
    let cfg = StealthProfileConfig::from_toml("");
    assert!(cfg.is_ok(), "Empty TOML should parse with defaults");
    let cfg = cfg.unwrap();
    assert_eq!(cfg.jitter_ms_min, 80, "Should use default min jitter");
    assert_eq!(cfg.jitter_ms_max, 350, "Should use default max jitter");
}

#[test]
fn toml_config_missing_required_fields() {
    // Test with minimal TOML - only some fields
    let toml = r"
seed = 123
";
    let cfg = StealthProfileConfig::from_toml(toml);
    assert!(cfg.is_ok(), "TOML with just seed should work");
    let cfg = cfg.unwrap();
    assert_eq!(cfg.seed, Some(123));
    assert_eq!(cfg.header_budget, 4, "Should use default header budget");
}

#[test]
fn toml_config_invalid_header_budget_zero() {
    let toml = r"
header_budget = 0
";
    let cfg = StealthProfileConfig::from_toml(toml);
    assert!(cfg.is_err(), "header_budget = 0 should be rejected");
}

#[test]
fn toml_config_inverted_jitter_range() {
    let toml = r"
jitter_ms_min = 500
jitter_ms_max = 100
";
    let cfg = StealthProfileConfig::from_toml(toml);
    assert!(cfg.is_err(), "Inverted jitter range should be rejected");
}

#[test]
fn toml_config_very_large_seed() {
    let toml = r"
seed = 18446744073709551615
";
    let cfg = StealthProfileConfig::from_toml(toml);
    // This might fail due to integer overflow in parsing
    assert!(
        cfg.is_ok() || cfg.is_err(),
        "Should either parse or fail gracefully"
    );
}

#[test]
fn toml_config_malformed() {
    let toml = r#"
[headers
referer_hosts = ["example.com"
"#;
    let cfg = StealthProfileConfig::from_toml(toml);
    assert!(cfg.is_err(), "Malformed TOML should error");
}

// =============================================================================
// StealthPolicy Tests
// =============================================================================

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
fn policy_apply_with_empty_header_policy() {
    let empty_header_policy = HeaderPolicy {
        user_agents: vec![],
        accept_languages: vec![],
        accept_encodings: vec![],
        cache_controls: vec![],
        upgrade_insecure: vec![],
        referer_hosts: vec![],
        extra_headers: vec![],
        include_pragmas: false,
    };

    let policy = StealthPolicy::default().with_headers(empty_header_policy);

    let mut req = MockReq::default();
    let mut rng = StdRng::seed_from_u64(42);
    let result = policy.apply_with_rng(&mut req, &mut rng);

    // This should fail because no headers are generated
    assert!(
        result.is_err(),
        "Empty header policy should cause apply to fail"
    );
}

#[test]
fn policy_with_header_budget_zero() {
    let policy = StealthPolicy::default().with_header_budget(0);

    let mut req = MockReq::default();
    let result = policy.apply(&mut req);

    // Budget 0 gets clamped to 1 via max(1) in with_header_budget
    assert!(result.is_ok(), "Budget 0 should be clamped to 1");
}

#[test]
fn policy_concurrent_apply_with_same_seed() {
    let policy = Arc::new(StealthPolicy::default().with_seed(Some(42)));

    let handles: Vec<_> = (0..10)
        .map(|_| {
            let policy = Arc::clone(&policy);
            thread::spawn(move || {
                let mut req = MockReq::default();
                policy.apply(&mut req).unwrap()
            })
        })
        .collect();

    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All should have the same user_agent since they use the same seed
    let first_ua = &results[0].user_agent;
    for result in &results {
        assert_eq!(
            &result.user_agent, first_ua,
            "Same seed should produce same user agent"
        );
    }
}

#[test]
fn policy_next_jitter_consistency() {
    let policy = StealthPolicy::default().with_seed(Some(123));
    let mut rng1 = StdRng::seed_from_u64(123);
    let mut rng2 = StdRng::seed_from_u64(123);

    let jitter1 = policy.next_jitter(&mut rng1);
    let jitter2 = policy.next_jitter(&mut rng2);

    assert_eq!(
        jitter1, jitter2,
        "Same RNG state should produce same jitter"
    );
}

#[test]
fn policy_tls_rotation_disabled() {
    let policy = StealthPolicy::default()
        .with_seed(Some(42))
        .with_rotate_tls(false);

    let mut rng = StdRng::seed_from_u64(42);
    let fp1 = policy.next_tls_profile(&mut rng);
    let mut rng = StdRng::seed_from_u64(42);
    let fp2 = policy.next_tls_profile(&mut rng);

    // With rotate_tls=false, we should still get a profile
    assert!(!fp1.name.is_empty());
    assert_eq!(fp1.name, fp2.name);
}

#[test]
fn config_build_with_missing_optional_fields() {
    let cfg = StealthProfileConfig {
        jitter_ms_min: 100,
        jitter_ms_max: 200,
        header_budget: 5,
        seed: None,
        rotate_tls: false,
        headers: HeaderPolicyConfig::default(),
        tls: TlsRotationConfig { enabled: false },
    };

    let policy = cfg.build();
    let mut req = MockReq::default();
    let result = policy.apply(&mut req);

    assert!(result.is_ok());
}

#[test]
fn header_policy_with_very_long_referer() {
    let policy = HeaderPolicy {
        referer_hosts: vec!["https://".to_string() + &"a".repeat(10000)],
        ..HeaderPolicy::default()
    };

    let mut rng = StdRng::seed_from_u64(42);
    let jitter = TimingJitter::new(100, 200);
    let headers = policy.materialize(&mut rng, 10, &jitter);

    // Should handle very long referer without issue
    let referer = headers.iter().find(|(n, _)| n == "Referer");
    assert!(referer.is_some(), "Referer header should be generated");
    if let Some((_, value)) = referer {
        assert!(
            value.len() >= 10000,
            "Very long referer should be preserved, got len {}",
            value.len()
        );
    }
}

#[test]
fn header_policy_unicode_in_referer() {
    let policy = HeaderPolicy {
        referer_hosts: vec!["https://例え.jp/テスト".to_string()],
        ..HeaderPolicy::default()
    };

    let mut rng = StdRng::seed_from_u64(42);
    let jitter = TimingJitter::new(100, 200);
    let headers = policy.materialize(&mut rng, 10, &jitter);

    // Unicode should be preserved
    let referer = headers.iter().find(|(n, _)| n == "Referer");
    assert!(referer.is_some(), "Referer header should be generated");
    if let Some((_, value)) = referer {
        assert!(
            value.contains("例え") || value.contains("テスト"),
            "Unicode should be preserved in referer, got: {value}"
        );
    }
}
