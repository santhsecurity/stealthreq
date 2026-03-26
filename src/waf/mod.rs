//! WAF detection and evasion lookup.
//!
//! The logic is extracted from the existing project detector and generalized
//! into a reusable crate.

mod check;
mod fingerprint;
mod helpers;
mod signature;

use check::ResponseContext;
use fingerprint::MIN_CONFIDENCE_THRESHOLD;
pub use fingerprint::{WafEncoding, WafFingerprint};
use signature::{parse_encoding, signatures};

/// HTTP-like response snapshot used for WAF detection.
#[derive(Debug, Clone)]
pub struct HttpResponseSnapshot {
    /// Numeric status code.
    pub status: u16,
    /// Header tuples, any casing accepted.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

impl HttpResponseSnapshot {
    pub fn body_str(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    pub fn body_str_lower(&self) -> String {
        self.body_str().to_ascii_lowercase()
    }
}

/// Infer the most likely WAF from a response snapshot.
pub fn detect_waf(response: &HttpResponseSnapshot) -> Option<WafFingerprint> {
    let headers: Vec<(String, String)> = response
        .headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.to_ascii_lowercase()))
        .collect();
    let body = response.body_str_lower();
    let cookies = helpers::extract_cookies(&headers);

    let ctx = ResponseContext {
        headers: &headers,
        body: &body,
        cookies: &cookies,
        status: response.status,
    };

    let mut best_match: Option<WafFingerprint> = None;

    for sig in signatures() {
        let mut score = 0.0_f64;
        let mut indicators = Vec::new();

        for indicator in &sig.indicators {
            if indicator.check.evaluate(&ctx) {
                score += indicator.weight;
                indicators.push(indicator.description.clone());
            }
        }

        if score > 0.0
            && score
                > best_match
                    .as_ref()
                    .map_or(0.0, |current| current.confidence)
        {
            best_match = Some(WafFingerprint {
                name: sig.name.clone(),
                confidence: score.min(1.0),
                indicators,
            });
        }
    }

    best_match.filter(|fp| fp.confidence >= MIN_CONFIDENCE_THRESHOLD)
}

/// Suggest evasive encodings for a detected WAF.
pub fn suggest_evasion(waf: &WafFingerprint) -> Vec<WafEncoding> {
    signatures()
        .iter()
        .find(|sig| sig.name == waf.name)
        .map_or_else(
            || vec![WafEncoding::UrlEncode],
            |sig| {
                if sig.evasion.is_empty() {
                    vec![WafEncoding::UrlEncode]
                } else {
                    sig.evasion
                        .iter()
                        .filter_map(|s| parse_encoding(s))
                        .collect()
                }
            },
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16, headers: Vec<(&str, &str)>, body: &str) -> HttpResponseSnapshot {
        HttpResponseSnapshot {
            status,
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn detects_cloudflare() {
        let waf = detect_waf(&response(
            403,
            vec![
                ("CF-Ray", "1234"),
                ("Set-Cookie", "__cfduid=abc; path=/"),
                ("Server", "cloudflare"),
            ],
            "Attention Required! Cloudflare Ray ID: 1234",
        ))
        .unwrap();
        assert_eq!(waf.name, "Cloudflare");
        assert_eq!(waf.confidence, 1.0);
    }

    #[test]
    fn detects_aws_waf() {
        let waf = detect_waf(&response(
            403,
            vec![
                ("x-amzn-requestid", "req-1"),
                ("x-amzn-errortype", "WAFBlocked"),
            ],
            "Request blocked by AWS WAF security rules.",
        ))
        .unwrap();
        assert_eq!(waf.name, "AWS WAF");
        assert_eq!(waf.confidence, 1.0);
    }

    #[test]
    fn detects_akamai() {
        let waf = detect_waf(&response(
            403,
            vec![
                ("Server", "AkamaiGHost"),
                ("X-Akamai-Transformed", "9 12345 0 pmb=mRUM,1"),
            ],
            "Access Denied. Reference #18.3f5d3e17.1710000000.1234567 Reference ID: 18.3f5d3e17",
        ))
        .unwrap();
        assert_eq!(waf.name, "Akamai");
        assert_eq!(waf.confidence, 1.0);
    }

    #[test]
    fn partial_indicators_do_not_cross_detection_threshold() {
        let result = detect_waf(&response(
            403,
            vec![("Server", "cloudflare")],
            "generic forbidden page",
        ));
        assert!(result.is_none());
    }

    #[test]
    fn returns_none_for_unrecognized() {
        let result = detect_waf(&response(
            200,
            vec![("Content-Type", "text/html")],
            "<html><body>Hello</body></html>",
        ));
        assert!(result.is_none());
    }

    #[test]
    fn suggest_evasion_returns_default_for_unknown() {
        let fp = WafFingerprint {
            name: "Unknown".to_string(),
            confidence: 0.6,
            indicators: vec![],
        };
        assert_eq!(suggest_evasion(&fp), vec![WafEncoding::UrlEncode]);
    }
}
