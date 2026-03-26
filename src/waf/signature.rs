use std::sync::OnceLock;

use serde::Deserialize;

use crate::waf::check::Check;
use crate::waf::fingerprint::WafEncoding;

pub(crate) fn signatures() -> &'static [WafSignature] {
    static SIGNATURES: OnceLock<Vec<WafSignature>> = OnceLock::new();
    SIGNATURES.get_or_init(|| {
        // Parse embedded TOML at runtime; failures return empty vec rather than panicking
        toml::from_str::<SignatureFile>(SIGNATURES_TOML)
            .map(|file| file.signatures)
            .unwrap_or_default()
    })
}

const SIGNATURES_TOML: &str = include_str!("../../data/waf_signatures.toml");

#[derive(Debug, Deserialize)]
struct SignatureFile {
    signatures: Vec<WafSignature>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct WafSignature {
    pub name: String,
    pub evasion: Vec<String>,
    pub indicators: Vec<Indicator>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Indicator {
    pub check: Check,
    pub weight: f64,
    pub description: String,
}

pub(crate) fn parse_encoding(name: &str) -> Option<WafEncoding> {
    match name {
        "UrlEncode" => Some(WafEncoding::UrlEncode),
        "DoubleUrlEncode" => Some(WafEncoding::DoubleUrlEncode),
        "HtmlEncode" => Some(WafEncoding::HtmlEncode),
        "UnicodeEncode" => Some(WafEncoding::UnicodeEncode),
        "Base64Encode" => Some(WafEncoding::Base64Encode),
        "HexEncode" => Some(WafEncoding::HexEncode),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_toml_parses() {
        let sigs = signatures();
        assert!(sigs.len() >= 12);
    }

    #[test]
    fn indicators_have_weights() {
        for sig in signatures() {
            assert!(!sig.indicators.is_empty());
            for ind in &sig.indicators {
                assert!(ind.weight > 0.0 && ind.weight <= 1.0);
            }
        }
    }

    #[test]
    fn all_encodings_known() {
        for sig in signatures() {
            for e in &sig.evasion {
                assert!(parse_encoding(e).is_some());
            }
        }
    }
}
