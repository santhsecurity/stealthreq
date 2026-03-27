/// Minimum confidence score required to consider a signature match.
pub(crate) const MIN_CONFIDENCE_THRESHOLD: f64 = 0.35;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct WafFingerprint {
    pub name: String,
    pub confidence: f64,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum WafEncoding {
    UrlEncode,
    DoubleUrlEncode,
    HtmlEncode,
    UnicodeEncode,
    Base64Encode,
    HexEncode,
}
