/// Minimum confidence score required to consider a signature match.
pub(crate) const MIN_CONFIDENCE_THRESHOLD: f64 = 0.35;

#[derive(Debug, Clone, PartialEq)]
pub struct WafFingerprint {
    pub name: String,
    pub confidence: f64,
    pub indicators: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WafEncoding {
    UrlEncode,
    DoubleUrlEncode,
    HtmlEncode,
    UnicodeEncode,
    Base64Encode,
    HexEncode,
}
