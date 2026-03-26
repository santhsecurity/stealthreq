use serde::Deserialize;

/// Pre-processed response fields, lowercased and ready for matching.
pub(crate) struct ResponseContext<'a> {
    pub headers: &'a [(String, String)],
    pub body: &'a str,
    pub cookies: &'a [String],
    pub status: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Check {
    HeaderExists { value: String },
    HeaderAnyExists { values: Vec<String> },
    HeaderContains { name: String, value: String },
    BodyContains { value: String },
    BodyAny { values: Vec<String> },
    CookieExists { value: String },
    CookieAny { values: Vec<String> },
    CookiePrefix { value: String },
    CookieContains { value: String },
    AnyHeaderContains { value: String },
    StatusIn { values: Vec<u16> },
    AllOf { checks: Vec<Check> },
    AnyOf { checks: Vec<Check> },
}

impl Check {
    pub(crate) fn evaluate(&self, ctx: &ResponseContext<'_>) -> bool {
        match self {
            Self::HeaderExists { value } => ctx.headers.iter().any(|(name, _)| name == value),
            Self::HeaderAnyExists { values } => values
                .iter()
                .any(|v| ctx.headers.iter().any(|(name, _)| name == v)),
            Self::HeaderContains { name, value } => ctx
                .headers
                .iter()
                .any(|(h, v)| h == name && v.contains(value.as_str())),
            Self::BodyContains { value } => ctx.body.contains(value.as_str()),
            Self::BodyAny { values } => values.iter().any(|v| ctx.body.contains(v.as_str())),
            Self::CookieExists { value } => ctx.cookies.iter().any(|c| c == value),
            Self::CookieAny { values } => values.iter().any(|v| ctx.cookies.iter().any(|c| c == v)),
            Self::CookiePrefix { value } => {
                ctx.cookies.iter().any(|c| c.starts_with(value.as_str()))
            }
            Self::CookieContains { value } => {
                ctx.cookies.iter().any(|c| c.contains(value.as_str()))
            }
            Self::AnyHeaderContains { value } => ctx
                .headers
                .iter()
                .any(|(name, v)| name.contains(value.as_str()) || v.contains(value.as_str())),
            Self::StatusIn { values } => values.contains(&ctx.status),
            Self::AllOf { checks } => checks.iter().all(|c| c.evaluate(ctx)),
            Self::AnyOf { checks } => checks.iter().any(|c| c.evaluate(ctx)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(
        headers: &'a [(String, String)],
        body: &'a str,
        cookies: &'a [String],
        status: u16,
    ) -> ResponseContext<'a> {
        ResponseContext {
            headers,
            body,
            cookies,
            status,
        }
    }

    #[test]
    fn header_exists_matches_present_header() {
        let headers = vec![("cf-ray".into(), "abc123".into())];
        let check = Check::HeaderExists {
            value: "cf-ray".into(),
        };
        assert!(check.evaluate(&ctx(&headers, "", &[], 200)));
    }

    #[test]
    fn status_in_matches() {
        let check = Check::StatusIn {
            values: vec![403, 404],
        };
        assert!(check.evaluate(&ctx(&[], "", &[], 403)));
    }
}
