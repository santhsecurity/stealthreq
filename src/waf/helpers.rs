pub(crate) fn extract_cookies(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(name, _)| name == "set-cookie" || name == "cookie")
        .flat_map(|(_, value)| {
            value.split(';').filter_map(|part| {
                let trimmed = part.trim();
                trimmed
                    .split_once('=')
                    .map(|(name, _)| name.trim().to_ascii_lowercase())
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_cookie_names() {
        let headers = vec![
            ("set-cookie".to_string(), "__cfduid=abc; path=/".to_string()),
            ("cookie".to_string(), "session=1; lang=en".to_string()),
        ];
        let cookies = extract_cookies(&headers);
        assert!(cookies.contains(&"__cfduid".to_string()));
        assert!(cookies.contains(&"session".to_string()));
    }
}
