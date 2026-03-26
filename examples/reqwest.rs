use stealthreq::{MutableRequest, RequestModifier, StealthPolicy};

struct ReqwestAdapter {
    builder: Option<reqwest::RequestBuilder>,
}

impl MutableRequest for ReqwestAdapter {
    fn set_header(&mut self, name: &str, value: &str) {
        let current = self
            .builder
            .take()
            .expect("request builder should be available");
        self.builder = Some(current.header(name, value));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let mut adapter = ReqwestAdapter {
        builder: Some(client.get("https://example.com")),
    };

    let policy = StealthPolicy::default().with_seed(Some(42));
    let _ = policy.apply(&mut adapter)?;

    let request = adapter
        .builder
        .take()
        .expect("builder is prepared")
        .build()?;
    println!(
        "prepared request method={} uri={}",
        request.method(),
        request.url()
    );
    let _ = request;
    Ok(())
}
