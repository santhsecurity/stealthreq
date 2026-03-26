use stealthreq::{MutableRequest, RequestModifier, StealthPolicy};

#[derive(Default)]
struct DemoRequest {
    headers: Vec<(String, String)>,
}

impl MutableRequest for DemoRequest {
    fn set_header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }
}

fn main() -> stealthreq::Result<()> {
    let mut request = DemoRequest::default();
    let applied = StealthPolicy::default()
        .with_seed(Some(7))
        .apply(&mut request)?;

    println!("user-agent={}", applied.user_agent);
    println!("headers={}", applied.applied_headers.len());
    println!("jitter_ms={}", applied.jitter.as_millis());
    println!("tls={}", applied.tls_profile.name);
    Ok(())
}
