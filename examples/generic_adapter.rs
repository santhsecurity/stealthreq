use stealthreq::{MutableRequest, RequestModifier, StealthPolicy};

struct RequestBag {
    pub headers: Vec<(String, String)>,
}

impl MutableRequest for RequestBag {
    fn set_header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_string(), value.to_string()));
    }
}

fn main() {
    let mut req = RequestBag {
        headers: Vec::new(),
    };
    let policy = StealthPolicy::default();

    let applied = policy.apply(&mut req).expect("apply policy");
    println!("ua={}", applied.user_agent);
    println!("jitter={:?}", applied.jitter);
    println!("tls={}", applied.tls_profile.name);
    println!("headers={:?}", req.headers);
}
