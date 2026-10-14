//! Печатает конфиг движка — чтобы проверять его настоящим sing-box:
//!
//!     cargo run -q --example dump_config > /tmp/c.json
//!     sing-box check -c /tmp/c.json
//!
//! Нужен затем, что наши тесты проверяют СМЫСЛ конфига, а примет ли его
//! движок — знает только движок.
use nexusproxy_core::tunnel::{build_config, Kind, Upstream};

fn main() {
    let proxy = Upstream {
        tag: "корпоративный".into(),
        kind: Kind::Http,
        address: "172.31.211.1".into(),
        port: 8080,
        user: None,
        password: None,
        from_subscription: false,
    };
    let c = build_config(&[], &[proxy]);
    println!("{}", serde_json::to_string_pretty(&c).unwrap());
}
