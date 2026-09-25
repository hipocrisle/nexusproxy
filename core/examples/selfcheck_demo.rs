//! Показывает, как выглядит проверка при запуске — чтобы видеть отчёт
//! глазами до того, как его увидит человек.
fn main() {
    let dir = std::env::temp_dir().join("np-selfcheck-demo");
    let _ = std::fs::create_dir_all(&dir);
    let log = dir.join("nexusproxy.log");
    let _ = std::fs::remove_file(&log);
    nexusproxy_core::logfile::open(log.clone()).unwrap();

    let mut cfg: nexusproxy_core::config::Config = serde_json::from_str("{}").unwrap();
    cfg.upstreams.push(nexusproxy_core::upstream::Upstream {
        name: "основной".into(),
        kind: nexusproxy_core::upstream::Kind::Socks5,
        address: "172.31.211.1".into(), port: 1081,
        user: Some("i.korobkov".into()), password: Some("тайна".into()),
        from_subscription: false,
    });
    cfg.default_upstream = "основной".into();
    cfg.through_proxy = vec!["example.com".into(), "openai.com".into()];
    cfg.tunnel_mode = true;

    nexusproxy_core::selfcheck::run(&cfg, &dir.join("config.json").display().to_string(), "1.1.1");
    print!("{}", std::fs::read_to_string(&log).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}
