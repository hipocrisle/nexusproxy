//! Проверка живой статистики на настоящем движке: поднимаем sing-box,
//! открываем через него соединение и смотрим, что видит программа.
use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::args().nth(1).expect("папка"));
    nexusproxy_core::journal::enable();
    let api = nexusproxy_core::tunnel::api_access(&dir);
    println!("порт {} пароль {}…", api.port, &api.secret[..8]);

    let cfg = serde_json::json!({
        "log": {"level": "warn"},
        "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": 41081}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"rules": [], "final": "direct"},
        "experimental": {"clash_api": {
            "external_controller": format!("127.0.0.1:{}", api.port),
            "secret": api.secret
        }}
    });
    std::fs::write(dir.join("probe.json"), serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();

    let mut child = std::process::Command::new(std::env::args().nth(2).expect("движок"))
        .arg("run").arg("-c").arg(dir.join("probe.json"))
        .spawn().expect("движок не запустился");
    std::thread::sleep(std::time::Duration::from_secs(2));

    // качаем через движок — проверяем, что байты считаются
    let load = std::thread::spawn(|| {
        let _ = std::process::Command::new("curl")
            .args(["-s", "--limit-rate", "300k", "-x", "socks5h://127.0.0.1:41081",
                   "-m", "12", "-o", "/dev/null",
                   "https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-linux-amd64.tar.gz"])
            .status();
    });

    // держим соединение открытым
    let holder = std::thread::spawn(|| {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect("127.0.0.1:41081").unwrap();
        s.write_all(&[5, 1, 0]).unwrap();
        let mut b = [0u8; 2];
        s.read_exact(&mut b).unwrap();
        let host = b"example.com";
        let mut req = vec![5, 1, 0, 3, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&80u16.to_be_bytes());
        s.write_all(&req).unwrap();
        let mut r = [0u8; 10];
        let _ = s.read(&mut r);
        // настоящие данные, чтобы счётчикам было что показать
        s.write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n").unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        for _ in 0..4 {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
            std::thread::sleep(std::time::Duration::from_millis(600));
        }
        println!("получено байт напрямую: {}", got.len());
        std::thread::sleep(std::time::Duration::from_secs(5));
    });

    // ⛔ Три снимка подряд: если прирост считается неверно, трафик в
    // итогах вырастет кратно числу опросов.
    std::thread::sleep(std::time::Duration::from_secs(3));
    for n in 1..=3 {
        match nexusproxy_core::engine_stats::refresh(&dir) {
            Ok(()) => {
                let t = nexusproxy_core::engine_stats::totals();
                let sum: u64 = t.iter().map(|d| d.sent + d.received).sum();
                let conns: u64 = t.iter().map(|d| d.conns).sum();
                println!("снимок {n}: всего {sum} байт, соединений {conns}");
            }
            Err(e) => println!("снимок {n}: ОШИБКА {e}"),
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    match nexusproxy_core::engine_stats::refresh(&dir) {
        Ok(()) => {
            let a = nexusproxy_core::engine_stats::active();
            println!("открыто сейчас: {}", a.len());
            for c in &a {
                println!("  {}:{} через {} ({}) программа «{}» путь «{}» {}с отдано {} получено {}",
                    c.host, c.port, if c.via.is_empty() { &c.route } else { &c.via },
                    c.route, c.app, c.app_path, c.seconds, c.sent, c.received);
            }
            let t = nexusproxy_core::engine_stats::totals();
            println!("доменов в итогах: {}", t.len());
            for d in &t {
                println!("  {} через {} соединений {} отдано {} получено {}",
                    d.domain, if d.via.is_empty() { &d.route } else { &d.via },
                    d.conns, d.sent, d.received);
            }
        }
        Err(e) => println!("ОШИБКА: {e}"),
    }
    let j = nexusproxy_core::journal::since(0);
    println!("записей в журнале: {}", j.len());
    for e in j.iter().take(5) {
        println!("  {} {}:{} {} {}", e.at, e.host, e.port, e.route, e.via);
    }

    let _ = holder.join();
    let _ = load.join();
    let _ = child.kill();
}
