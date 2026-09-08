//! Системные настройки прокси в macOS.
//!
//! В отличие от Windows настройки здесь общие для системы и задаются
//! на КАЖДУЮ сетевую службу отдельно — Wi-Fi, Ethernet и так далее.
//! Поэтому проходим по всем и запоминаем прежнее состояние каждой,
//! чтобы вернуть как было.

/// Что было до нас — по одной записи на сетевую службу.
#[derive(Debug, Default, Clone)]
pub struct Saved {
    pub services: Vec<ServiceState>,
}

#[derive(Debug, Clone)]
pub struct ServiceState {
    pub name: String,
    pub web_on: bool,
    pub web: String,
    pub secure_on: bool,
    pub secure: String,
    pub socks_on: bool,
    pub socks: String,
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{Saved, ServiceState};
    use std::io;
    use std::process::Command;

    fn networksetup(args: &[&str]) -> io::Result<String> {
        let out = Command::new("/usr/sbin/networksetup").args(args).output()?;
        if !out.status.success() {
            return Err(io::Error::other(format!(
                "networksetup {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    /// Сетевые службы, кроме отключённых (у тех имя начинается со звёздочки).
    fn services() -> Vec<String> {
        networksetup(&["-listallnetworkservices"])
            .unwrap_or_default()
            .lines()
            .skip(1)
            .filter(|l| !l.trim().is_empty() && !l.starts_with('*'))
            .map(|l| l.trim().to_string())
            .collect()
    }

    /// Разбирает вывод вида «Enabled: Yes / Server: x / Port: 8080».
    fn read_proxy(service: &str, kind: &str) -> (bool, String) {
        let out = networksetup(&[kind, service]).unwrap_or_default();
        let mut on = false;
        let (mut host, mut port) = (String::new(), String::new());
        for line in out.lines() {
            let (k, v) = match line.split_once(':') {
                Some((k, v)) => (k.trim(), v.trim()),
                None => continue,
            };
            match k {
                "Enabled" => on = v.eq_ignore_ascii_case("yes"),
                "Server" => host = v.to_string(),
                "Port" => port = v.to_string(),
                _ => {}
            }
        }
        (on, if host.is_empty() { String::new() } else { format!("{host}:{port}") })
    }

    fn split(addr: &str) -> (String, String) {
        match addr.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.to_string()),
            None => (addr.to_string(), "0".into()),
        }
    }

    pub fn apply(proxy: &str, _no_proxy: &str) -> io::Result<Saved> {
        let (host, port) = split(proxy);
        let mut saved = Saved::default();
        let list = services();
        if list.is_empty() {
            return Err(io::Error::other("не найдено ни одной сетевой службы"));
        }
        for s in list {
            let (web_on, web) = read_proxy(&s, "-getwebproxy");
            let (secure_on, secure) = read_proxy(&s, "-getsecurewebproxy");
            let (socks_on, socks) = read_proxy(&s, "-getsocksfirewallproxy");
            saved.services.push(ServiceState {
                name: s.clone(), web_on, web, secure_on, secure, socks_on, socks,
            });
            // и обычный, и защищённый: без второго не пойдёт https
            networksetup(&["-setwebproxy", &s, &host, &port])?;
            networksetup(&["-setsecurewebproxy", &s, &host, &port])?;
            networksetup(&["-setwebproxystate", &s, "on"])?;
            networksetup(&["-setsecurewebproxystate", &s, "on"])?;
        }
        Ok(saved)
    }

    pub fn restore(s: &Saved) {
        for svc in &s.services {
            let n = &svc.name;
            if svc.web_on && !svc.web.is_empty() {
                let (h, p) = split(&svc.web);
                let _ = networksetup(&["-setwebproxy", n, &h, &p]);
                let _ = networksetup(&["-setwebproxystate", n, "on"]);
            } else {
                let _ = networksetup(&["-setwebproxystate", n, "off"]);
            }
            if svc.secure_on && !svc.secure.is_empty() {
                let (h, p) = split(&svc.secure);
                let _ = networksetup(&["-setsecurewebproxy", n, &h, &p]);
                let _ = networksetup(&["-setsecurewebproxystate", n, "on"]);
            } else {
                let _ = networksetup(&["-setsecurewebproxystate", n, "off"]);
            }
        }
    }

    pub fn current() -> String {
        for s in services() {
            let (on, addr) = read_proxy(&s, "-getsecurewebproxy");
            if on {
                return format!("включён, {addr} ({s})");
            }
        }
        "выключен".into()
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use super::Saved;
    use std::io;
    pub fn apply(_proxy: &str, _no_proxy: &str) -> io::Result<Saved> {
        Err(io::Error::other("доступно только в macOS"))
    }
    pub fn restore(_s: &Saved) {}
    pub fn current() -> String {
        "не поддерживается на этой системе".into()
    }
}

pub use imp::{apply, current, restore};
