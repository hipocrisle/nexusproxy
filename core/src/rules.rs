//! Правила маршрутизации: какой ресурс идёт через вышестоящий прокси,
//! а какой — напрямую. По умолчанию НАПРЯМУЮ: через прокси уходит только
//! то, что явно перечислено.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Route {
    Proxy,
    Direct,
    Block,
}

#[derive(Debug, Clone)]
enum Pattern {
    /// example.com и любой поддомен
    DomainSuffix(String),
    /// точное совпадение имени
    Exact(String),
    /// подстрока в имени
    Contains(String),
    /// подсеть
    Cidr { addr: IpAddr, prefix: u8 },
}

#[derive(Debug, Clone)]
pub struct Rules {
    patterns: Vec<(Pattern, Route)>,
    default: Route,
}

impl Rules {
    pub fn new(default: Route) -> Self {
        Self { patterns: Vec::new(), default }
    }

    /// Разбирает строку правила. Поддерживаются формы:
    ///   `example.com`         — домен и поддомены
    ///   `domain:example.com`  — то же явно
    ///   `full:host.example`   — точное имя
    ///   `keyword:openai`      — подстрока
    ///   `ip:10.0.0.0/8`       — подсеть
    pub fn add(&mut self, raw: &str, route: Route) -> Result<(), String> {
        let raw = raw.trim();
        // пустое, # и _ — это комментарии и заголовки разделов в списке
        if raw.is_empty() || raw.starts_with('#') || raw.starts_with('_') {
            return Ok(());
        }
        let pat = match raw.split_once(':') {
            Some(("domain", v)) => Pattern::DomainSuffix(v.trim().to_ascii_lowercase()),
            Some(("full", v)) => Pattern::Exact(v.trim().to_ascii_lowercase()),
            Some(("keyword", v)) => Pattern::Contains(v.trim().to_ascii_lowercase()),
            Some(("ip", v)) => Self::parse_cidr(v.trim())?,
            _ => {
                // без префикса: подсеть, если похоже на неё, иначе домен
                if raw.contains('/') && raw.chars().next().map_or(false, |c| c.is_ascii_digit() || c == ':') {
                    Self::parse_cidr(raw)?
                } else {
                    Pattern::DomainSuffix(raw.to_ascii_lowercase())
                }
            }
        };
        self.patterns.push((pat, route));
        Ok(())
    }

    fn parse_cidr(v: &str) -> Result<Pattern, String> {
        let (a, p) = match v.split_once('/') {
            Some((a, p)) => (a, p.parse::<u8>().map_err(|_| format!("плохая длина префикса: {v}"))?),
            None => (v, 0u8),
        };
        let addr: IpAddr = a.parse().map_err(|_| format!("плохой адрес: {v}"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = if v.contains('/') { p } else { max };
        if prefix > max {
            return Err(format!("длина префикса больше допустимой: {v}"));
        }
        Ok(Pattern::Cidr { addr, prefix })
    }

    /// Куда направить обращение к указанному узлу.
    /// `host` — имя или строковый адрес, как его прислал клиент.
    pub fn decide(&self, host: &str) -> Route {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        let ip = h.parse::<IpAddr>().ok();

        for (pat, route) in &self.patterns {
            let hit = match pat {
                Pattern::DomainSuffix(d) => h == *d || h.ends_with(&format!(".{d}")),
                Pattern::Exact(d) => h == *d,
                Pattern::Contains(d) => h.contains(d.as_str()),
                Pattern::Cidr { addr, prefix } => {
                    ip.as_ref().map_or(false, |i| cidr_match(i, addr, *prefix))
                }
            };
            if hit {
                return route.clone();
            }
        }
        self.default.clone()
    }
}

fn cidr_match(ip: &IpAddr, net: &IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => bits_match(&a.octets(), &b.octets(), prefix),
        (IpAddr::V6(a), IpAddr::V6(b)) => bits_match(&a.octets(), &b.octets(), prefix),
        _ => false,
    }
}

fn bits_match(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    let rest = prefix % 8;
    if a[..full] != b[..full] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - rest);
    a[full] & mask == b[full] & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Rules {
        let mut r = Rules::new(Route::Direct);
        r.add("domain:anthropic.com", Route::Proxy).unwrap();
        r.add("full:exact.example", Route::Proxy).unwrap();
        r.add("keyword:openai", Route::Proxy).unwrap();
        r.add("ip:10.0.0.0/8", Route::Proxy).unwrap();
        r
    }

    #[test]
    fn domain_and_subdomains() {
        let r = rules();
        assert_eq!(r.decide("anthropic.com"), Route::Proxy);
        assert_eq!(r.decide("api.anthropic.com"), Route::Proxy);
        assert_eq!(r.decide("API.Anthropic.COM."), Route::Proxy);
        // ключевая проверка: чужой домен, лишь оканчивающийся похоже
        assert_eq!(r.decide("notanthropic.com"), Route::Direct);
        assert_eq!(r.decide("example.com"), Route::Direct);
    }

    #[test]
    fn exact_only() {
        let r = rules();
        assert_eq!(r.decide("exact.example"), Route::Proxy);
        assert_eq!(r.decide("sub.exact.example"), Route::Direct);
    }

    #[test]
    fn keyword_anywhere() {
        let r = rules();
        assert_eq!(r.decide("api.openai.com"), Route::Proxy);
        assert_eq!(r.decide("myopenaiproxy.net"), Route::Proxy);
    }

    #[test]
    fn cidr() {
        let r = rules();
        assert_eq!(r.decide("10.1.2.3"), Route::Proxy);
        assert_eq!(r.decide("11.1.2.3"), Route::Direct);
    }

    #[test]
    fn comments_and_headers_ignored() {
        let mut r = Rules::new(Route::Direct);
        r.add("_ChatGPT и Codex", Route::Proxy).unwrap();
        r.add("# просто заметка", Route::Proxy).unwrap();
        r.add("", Route::Proxy).unwrap();
        r.add("domain:openai.com", Route::Proxy).unwrap();
        assert_eq!(r.decide("api.openai.com"), Route::Proxy);
        assert_eq!(r.decide("_ChatGPT и Codex"), Route::Direct);
    }

    #[test]
    fn default_is_direct() {
        let r = rules();
        assert_eq!(r.decide("anything.else"), Route::Direct);
    }

    #[test]
    fn partial_byte_prefix() {
        let mut r = Rules::new(Route::Direct);
        r.add("ip:192.168.4.0/22", Route::Proxy).unwrap();
        assert_eq!(r.decide("192.168.5.9"), Route::Proxy);
        assert_eq!(r.decide("192.168.8.1"), Route::Direct);
    }
}
