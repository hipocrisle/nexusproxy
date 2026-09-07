//! Учёт соединений: что открыто прямо сейчас и сколько куда утекло.
//!
//! Колонки те же, что в Proxifier: цель, время, каким правилом и через
//! какой прокси, отправлено, получено. Плюс приложение — именно ради этой
//! колонки Proxifier и держат, и её можно получить, сопоставив порт
//! соединения с процессом.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

#[derive(Clone, Debug, serde::Serialize)]
pub struct Conn {
    pub id: u64,
    pub host: String,
    pub port: u16,
    /// «proxy» | «direct» | «block»
    pub route: String,
    /// через какой прокси, если через прокси
    pub via: String,
    /// имя приложения, если удалось определить
    pub app: String,
    pub seconds: u64,
    pub sent: u64,
    pub received: u64,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct DomainStat {
    pub domain: String,
    pub route: String,
    pub conns: u64,
    pub sent: u64,
    pub received: u64,
}

struct Live {
    host: String,
    port: u16,
    route: String,
    via: String,
    app: String,
    started: Instant,
    /// Счётчики обновляются по ходу перекачки, поэтому в таблице
    /// видно объём ещё до закрытия соединения.
    counters: std::sync::Arc<crate::pump::Counters>,
}

#[derive(Default)]
struct State {
    live: BTreeMap<u64, Live>,
    totals: BTreeMap<String, DomainStat>,
}

static S: Mutex<Option<State>> = Mutex::new(None);
static NEXT: AtomicU64 = AtomicU64::new(1);

pub fn enable() {
    *S.lock().unwrap() = Some(State::default());
}

/// Соединение открылось. Возвращает номер и счётчики, которые
/// заполняются по ходу передачи.
pub fn open(host: &str, port: u16, route: &str, via: &str, app: &str)
    -> (u64, std::sync::Arc<crate::pump::Counters>)
{
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let counters = std::sync::Arc::new(crate::pump::Counters::default());
    if let Some(s) = S.lock().unwrap().as_mut() {
        s.live.insert(id, Live {
            host: host.to_string(), port, route: route.to_string(),
            via: via.to_string(), app: app.to_string(),
            started: Instant::now(), counters: counters.clone(),
        });
    }
    (id, counters)
}

/// Соединение закрылось: переносим объём в итоги по домену.
pub fn close(id: u64, sent: u64, received: u64) {
    let mut g = S.lock().unwrap();
    let Some(s) = g.as_mut() else { return };
    let Some(c) = s.live.remove(&id) else { return };
    let domain = crate::domain::registrable(&c.host);
    let e = s.totals.entry(domain.clone()).or_insert_with(|| DomainStat {
        domain, route: c.route.clone(), ..Default::default()
    });
    e.conns += 1;
    e.sent += sent;
    e.received += received;
}

pub fn active() -> Vec<Conn> {
    let g = S.lock().unwrap();
    let Some(s) = g.as_ref() else { return Vec::new() };
    let mut v: Vec<Conn> = s.live.iter().map(|(id, c)| {
        let (sent, received) = c.counters.get();
        Conn {
            id: *id, host: c.host.clone(), port: c.port, route: c.route.clone(),
            via: c.via.clone(), app: c.app.clone(),
            seconds: c.started.elapsed().as_secs(), sent, received,
        }
    }).collect();
    v.sort_by(|a, b| b.id.cmp(&a.id));
    v
}

/// Итоги по доменам, самые объёмные сверху.
pub fn totals() -> Vec<DomainStat> {
    let g = S.lock().unwrap();
    let Some(s) = g.as_ref() else { return Vec::new() };
    let mut v: Vec<DomainStat> = s.totals.values().cloned().collect();
    v.sort_by(|a, b| (b.sent + b.received).cmp(&(a.sent + a.received)));
    v
}

pub fn reset_totals() {
    if let Some(s) = S.lock().unwrap().as_mut() {
        s.totals.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> std::sync::MutexGuard<'static, ()> {
        let g = crate::logfile::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        enable();
        g
    }

    #[test]
    fn open_shows_up_and_close_moves_to_totals() {
        let _g = fresh();
        let (id, counters) = open("api.openai.com", 443, "proxy", "офис", "codex.exe");
        counters.sent.fetch_add(700, std::sync::atomic::Ordering::Relaxed);
        let live = active();
        assert_eq!(live[0].sent, 700, "объём должен быть виден до закрытия");
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].host, "api.openai.com");
        assert_eq!(live[0].via, "офис");
        assert_eq!(live[0].app, "codex.exe");

        close(id, 1024, 4096);
        assert!(active().is_empty(), "закрытое соединение не должно висеть");
        let t = totals();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].domain, "openai.com", "итоги считаются по домену");
        assert_eq!(t[0].sent, 1024);
        assert_eq!(t[0].received, 4096);
    }

    #[test]
    fn generated_hostnames_add_up_to_one_domain() {
        // у ютуба каждое соединение с новым именем — в итогах должна быть одна строка
        let _g = fresh();
        for i in 0..3 {
            let (id, _) = open(&format!("rr{i}---sn-x.googlevideo.com"), 443, "proxy", "", "");
            close(id, 100, 1_000_000);
        }
        let t = totals();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].domain, "googlevideo.com");
        assert_eq!(t[0].conns, 3);
        assert_eq!(t[0].received, 3_000_000);
    }

    #[test]
    fn totals_sorted_by_volume() {
        let _g = fresh();
        let (a, _) = open("small.example", 443, "direct", "", ""); close(a, 1, 1);
        let (b, _) = open("big.example", 443, "direct", "", ""); close(b, 1, 999_999);
        assert_eq!(totals()[0].domain, "big.example");
    }
}
