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
    /// имя исполняемого файла, если удалось определить
    pub app: String,
    /// полный путь — различает одноимённые программы
    pub app_path: String,
    pub pid: u32,
    pub seconds: u64,
    pub sent: u64,
    pub received: u64,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct DomainStat {
    pub domain: String,
    pub route: String,
    /// через какой прокси шло — иначе в таблице стоит безликое «через прокси»
    pub via: String,
    pub conns: u64,
    pub sent: u64,
    pub received: u64,
}

struct Live {
    host: String,
    port: u16,
    route: String,
    via: String,
    app: crate::proc::AppInfo,
    started: Instant,
    /// Счётчики обновляются по ходу перекачки, поэтому в таблице
    /// видно объём ещё до закрытия соединения.
    counters: std::sync::Arc<crate::pump::Counters>,
    /// Чем оборвать соединение, если правило для него поменялось.
    kill: std::sync::Arc<tokio::sync::Notify>,
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
pub fn open(host: &str, port: u16, route: &str, via: &str, app: &crate::proc::AppInfo)
    -> (u64, std::sync::Arc<crate::pump::Counters>, std::sync::Arc<tokio::sync::Notify>)
{
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let counters = std::sync::Arc::new(crate::pump::Counters::default());
    let kill = std::sync::Arc::new(tokio::sync::Notify::new());
    if let Some(s) = S.lock().unwrap().as_mut() {
        s.live.insert(id, Live {
            host: host.to_string(), port, route: route.to_string(),
            via: via.to_string(), app: app.clone(),
            started: Instant::now(), counters: counters.clone(), kill: kill.clone(),
        });
    }
    (id, counters, kill)
}

/// Оборвать соединения, для которых правила теперь дают другой путь.
/// Возвращает, сколько разорвано.
///
/// Без этого правка правил не действует на уже открытые соединения:
/// браузеры держат их подолгу, и человек видит «настройка не работает».
pub fn drop_changed(rules: &std::sync::RwLock<crate::rules::Rules>) -> usize {
    let g = S.lock().unwrap();
    let Some(s) = g.as_ref() else { return 0 };
    let r = rules.read().unwrap();
    let mut n = 0;
    for c in s.live.values() {
        let now = r.decide(&c.host);
        let same_route = now.tag() == c.route;
        let same_via = match &now {
            crate::rules::Route::Proxy(name) => name.is_empty() || *name == c.via,
            _ => true,
        };
        if !(same_route && same_via) {
            c.kill.notify_waiters();
            n += 1;
        }
    }
    n
}

/// Соединение закрылось: переносим объём в итоги по домену.
pub fn close(id: u64, sent: u64, received: u64) {
    let mut g = S.lock().unwrap();
    let Some(s) = g.as_mut() else { return };
    let Some(c) = s.live.remove(&id) else { return };
    let domain = crate::domain::registrable(&c.host);
    let e = s.totals.entry(domain.clone()).or_insert_with(|| DomainStat {
        domain, route: c.route.clone(), via: c.via.clone(), ..Default::default()
    });
    e.route = c.route.clone();
    e.via = c.via.clone();
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
            via: c.via.clone(), app: c.app.name.clone(),
            app_path: c.app.path.clone(), pid: c.app.pid,
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
        let app = crate::proc::AppInfo {
            name: "codex.exe".into(), path: r"C:\tools\codex.exe".into(), pid: 4242,
        };
        let (id, counters, _) = open("api.openai.com", 443, "proxy", "офис", &app);
        counters.sent.fetch_add(700, std::sync::atomic::Ordering::Relaxed);
        let live = active();
        assert_eq!(live[0].sent, 700, "объём должен быть виден до закрытия");
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].host, "api.openai.com");
        assert_eq!(live[0].via, "офис");
        assert_eq!(live[0].app, "codex.exe");
        assert_eq!(live[0].pid, 4242, "номер процесса различает одноимённые программы");
        assert!(live[0].app_path.ends_with("codex.exe"));

        close(id, 1024, 4096);
        assert!(active().is_empty(), "закрытое соединение не должно висеть");
        let t = totals();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].domain, "openai.com", "итоги считаются по домену");
        assert_eq!(t[0].via, "офис", "в итогах должно стоять имя прокси");
        assert_eq!(t[0].sent, 1024);
        assert_eq!(t[0].received, 4096);
    }

    #[test]
    fn generated_hostnames_add_up_to_one_domain() {
        // у ютуба каждое соединение с новым именем — в итогах должна быть одна строка
        let _g = fresh();
        for i in 0..3 {
            let (id, _, _) = open(&format!("rr{i}---sn-x.googlevideo.com"), 443, "proxy", "", &Default::default());
            close(id, 100, 1_000_000);
        }
        let t = totals();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].domain, "googlevideo.com");
        assert_eq!(t[0].conns, 3);
        assert_eq!(t[0].received, 3_000_000);
    }

    #[test]
    fn drops_only_connections_whose_route_changed() {
        use crate::rules::{Route, Rules};
        let _g = fresh();
        let (_, _, _) = open("stays.example", 443, "direct", "", &Default::default());
        let (_, _, _) = open("moves.example", 443, "direct", "", &Default::default());

        let mut r = Rules::new(Route::Direct);
        r.add("domain:moves.example", Route::proxy()).unwrap();
        let lock = std::sync::RwLock::new(r);

        assert_eq!(drop_changed(&lock), 1, "рвётся только то, у чего путь изменился");
    }

    #[test]
    fn totals_sorted_by_volume() {
        let _g = fresh();
        let (a, _, _) = open("small.example", 443, "direct", "", &Default::default()); close(a, 1, 1);
        let (b, _, _) = open("big.example", 443, "direct", "", &Default::default()); close(b, 1, 999_999);
        assert_eq!(totals()[0].domain, "big.example");
    }
}
