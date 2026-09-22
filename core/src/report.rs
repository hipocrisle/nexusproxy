//! Подбор доменов для конкретного сервиса.
//!
//! Проблема прошлого подхода: в отчёт валилось всё подряд — внутренний
//! мониторинг, реклама, телеметрия. Найти среди этого домены нужного
//! сервиса невозможно.
//!
//! Здесь иначе. Пользователь начинает подбор, открывает нужный сервис,
//! заканчивает. В список попадает только то, чего НЕ БЫЛО до начала
//! подбора: постоянный фон отсекается сам, потому что он уже был виден.

use crate::rules::Route;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Насколько близко по времени, чтобы счесть обращение частью того же действия.
const RELATED_WINDOW: Duration = Duration::from_secs(15);

/// Кандидат — это ДОМЕН, а не отдельное имя узла.
///
/// У ютуба видео раздаётся с имён вида `rr3---sn-4g5edndz.googlevideo.com`,
/// которые генерируются на каждый сеанс. Предлагать их поштучно бесполезно:
/// добавишь — в следующий раз придут другие, и сайт всё равно откроется
/// наполовину. Поэтому предлагаем `googlevideo.com`, а конкретные имена
/// показываем рядом, чтобы было видно, откуда взялось.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Candidate {
    /// что предлагаем добавить
    pub domain: String,
    /// сколько всего обращений по всем именам этого домена
    pub count: u32,
    /// сколько разных имён узлов встретилось
    pub hosts_count: usize,
    /// несколько примеров имён — для наглядности
    pub examples: Vec<String>,
    /// Через какой уже настроенный ресурс он, судя по времени, вызван.
    pub triggered_by: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SessionResult {
    pub seconds: u64,
    /// Новые адреса, ушедшие НАПРЯМУЮ — кандидаты на добавление.
    pub candidates: Vec<Candidate>,
    /// Новые адреса, уже уходившие через прокси — для сверки.
    pub already_proxied: Vec<Candidate>,
}

struct Live {
    /// что видели вообще когда-либо — служит фоном
    ever: BTreeSet<String>,
    session: Option<Session>,
    last_proxy: Option<(String, Instant)>,
}

struct Session {
    started: Instant,
    seen: BTreeMap<String, (u32, Route, Option<String>)>,
}

static STATE: Mutex<Option<Live>> = Mutex::new(None);

pub fn enable() {
    *STATE.lock().unwrap() = Some(Live {
        ever: BTreeSet::new(),
        session: None,
        last_proxy: None,
    });
}

/// Начать подбор. Всё, что уже встречалось, становится фоном и в итог не попадёт.
pub fn start_session() {
    if let Some(l) = STATE.lock().unwrap().as_mut() {
        l.session = Some(Session {
            started: Instant::now(),
            seen: BTreeMap::new(),
        });
    }
}

pub fn session_active() -> bool {
    STATE.lock().unwrap().as_ref().map_or(false, |l| l.session.is_some())
}

pub fn note(host: &str, route: &Route) {
    let mut g = STATE.lock().unwrap();
    let Some(l) = g.as_mut() else { return };
    let now = Instant::now();

    let trigger = match &l.last_proxy {
        Some((h, t)) if now.duration_since(*t) <= RELATED_WINDOW => Some(h.clone()),
        _ => None,
    };
    if *route == Route::proxy() {
        l.last_proxy = Some((host.to_string(), now));
    }
    l.ever.insert(host.to_string());

    if let Some(s) = l.session.as_mut() {
        let e = s.seen.entry(host.to_string()).or_insert((0, route.clone(), trigger));
        e.0 += 1;
        e.1 = route.clone();
    }
}

/// Кандидаты прямо сейчас, не прерывая подбор — для показа в реальном времени.
pub fn live_candidates() -> Vec<Candidate> {
    let g = STATE.lock().unwrap();
    let Some(l) = g.as_ref() else { return Vec::new() };
    let Some(s) = l.session.as_ref() else { return Vec::new() };
    group(s.seen.iter().filter(|(_, (_, r, _))| *r != Route::proxy()))
}

/// Свести имена узлов к доменам.
fn group<'a, I>(items: I) -> Vec<Candidate>
where
    I: Iterator<Item = (&'a String, &'a (u32, Route, Option<String>))>,
{
    let mut acc: BTreeMap<String, (u32, BTreeSet<String>, Option<String>)> = BTreeMap::new();
    for (host, (count, _, trigger)) in items {
        let dom = crate::domain::registrable(host);
        let e = acc.entry(dom).or_insert((0, BTreeSet::new(), None));
        e.0 += count;
        e.1.insert(host.clone());
        if e.2.is_none() {
            e.2 = trigger.clone();
        }
    }
    let mut v: Vec<Candidate> = acc
        .into_iter()
        .map(|(domain, (count, hosts, trigger))| Candidate {
            domain,
            count,
            hosts_count: hosts.len(),
            examples: hosts.into_iter().take(3).collect(),
            triggered_by: trigger,
        })
        .collect();
    // сначала те, у кого понятна причина, потом по числу обращений
    v.sort_by(|a, b| {
        b.triggered_by.is_some().cmp(&a.triggered_by.is_some())
            .then(b.count.cmp(&a.count))
            .then(a.domain.cmp(&b.domain))
    });
    v
}

/// Закончить подбор и получить только то, что относится к делу.
pub fn finish_session() -> Option<SessionResult> {
    let mut g = STATE.lock().unwrap();
    let l = g.as_mut()?;
    let s = l.session.take()?;
    let fresh: BTreeMap<String, (u32, Route, Option<String>)> = s.seen.into_iter().collect();
    let candidates = group(fresh.iter().filter(|(_, (_, r, _))| *r != Route::proxy()));
    let already = group(fresh.iter().filter(|(_, (_, r, _))| *r == Route::proxy()));
    Some(SessionResult {
        seconds: s.started.elapsed().as_secs(),
        candidates,
        already_proxied: already,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Состояние подбора — общее на всю программу, поэтому тесты идут по одному.
    fn reset() -> std::sync::MutexGuard<'static, ()> {
        let g = crate::logfile::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        enable();
        g
    }

    /// ⛔ Раньше в подбор попадали только имена, не встречавшиеся ДО его
    /// включения. Браузер ходит по одним и тем же адресам, поэтому список
    /// был пуст всегда. Теперь показываем всё, что ушло мимо прокси — в
    /// том числе то, что видели и раньше.
    #[test]
    fn показываем_всё_что_ушло_мимо_прокси() {
        let _guard = reset();
        note("seen.example", &Route::Direct); // видели до начала подбора

        start_session();
        note("seen.example", &Route::Direct);
        note("chatgpt.com", &Route::proxy());
        note("oaistatic.com", &Route::Direct);

        let r = finish_session().unwrap();
        let mut hosts: Vec<_> = r.candidates.iter().map(|c| c.domain.clone()).collect();
        hosts.sort();
        assert_eq!(hosts, vec!["oaistatic.com", "seen.example"],
                   "виденное раньше тоже должно предлагаться");
        assert_eq!(r.already_proxied.len(), 1, "ушедшее через прокси — отдельно");
    }

    #[test]
    fn список_наполняется_по_ходу() {
        let _guard = reset();
        start_session();
        note("chatgpt.com", &Route::proxy());
        note("oaistatic.com", &Route::Direct);
        let live = live_candidates();
        assert_eq!(live.len(), 1, "ушедшее через прокси в подбор не идёт");
        assert_eq!(live[0].domain, "oaistatic.com");
        assert_eq!(live[0].triggered_by.as_deref(), Some("chatgpt.com"));
        assert!(session_active(), "подбор не должен прерываться");
    }

    #[test]
    fn generated_hostnames_collapse_into_one_domain() {
        // ровно случай ютуба: имена разные, домен один
        let _guard = reset();
        start_session();
        note("youtube.com", &Route::proxy());
        note("rr3---sn-4g5edndz.googlevideo.com", &Route::Direct);
        note("rr1---sn-4g5ednsy.googlevideo.com", &Route::Direct);
        note("rr5---sn-4g5e6nzz.googlevideo.com", &Route::Direct);
        let live = live_candidates();
        assert_eq!(live.len(), 1, "три имени одного домена — одна строка");
        assert_eq!(live[0].domain, "googlevideo.com");
        assert_eq!(live[0].hosts_count, 3);
        assert_eq!(live[0].count, 3);
        assert_eq!(live[0].triggered_by.as_deref(), Some("youtube.com"));
    }

    /// Пустой список означает ровно одно: за время наблюдения мимо
    /// прокси не ушло ничего. Если человек видит пустоту — значит
    /// добавлять нечего, а не «подбор сломался».
    #[test]
    fn без_обращений_мимо_прокси_список_пуст() {
        let _guard = reset();
        start_session();
        note("a.example", &Route::proxy());
        let r = finish_session().unwrap();
        assert!(r.candidates.is_empty(), "всё ушло через прокси — предлагать нечего");
        assert_eq!(r.already_proxied.len(), 1);
    }

    #[test]
    fn no_session_no_result() {
        let _guard = reset();
        assert!(finish_session().is_none());
        assert!(!session_active());
    }

    #[test]
    fn trigger_expires_after_window() {
        let _guard = reset();
        start_session();
        note("chatgpt.com", &Route::proxy());
        // подделываем давность: сдвигаем отметку назад
        if let Some(l) = STATE.lock().unwrap().as_mut() {
            if let Some((h, _)) = l.last_proxy.take() {
                l.last_proxy = Some((h, Instant::now() - Duration::from_secs(60)));
            }
        }
        note("unrelated.example", &Route::Direct);
        let r = finish_session().unwrap();
        let c = r.candidates.iter().find(|c| c.domain == "unrelated.example").unwrap();
        assert!(c.triggered_by.is_none(), "давнее обращение не должно считаться причиной");
    }
}
