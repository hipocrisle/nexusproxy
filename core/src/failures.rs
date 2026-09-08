//! Неудавшиеся соединения — чтобы предлагать исправление, а не молчать.
//!
//! Отказ выглядит для человека как «сайт не открывается», и связать это
//! с настройками прокси он не может. Здесь копятся адреса, к которым не
//! удалось подключиться, с причиной и текущим путём: по ним окно
//! предлагает конкретное действие.

use crate::rules::Route;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Clone, Debug, serde::Serialize)]
pub struct Failure {
    /// домен, к которому не удалось подключиться
    pub domain: String,
    /// сколько раз подряд
    pub count: u32,
    /// каким путём шли: «proxy» | «direct» | «block»
    pub route: String,
    /// через какой прокси, если через прокси
    pub via: String,
    /// текст последней ошибки
    pub error: String,
    pub secs_ago: u64,
}

struct Item {
    count: u32,
    route: String,
    via: String,
    error: String,
    at: Instant,
}

static S: Mutex<Option<BTreeMap<String, Item>>> = Mutex::new(None);

pub fn enable() {
    *S.lock().unwrap() = Some(BTreeMap::new());
}

pub fn note(host: &str, route: &Route, via: &str, error: &str) {
    let domain = crate::domain::registrable(host);
    let mut g = S.lock().unwrap();
    let Some(m) = g.as_mut() else { return };
    let e = m.entry(domain).or_insert(Item {
        count: 0, route: route.tag().into(), via: via.into(),
        error: error.into(), at: Instant::now(),
    });
    e.count += 1;
    e.route = route.tag().into();
    e.via = via.into();
    e.error = error.into();
    e.at = Instant::now();
}

/// Успешное соединение снимает домен с учёта: проблема ушла.
pub fn forget(host: &str) {
    let domain = crate::domain::registrable(host);
    if let Some(m) = S.lock().unwrap().as_mut() {
        m.remove(&domain);
    }
}

/// Отказы за последние `within_secs` секунд, свежие сверху.
pub fn recent(within_secs: u64) -> Vec<Failure> {
    let g = S.lock().unwrap();
    let Some(m) = g.as_ref() else { return Vec::new() };
    let mut v: Vec<Failure> = m
        .iter()
        .filter(|(_, i)| i.at.elapsed().as_secs() <= within_secs)
        .map(|(domain, i)| Failure {
            domain: domain.clone(), count: i.count, route: i.route.clone(),
            via: i.via.clone(), error: i.error.clone(),
            secs_ago: i.at.elapsed().as_secs(),
        })
        .collect();
    v.sort_by(|a, b| a.secs_ago.cmp(&b.secs_ago).then(b.count.cmp(&a.count)));
    v
}

pub fn clear() {
    if let Some(m) = S.lock().unwrap().as_mut() {
        m.clear();
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
    fn counts_by_domain_and_keeps_reason() {
        let _g = fresh();
        note("rr1---sn-x.googlevideo.com", &Route::Direct, "", "соединение отклонено");
        note("rr2---sn-y.googlevideo.com", &Route::Direct, "", "соединение отклонено");
        let v = recent(600);
        assert_eq!(v.len(), 1, "разные имена одного домена — одна запись");
        assert_eq!(v[0].domain, "googlevideo.com");
        assert_eq!(v[0].count, 2);
        assert_eq!(v[0].error, "соединение отклонено");
    }

    #[test]
    fn success_removes_the_warning() {
        let _g = fresh();
        note("api.openai.com", &Route::proxy(), "офис", "прокси не отвечает");
        assert_eq!(recent(600).len(), 1);
        forget("chat.openai.com");
        assert!(recent(600).is_empty(), "успех по тому же домену снимает отказ");
    }

    #[test]
    fn old_failures_drop_out() {
        let _g = fresh();
        note("a.example", &Route::Direct, "", "нет связи");
        assert!(recent(0).is_empty() || recent(600).len() == 1);
    }
}
