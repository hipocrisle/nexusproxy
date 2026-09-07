//! Состояние вышестоящего прокси: доступен или нет.
//! Нужно, чтобы окно показывало причину, когда всё вдруг перестало ходить,
//! а не оставляло гадать.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Clone, Debug, serde::Serialize)]
pub struct Health {
    pub up: bool,
    pub last_error: Option<String>,
    /// сколько секунд назад менялось состояние
    pub since_secs: u64,
}

/// Состояние одного прокси для показа в окне.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ProxyHealth {
    pub name: String,
    pub up: bool,
    /// отклик в миллисекундах на последней проверке
    pub ms: u64,
    pub checked_secs_ago: u64,
}

struct One {
    up: bool,
    ms: u64,
    checked: Instant,
}

static EACH: Mutex<Option<BTreeMap<String, One>>> = Mutex::new(None);

/// Отметить результат проверки конкретного прокси.
pub fn set_proxy(name: &str, up: bool, ms: u64) {
    let mut g = EACH.lock().unwrap();
    let m = g.get_or_insert_with(BTreeMap::new);
    m.insert(name.to_string(), One { up, ms, checked: Instant::now() });
}

/// Состояние всех прокси — по одному на каждый из настроек.
pub fn proxies() -> Vec<ProxyHealth> {
    let g = EACH.lock().unwrap();
    let Some(m) = g.as_ref() else { return Vec::new() };
    m.iter()
        .map(|(name, o)| ProxyHealth {
            name: name.clone(),
            up: o.up,
            ms: o.ms,
            checked_secs_ago: o.checked.elapsed().as_secs(),
        })
        .collect()
}

struct State {
    up: bool,
    last_error: Option<String>,
    changed: Instant,
}

static S: Mutex<Option<State>> = Mutex::new(None);

pub fn enable() {
    *S.lock().unwrap() = Some(State { up: true, last_error: None, changed: Instant::now() });
}

pub fn mark_up() {
    let mut g = S.lock().unwrap();
    if let Some(s) = g.as_mut() {
        if !s.up {
            s.up = true;
            s.last_error = None;
            s.changed = Instant::now();
        }
    }
}

pub fn mark_down(err: &str) {
    let mut g = S.lock().unwrap();
    if let Some(s) = g.as_mut() {
        if s.up {
            s.changed = Instant::now();
        }
        s.up = false;
        s.last_error = Some(err.to_string());
    }
}

pub fn get() -> Health {
    let g = S.lock().unwrap();
    match g.as_ref() {
        Some(s) => Health {
            up: s.up,
            last_error: s.last_error.clone(),
            since_secs: s.changed.elapsed().as_secs(),
        },
        None => Health { up: true, last_error: None, since_secs: 0 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_proxy_state_is_kept() {
        set_proxy("офис", true, 12);
        set_proxy("vpn", false, 0);
        let v = proxies();
        let office = v.iter().find(|p| p.name == "офис").unwrap();
        assert!(office.up);
        assert_eq!(office.ms, 12);
        assert!(!v.iter().find(|p| p.name == "vpn").unwrap().up);
    }

    #[test]
    fn tracks_transitions() {
        enable();
        assert!(get().up);
        mark_down("прокси не отвечает");
        let h = get();
        assert!(!h.up);
        assert_eq!(h.last_error.as_deref(), Some("прокси не отвечает"));
        mark_up();
        let h = get();
        assert!(h.up);
        assert!(h.last_error.is_none(), "после восстановления ошибка не висит");
    }
}
