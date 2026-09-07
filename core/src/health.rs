//! Состояние вышестоящего прокси: доступен или нет.
//! Нужно, чтобы окно показывало причину, когда всё вдруг перестало ходить,
//! а не оставляло гадать.

use std::sync::Mutex;
use std::time::Instant;

#[derive(Clone, Debug, serde::Serialize)]
pub struct Health {
    pub up: bool,
    pub last_error: Option<String>,
    /// сколько секунд назад менялось состояние
    pub since_secs: u64,
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
