//! Кольцевой журнал соединений для показа в окне программы.

use crate::rules::Route;
use std::collections::VecDeque;
use std::sync::Mutex;

const CAP: usize = 3000;

#[derive(Clone, Debug, serde::Serialize)]
pub struct Entry {
    pub id: u64,
    /// Время по местным часам — то же, что и в файле журнала.
    pub at: String,
    pub host: String,
    pub port: u16,
    /// «proxy» | «direct» | «block»
    pub route: String,
    /// Через какой прокси, если через прокси.
    pub via: String,
}

struct Journal {
    items: VecDeque<Entry>,
    next_id: u64,
}

static J: Mutex<Option<Journal>> = Mutex::new(None);

pub fn enable() {
    *J.lock().unwrap() = Some(Journal { items: VecDeque::new(), next_id: 1 });
}

pub fn push(host: &str, port: u16, route: &Route) {
    let stamp = crate::logfile::now_stamp();
    // в окне удобнее только время, дата и так видна в файле
    let short = stamp.rsplit(' ').next().unwrap_or(&stamp).to_string();
    let via = match route {
        Route::Proxy(n) => n.clone(),
        _ => String::new(),
    };
    let mut g = J.lock().unwrap();
    let Some(j) = g.as_mut() else { return };
    let id = j.next_id;
    j.next_id += 1;
    j.items.push_back(Entry {
        id,
        at: short,
        host: host.to_string(),
        port,
        route: route.tag().to_string(),
        via,
    });
    while j.items.len() > CAP {
        j.items.pop_front();
    }
    drop(g);
    crate::logfile::line(&stamp, &format!("{:12} {host}:{port}", route.label()));
}

/// Всё, что появилось после указанного номера.
pub fn since(after: u64) -> Vec<Entry> {
    J.lock()
        .unwrap()
        .as_ref()
        .map(|j| j.items.iter().filter(|e| e.id > after).cloned().collect())
        .unwrap_or_default()
}

pub fn clear() {
    if let Some(j) = J.lock().unwrap().as_mut() {
        j.items.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Журнал общий на всю программу, поэтому проверки идут одной цепочкой:
    // раздельные тесты сбрасывали бы состояние друг другу.
    #[test]
    fn journal_behaviour() {
        let _guard = crate::logfile::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        enable();
        push("a.example", 443, &Route::proxy());
        push("b.example", 80, &Route::Direct);
        let all = since(0);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].host, "a.example");
        assert_eq!(all[0].route, "proxy");
        let tail = since(all[0].id);
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].host, "b.example");

        clear();
        assert!(since(0).is_empty(), "очистка должна опустошать журнал");

        for i in 0..(CAP + 50) {
            push(&format!("h{i}.example"), 443, &Route::Direct);
        }
        assert_eq!(since(0).len(), CAP);
    }
}
