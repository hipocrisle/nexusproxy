//! Живая статистика перехвата — по данным самого движка.
//!
//! ⛔ В режиме перехвата программы обращаются не к нашему входу, а прямо
//! в сеть. Свои счётчики при этом пусты: человек видит нули и пустые
//! списки при работающем туннеле и решает, что всё сломалось. Движок
//! ведёт учёт сам, и здесь мы его забираем — это единственный источник
//! правды о том, что куда пошло.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

use crate::conns::{Conn, DomainStat};

#[derive(serde::Deserialize)]
struct Snapshot {
    connections: Option<Vec<Raw>>,
}

#[derive(serde::Deserialize)]
struct Raw {
    id: String,
    #[serde(default)]
    chains: Vec<String>,
    #[serde(default)]
    upload: u64,
    #[serde(default)]
    download: u64,
    metadata: Meta,
}

#[derive(serde::Deserialize)]
struct Meta {
    #[serde(default)]
    host: String,
    #[serde(rename = "destinationIP", default)]
    destination_ip: String,
    #[serde(rename = "destinationPort", default)]
    destination_port: String,
    #[serde(rename = "processPath", default)]
    process_path: String,
}

#[derive(Default)]
struct State {
    /// Сколько уже засчитано по каждому соединению — считаем прирост.
    counted: HashMap<String, (u64, u64)>,
    /// Когда соединение увидели впервые: движок отдаёт время началом
    /// строки, а разбирать её незачем — своё время точнее.
    since: HashMap<String, Instant>,
    totals: HashMap<String, DomainStat>,
    active: Vec<Conn>,
}

static S: Mutex<Option<State>> = Mutex::new(None);

/// Куда ушло соединение: цепочка исходящих оканчивается тем, через что
/// оно в итоге пошло.
fn route_of(chains: &[String]) -> (String, String) {
    match chains.first().map(|s| s.as_str()) {
        Some("direct") | None => ("direct".into(), String::new()),
        Some(tag) => ("proxy".into(), tag.to_string()),
    }
}

fn snapshot(api: &crate::tunnel::Api) -> Result<Vec<Raw>, String> {
    let url = format!("http://127.0.0.1:{}/connections", api.port);
    let body: Snapshot = ureq::get(&url)
        .header("Authorization", &format!("Bearer {}", api.secret))
        .call()
        .map_err(|e| format!("движок не отвечает: {e}"))?
        .body_mut()
        .read_json()
        .map_err(|e| format!("движок ответил непонятным: {e}"))?;
    Ok(body.connections.unwrap_or_default())
}

/// Забрать у движка свежий снимок и обновить учёт.
pub fn refresh(dir: &Path) -> Result<(), String> {
    let api = crate::tunnel::api_access(dir);
    apply(snapshot(&api)?);
    Ok(())
}

fn apply(raw: Vec<Raw>) {
    let mut g = S.lock().unwrap();
    apply_to(g.get_or_insert_with(State::default), &raw);
}

/// Чистый учёт — отдельно от общего состояния, чтобы его можно было
/// проверять без движка.
fn apply_to(st: &mut State, raw: &[Raw]) {

    let mut alive: Vec<Conn> = Vec::with_capacity(raw.len());
    let mut seen: Vec<String> = Vec::with_capacity(raw.len());

    for c in raw {
        seen.push(c.id.clone());
        let started = *st.since.entry(c.id.clone()).or_insert_with(Instant::now);

        // ⛔ Считаем ПРИРОСТ, а не сумму: движок отдаёт счётчики
        // соединения целиком, и складывать их на каждом снимке значило
        // бы умножать трафик на число опросов.
        //
        // ⛔ Новизна — по тому, видели ли мы соединение раньше, а НЕ по
        // нулевым счётчикам: соединение без трафика иначе считается
        // новым на каждом снимке, и число соединений растёт само собой.
        let first_time = !st.counted.contains_key(&c.id);
        let was = st.counted.get(&c.id).copied().unwrap_or((0, 0));
        let up = c.upload.saturating_sub(was.0);
        let down = c.download.saturating_sub(was.1);
        st.counted.insert(c.id.clone(), (c.upload, c.download));

        let host = if c.metadata.host.is_empty() {
            c.metadata.destination_ip.clone()
        } else {
            c.metadata.host.clone()
        };
        let (route, via) = route_of(&c.chains);

        if up > 0 || down > 0 || first_time {
            let domain = crate::domain::registrable(&host);
            let key = format!("{domain}|{route}|{via}");
            let e = st.totals.entry(key).or_insert_with(|| DomainStat {
                domain,
                route: route.clone(),
                via: via.clone(),
                ..Default::default()
            });
            if first_time {
                e.conns += 1;
            }
            e.sent += up;
            e.received += down;
        }

        alive.push(Conn {
            id: 0,
            host,
            port: c.metadata.destination_port.parse().unwrap_or(0),
            route,
            via,
            app: if c.metadata.process_path.is_empty() {
                String::new()
            } else {
                crate::launch::process_name(&c.metadata.process_path)
            },
            app_path: c.metadata.process_path.clone(),
            pid: 0,
            seconds: started.elapsed().as_secs(),
            sent: c.upload,
            received: c.download,
        });
    }

    // Закрытые соединения больше не занимают память.
    st.counted.retain(|id, _| seen.contains(id));
    st.since.retain(|id, _| seen.contains(id));

    alive.sort_by(|a, b| (b.sent + b.received).cmp(&(a.sent + a.received)));
    st.active = alive;
}

pub fn active() -> Vec<Conn> {
    S.lock().unwrap().as_ref().map(|s| s.active.clone()).unwrap_or_default()
}

pub fn totals() -> Vec<DomainStat> {
    let g = S.lock().unwrap();
    let Some(s) = g.as_ref() else { return Vec::new() };
    let mut v: Vec<DomainStat> = s.totals.values().cloned().collect();
    v.sort_by(|a, b| (b.sent + b.received).cmp(&(a.sent + a.received)));
    v
}

pub fn reset() {
    if let Some(s) = S.lock().unwrap().as_mut() {
        s.totals.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn снимок(текст: &str) -> Vec<Raw> {
        serde_json::from_str::<Snapshot>(текст).unwrap().connections.unwrap_or_default()
    }

    fn одно(id: &str, up: u64, down: u64) -> String {
        format!(r#"{{"connections":[{{"id":"{id}","chains":["direct"],
            "upload":{up},"download":{down},
            "metadata":{{"host":"example.com","destinationPort":"443",
                         "destinationIP":"1.2.3.4","processPath":""}}}}]}}"#)
    }

    /// ⛔ Движок отдаёт счётчики соединения ЦЕЛИКОМ. Складывая их на
    /// каждом снимке, программа умножала бы трафик на число опросов.
    fn итоги(st: &State) -> Vec<DomainStat> {
        st.totals.values().cloned().collect()
    }

    #[test]
    fn трафик_не_умножается_на_число_опросов() {
        let mut st = State::default();
        for _ in 0..5 {
            apply_to(&mut st, &снимок(&одно("a", 100, 900)));
        }
        let t = итоги(&st);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].sent, 100, "отданное посчитано неверно");
        assert_eq!(t[0].received, 900, "полученное посчитано неверно");
    }

    /// Прирост между снимками засчитывается, а не теряется.
    #[test]
    fn прирост_между_снимками_засчитывается() {
        let mut st = State::default();
        apply_to(&mut st, &снимок(&одно("b", 10, 20)));
        apply_to(&mut st, &снимок(&одно("b", 30, 70)));
        let t = итоги(&st);
        assert_eq!(t[0].sent, 30);
        assert_eq!(t[0].received, 70);
    }

    /// ⛔ Соединение без трафика иначе считается новым на каждом снимке,
    /// и число соединений растёт само собой — это поймала проверка на
    /// живом движке.
    #[test]
    fn соединение_без_трафика_считается_один_раз() {
        let mut st = State::default();
        for _ in 0..4 {
            apply_to(&mut st, &снимок(&одно("c", 0, 0)));
        }
        assert_eq!(итоги(&st)[0].conns, 1, "соединение посчитано несколько раз");
    }

    #[test]
    fn прямое_и_через_прокси_различаются() {
        assert_eq!(route_of(&["direct".into()]), ("direct".into(), String::new()));
        assert_eq!(route_of(&["основной".into()]), ("proxy".into(), "основной".into()));
        assert_eq!(route_of(&[]), ("direct".into(), String::new()));
    }
}
