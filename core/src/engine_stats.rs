//! Живая статистика перехвата — по данным самого движка.
//!
//! ⛔ В режиме перехвата программы обращаются не к нашему входу, а прямо
//! в сеть. Свои счётчики при этом пусты: человек видит нули и пустые
//! списки при работающем туннеле и решает, что всё сломалось. Движок
//! ведёт учёт сам, и здесь мы его забираем — это единственный источник
//! правды о том, что куда пошло.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

use crate::conns::{Conn, DomainStat};

#[derive(serde::Deserialize)]
struct Snapshot {
    connections: Option<Vec<Raw>>,
    /// ⛔ Итог за всё время ведёт сам движок. Складывать его из снимков
    /// нельзя: соединения, открывшиеся и закрывшиеся между двумя
    /// опросами, в snapshot_of не попадают вовсе, и сумма выходит заниженной.
    #[serde(rename = "downloadTotal", default)]
    download_total: u64,
    #[serde(rename = "uploadTotal", default)]
    upload_total: u64,
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

/// Сколько доменов держим в итогах. ⛔ Без предела карта росла вечно:
/// браузер с рекламой и телеметрией даёт десятки тысяч имён за сутки, а
/// окно копирует и сортирует её каждую секунду.
const ПРЕДЕЛ_ДОМЕНОВ: usize = 2000;

#[derive(Default)]
struct State {
    /// Сколько уже засчитано по каждому соединению — считаем прирост.
    counted: HashMap<String, (u64, u64)>,
    /// Когда соединение увидели впервые: движок отдаёт время началом
    /// строки, а разбирать её незачем — своё время точнее.
    since: HashMap<String, Instant>,
    totals: HashMap<String, DomainStat>,
    active: Vec<Conn>,
    /// Сколько всего прошло через движок — по его собственному счёту.
    sent_all: u64,
    received_all: u64,
}

static S: Mutex<Option<State>> = Mutex::new(None);

/// ⛔ Паника под замком отравляет мьютекс, и дальше КАЖДОЕ обращение к
/// учёту паникует: окно перестаёт отвечать целиком. Берём содержимое и
/// в таком случае — оно от этого не портится.
fn lock() -> std::sync::MutexGuard<'static, Option<State>> {
    S.lock().unwrap_or_else(|e| e.into_inner())
}

/// Куда ушло соединение: цепочка исходящих оканчивается тем, через что
/// оно в итоге пошло.
fn route_of(chains: &[String]) -> (String, String) {
    match chains.first().map(|s| s.as_str()) {
        Some("direct") | None => ("direct".into(), String::new()),
        Some(tag) => ("proxy".into(), tag.to_string()),
    }
}

fn port_of(m: &Meta) -> u16 {
    m.destination_port.parse().unwrap_or(0)
}

fn snapshot(api: &crate::tunnel::Api) -> Result<Snapshot, String> {
    // ⛔ Со сроком ожидания: иначе поток опроса замирает навсегда, если
    // на том конце соединение принимают, но не отвечают.
    let text = crate::tunnel::api_get(api, "connections")?;
    serde_json::from_str(&text).map_err(|e| format!("движок ответил непонятным: {e}"))
}

/// Забрать у движка свежий snapshot_of и обновить учёт.
pub fn refresh(dir: &Path) -> Result<(), String> {
    let api = crate::tunnel::api_access(dir);
    apply(snapshot(&api)?);
    Ok(())
}

fn apply(snap: Snapshot) {
    let raw = snap.connections.unwrap_or_default();
    let fresh = {
        let mut g = lock();
        let st = g.get_or_insert_with(State::default);
        st.sent_all = snap.upload_total;
        st.received_all = snap.download_total;
        apply_to(st, &raw)
    };
    // ⛔ Журнал наполняем ЗДЕСЬ, а не в учёте: учёт должен оставаться
    // без побочных действий, иначе его проверки пишут в общий журнал и
    // сбивают чужие.
    for (host, port, route, via) in fresh {
        let r = if route == "proxy" {
            crate::rules::Route::Proxy(via.clone())
        } else {
            crate::rules::Route::Direct
        };
        crate::journal::push(&host, port, &r, &via);
    }
}

/// Чистый учёт — без побочных действий, чтобы его можно было проверять
/// без движка. Возвращает соединения, увиденные впервые.
fn apply_to(st: &mut State, raw: &[Raw]) -> Vec<(String, u16, String, String)> {

    let mut alive: Vec<Conn> = Vec::with_capacity(raw.len());
    // ⛔ Множество, а не список: поиск в списке делал уборку
    // квадратичной, и на тысяче соединений это миллионы сравнений строк
    // каждые пару секунд — всё это время окно ждёт на замке.
    let mut seen: HashSet<&str> = HashSet::with_capacity(raw.len());
    let mut fresh: Vec<(String, u16, String, String)> = Vec::new();

    for c in raw {
        seen.insert(c.id.as_str());
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

        // ⛔ Пустое имя не схлопываем в безымянную строку: движок может
        // не дать ни имени, ни адреса, и весь такой трафик сваливался в
        // одну строку без названия.
        let host = match (c.metadata.host.trim(), c.metadata.destination_ip.trim()) {
            ("", "") => "без имени".to_string(),
            ("", ip) => ip.to_string(),
            (h, _) => h.to_string(),
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

        if first_time {
            fresh.push((host.clone(), port_of(&c.metadata), route.clone(), via.clone()));
        }

        alive.push(Conn {
            id: 0,
            host,
            port: port_of(&c.metadata),
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
    st.counted.retain(|id, _| seen.contains(id.as_str()));
    st.since.retain(|id, _| seen.contains(id.as_str()));

    alive.sort_by(|a, b| (b.sent + b.received).cmp(&(a.sent + a.received)));
    st.active = alive;

    // ⛔ Держим только самые объёмные. Без предела карта росла вечно —
    // за сутки работы это десятки тысяч имён, которые окно копирует и
    // сортирует каждую секунду.
    if st.totals.len() > ПРЕДЕЛ_ДОМЕНОВ {
        let mut by_volume: Vec<(String, u64)> = st.totals.iter()
            .map(|(k, v)| (k.clone(), v.sent + v.received))
            .collect();
        by_volume.sort_by(|a, b| b.1.cmp(&a.1));
        let keep: HashSet<String> = by_volume.into_iter()
            .take(ПРЕДЕЛ_ДОМЕНОВ)
            .map(|(k, _)| k)
            .collect();
        st.totals.retain(|k, _| keep.contains(k));
    }
    fresh
}

pub fn active() -> Vec<Conn> {
    lock().as_ref().map(|s| s.active.clone()).unwrap_or_default()
}

pub fn totals() -> Vec<DomainStat> {
    let g = lock();
    let Some(s) = g.as_ref() else { return Vec::new() };
    let mut v: Vec<DomainStat> = s.totals.values().cloned().collect();
    v.sort_by(|a, b| (b.sent + b.received).cmp(&(a.sent + a.received)));
    v
}

pub fn reset() {
    if let Some(s) = lock().as_mut() {
        s.totals.clear();
        // ⛔ И память о том, какие соединения уже видели. Иначе живые
        // соединения не считаются заново: домены с долгой связью
        // показывают растущие байты при нуле соединений, а простаивающие
        // вовсе исчезают из таблицы.
        s.counted.clear();
        s.sent_all = 0;
        s.received_all = 0;
    }
}

/// Сколько всего прошло через перехват — по счёту самого движка.
pub fn totals_all() -> (u64, u64) {
    lock().as_ref().map(|s| (s.sent_all, s.received_all)).unwrap_or((0, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot_of(text: &str) -> Vec<Raw> {
        serde_json::from_str::<Snapshot>(text).unwrap().connections.unwrap_or_default()
    }

    fn one_conn(id: &str, up: u64, down: u64) -> String {
        format!(r#"{{"connections":[{{"id":"{id}","chains":["direct"],
            "upload":{up},"download":{down},
            "metadata":{{"host":"example.com","destinationPort":"443",
                         "destinationIP":"1.2.3.4","processPath":""}}}}]}}"#)
    }

    /// ⛔ Движок отдаёт счётчики соединения ЦЕЛИКОМ. Складывая их на
    /// каждом снимке, программа умножала бы трафик на число опросов.
    fn totals_of(st: &State) -> Vec<DomainStat> {
        st.totals.values().cloned().collect()
    }

    #[test]
    fn трафик_не_умножается_на_число_опросов() {
        let mut st = State::default();
        for _ in 0..5 {
            let _ = apply_to(&mut st, &snapshot_of(&one_conn("a", 100, 900)));
        }
        let t = totals_of(&st);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].sent, 100, "отданное посчитано неверно");
        assert_eq!(t[0].received, 900, "полученное посчитано неверно");
    }

    /// Прирост между снимками засчитывается, а не теряется.
    #[test]
    fn прирост_между_снимками_засчитывается() {
        let mut st = State::default();
        apply_to(&mut st, &snapshot_of(&one_conn("b", 10, 20)));
        apply_to(&mut st, &snapshot_of(&one_conn("b", 30, 70)));
        let t = totals_of(&st);
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
            apply_to(&mut st, &snapshot_of(&one_conn("c", 0, 0)));
        }
        assert_eq!(totals_of(&st)[0].conns, 1, "соединение посчитано несколько раз");
    }

    #[test]
    fn прямое_и_через_прокси_различаются() {
        assert_eq!(route_of(&["direct".into()]), ("direct".into(), String::new()));
        assert_eq!(route_of(&["основной".into()]), ("proxy".into(), "основной".into()));
        assert_eq!(route_of(&[]), ("direct".into(), String::new()));
    }
}
