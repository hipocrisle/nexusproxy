//! Перехват трафика по приложению — «как VPN».
//!
//! Обычный режим полагается на добрую волю программы: она должна сама
//! посмотреть в системные настройки прокси и послушаться. Cursor,
//! например, этого не делает — его запросы к моделям идут напрямую,
//! мимо любых настроек. Здесь трафик забирается независимо от желания
//! программы: поднимается сетевой интерфейс, и соединения выбранных
//! приложений уходят в наш прокси.
//!
//! Движок — sing-box: он умеет отбирать трафик по имени процесса и
//! работает на Windows и macOS. Писать своё поверх драйверов не нужно.
//!
//! ⛔ Через прокси уходят ТОЛЬКО перечисленные приложения. Всё остальное
//! идёт напрямую: завернуть всё — значит оборвать человеку почту и
//! внутренние ресурсы, которые через корпоративный прокси не ходят.

use std::path::{Path, PathBuf};

const RELEASES: &str = "https://api.github.com/repos/SagerNet/sing-box/releases/latest";

/// Адрес сетевого интерфейса. Подсеть маленькая и невзрачная — берём
/// из диапазона для частных сетей, чтобы не столкнуться с настоящими.
const TUN_ADDR: &str = "172.19.0.1/30";

fn exe_name() -> &'static str {
    if cfg!(windows) { "sing-box.exe" } else { "sing-box" }
}

/// Движок, который запускает служба. ⛔ Лежит в закрытой от записи
/// папке: его выполняет учётная запись системы, и подмена означала бы
/// выполнение чужого кода с её правами.
pub fn binary_path(dir: &Path) -> std::path::PathBuf {
    crate::tunnel_service::secure_dir(dir).join(engine_file_name())
}

/// Куда движок скачивается. Сюда пишет программа правами обычного
/// пользователя, а в закрытую папку его переносит установка службы.
pub fn downloaded_engine(dir: &Path) -> std::path::PathBuf {
    dir.join(engine_file_name())
}

fn engine_file_name() -> &'static str {
    if cfg!(windows) { "sing-box.exe" } else { "sing-box" }
}

pub fn is_installed(dir: &Path) -> bool {
    // Движок считается установленным, когда он скачан: перенести его в
    // закрытую папку — дело установки службы.
    downloaded_engine(dir).is_file() || binary_path(dir).is_file()
}

/// Чем проверять настройки и что показывать человеку: берём тот, что
/// работает, иначе скачанный.
fn engine_at_hand(dir: &Path) -> std::path::PathBuf {
    let secure = binary_path(dir);
    if secure.is_file() { secure } else { downloaded_engine(dir) }
}

/// Имя файла в выпуске под текущую систему.
fn asset_suffix() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => Some("windows-amd64"),
        ("windows", "aarch64") => Some("windows-arm64"),
        ("macos", "x86_64") => Some("darwin-amd64"),
        ("macos", "aarch64") => Some("darwin-arm64"),
        ("linux", "x86_64") => Some("linux-amd64"),
        ("linux", "aarch64") => Some("linux-arm64"),
        _ => None,
    }
}

/// Какое приложение через какой прокси ведём.
#[derive(Debug, Clone, PartialEq)]
pub struct Route {
    /// Имя исполняемого файла — по нему движок узнаёт процесс.
    pub process: String,
    /// Полный путь, как его указал человек.
    ///
    /// ⛔ Нужен, потому что одно приложение — это несколько процессов.
    /// У Cursor запросы к моделям делает отдельный вспомогательный
    /// процесс с другим именем; ловя только главный, мы пропускаем как
    /// раз то, ради чего всё затевалось. По пути ловятся все.
    pub path: String,
    /// Тег прокси, через который идёт трафик.
    pub via: String,
}

/// Во что превращается путь приложения для отбора по нему.
///
/// На macOS `.app` — папка со всем хозяйством приложения, и её путь
/// годится целиком. На Windows процессы приложения лежат в своей папке,
/// поэтому берём её.
fn path_prefix(path: &str) -> Option<String> {
    let p = path.trim_end_matches(['/', '\\']);
    if p.is_empty() {
        return None;
    }
    if p.to_lowercase().ends_with(".app") {
        return Some(p.to_string());
    }
    let cut = p.rfind(['/', '\\'])?;
    let папка = &p[..cut];
    // ⛔ Программа, лежащая прямо в корне диска, давала префикс вида
    // «D:» — и под правило попадали ВСЕ процессы с этого диска, то есть
    // трафик всей машины уходил в корпоративный прокси. Со стороны это
    // выглядит как «отвалились почта и внутренние ресурсы», причём
    // выборочно и необъяснимо. В таком случае ловим только по имени.
    let корень = папка.is_empty()
        || папка.ends_with(':')
        || папка.chars().all(|c| c == '/' || c == '\\');
    if корень {
        return None;
    }
    Some(папка.to_string())
}

/// Приложения, которые ходят в сеть не сами, а через отдельный процесс
/// системы. Его путь лежит вне папки приложения, и обычное правило по
/// пути до него не достаёт.
///
/// ⛔ Safari именно таков: в журнале его соединения принадлежат
/// `com.apple.WebKit.Networking` из StagedFrameworks, а не самому
/// Safari.app. Без этого правила перехват его не ловит, хотя видит.
fn helper_paths(path: &str) -> Vec<String> {
    let low = path.to_lowercase();
    let mut extra = Vec::new();
    if low.contains("safari.app") {
        extra.push("StagedFrameworks[\\\\/]Safari[\\\\/]".to_string());
    }
    extra
}

/// Отбор по пути: экранируем всё, что значимо для выражения, иначе
/// точка в «Cursor.app» совпадёт с любым знаком, а обратная косая
/// в путях Windows — испортит выражение целиком.
fn path_regex(prefix: &str) -> String {
    let mut out = String::from("^");
    for c in prefix.chars() {
        match c {
            '\\' => out.push_str("[\\\\/]"),
            '/' => out.push_str("[\\\\/]"),
            '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out.push_str("[\\\\/]");
    out
}

/// Вышестоящий прокси в том виде, в каком его понимает движок.
#[derive(Debug, Clone, PartialEq)]
pub struct Upstream {
    pub tag: String,
    pub kind: Kind,
    pub address: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Socks5,
    Http,
}

/// Собрать настройки движка.
///
/// ⛔ Два правила обязаны идти ПЕРЕД остальными: свои адреса и адрес
/// самого прокси. Без первого перехват заберёт обращения к локальной
/// сети, без второго — обращения к прокси, и получится петля: чтобы
/// дойти до прокси, надо пройти через прокси.
/// Правило по адресам: какие домены и подсети куда ведём.
#[derive(Debug, Clone, PartialEq)]
pub struct DomainRule {
    /// Образец: домен или подсеть.
    pub pattern: String,
    /// Тег прокси.
    pub via: String,
}

/// Куда движок пишет свой журнал.
pub fn engine_log_path(dir: &Path) -> PathBuf {
    dir.join("sing-box.log")
}

pub fn build_config(routes: &[Route], upstreams: &[Upstream]) -> serde_json::Value {
    build_config_with(Path::new("."), routes, &[], upstreams)
}

/// ⛔ TUN режим заменяет режим прокси целиком, а не дополняет его.
/// Системные настройки при нём не трогаются, поэтому всё, что раньше
/// шло через прокси по правилам доменов, пойдёт напрямую — если не
/// перенести эти правила сюда. У пользователя так разом отвалилось всё,
/// кроме приложений из списка.
pub fn build_config_with(
    dir_hint: &Path,
    routes: &[Route],
    domains: &[DomainRule],
    upstreams: &[Upstream],
) -> serde_json::Value {
    let mut resolvers = system_resolvers();
    if resolvers.is_empty() {
        // ⛔ Пустой список означает, что движок не запустится вовсе.
        // Лучше общеизвестный сервер, чем неработающий перехват.
        resolvers.push("1.1.1.1".to_string());
    }
    let mut outbounds: Vec<serde_json::Value> = vec![
        serde_json::json!({ "type": "direct", "tag": "direct" }),
    ];
    for u in upstreams {
        let mut o = serde_json::json!({
            "type": match u.kind { Kind::Socks5 => "socks", Kind::Http => "http" },
            "tag": u.tag,
            "server": u.address,
            "server_port": u.port,
        });
        if let (Some(user), Some(pass)) = (&u.user, &u.password) {
            if !user.is_empty() {
                o["username"] = serde_json::json!(user);
                o["password"] = serde_json::json!(pass);
            }
        }
        outbounds.push(o);
    }

    let mut rules: Vec<serde_json::Value> = vec![
        // ⛔ Без этого правила движок видит только адреса, а домены —
        // нет: в туннеле нет ни запроса, ни имени, только пакеты. Тогда
        // правила вида «grid.gg через прокси» не срабатывают вовсе, и
        // работает лишь то, что совпало по адресу.
        serde_json::json!({ "action": "sniff" }),
    ];
    // адреса прокси — иначе петля
    let proxy_ips: Vec<String> = upstreams.iter()
        .filter(|u| u.address.parse::<std::net::IpAddr>().is_ok())
        .map(|u| format!("{}/32", u.address))
        .collect();
    if !proxy_ips.is_empty() {
        rules.push(serde_json::json!({
            "ip_cidr": proxy_ips,
            "action": "route",
            "outbound": "direct"
        }));
    }

    // ⛔ Своё хозяйство мимо СТРАН подписки — иначе петля.
    //
    // Страны подписки подняты как локальные порты нашего же помощника.
    // Стоит правилу увести в такую страну трафик самого помощника — и
    // получается круг: программа идёт в туннель, туннель отдаёт её в
    // локальный порт, помощник идёт к своему серверу, и тот же туннель
    // отправляет его обратно в тот же порт.
    //
    // ⛔ Правило ставится ТОЛЬКО когда страны есть. Без них петле взяться
    // неоткуда, а лишнее «напрямую» сломало бы работу там, где выход в
    // сеть есть только через корпоративный прокси.
    let есть_страны = upstreams.iter().any(|u| u.address == "127.0.0.1");
    if есть_страны {
        // Берём всю папку программы, а не только папку перехвата:
        // помощник лежит в соседней.
        let своё: Vec<String> = dir_hint.parent()
            .map(|d| vec![path_regex(&d.to_string_lossy())])
            .unwrap_or_default();
        if !своё.is_empty() {
            rules.push(serde_json::json!({
                "process_path_regex": своё,
                "action": "route",
                "outbound": "direct"
            }));
        }
    }

    // приложения — каждое в свой прокси
    let mut by_via: std::collections::BTreeMap<&str, (Vec<String>, Vec<String>)> = Default::default();
    for r in routes {
        let e = by_via.entry(r.via.as_str()).or_default();
        e.0.push(r.process.clone());
        // ⛔ Ловим и по пути: приложение — это несколько процессов, и
        // нужный нам может зваться иначе, чем главный.
        if let Some(prefix) = path_prefix(&r.path) {
            e.1.push(path_regex(&prefix));
        }
        // и сетевой процесс, если приложение ходит в сеть не само
        for extra in helper_paths(&r.path) {
            if !e.1.contains(&extra) {
                e.1.push(extra);
            }
        }
    }
    // ⛔ ВЕСЬ UDP идёт напрямую, а не только QUIC.
    //
    // Через SOCKS5 протокол UDP не проходит вовсе — тот его не умеет.
    // Поэтому заворачивать UDP в прокси бессмысленно: он либо не дойдёт,
    // либо приложение свалится на запасной путь по TCP. Видеозвонки так
    // и теряли качество: они ходят по портам 3478 и выше, под правило
    // для QUIC не попадали, уходили в прокси и откатывались на TCP.
    //
    // Правило стоит ПЕРЕД правилами приложений: иначе их UDP уйдёт в
    // прокси раньше, чем дойдёт очередь сюда.
    rules.push(serde_json::json!({
        "network": "udp",
        "action": "route",
        "outbound": "direct"
    }));

    // ⛔ Запросы имён — мимо прокси, и ДО правил приложений. Стоя после
    // них, это правило было мёртвым: запрос имени по TCP от выбранной
    // программы уходил в корпоративный прокси, который соединения на
    // порт 53 обычно запрещает, — имя не разрешалось, и программа
    // просто висела. Внутренние зоны за прокси не видны, а отвечать за
    // систему мы не беремся.
    rules.push(serde_json::json!({
        "port": [53],
        "action": "route",
        "outbound": "direct"
    }));

    // ⛔ Имя и путь — РАЗНЫМИ правилами. Внутри одного правила движок
    // требует совпадения всех условий сразу, а у приложения процессы
    // зовутся по-разному: главный «Cursor», рабочий «Cursor Helper
    // (Plugin)». Путь подходит, имя — нет, и правило не срабатывает
    // никогда. Именно поэтому перехват приложений не работал вовсе.
    for (via, (procs, paths)) in by_via {
        if !procs.is_empty() {
            rules.push(serde_json::json!({
                "process_name": procs,
                "action": "route",
                "outbound": via
            }));
        }
        if !paths.is_empty() {
            rules.push(serde_json::json!({
                "process_path_regex": paths,
                "action": "route",
                "outbound": via
            }));
        }
    }

    // ⛔ QUIC закрываем наглухо. Это HTTP/2 и HTTP/3 поверх UDP, а через
    // SOCKS5 протокол UDP не проходит вовсе: соединение просто виснет.
    // Программа при этом не сообщает об ошибке — она молча не работает,
    // хотя на обычном TCP всё в порядке. Закрыв QUIC, мы заставляем её
    // откатиться на TCP, который через прокси проходит.
    // правила по доменам и подсетям — то же, что в режиме прокси
    let mut dom_by_via: std::collections::BTreeMap<&str, (Vec<String>, Vec<String>)> = Default::default();
    for d in domains {
        let e = dom_by_via.entry(d.via.as_str()).or_default();
        let p = d.pattern.trim();
        if let Some(rest) = p.strip_prefix("domain:") {
            e.0.push(rest.to_string());
        } else if p.contains('/') && p.chars().next().map_or(false, |c| c.is_ascii_digit() || c == ':') {
            e.1.push(p.to_string());
        } else if p.parse::<std::net::IpAddr>().is_ok() {
            e.1.push(format!("{p}/32"));
        } else if !p.is_empty() && !p.starts_with('_') {
            e.0.push(p.to_string());
        }
    }
    for (via, (doms, nets)) in dom_by_via {
        let mut rule = serde_json::json!({ "action": "route", "outbound": via });
        if !doms.is_empty() {
            rule["domain_suffix"] = serde_json::json!(doms);
        }
        if !nets.is_empty() {
            rule["ip_cidr"] = serde_json::json!(nets);
        }
        if rule.get("domain_suffix").is_some() || rule.get("ip_cidr").is_some() {
            rules.push(rule);
        }
    }

    // ⛔ Свои адреса — напрямую, но ПОСЛЕ правил человека. Стоя третьим
    // сверху, это правило делало невозможным ровно тот случай, ради
    // которого программу и заводят: внутренний ресурс, доступный ТОЛЬКО
    // через корпоративный прокси. Такое правило не срабатывало никогда —
    // решение принималось раньше, чем до него доходила очередь. Теперь
    // оно ловит лишь то, о чём человек не распорядился сам.
    rules.push(serde_json::json!({
        "ip_is_private": true,
        "action": "route",
        "outbound": "direct"
    }));

    let api = api_access(dir_hint);
    serde_json::json!({
        // ⛔ DNS оставляем системе. Туннель по умолчанию отвечает на
        // запросы сам, и внутренние имена — контроллеры домена, файловые
        // ресурсы — перестают разрешаться: у человека виснет оснастка
        // управления доменом, хотя по адресам всё доступно. Наше дело —
        // вести трафик, а не подменять разрешение имён.
        "dns": {
            // ⛔ Явные адреса, снятые ДО включения туннеля. Указание
            // «спросить у системы» здесь не годится: система к этому
            // моменту уже указывает на туннель, и запрос идёт по кругу.
            "servers": resolvers.iter().enumerate().map(|(i, ip)| serde_json::json!({
                "type": "udp",
                "tag": format!("сервер-{i}"),
                "server": ip
            })).collect::<Vec<_>>(),
            "strategy": "prefer_ipv4"
        },
        // ⛔ Уровень «info», а не «warn»: при «warn» движок молчит, и
        // когда перехват не работает, мы не видим даже того, создался ли
        // сетевой интерфейс. Журнал пишется в свой файл, чтобы не
        // теряться среди записей наблюдателя.
        "log": {
            // ⛔ «debug», а не «info»: на «info» не видно, какое правило
            // сработало и куда ушло соединение — только что оно было.
            // Разбирать «идёт через туннель, но не работает» на этом
            // уровне невозможно.
            "level": "debug",
            "timestamp": true,
            "output": engine_log_path(dir_hint).display().to_string()
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "address": [TUN_ADDR],
            "auto_route": true,
            // ⛔ Строгий режим выключен: он мешает работе части программ
            // Windows, обращающихся к службам своей сети — у пользователя
            // из-за него повисала оснастка управления доменом, при живом
            // RDP и пинге. Нужен он для защиты от утечки запросов имён, а
            // мы их и так не перехватываем.
            "strict_route": false,
            // ⛔ Размер пакета задаём явно. По умолчанию движок берёт
            // сильно больше, чем пропускает обычная сеть: мелкое ходит,
            // а крупное — ответы со списками, выгрузки — молча теряется.
            // Программа при этом не сообщает об ошибке, а виснет.
            "mtu": 1400
        }],
        // ⛔ Живая статистика. Слушает только свою машину и под паролем.
        "experimental": {
            "clash_api": {
                "external_controller": format!("127.0.0.1:{}", api.port),
                "secret": api.secret
            }
        },
        "outbounds": outbounds,
        "route": {
            // ⛔ Движок обязан знать, каким сервером имён пользоваться
            // при своих собственных обращениях. Без этого он отказывается
            // запускаться вовсе: «missing route.default_domain_resolver».
            // Наблюдатель поднимал его заново каждые две секунды, а в
            // окне это выглядело как «перехват включён, но не работает».
            "default_domain_resolver": resolvers.first()
                .map(|_| "сервер-0".to_string())
                .unwrap_or_else(|| "сервер-0".to_string()),
            "rules": rules,
            // ⛔ Всё, что не перечислено, идёт НАПРЯМУЮ. Завернуть всё —
            // значит оборвать почту и внутренние ресурсы, которые через
            // корпоративный прокси не ходят.
            "final": "direct",
            "auto_detect_interface": true
        }
    })
}

#[cfg(test)]
mod tests {

    /// ⛔ Падающий по кругу движок не должен считаться работающим.
    /// Журнал он при этом обновляет каждую секунду — по нему судить
    /// нельзя.
    /// ⛔ Порядок правил решает всё. Проверяем именно очерёдность, а не
    /// наличие: правило, до которого не доходит очередь, — мёртвое.
    #[test]
    fn очерёдность_правил_не_глушит_нужное() {
        let c = build_config_with(
            Path::new("."),
            &[Route { process: "app.exe".into(), path: "C:\\П\\app.exe".into(), via: "основной".into() }],
            &[DomainRule { pattern: "10.10.0.0/16".into(), via: "основной".into() },
              DomainRule { pattern: "intranet.corp".into(), via: "основной".into() }],
            &[corp()],
        );
        let rules = rules_of(&c);
        let место = |ищем: &dyn Fn(&serde_json::Value) -> bool| -> usize {
            rules.iter().position(|r| ищем(r)).unwrap_or(usize::MAX)
        };
        let udp = место(&|r| r["network"] == "udp");
        let имена = место(&|r| r["port"].as_array().map(|a| a.contains(&serde_json::json!(53))).unwrap_or(false));
        let процессы = место(&|r| r.get("process_name").is_some());
        let свои = место(&|r| r["ip_is_private"] == true);
        let подсеть = место(&|r| r["ip_cidr"].as_array()
            .map(|a| a.iter().any(|v| v == "10.10.0.0/16")).unwrap_or(false));

        assert!(udp < процессы, "UDP выбранной программы уйдёт в прокси, а через него он не ходит");
        assert!(имена < процессы,
                "запрос имени по TCP уйдёт в прокси, и программа повиснет: {имена} !< {процессы}");
        assert!(подсеть < свои,
                "внутренний ресурс через прокси невозможен — решает правило «свои адреса»");
        assert!(свои < rules.len(), "правило «свои адреса» потерялось");
    }

    /// ⛔ Когда есть страны подписки, помощник программы обязан идти
    /// мимо них: иначе его собственный трафик возвращается в тот же
    /// локальный порт, и получается круг.
    #[test]
    fn при_странах_своё_хозяйство_идёт_напрямую() {
        let страна = Upstream {
            tag: "Германия".into(), kind: Kind::Socks5,
            address: "127.0.0.1".into(), port: 20800, user: None, password: None,
        };
        let c = build_config_with(
            Path::new("/данные/org.hipogas.nexusproxy/tunnel"),
            &[],
            &[DomainRule { pattern: "hipogas.org".into(), via: "Германия".into() }],
            &[corp(), страна],
        );
        let rules = rules_of(&c);
        let своё = rules.iter().position(|r| r["process_path_regex"].as_array()
            .map(|a| a.iter().any(|v| v.as_str().unwrap_or("").contains("nexusproxy")))
            .unwrap_or(false)).expect("нет правила для своего хозяйства");
        let домен = rules.iter().position(|r| r.get("domain_suffix").is_some())
            .unwrap_or(usize::MAX);
        assert!(своё < домен, "своё хозяйство разбирается позже правил — возможен круг");
        assert_eq!(rules[своё]["outbound"], "direct");
    }

    /// ⛔ А без стран такого правила быть не должно: в сети, где выход
    /// только через корпоративный прокси, «напрямую» означает «никуда».
    #[test]
    fn без_стран_лишнего_правила_нет() {
        let c = build_config_with(
            Path::new("/данные/org.hipogas.nexusproxy/tunnel"),
            &[],
            &[DomainRule { pattern: "example.com".into(), via: "основной".into() }],
            &[corp()],
        );
        let есть = rules_of(&c).iter().any(|r| r["process_path_regex"].as_array()
            .map(|a| a.iter().any(|v| v.as_str().unwrap_or("").contains("nexusproxy")))
            .unwrap_or(false));
        assert!(!есть, "лишнее правило «напрямую» сломает работу через корпоративный прокси");
    }

    /// ⛔ Программа в корне диска не должна заворачивать весь диск.
    #[test]
    fn программа_в_корне_диска_не_забирает_весь_диск() {
        assert_eq!(path_prefix("D:\\game.exe"), None, "под правило попал весь диск D");
        assert_eq!(path_prefix("/app"), None, "под правило попал весь корень");
        assert_eq!(path_prefix("C:\\Program Files\\App\\app.exe").as_deref(),
                   Some("C:\\Program Files\\App"));
    }

    #[test]
    fn падающий_по_кругу_движок_не_считается_живым() {
        let dir = std::env::temp_dir().join(format!("np-alive-{}", random_tag()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(engine_log_path(&dir), "только что писали").unwrap();
        // доступа к движку нет вовсе
        assert!(!is_alive(&dir), "свежий журнал принят за живой движок");

        // и с записанным доступом, но никем не занятым портом — тоже
        let свободный = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let порт = свободный.local_addr().unwrap().port();
        drop(свободный);
        std::fs::write(api_path(&dir),
            serde_json::to_vec(&Api { port: порт, secret: "x".repeat(32) }).unwrap()).unwrap();
        assert!(!is_alive(&dir), "движка нет, а программа считает его живым");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// А отвечающий движок — живой, даже если его процесс нам не виден.
    #[test]
    fn отвечающий_движок_считается_живым() {
        let dir = std::env::temp_dir().join(format!("np-alive2-{}", random_tag()));
        let _ = std::fs::create_dir_all(&dir);
        let слушает = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let порт = слушает.local_addr().unwrap().port();
        std::fs::write(api_path(&dir),
            serde_json::to_vec(&Api { port: порт, secret: "x".repeat(32) }).unwrap()).unwrap();
        assert!(is_alive(&dir), "движок отвечает, а считается мёртвым");
        let _ = std::fs::remove_dir_all(&dir);
    }
    use super::*;

    fn corp() -> Upstream {
        Upstream {
            tag: "основной".into(), kind: Kind::Socks5,
            address: "172.31.211.1".into(), port: 1081,
            user: None, password: None,
        }
    }

    fn rules_of(v: &serde_json::Value) -> &Vec<serde_json::Value> {
        v["route"]["rules"].as_array().unwrap()
    }

    #[test]
    fn приложение_идёт_в_свой_прокси() {
        let c = build_config(
            &[Route { process: "Cursor.exe".into(),
                      path: "/Apps/Cursor.exe".into(),
                      via: "основной".into() }],
            &[corp()],
        );
        let by_name = rules_of(&c).iter()
            .find(|r| r["process_name"][0] == "Cursor.exe")
            .expect("правило по имени должно быть");
        assert_eq!(by_name["outbound"], "основной");
    }

    /// ⛔ Без этого правила перехват заберёт и обращения к самому прокси:
    /// чтобы дойти до него, надо пройти через него. Соединений не будет
    /// вообще, а причина со стороны выглядит как «интернет пропал».
    #[test]
    fn адрес_прокси_идёт_напрямую() {
        let c = build_config(&[], &[corp()]);
        let has = rules_of(&c).iter().any(|r| {
            r["ip_cidr"].as_array().map_or(false, |a| a.iter().any(|x| x == "172.31.211.1/32"))
                && r["outbound"] == "direct"
        });
        assert!(has, "адрес прокси обязан идти напрямую");
    }

    /// Своя сеть мимо перехвата: прокси до неё не достанет, а обращения
    /// к самому себе он и вовсе завернёт в петлю.
    #[test]
    fn свои_адреса_идут_напрямую() {
        let c = build_config(&[], &[corp()]);
        let hit = rules_of(&c).iter().any(|r| {
            r["ip_is_private"] == true && r["outbound"] == "direct"
        });
        assert!(hit, "локальная сеть обязана идти напрямую");
    }

    /// ⛔ Всё лишнее должно идти напрямую: завернув весь трафик, мы
    /// оборвём почту и внутренние ресурсы, которых в прокси нет.
    #[test]
    fn остальное_не_заворачиваем() {
        let c = build_config(
            &[Route { process: "Cursor.exe".into(), path: format!("/Apps/{}", "Cursor.exe"), via: "основной".into() }],
            &[corp()],
        );
        assert_eq!(c["route"]["final"], "direct");
    }

    #[test]
    fn приложения_одного_прокси_идут_одним_правилом() {
        let c = build_config(
            &[
                Route { process: "a.exe".into(), path: format!("/Apps/{}", "a.exe"), via: "основной".into() },
                Route { process: "b.exe".into(), path: format!("/Apps/{}", "b.exe"), via: "основной".into() },
            ],
            &[corp()],
        );
        let app_rules: Vec<_> = rules_of(&c).iter()
            .filter(|r| r["process_name"].is_array()).collect();
        assert_eq!(app_rules.len(), 1, "одно правило на прокси");
        assert_eq!(app_rules[0]["process_name"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn логин_и_пароль_доходят_до_движка() {
        let mut u = corp();
        u.user = Some("ivan".into());
        u.password = Some("секрет".into());
        let c = build_config(&[], &[u]);
        let o = c["outbounds"].as_array().unwrap().iter()
            .find(|o| o["tag"] == "основной").unwrap();
        assert_eq!(o["username"], "ivan");
        assert_eq!(o["password"], "секрет");
    }

    /// Пустой логин — это «входа по логину нет», а не логин из пустой
    /// строки: иначе движок предложит прокси вход, которого тот не ждёт.
    #[test]
    fn пустой_логин_не_отправляем() {
        let mut u = corp();
        u.user = Some(String::new());
        u.password = Some(String::new());
        let c = build_config(&[], &[u]);
        let o = c["outbounds"].as_array().unwrap().iter()
            .find(|o| o["tag"] == "основной").unwrap();
        assert!(o.get("username").is_none(), "пустой логин отправлять нельзя");
    }
}

/// Скачать движок перехвата. Возвращает версию.
///
/// В состав программы он не входит: нужен не всем, а весит немало.
pub fn download(dir: &Path) -> Result<String, String> {
    let suffix = asset_suffix().ok_or("для этой системы готовой сборки движка нет")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("не создать папку: {e}"))?;

    let meta: serde_json::Value = ureq::get(RELEASES)
        .header("User-Agent", "NexusProxy")
        .call()
        .map_err(|e| format!("не получить список выпусков: {e}"))?
        .body_mut()
        .read_json()
        .map_err(|e| format!("испорченный ответ: {e}"))?;

    let version = meta["tag_name"].as_str().unwrap_or("неизвестно").to_string();
    let want_zip = cfg!(windows);
    let ext = if want_zip { ".zip" } else { ".tar.gz" };
    let asset = meta["assets"].as_array().ok_or("в выпуске нет файлов")?
        .iter()
        .find(|a| {
            let n = a["name"].as_str().unwrap_or("");
            n.contains(suffix) && n.ends_with(ext)
        })
        .ok_or_else(|| format!("в выпуске нет сборки для {suffix}"))?;
    // ⛔ Берём только то, что выложено самим проектом движка: адрес
    // приходит из ответа стороннего сервиса, и переход на чужой узел
    // означал бы запуск чужого кода с правами системы.
    let ok_host = |u: &str| {
        u.starts_with("https://github.com/")
            || u.starts_with("https://objects.githubusercontent.com/")
            || u.starts_with("https://release-assets.githubusercontent.com/")
    };
    let url = asset["browser_download_url"].as_str()
        .ok_or("у файла нет ссылки")?.to_string();
    if !ok_host(&url) {
        return Err(format!("движок предлагают скачать с чужого адреса: {url}"));
    }

    let body: Vec<u8> = ureq::get(&url)
        .header("User-Agent", "NexusProxy")
        .call()
        .map_err(|e| format!("не скачать движок: {e}"))?
        .body_mut()
        .with_config()
        .limit(120 * 1024 * 1024)
        .read_to_vec()
        .map_err(|e| format!("обрыв при скачивании: {e}"))?;

    // ⛔ Распаковываем рядом и подставляем в самом конце. Прежде файл
    // сразу обрезался до нуля, и обрыв связи посреди скачивания оставлял
    // огрызок, который программа считала установленным движком: запуск
    // падал с невнятной ошибкой, а перекачать было нечем.
    let dest_final = downloaded_engine(dir);
    let dest = dir.join(format!("sing-box.{}.part", random_tag()));
    let found = if want_zip {
        unpack_zip(&body, &dest)?
    } else {
        unpack_tar_gz(&body, &dest)?
    };
    if !found {
        let _ = std::fs::remove_file(&dest);
        return Err("в архиве не оказалось самого движка".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755));
    }
    std::fs::rename(&dest, &dest_final).map_err(|e| {
        let _ = std::fs::remove_file(&dest);
        format!("не подставить скачанный движок: {e}")
    })?;
    Ok(version)
}

fn unpack_zip(body: &[u8], dest: &Path) -> Result<bool, String> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(body))
        .map_err(|e| format!("архив не читается: {e}"))?;
    for i in 0..zip.len() {
        let mut f = zip.by_index(i).map_err(|e| e.to_string())?;
        let name = f.name().rsplit('/').next().unwrap_or("").to_string();
        if name == exe_name() {
            let mut out = std::fs::File::create(dest)
                .map_err(|e| format!("не записать движок: {e}"))?;
            std::io::copy(&mut f, &mut out).map_err(|e| format!("не записать движок: {e}"))?;
            return Ok(true);
        }
    }
    Ok(false)
}

fn unpack_tar_gz(body: &[u8], dest: &Path) -> Result<bool, String> {
    let gz = flate2::read::GzDecoder::new(std::io::Cursor::new(body));
    let mut ar = tar::Archive::new(gz);
    for e in ar.entries().map_err(|e| format!("архив не читается: {e}"))? {
        let mut e = e.map_err(|e| e.to_string())?;
        let path = e.path().map_err(|e| e.to_string())?.to_path_buf();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == exe_name() {
            let mut out = std::fs::File::create(dest)
                .map_err(|e| format!("не записать движок: {e}"))?;
            std::io::copy(&mut e, &mut out).map_err(|e| format!("не записать движок: {e}"))?;
            return Ok(true);
        }
    }
    Ok(false)
}

use std::sync::Mutex;
static CHILD: Mutex<Option<std::process::Child>> = Mutex::new(None);
static STARTING: Mutex<()> = Mutex::new(());
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

pub fn log_path(dir: &Path) -> PathBuf {
    dir.join("tunnel.log")
}

/// Последняя жалоба движка — чтобы человек видел причину, а не просто
/// «не включилось».
pub fn last_error() -> Option<String> {
    LAST_ERROR.lock().unwrap().clone()
}

/// Поднят ли движок хоть кем-то — нами или службой.
///
/// ⛔ Служба работает от имени системы, её движок нам не принадлежит, и
/// обычной проверки своего дочернего процесса мало: программа считала
/// перехват выключенным при работающем туннеле.
pub fn is_alive(dir: &Path) -> bool {
    if is_running() || crate::xray::is_alive(&binary_path(dir)) {
        return true;
    }
    // ⛔ Спрашиваем сам движок, а НЕ смотрим на свежесть его журнала.
    // Журнал обнуляется перед каждым запуском, поэтому при падении по
    // кругу он обновлялся каждую секунду — и программа показывала
    // «перехват работает» при полностью мёртвом туннеле, то есть ровно
    // тогда, когда человеку нужнее всего правда.
    //
    // Процесс движка принадлежит системе и в списке процессов
    // пользователю не виден, зато его управляющий вход отвечает.
    let Some(api) = api_stored(dir) else { return false };
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], api.port));
    std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(300)).is_ok()
}

/// Записанный доступ к движку — без проверок и без обращений к сети.
fn api_stored(dir: &Path) -> Option<Api> {
    let text = std::fs::read_to_string(api_path(dir)).ok()?;
    let a: Api = serde_json::from_str(&text).ok()?;
    (a.port != 0 && !a.secret.is_empty()).then_some(a)
}

pub fn is_running() -> bool {
    let mut g = CHILD.lock().unwrap();
    match g.as_mut() {
        Some(c) => match c.try_wait() {
            Ok(None) => true,
            _ => { *g = None; false }
        },
        None => false,
    }
}

pub fn stop() {
    if let Some(mut c) = CHILD.lock().unwrap().take() {
        let _ = c.kill();
        let _ = c.wait();
    }
}

/// Поднять перехват.
///
/// ⛔ Нужны права администратора: движок создаёт сетевой интерфейс.
/// Без них он просто не запустится, и в журнале будет отказ доступа —
/// человеку надо показать это прямо, а не молчать.
pub fn start(dir: &Path, routes: &[Route], upstreams: &[Upstream]) -> Result<(), String> {
    let _one_at_a_time = STARTING.lock().unwrap_or_else(|e| e.into_inner());
    stop();
    *LAST_ERROR.lock().unwrap() = None;

    if routes.is_empty() {
        return Err("нет ни одного приложения — перехватывать нечего".into());
    }
    let bin = binary_path(dir);
    if !bin.is_file() {
        return Err("движок перехвата ещё не скачан".into());
    }

    let cfg_path = dir.join("tunnel-config.json");
    let cfg = build_config(routes, upstreams);
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg).unwrap())
        .map_err(|e| format!("не записать настройки: {e}"))?;

    // ⛔ Вывод движка обязан куда-то писаться: иначе его отказ выглядит
    // как «перехват не включился» без единой подсказки почему.
    let log = std::fs::File::create(log_path(dir))
        .map_err(|e| format!("не создать журнал: {e}"))?;
    let log_err = log.try_clone().map_err(|e| format!("не создать журнал: {e}"))?;

    let mut cmd = std::process::Command::new(&bin);
    cmd.arg("run").arg("-c").arg(&cfg_path)
       .current_dir(dir)
       .stdout(log).stderr(log_err);

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // без чёрного окна
    }

    let child = cmd.spawn().map_err(|e| format!("не запустить движок: {e}"))?;
    *CHILD.lock().unwrap() = Some(child);

    // Даём подняться и проверяем, что не упал сразу: чаще всего это
    // нехватка прав, и человеку надо сказать именно это.
    std::thread::sleep(std::time::Duration::from_millis(700));
    if !is_running() {
        let tail = std::fs::read_to_string(log_path(dir)).unwrap_or_default();
        let why = tail.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").to_string();
        *LAST_ERROR.lock().unwrap() = Some(why.clone());
        return Err(if why.to_lowercase().contains("permission")
                      || why.to_lowercase().contains("denied")
                      || why.contains("отказ") {
            "не хватает прав: перехват создаёт сетевой интерфейс, нужен запуск от администратора".into()
        } else if why.is_empty() {
            "движок перехвата не запустился".into()
        } else {
            format!("движок перехвата не запустился: {why}")
        });
    }
    Ok(())
}

/// Запустить движок с правами администратора.
///
/// ⛔ Сетевой интерфейс без них не создать. Поэтому здесь просим
/// повышение у системы: человек один раз подтверждает, и перехват
/// работает. Обычное окно программы правами не обладает и обладать
/// не должно — иначе их требовал бы каждый её запуск, как у Proxifier.
/// Остановить движок.
///
/// ⛔ Раньше программа умела поднимать движок сама, с запросом прав при
/// каждом включении, и отдельно хранила его дескриптор. Теперь движок
/// поднимает служба от имени системы, и снимать его так уже нельзя —
/// прав у программы нет. Остаётся снять тот, что запущен ею самой.
pub fn stop_elevated() { stop(); }

/// Снять движок, оставшийся от прошлого запуска.
///
/// ⛔ Обязательно при старте программы. Если она ушла не по-хорошему —
/// упала, была снята, пережила перезагрузку, — движок остаётся работать
/// и держит сетевой интерфейс. Человек при этом видит, что половина
/// всего не работает, а причины не видно: наше окно закрыто, а трафик
/// всё ещё заворачивается. Это та же беда, что с системным прокси,
/// только крупнее.
pub fn kill_orphans(dir: &Path) -> usize {
    // ⛔ И тот, что остался от прежних версий рядом с настройками: он
    // держит сетевой интерфейс, и новый движок из-за него не поднимется.
    let old = downloaded_engine(dir);
    let mut killed = if old.is_file() { crate::xray::kill_orphans(&old) } else { 0 };
    let bin = binary_path(dir);
    if bin.is_file() {
        killed += crate::xray::kill_orphans(&bin);
    }
    killed
}

/// Записать настройки для движка. Служба читает их при запуске.
pub fn write_config(dir: &Path, routes: &[Route], domains: &[DomainRule],
                    upstreams: &[Upstream]) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("не создать папку: {e}"))?;
    let cfg = build_config_with(dir, routes, domains, upstreams);
    let text = serde_json::to_vec_pretty(&cfg).unwrap();

    // ⛔ Если настройки не изменились, не трогаем файл вовсе: служба
    // следит за его отпечатком и на любую запись перезапускает движок.
    // Лишний перезапуск — это разрыв всех соединений на ровном месте.
    if std::fs::read(config_path(dir)).map(|было| было == text).unwrap_or(false) {
        crate::logfile::line(&crate::logfile::now_stamp(),
            "перехват: настройки движка не изменились, перезапуск не нужен");
        return Ok(());
    }

    // ⛔ Пишем целиком и только потом подставляем под нужное имя.
    // Обычная запись сначала обрезает файл до нуля, а служба читает его
    // раз в секунду — и успевала прочесть огрызок: движок падал, а
    // человек видел разрыв связи при каждой правке списка.
    let tmp = dir.join(format!("tunnel-config.{}.tmp", random_tag()));
    std::fs::write(&tmp, &text).map_err(|e| format!("не записать настройки: {e}"))?;
    std::fs::rename(&tmp, config_path(dir)).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("не записать настройки: {e}")
    })?;

    // ⛔ Проверяем настройки самим движком, прежде чем он на них
    // запустится. Иначе негодные настройки означают бесконечный круг:
    // движок падает, наблюдатель поднимает его снова, и так каждые две
    // секунды — а в окне это выглядит как «перехват включён, но не
    // работает», без единого намёка на причину.
    if let Err(why) = check_config(dir) {
        crate::logfile::line(&crate::logfile::now_stamp(),
            &format!("перехват: настройки негодны — {why}"));
        return Err(format!("движок не принял настройки: {why}"));
    }
    // Какие именно процессы ловим — самое важное для разбора: если имя
    // не совпадёт с настоящим, перехват работает, а трафик идёт мимо.
    crate::logfile::line(&crate::logfile::now_stamp(), &format!(
        "перехват: настройки движка обновлены\n  \
         программы: [{}]\n  \
         правил по адресам: {}\n  \
         прокси: [{}]\n  \
         файл: {} ({} Б)",
        routes.iter().map(|r| format!("{} → {}", r.process, r.via))
              .collect::<Vec<_>>().join(", "),
        domains.len(),
        upstreams.iter().map(|u| format!("{} = {}:{}", u.tag, u.address, u.port))
                 .collect::<Vec<_>>().join(", "),
        config_path(dir).display(),
        text.len(),
    ));
    Ok(())
}

pub fn config_path(dir: &Path) -> PathBuf {
    dir.join("tunnel-config.json")
}

/// Поднять движок и ждать его — этим занимается наш же файл, запущенный
/// задачей планировщика.
///
/// ⛔ Задача не умеет прятать окно консоли: запусти она движок напрямую,
/// у человека на экране постоянно висело бы чёрное окно с журналом.
/// Поэтому запускает нас, а окно прячем мы сами.
/// Следить за признаком включения и держать движок, пока он есть.
///
/// ⛔ На macOS демон поднимается системой один раз и дальше живёт сам.
/// Полагаться на то, что launchd заметит появление файла и перезапустит
/// его, нельзя: у пользователя движок так и работал с настройками
/// часовой давности, а в журнале не было ни одной записи о запуске.
/// Поэтому следим сами: есть признак — движок работает и перечитывает
/// настройки при каждом изменении, нет — стоит.
pub fn watch_flag(dir: &Path, flag: &Path) -> Result<(), String> {
    crate::logfile::open(dir.join("runner.log")).ok();
    crate::logfile::line(&crate::logfile::now_stamp(),
        &format!("перехват: слежу за признаком {}", flag.display()));

    let mut running: Option<std::process::Child> = None;
    let mut cfg_stamp = config_stamp(dir);
    let mut tick: u64 = 0;
    loop {
        let want = flag.exists();
        let fresh = config_stamp(dir);
        let changed = fresh != cfg_stamp;

        match (&mut running, want) {
            // просят работать, а движка нет — поднимаем
            (None, true) => {
                cfg_stamp = fresh;
                // ⛔ Движок от прошлого запуска держит сетевой интерфейс,
                // и новый падает с «The object already exists». Снимаем
                // старый и ждём, пока система уберёт интерфейс.
                let left = kill_orphans(dir);
                if left > 0 {
                    crate::logfile::line(&crate::logfile::now_stamp(),
                        &format!("перехват: снят прежний движок ({left})"));
                    std::thread::sleep(std::time::Duration::from_millis(1200));
                }
                match spawn_engine(dir) {
                    Ok(c) => {
                        crate::logfile::line(&crate::logfile::now_stamp(), "перехват: движок поднят");
                        running = Some(c);
                    }
                    Err(e) => {
                        crate::logfile::line(&crate::logfile::now_stamp(),
                            &format!("перехват: движок не поднялся: {e}"));
                        std::thread::sleep(std::time::Duration::from_secs(5));
                    }
                }
            }
            // просят остановиться
            (Some(c), false) => {
                let _ = c.kill();
                let _ = c.wait();
                running = None;
                crate::logfile::line(&crate::logfile::now_stamp(), "перехват: движок остановлен");
            }
            // настройки поменялись — движок обязан их перечитать
            (Some(c), true) if changed => {
                cfg_stamp = fresh;
                let _ = c.kill();
                let _ = c.wait();
                running = None;
                crate::logfile::line(&crate::logfile::now_stamp(),
                    "перехват: настройки изменились, перезапускаю движок");
            }
            // движок упал сам — поднимем на следующем круге
            (Some(c), true) => {
                if matches!(c.try_wait(), Ok(Some(_))) {
                    crate::logfile::line(&crate::logfile::now_stamp(),
                        "перехват: движок завершился, поднимаю заново");
                    running = None;
                }
            }
            (None, false) => {}
        }
        // ⛔ Журнал движка на подробном уровне растёт мегабайтами в час.
        // Без обрезки он съедает место, а программа виснет, читая его.
        tick += 1;
        if tick % 60 == 0 {
            trim_log(dir);
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// Где у движка спрашивать живую статистику.
///
/// ⛔ В режиме перехвата программы обращаются не к нам, а прямо в сеть:
/// свои счётчики остаются пустыми, и человек видит нули при работающем
/// туннеле. Движок ведёт учёт сам — домен, программу, трафик в обе
/// стороны, сработавшее правило, — и это единственный источник правды.
pub fn api_path(dir: &Path) -> std::path::PathBuf {
    dir.join("api.json")
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Api {
    pub port: u16,
    pub secret: String,
}

/// ⛔ Пароль обязателен. Через это же API движком можно управлять, а
/// слушает он на своей машине: без пароля любая программа на компьютере
/// получила бы над перехватом полную власть.
pub fn api_access(dir: &Path) -> Api {
    if let Ok(t) = std::fs::read_to_string(api_path(dir)) {
        if let Ok(a) = serde_json::from_str::<Api>(&t) {
            if a.port != 0 && !a.secret.is_empty() && port_usable(&a) {
                return a;
            }
        }
    }
    let a = Api { port: free_port(), secret: fresh_secret() };
    // ⛔ Если записать не удалось, следующий вызов выдумает новые порт и
    // пароль — они разойдутся с теми, что уже у работающего движка.
    // Статистика становится вечно нулевой, а каждая запись настроек
    // выглядит изменением и заставляет службу перезапускать движок по
    // кругу. Лучше честно сказать об этом в журнал.
    if let Err(e) = std::fs::write(api_path(dir), serde_json::to_vec_pretty(&a).unwrap_or_default()) {
        crate::logfile::line(&crate::logfile::now_stamp(),
            &format!("перехват: не записать доступ к движку ({}): {e}", api_path(dir).display()));
    }
    a
}

/// Можно ли по-прежнему пользоваться этим портом.
///
/// ⛔ Занятый посторонней программой порт роняет движок ЦЕЛИКОМ:
/// «external controller listen error: address already in use» — и
/// перехват не поднимается вовсе. Порт выбирается однажды и живёт в
/// файле, а за время до следующей загрузки его может занять кто угодно.
///
/// ⛔ Но просто «занят — берём новый» нельзя: чаще всего его держит наш
/// же движок. Меняя порт при каждой проверке, мы переписывали бы
/// настройки и перезапускали движок по кругу. Поэтому спрашиваем: если
/// на нашем пароле отвечают — это он и есть.
fn port_usable(a: &Api) -> bool {
    if std::net::TcpListener::bind(("127.0.0.1", a.port)).is_ok() {
        return true;
    }
    api_get(a, "version").is_ok()
}

/// Спросить движок — со сроком ожидания.
///
/// ⛔ Срок обязателен. Порт может держать программа, которая соединение
/// принимает, но не отвечает: без срока ожидание длится вечно, и вместе
/// с ним замирает всё, что спрашивало, — и проверка порта, и опрос
/// статистики.
pub fn api_get(a: &Api, what: &str) -> Result<String, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(3)))
        .build()
        .into();
    agent
        .get(&format!("http://127.0.0.1:{}/{what}", a.port))
        .header("Authorization", &format!("Bearer {}", a.secret))
        .call()
        .map_err(|e| format!("движок не отвечает: {e}"))?
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("движок ответил непонятным: {e}"))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
        .unwrap_or(9191)
}

/// ⛔ Пароль берём у системного источника случайности. Собранный из
/// номера процесса, времени и адреса переменной — предсказуем, а через
/// это же API движком, работающим от имени системы, можно управлять:
/// переключать исходящие, смотреть все соединения, снимать перехват.
/// Случайная метка для имён временных файлов.
pub fn random_tag() -> String {
    let mut raw = [0u8; 8];
    if getrandom::getrandom(&mut raw).is_err() {
        // Хуже предсказуемого имени только отсутствие имени.
        return format!("{:x}", std::process::id());
    }
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

fn fresh_secret() -> String {
    let mut raw = [0u8; 24];
    if getrandom::getrandom(&mut raw).is_err() {
        // Источник случайности недоступен — лучше не поднимать API
        // вовсе, чем открыть его с предсказуемым паролем.
        return String::new();
    }
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

/// Отпечаток настроек — по нему видно, что их изменили.
fn config_stamp(dir: &Path) -> Option<(u64, std::time::SystemTime)> {
    let m = std::fs::metadata(config_path(dir)).ok()?;
    Some((m.len(), m.modified().ok()?))
}

fn spawn_engine(dir: &Path) -> Result<std::process::Child, String> {
    let bin = binary_path(dir);
    if !bin.is_file() {
        return Err(format!("движок не найден: {}", bin.display()));
    }
    // ⛔ Журнал движка начинаем заново: иначе вчерашние отказы
    // выглядят как сегодняшние и уводят разбор в сторону.
    let _ = std::fs::write(engine_log_path(dir), b"");
    let log = std::fs::File::create(log_path(dir))
        .map_err(|e| format!("не создать журнал: {e}"))?;
    let log_err = log.try_clone().map_err(|e| format!("не создать журнал: {e}"))?;
    let mut cmd = std::process::Command::new(&bin);
    cmd.arg("run").arg("-c").arg(config_path(dir))
       .current_dir(dir)
       .stdout(log).stderr(log_err);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let child = cmd.spawn().map_err(|e| format!("не запустить движок: {e}"))?;
    #[cfg(windows)]
    crate::xray::assign_to_job(&child);
    Ok(child)
}


/// Последние строки журнала движка — чтобы человек видел причину, а не
/// пустой экран с невключившимся перехватом.
pub fn log_tail(dir: &Path, lines: usize) -> String {
    let mut out = Vec::new();
    // Собираем все следы: что делали мы, что ответила система, что сказал
    // сам движок. Разбирать «не работает» по одному из них невозможно.
    for name in ["runner.log", "tunnel.log", "daemon.log", "sing-box.log"] {
        if let Ok(t) = std::fs::read_to_string(dir.join(name)) {
            out.extend(t.lines().rev()
                // ⛔ Убираем шум, за которым не видно сути:
                // — наши собственные обращения к прокси (их десятки в минуту);
                // — соединения, ушедшие напрямую и не дошедшие: это сеть.
                // Иначе решение по нужному приложению тонет в мусоре.
                .filter(|l| !l.contains("outbound/direct"))
                .filter(|l| !l.contains("NexusProxy.app") && !l.contains("nexusproxy.exe"))
                .filter(|l| !l.contains("inbound connection from"))
                // на подробном уровне движок сыплет служебным; оставляем
                // то, по чему видно судьбу соединения
                .filter(|l| {
                    !l.contains("DEBUG")
                        || l.contains("match")
                        || l.contains("outbound")
                        || l.contains("rejected")
                        || l.contains("sniff")
                })
                .take(lines)
                .map(|s| s.to_string()));
        }
    }
    // ⛔ Главное — что делала сама программа: какие команды выполняла и
    // что ответила система. Эти записи идут в общий журнал, и без них в
    // окне была пустота вместо причины.
    if let Some(parent) = dir.parent() {
        if let Ok(t) = std::fs::read_to_string(parent.join("nexusproxy.log")) {
            out.extend(t.lines().rev()
                .filter(|l| l.contains("перехват"))
                .take(lines)
                .map(|s| s.to_string()));
        }
    }
    // ⛔ Строки идут из разных файлов, и часть повторяется. Без
    // упорядочивания и отсева человек читает мешанину, в которой
    // последовательность событий не видна.
    let mut clean: Vec<String> = out.into_iter()
        .map(|l| strip_colors(&l))
        .filter(|l| !l.trim().is_empty())
        .collect();
    clean.sort_by(|a, b| stamp_of(a).cmp(&stamp_of(b)));
    clean.dedup();
    let from = clean.len().saturating_sub(lines);
    clean[from..].join("\n")
}

/// Метка времени в начале строки — по ней раскладываем события по
/// порядку. Строки без метки идут последними: это продолжение вывода.
fn stamp_of(line: &str) -> String {
    // «2026-09-23 10:48:35 …» или «+0300 2026-09-23 10:48:35 …»
    let start = if line.starts_with('+') {
        line.find(' ').map(|i| i + 1).unwrap_or(0)
    } else {
        0
    };
    // ⛔ Режем по СИМВОЛАМ, а не по байтам: в строке лежит сырой вывод
    // движка, и не-ASCII в первых девятнадцати байтах (кириллица в
    // ответе системы, имя на своём языке) роняло разбор прямо в команде
    // окна.
    let rest = &line[start.min(line.len())..];
    let head: String = rest.chars().take(19).collect();
    if head.chars().count() == 19 && head.starts_with(|c: char| c.is_ascii_digit()) {
        head
    } else {
        "9999".to_string()
    }
}

fn strip_colors(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // пропускаем до буквы, которой заканчивается управляющая метка
            for n in chars.by_ref() {
                if n.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod log_tests {
    use super::*;

    /// Движок красит вывод управляющими метками — в окне программы это
    /// нечитаемый мусор вида ←[31mERROR←[0m.
    #[test]
    fn метки_цвета_убираются() {
        assert_eq!(strip_colors("\u{1b}[31mERROR\u{1b}[0m тут"), "ERROR тут");
        assert_eq!(strip_colors("обычная строка"), "обычная строка");
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;

    fn corp() -> Upstream {
        Upstream {
            tag: "основной".into(), kind: Kind::Socks5,
            address: "172.31.211.1".into(), port: 1081,
            user: None, password: None,
        }
    }

    /// ⛔ Одно приложение — это несколько процессов. У Cursor запросы к
    /// моделям делает отдельный вспомогательный процесс с другим именем;
    /// ловя только главный, мы пропускаем как раз то, ради чего всё
    /// затевалось. На macOS это и было причиной «перехват включён, а
    /// Cursor не работает».
    #[test]
    fn ловим_все_процессы_приложения_по_пути() {
        let c = build_config(
            &[Route {
                process: "Cursor".into(),
                path: "/Applications/Cursor.app".into(),
                via: "основной".into(),
            }],
            &[corp()],
        );
        let by_path = c["route"]["rules"].as_array().unwrap().iter()
            .find(|r| r.get("process_path_regex").is_some() && r["outbound"] != "direct")
            .expect("правило по пути должно быть");
        let re = by_path["process_path_regex"][0].as_str().unwrap();
        assert!(re.contains("Cursor"), "{re}");
        assert!(re.starts_with('^'), "отбор должен быть от начала пути: {re}");
    }

    /// На Windows процессы приложения лежат в своей папке — берём её,
    /// а не сам файл, иначе вспомогательные процессы снова пройдут мимо.
    #[test]
    fn у_обычного_файла_берём_его_папку() {
        let p = path_prefix(r"C:\Users\i\AppData\Local\Programs\cursor\Cursor.exe").unwrap();
        assert!(p.ends_with("cursor"), "{p}");
        assert!(!p.ends_with(".exe"), "{p}");
    }

    /// ⛔ Точка в выражении совпадает с любым знаком, а обратная косая
    /// его ломает. Без экранирования отбор по пути ловил бы лишнее или
    /// не работал вовсе.
    #[test]
    fn особые_знаки_пути_экранируются() {
        let re = path_regex(r"C:\Program Files\Cursor.app");
        assert!(re.contains(r"Cursor\.app"), "точка должна быть экранирована: {re}");
        assert!(!re.contains(r"\P"), "обратная косая не должна попасть как есть: {re}");
    }
}

#[cfg(test)]
mod order_tests {
    use super::*;

    /// ⛔ Журнал собирается из разных файлов, и без упорядочивания
    /// человек читает мешанину, в которой не видно последовательности
    /// событий — а ради неё журнал и сделан.
    #[test]
    fn строки_раскладываются_по_времени() {
        let mut v = vec![
            "2026-09-23 11:44:38 второе".to_string(),
            "+0300 2026-09-23 10:48:35 первое".to_string(),
            "продолжение без метки".to_string(),
        ];
        v.sort_by(|a, b| stamp_of(a).cmp(&stamp_of(b)));
        assert!(v[0].contains("первое"), "{v:?}");
        assert!(v[1].contains("второе"), "{v:?}");
        assert!(v[2].contains("продолжение"), "строки без метки идут последними");
    }
}

#[cfg(test)]
mod domain_tests {
    use super::*;

    fn corp() -> Upstream {
        Upstream {
            tag: "основной".into(), kind: Kind::Socks5,
            address: "172.31.211.1".into(), port: 1081,
            user: None, password: None,
        }
    }

    fn rules_of(v: &serde_json::Value) -> &Vec<serde_json::Value> {
        v["route"]["rules"].as_array().unwrap()
    }

    /// ⛔ TUN режим заменяет режим прокси целиком: системные настройки
    /// при нём не трогаются. Не перенеся сюда правила по доменам, мы
    /// отправляем напрямую всё, что раньше шло через прокси — у
    /// пользователя так разом отвалилось всё, кроме приложений.
    #[test]
    fn правила_доменов_переходят_в_туннель() {
        let c = build_config_with(
            Path::new("."),
            &[],
            &[DomainRule { pattern: "domain:grid.gg".into(), via: "основной".into() }],
            &[corp()],
        );
        let hit = rules_of(&c).iter().any(|r| {
            r["domain_suffix"].as_array().map_or(false, |a| a.iter().any(|x| x == "grid.gg"))
                && r["outbound"] == "основной"
        });
        assert!(hit, "домен из правил обязан идти через прокси и в туннеле");
    }

    #[test]
    fn подсети_тоже_переходят() {
        let c = build_config_with(
            Path::new("."),
            &[],
            &[DomainRule { pattern: "10.0.0.0/8".into(), via: "основной".into() }],
            &[corp()],
        );
        let hit = rules_of(&c).iter().any(|r| {
            r["ip_cidr"].as_array().map_or(false, |a| a.iter().any(|x| x == "10.0.0.0/8"))
                && r["outbound"] == "основной"
        });
        assert!(hit, "подсеть из правил обязана сохраниться");
    }

    /// Служебные записи списка (группы) адресами не являются.
    #[test]
    fn служебные_записи_не_попадают() {
        let c = build_config_with(
            Path::new("."),
            &[],
            &[DomainRule { pattern: "_Группа".into(), via: "основной".into() }],
            &[corp()],
        );
        let has = rules_of(&c).iter().any(|r| r.get("domain_suffix").is_some());
        assert!(!has, "служебной записи в настройках движка не место");
    }
}

/// Полная картина: что есть на диске, что работает, что в журналах.
///
/// ⛔ Без этого разбор сводится к догадкам: «перехват включён, а не
/// работает» не говорит ничего. Здесь видно, дошло ли дело до файлов,
/// поднялся ли наблюдатель, что ответила система.
pub fn diagnosis(dir: &Path) -> String {
    let mut out = String::new();
    let say = |o: &mut String, name: &str, p: std::path::PathBuf| {
        let mark = if p.exists() {
            match std::fs::metadata(&p) {
                Ok(m) => format!("есть, {} Б", m.len()),
                Err(_) => "есть".into(),
            }
        } else {
            "НЕТ".into()
        };
        o.push_str(&format!("{name}: {mark}\n  {}\n", p.display()));
    };

    out.push_str("── файлы ──\n");
    say(&mut out, "закрытая папка", crate::tunnel_service::secure_dir(dir));
    say(&mut out, "копия для службы", crate::tunnel_service::runner_path(dir));
    say(&mut out, "движок", engine_at_hand(dir));
    say(&mut out, "настройки", config_path(dir));
    say(&mut out, "признак включения", dir.join("enabled"));
    say(&mut out, "журнал движка", engine_log_path(dir));
    #[cfg(target_os = "macos")]
    {
        say(&mut out, "наблюдатель", dir.join("watch.sh"));
        say(&mut out, "описание демона",
            std::path::PathBuf::from("/Library/LaunchDaemons/NexusProxyTunnel.plist"));
    }

    // ⛔ Что именно мы ловим — половина разбора. Если в журнале движка
    // нет нужного процесса, надо сразу видеть, по какому образцу его
    // искали: имя могло не совпасть с настоящим.
    out.push_str("\n── кого ловим ──\n");
    match std::fs::read_to_string(config_path(dir))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
    {
        Some(cfg) => {
            let empty = Vec::new();
            let rules = cfg["route"]["rules"].as_array().unwrap_or(&empty);
            for r in rules {
                let to = r["outbound"].as_str().unwrap_or("?");
                if let Some(names) = r["process_name"].as_array() {
                    out.push_str(&format!("по имени: {} → {to}\n",
                        names.iter().filter_map(|n| n.as_str())
                             .collect::<Vec<_>>().join(", ")));
                }
                if let Some(paths) = r["process_path_regex"].as_array() {
                    for p in paths.iter().filter_map(|p| p.as_str()) {
                        out.push_str(&format!("по пути: {p} → {to}\n"));
                    }
                }
            }
            let doms = rules.iter()
                .filter_map(|r| r["domain_suffix"].as_array().map(|a| a.len()))
                .sum::<usize>();
            out.push_str(&format!("правил по доменам: {doms}\n"));
        }
        None => out.push_str("настройки не читаются\n"),
    }

    out.push_str("\n── состояние ──\n");
    out.push_str(&format!("служба: {:?}\n", crate::tunnel_service::state_in(dir)));
    // ⛔ Не по списку процессов: движок принадлежит системе и человеку
    // в нём не виден — при работающем перехвате тут неизменно значилось
    // «нет», и разбор уходил в сторону.
    out.push_str(&format!("движок работает: {}\n",
        if is_alive(dir) { "да" } else { "нет" }));

    // ⛔ Какие процессы движок РЕАЛЬНО увидел. Если приложения тут нет,
    // значит система не отдала ему путь — и никакое правило по процессу
    // не сработает, сколько его ни правь.
    // ⛔ Системные настройки прокси — первое, что надо видеть. Браузеры
    // (кроме Firefox) читают их и идут туда напрямую, минуя туннель: их
    // соединений в журнале нет вовсе, и это выглядит как «перехват их не
    // ловит», хотя он их просто не видит.
    out.push_str("\n── системные настройки прокси ──\n");
    out.push_str(&crate::sysproxy::current());
    out.push('\n');

    out.push_str("\n── чьи соединения движок опознал ──\n");
    match std::fs::read_to_string(engine_log_path(dir)) {
        Ok(t) => {
            let mut seen: Vec<String> = t.lines()
                .filter_map(|l| l.split("found process path: ").nth(1))
                .map(|rest| rest.split(", user:").next().unwrap_or(rest).to_string())
                .collect();
            seen.sort();
            seen.dedup();
            if seen.is_empty() {
                out.push_str("ни одного — система не отдаёт пути процессов\n");
            } else {
                for p in seen.iter().take(20) {
                    out.push_str(&format!("{p}\n"));
                }
            }
        }
        Err(_) => out.push_str("журнал движка не читается\n"),
    }

    out.push_str("\n── журнал ──\n");
    out.push_str(&log_tail(dir, 40));
    out
}

/// Работает ли движок прямо сейчас — смотрим в списке процессов, а не
/// по своим записям: он мог уйти сам.
pub fn engine_running(dir: &Path) -> bool {
    let bin = binary_path(dir);
    if !bin.is_file() {
        return false;
    }
    #[cfg(windows)]
    {
        crate::proc::path_of_pid(std::process::id()); // прогреваем доступ
        count_processes(&bin) > 0
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new("pgrep")
            .arg("-f").arg(bin.to_string_lossy().as_ref())
            .output()
            .map(|o| !o.stdout.is_empty())
            .unwrap_or(false)
    }
}

#[cfg(windows)]
fn count_processes(bin: &Path) -> usize {
    use windows_sys::Win32::System::ProcessStatus::EnumProcesses;
    let want = bin.to_string_lossy().to_lowercase();
    let mut pids = vec![0u32; 4096];
    let mut needed = 0u32;
    let mut n = 0;
    unsafe {
        if EnumProcesses(pids.as_mut_ptr(), (pids.len() * 4) as u32, &mut needed) == 0 {
            return 0;
        }
        for &pid in pids.iter().take(needed as usize / 4) {
            if pid == 0 {
                continue;
            }
            if let Some(p) = crate::proc::path_of_pid(pid) {
                if p.to_lowercase() == want {
                    n += 1;
                }
            }
        }
    }
    n
}

#[cfg(test)]
mod quic_tests {
    use super::*;

    /// ⛔ Весь UDP идёт напрямую: через SOCKS5 он не проходит вовсе.
    /// Заворачивая его в прокси, мы либо теряем соединение, либо
    /// вынуждаем программу откатиться на TCP — так у видеозвонков и
    /// падало качество.
    #[test]
    fn весь_udp_идёт_напрямую() {
        let c = build_config(
            &[Route { process: "Cursor".into(), path: "/Applications/Cursor.app".into(),
                      via: "основной".into() }],
            &[Upstream { tag: "основной".into(), kind: Kind::Socks5,
                         address: "172.31.211.1".into(), port: 1081,
                         user: None, password: None }],
        );
        let rules = c["route"]["rules"].as_array().unwrap();
        let udp = rules.iter().position(|r| {
            r["network"] == "udp" && r["outbound"] == "direct" && r.get("port").is_none()
        }).expect("весь UDP обязан идти напрямую");
        let app = rules.iter().position(|r| r.get("process_name").is_some()).unwrap();
        assert!(udp < app,
                "UDP должен уходить напрямую раньше правил приложений: {udp} и {app}");
    }
}

#[cfg(test)]
mod sniff_tests {
    use super::*;

    /// ⛔ В туннеле движок видит пакеты, а не запросы: имя узла ему
    /// неоткуда взять. Без распознавания домены не определяются, и
    /// правила по ним не работают — остаются только адреса.
    #[test]
    fn домены_распознаются() {
        let c = build_config(&[], &[]);
        let first = c["route"]["rules"].as_array().unwrap().first().unwrap();
        assert_eq!(first["action"], "sniff",
                   "распознавание должно стоять первым, до всех решений");
    }
}

#[cfg(test)]
mod dns_tests {
    use super::*;

    /// ⛔ Туннель не должен отвечать за разрешение имён: внутренние
    /// адреса — контроллеры домена, файловые ресурсы — за корпоративным
    /// прокси не видны. У пользователя из-за этого повисла оснастка
    /// управления доменом, хотя по адресам всё было доступно.
    #[test]
    fn запросы_имён_идут_мимо_нас() {
        let c = build_config(&[], &[]);
        let hit = c["route"]["rules"].as_array().unwrap().iter().any(|r| {
            r["port"].as_array().map_or(false, |p| p.iter().any(|x| x == 53))
                && r["outbound"] == "direct"
        });
        assert!(hit, "запросы имён обязаны идти напрямую");
        // ⛔ Адреса серверов имён снимаются с системы ДО включения
        // туннеля и задаются явно: «спросить у системы» после запуска
        // означало бы спросить у самого туннеля — запрос ушёл бы по
        // кругу, и внутренние имена перестали бы разрешаться.
        let servers = c["dns"]["servers"].as_array().unwrap();
        assert!(servers.iter().all(|s| s["type"] == "udp"),
                "серверы имён задаются явными адресами: {servers:?}");
        assert!(servers.iter().all(|s| {
            !s["server"].as_str().unwrap_or("").starts_with("172.19.0.")
        }), "адрес туннеля среди серверов имён — это петля");
    }
}

#[cfg(test)]
mod and_tests {
    use super::*;

    /// ⛔ Внутри одного правила движок требует совпадения ВСЕХ условий.
    /// Имя и путь вместе — условие, которое не выполняется никогда:
    /// главный процесс зовётся «Cursor», а работает «Cursor Helper
    /// (Plugin)» — путь подходит, имя нет. Перехват приложений из-за
    /// этого не работал вовсе.
    #[test]
    fn имя_и_путь_разными_правилами() {
        let c = build_config(
            &[Route { process: "Cursor".into(),
                      path: "/Applications/Cursor.app".into(),
                      via: "основной".into() }],
            &[Upstream { tag: "основной".into(), kind: Kind::Socks5,
                         address: "172.31.211.1".into(), port: 1081,
                         user: None, password: None }],
        );
        let rules = c["route"]["rules"].as_array().unwrap();
        let both = rules.iter().any(|r| {
            r.get("process_name").is_some() && r.get("process_path_regex").is_some()
        });
        assert!(!both, "имя и путь в одном правиле не сработают никогда");

        assert!(rules.iter().any(|r| r.get("process_name").is_some()),
                "правило по имени должно быть");
        assert!(rules.iter().any(|r| r.get("process_path_regex").is_some()
                                     && r["outbound"] != "direct"),
                "правило по пути должно быть");
    }
}

#[cfg(test)]
mod mtu_tests {
    use super::*;

    /// ⛔ Без явного размера пакета движок берёт куда больше, чем
    /// пропускает сеть: мелкое ходит, крупное молча теряется. Так у
    /// пользователя висла оснастка управления доменом — она тянет
    /// большие ответы, — при работающих RDP и пинге.
    #[test]
    fn размер_пакета_задан() {
        let c = build_config(&[], &[]);
        assert_eq!(c["inbounds"][0]["mtu"], 1400);
    }

    /// Строгий режим мешает программам, работающим со службами своей
    /// сети. Он защищает от утечки запросов имён, но мы их не трогаем.
    #[test]
    fn строгий_режим_выключен() {
        let c = build_config(&[], &[]);
        assert_eq!(c["inbounds"][0]["strict_route"], false);
    }
}

/// Настоящие серверы имён — те, что были в системе до нас.
///
/// ⛔ Спрашивать «у системы» нельзя: включив туннель, движок прописывает
/// себя её сервером имён, и указание «local» заворачивает запросы обратно
/// в него же. У пользователя `nslookup` показывал адрес туннеля вместо
/// корпоративного сервера, и внутренние имена разрешались неверно.
/// Поэтому спрашиваем ДО включения и передаём явными адресами.
pub fn system_resolvers() -> Vec<String> {
    let out = if cfg!(windows) {
        std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command",
                   "Get-DnsClientServerAddress -AddressFamily IPv4 | \
                    Select-Object -ExpandProperty ServerAddresses"])
            .output()
    } else if cfg!(target_os = "macos") {
        std::process::Command::new("scutil").arg("--dns").output()
    } else {
        std::process::Command::new("cat").arg("/etc/resolv.conf").output()
    };
    let text = match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return Vec::new(),
    };

    let mut found: Vec<String> = Vec::new();
    for line in text.lines() {
        let candidate = line
            .split_whitespace()
            .find(|w| w.parse::<std::net::Ipv4Addr>().is_ok())
            .map(|w| w.to_string());
        if let Some(ip) = candidate {
            // ⛔ Свой же адрес в список не берём: это и есть петля.
            if ip.starts_with("172.19.0.") || ip == "0.0.0.0" {
                continue;
            }
            if !found.contains(&ip) {
                found.push(ip);
            }
        }
    }
    found.truncate(4);
    found
}

#[cfg(test)]
mod resolver_tests {
    use super::*;

    /// Адрес самого туннеля в список попасть не должен — это петля:
    /// запрос имени уходит в туннель, который спрашивает туннель.
    #[test]
    fn свой_адрес_не_берём() {
        let r = system_resolvers();
        assert!(!r.iter().any(|ip| ip.starts_with("172.19.0.")),
                "адрес туннеля в серверах имён — петля: {r:?}");
    }
}

/// Спросить у движка, годятся ли настройки.
fn check_config(dir: &Path) -> Result<(), String> {
    let bin = engine_at_hand(dir);
    if !bin.is_file() {
        return Ok(()); // движка ещё нет — проверять нечем
    }
    let mut cmd = std::process::Command::new(&bin);
    cmd.arg("check").arg("-c").arg(config_path(dir)).current_dir(dir);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    match cmd.output() {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let said = String::from_utf8_lossy(&o.stdout).to_string()
                + &String::from_utf8_lossy(&o.stderr);
            Err(said.lines().rev()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("причина неизвестна")
                .to_string())
        }
        // Сам вызов не удался — не повод ломать включение.
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod resolver_setting_tests {
    use super::*;

    /// ⛔ Без указания сервера имён по умолчанию движок отказывается
    /// запускаться вовсе. Наблюдатель поднимал его каждые две секунды,
    /// а человек видел «перехват включён» и неработающую сеть.
    #[test]
    fn сервер_имён_по_умолчанию_задан() {
        let c = build_config(&[], &[]);
        let name = c["route"]["default_domain_resolver"].as_str().unwrap_or("");
        assert!(!name.is_empty(), "движок не запустится без этого");
        let servers = c["dns"]["servers"].as_array().unwrap();
        assert!(servers.iter().any(|s| s["tag"] == name),
                "названный сервер должен существовать: {servers:?}");
    }

    /// Даже если у системы не спросить адреса, настройки обязаны
    /// остаться рабочими: пустой список означал бы отказ запуска.
    #[test]
    fn серверов_имён_всегда_хотя_бы_один() {
        let c = build_config(&[], &[]);
        assert!(!c["dns"]["servers"].as_array().unwrap().is_empty());
    }
}

#[cfg(test)]
mod order_of_rules_tests {
    use super::*;

    /// ⛔ Правила по приложениям должны стоять как можно раньше. Движок
    /// спрашивает у системы, чей это процесс, когда до правила доходит
    /// очередь, — а короткие соединения браузера к этому моменту уже
    /// закрыты, и спрашивать не у кого. Системные службы держат
    /// соединения долго и потому опознавались, браузеры — никогда.
    #[test]
    fn приложения_проверяются_раньше_доменов() {
        let c = build_config_with(
            Path::new("."),
            &[Route { process: "Cursor".into(),
                      path: "/Applications/Cursor.app".into(),
                      via: "основной".into() }],
            &[DomainRule { pattern: "domain:grid.gg".into(), via: "основной".into() }],
            &[Upstream { tag: "основной".into(), kind: Kind::Socks5,
                         address: "172.31.211.1".into(), port: 1081,
                         user: None, password: None }],
        );
        let rules = c["route"]["rules"].as_array().unwrap();
        let app = rules.iter().position(|r| r.get("process_name").is_some()).unwrap();
        let dom = rules.iter().position(|r| r.get("domain_suffix").is_some()).unwrap();
        assert!(app < dom, "приложения обязаны проверяться раньше доменов: {app} и {dom}");
    }
}

#[cfg(test)]
mod helper_tests {
    use super::*;

    /// ⛔ Safari в сеть не ходит сам — за него это делает отдельный
    /// процесс системы, лежащий вне папки приложения. Обычное правило по
    /// пути до него не достаёт, и перехват его не ловит, хотя видит.
    #[test]
    fn сетевой_процесс_safari_тоже_ловится() {
        let c = build_config(
            &[Route { process: "Safari".into(),
                      path: "/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app".into(),
                      via: "основной".into() }],
            &[Upstream { tag: "основной".into(), kind: Kind::Socks5,
                         address: "172.31.211.1".into(), port: 1081,
                         user: None, password: None }],
        );
        let by_path = c["route"]["rules"].as_array().unwrap().iter()
            .find(|r| r.get("process_path_regex").is_some() && r["outbound"] != "direct")
            .expect("правило по пути должно быть");
        let all: Vec<&str> = by_path["process_path_regex"].as_array().unwrap()
            .iter().filter_map(|x| x.as_str()).collect();
        assert!(all.iter().any(|re| re.contains("StagedFrameworks")),
                "сетевой процесс Safari обязан попадать под правило: {all:?}");
    }

    /// Обычным программам лишних правил не добавляем.
    #[test]
    fn обычным_программам_ничего_лишнего() {
        assert!(helper_paths("/Applications/Cursor.app").is_empty());
        assert!(helper_paths(r"C:\Program Files\cursor\Cursor.exe").is_empty());
    }
}

/// Сколько журналу движка позволено занимать.
///
/// ⛔ На подробном уровне он растёт мегабайтами в час. Без обрезки за
/// неделю работы набежали бы сотни мегабайт в папке настроек — человек
/// такого не ждёт и не найдёт, куда делось место.
pub const LOG_LIMIT: u64 = 8 * 1024 * 1024;

/// Обрезать журнал, если разросся: оставляем хвост, начало не нужно.
pub fn trim_log(dir: &Path) {
    let path = engine_log_path(dir);
    let len = match std::fs::metadata(&path) {
        Ok(m) => m.len(),
        Err(_) => return,
    };
    if len <= LOG_LIMIT {
        return;
    }
    if let Some(tail) = tail_of(&path, LOG_LIMIT / 2) {
        let _ = std::fs::write(&path, tail);
        crate::logfile::line(&crate::logfile::now_stamp(),
            &format!("перехват: журнал движка обрезан ({len} байт)"));
    }
}

/// Последние байты файла — целиком его читать незачем и вредно.
fn tail_of(path: &Path, bytes: u64) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let from = len.saturating_sub(bytes);
    f.seek(SeekFrom::Start(from)).ok()?;
    let mut buf = Vec::with_capacity(bytes.min(len) as usize);
    f.read_to_end(&mut buf).ok()?;
    // Начало куска может рассечь строку посередине — отбрасываем её.
    let text = String::from_utf8_lossy(&buf).to_string();
    Some(if from > 0 {
        text.splitn(2, '\n').nth(1).unwrap_or("").to_string()
    } else {
        text
    })
}

#[cfg(test)]
mod api_tests {
    use super::*;

    /// ⛔ Занятый посторонним порт роняет движок целиком, и перехват не
    /// поднимается. Значит при занятом порте берём другой.
    #[test]
    fn занятый_чужим_порт_меняется() {
        let dir = std::env::temp_dir().join("np-api-busy");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::remove_file(api_path(&dir));

        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let busy = held.local_addr().unwrap().port();
        std::fs::write(api_path(&dir),
            serde_json::to_vec(&Api { port: busy, secret: "x".repeat(32) }).unwrap()).unwrap();

        let a = api_access(&dir);
        assert_ne!(a.port, busy, "остался занятый порт — движок не поднимется");
        drop(held);
        let _ = std::fs::remove_file(api_path(&dir));
    }

    /// А свой порт не трогаем: иначе настройки переписывались бы и
    /// движок перезапускался по кругу.
    #[test]
    fn свободный_порт_остаётся_прежним() {
        let dir = std::env::temp_dir().join("np-api-keep");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::remove_file(api_path(&dir));
        let first = api_access(&dir);
        let again = api_access(&dir);
        assert_eq!(first.port, again.port, "порт меняется на ровном месте");
        assert_eq!(first.secret, again.secret);
        let _ = std::fs::remove_file(api_path(&dir));
    }
}

#[cfg(test)]
mod tail_tests {
    use super::*;

    /// ⛔ Журнал движка растёт до мегабайтов за минуты. Читая его
    /// целиком, мы подвешивали окно — а читаем каждые несколько секунд.
    #[test]
    fn берём_только_хвост() {
        let d = std::env::temp_dir().join(format!("np-tail-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("big.log");
        let mut text = String::new();
        for i in 0..50_000 {
            text.push_str(&format!("строка номер {i}\n"));
        }
        std::fs::write(&f, &text).unwrap();

        let tail = tail_of(&f, 4096).unwrap();
        assert!(tail.len() <= 4096, "прочитали больше, чем просили: {}", tail.len());
        assert!(tail.contains("49999"), "хвост должен быть концом файла");
        assert!(!tail.contains("строка номер 0\n"), "начало файла читать незачем");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Обрезанную первую строку не показываем: она бессмысленна.
    #[test]
    fn рассечённую_строку_отбрасываем() {
        let d = std::env::temp_dir().join(format!("np-tail2-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("x.log");
        std::fs::write(&f, "первая строка\nвторая строка\nтретья\n").unwrap();
        let tail = tail_of(&f, 20).unwrap();
        assert!(!tail.starts_with("рая"), "обрывок строки не годится: {tail}");
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod trim_tests {
    use super::*;

    /// ⛔ Без обрезки журнал движка съедает сотни мегабайт за неделю:
    /// на подробном уровне он растёт мегабайтами в час.
    #[test]
    fn разросшийся_журнал_обрезается() {
        let d = std::env::temp_dir().join(format!("np-trim-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let big = "строка журнала движка\n".repeat(600_000);
        std::fs::write(engine_log_path(&d), &big).unwrap();
        assert!(std::fs::metadata(engine_log_path(&d)).unwrap().len() > LOG_LIMIT);

        trim_log(&d);
        let after = std::fs::metadata(engine_log_path(&d)).unwrap().len();
        assert!(after <= LOG_LIMIT, "после обрезки {after} байт");
        assert!(after > 0, "журнал не должен исчезать целиком");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn небольшой_журнал_не_трогаем() {
        let d = std::env::temp_dir().join(format!("np-trim2-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(engine_log_path(&d), "немного строк\n").unwrap();
        trim_log(&d);
        assert_eq!(std::fs::read_to_string(engine_log_path(&d)).unwrap(), "немного строк\n");
        let _ = std::fs::remove_dir_all(&d);
    }
}
