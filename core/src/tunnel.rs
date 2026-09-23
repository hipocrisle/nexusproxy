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

pub fn binary_path(dir: &Path) -> PathBuf {
    dir.join(exe_name())
}

pub fn is_installed(dir: &Path) -> bool {
    binary_path(dir).is_file()
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
    Some(p[..cut].to_string())
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

pub fn build_config(routes: &[Route], upstreams: &[Upstream]) -> serde_json::Value {
    build_config_with(routes, &[], upstreams)
}

/// ⛔ TUN режим заменяет режим прокси целиком, а не дополняет его.
/// Системные настройки при нём не трогаются, поэтому всё, что раньше
/// шло через прокси по правилам доменов, пойдёт напрямую — если не
/// перенести эти правила сюда. У пользователя так разом отвалилось всё,
/// кроме приложений из списка.
pub fn build_config_with(
    routes: &[Route],
    domains: &[DomainRule],
    upstreams: &[Upstream],
) -> serde_json::Value {
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
        // свои адреса — мимо перехвата
        serde_json::json!({
            "ip_is_private": true,
            "action": "route",
            "outbound": "direct"
        }),
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
    }
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

    for (via, (procs, paths)) in by_via {
        let mut rule = serde_json::json!({
            "process_name": procs,
            "action": "route",
            "outbound": via
        });
        if !paths.is_empty() {
            rule["process_path_regex"] = serde_json::json!(paths);
        }
        rules.push(rule);
    }

    serde_json::json!({
        "log": { "level": "warn", "timestamp": true },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "address": [TUN_ADDR],
            "auto_route": true,
            "strict_route": true
        }],
        "outbounds": outbounds,
        "route": {
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
            &[Route { process: "Cursor.exe".into(), path: format!("/Apps/{}", "Cursor.exe"), via: "основной".into() }],
            &[corp()],
        );
        let last = rules_of(&c).last().unwrap();
        assert_eq!(last["process_name"][0], "Cursor.exe");
        assert_eq!(last["outbound"], "основной");
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

    #[test]
    fn свои_адреса_идут_напрямую() {
        let c = build_config(&[], &[corp()]);
        assert_eq!(rules_of(&c)[0]["ip_is_private"], true);
        assert_eq!(rules_of(&c)[0]["outbound"], "direct");
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
    let url = asset["browser_download_url"].as_str()
        .ok_or("у файла нет ссылки")?.to_string();

    let body: Vec<u8> = ureq::get(&url)
        .header("User-Agent", "NexusProxy")
        .call()
        .map_err(|e| format!("не скачать движок: {e}"))?
        .body_mut()
        .with_config()
        .limit(120 * 1024 * 1024)
        .read_to_vec()
        .map_err(|e| format!("обрыв при скачивании: {e}"))?;

    let dest = binary_path(dir);
    let found = if want_zip {
        unpack_zip(&body, &dest)?
    } else {
        unpack_tar_gz(&body, &dest)?
    };
    if !found {
        return Err("в архиве не оказалось самого движка".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755));
    }
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
#[cfg(windows)]
pub fn start_elevated(dir: &Path, routes: &[Route], upstreams: &[Upstream]) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

    if routes.is_empty() {
        return Err("нет ни одного приложения — перехватывать нечего".into());
    }
    let bin = binary_path(dir);
    if !bin.is_file() {
        return Err("движок перехвата ещё не скачан".into());
    }

    let cfg_path = dir.join("tunnel-config.json");
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&build_config(routes, upstreams)).unwrap())
        .map_err(|e| format!("не записать настройки: {e}"))?;

    let wide = |s: &std::ffi::OsStr| -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    };
    let verb = wide(std::ffi::OsStr::new("runas"));
    let file = wide(bin.as_os_str());
    let args = wide(std::ffi::OsStr::new(
        &format!("run -c \"{}\"", cfg_path.display())));
    let cwd = wide(dir.as_os_str());

    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = args.as_ptr();
    info.lpDirectory = cwd.as_ptr();
    info.nShow = 0; // без окна

    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok == 0 {
        // Человек мог нажать «Нет» в окне подтверждения — это не ошибка
        // программы, и говорить надо именно так.
        return Err("права администратора не выданы — перехват не включён".into());
    }
    *ELEVATED.lock().unwrap() = Some(info.hProcess as isize);
    Ok(())
}

#[cfg(not(windows))]
pub fn start_elevated(dir: &Path, routes: &[Route], upstreams: &[Upstream]) -> Result<(), String> {
    // На macOS повышение прав устроено иначе; пока запускаем как есть —
    // если прав не хватит, start() скажет об этом прямо.
    start(dir, routes, upstreams)
}

static ELEVATED: Mutex<Option<isize>> = Mutex::new(None);

/// Остановить движок, запущенный с повышением.
#[cfg(windows)]
pub fn stop_elevated() {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::TerminateProcess;
    if let Some(h) = ELEVATED.lock().unwrap().take() {
        unsafe {
            TerminateProcess(h as *mut std::ffi::c_void, 0);
            CloseHandle(h as *mut std::ffi::c_void);
        }
    }
}

#[cfg(not(windows))]
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
    let bin = binary_path(dir);
    if !bin.is_file() {
        return 0;
    }
    crate::xray::kill_orphans(&bin)
}

/// Записать настройки для движка. Служба читает их при запуске.
pub fn write_config(dir: &Path, routes: &[Route], domains: &[DomainRule],
                    upstreams: &[Upstream]) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("не создать папку: {e}"))?;
    let cfg = build_config_with(routes, domains, upstreams);
    std::fs::write(config_path(dir), serde_json::to_vec_pretty(&cfg).unwrap())
        .map_err(|e| format!("не записать настройки: {e}"))?;
    // Какие именно процессы ловим — самое важное для разбора: если имя
    // не совпадёт с настоящим, перехват работает, а трафик идёт мимо.
    crate::logfile::line(&crate::logfile::now_stamp(),
        &format!("перехват: ловим процессы [{}], правил по адресам: {}",
                 routes.iter().map(|r| format!("{} → {}", r.process, r.via))
                       .collect::<Vec<_>>().join(", "),
                 domains.len()));
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
    loop {
        let want = flag.exists();
        let fresh = config_stamp(dir);
        let changed = fresh != cfg_stamp;

        match (&mut running, want) {
            // просят работать, а движка нет — поднимаем
            (None, true) => {
                cfg_stamp = fresh;
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
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
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

pub fn run_foreground(dir: &Path) -> Result<(), String> {
    crate::logfile::open(dir.join("runner.log")).ok();
    crate::logfile::line(&crate::logfile::now_stamp(),
        &format!("перехват: запускаю движок из {}", dir.display()));
    // ⛔ Движок от прошлого запуска держит сетевой интерфейс, и новый
    // падает с «The object already exists». Снимаем старый и ждём, пока
    // система уберёт интерфейс: иначе тот же отказ, только позже.
    let left = kill_orphans(dir);
    if left > 0 {
        crate::logfile::line(&crate::logfile::now_stamp(),
            &format!("перехват: снят прежний движок ({left})"));
        std::thread::sleep(std::time::Duration::from_millis(1200));
    }
    let bin = binary_path(dir);
    if !bin.is_file() {
        return Err(format!("движок перехвата не найден: {}", bin.display()));
    }
    let cfg = config_path(dir);
    let log = std::fs::File::create(log_path(dir))
        .map_err(|e| format!("не создать журнал: {e}"))?;
    let log_err = log.try_clone().map_err(|e| format!("не создать журнал: {e}"))?;

    let mut cmd = std::process::Command::new(&bin);
    cmd.arg("run").arg("-c").arg(&cfg)
       .current_dir(dir)
       .stdout(log).stderr(log_err);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // без окна
    }
    let mut child = cmd.spawn().map_err(|e| format!("не запустить движок: {e}"))?;
    // ⛔ Иначе движок переживает того, кто его запустил: задачу сняли, а
    // он продолжает держать сетевой интерфейс и заворачивать трафик.
    // Человек закрыл программу — и не понимает, почему всё ещё работает.
    #[cfg(windows)]
    crate::xray::assign_to_job(&child);
    let code = child.wait();
    crate::logfile::line(&crate::logfile::now_stamp(),
        &format!("перехват: движок завершился ({code:?})"));
    Ok(())
}

/// Последние строки журнала движка — чтобы человек видел причину, а не
/// пустой экран с невключившимся перехватом.
pub fn log_tail(dir: &Path, lines: usize) -> String {
    let mut out = Vec::new();
    // Собираем все следы: что делали мы, что ответила система, что сказал
    // сам движок. Разбирать «не работает» по одному из них невозможно.
    for name in ["runner.log", "tunnel.log", "daemon.log"] {
        if let Ok(t) = std::fs::read_to_string(dir.join(name)) {
            out.extend(t.lines().rev()
                // ⛔ Не наши беды в журнал не тащим: соединения, ушедшие
                // напрямую и не дошедшие, — это сеть, а не перехват. Они
                // забивают журнал и мешают увидеть настоящую причину.
                .filter(|l| !l.contains("outbound/direct"))
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
    let rest = &line[start.min(line.len())..];
    if rest.len() >= 19 && rest.starts_with(|c: char| c.is_ascii_digit()) {
        rest[..19].to_string()
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
        let last = c["route"]["rules"].as_array().unwrap().last().unwrap();
        let re = last["process_path_regex"][0].as_str().unwrap();
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
    say(&mut out, "движок", binary_path(dir));
    say(&mut out, "настройки", config_path(dir));
    say(&mut out, "признак включения", dir.join("enabled"));
    #[cfg(target_os = "macos")]
    {
        say(&mut out, "наблюдатель", dir.join("watch.sh"));
        say(&mut out, "описание демона",
            std::path::PathBuf::from("/Library/LaunchDaemons/NexusProxyTunnel.plist"));
    }

    out.push_str("\n── состояние ──\n");
    out.push_str(&format!("служба: {:?}\n", crate::tunnel_service::state_in(dir)));
    out.push_str(&format!("движок в списке процессов: {}\n",
        if engine_running(dir) { "да" } else { "нет" }));

    out.push_str("\n── журнал ──\n");
    out.push_str(&log_tail(dir, 25));
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
