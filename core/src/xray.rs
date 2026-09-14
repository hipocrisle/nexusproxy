//! Запуск xray по требованию.
//!
//! В состав программы xray НЕ входит: его бинарник ловит антивирус на
//! рабочих машинах, а нужен он только тем, кто пользуется подпиской.
//! Поэтому скачиваем из официальных выпусков по явному нажатию.
//!
//! Каждой стране из подписки поднимаем свой локальный вход. Дальше они
//! попадают в общий список прокси наравне с офисным, и правило можно
//! направить в любую страну.

use crate::subscription::Profile;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

/// Последняя причина, по которой ядро не поднялось. Держим отдельно:
/// процесс может умереть и через минуту после запуска, и тогда рассказать
/// об этом больше нечему.
pub static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

pub fn log_path(dir: &Path) -> PathBuf {
    dir.join("xray.log")
}

/// Хвост журнала ядра — то, что оно сказало перед смертью.
pub fn log_tail(dir: &Path, lines: usize) -> String {
    let text = std::fs::read_to_string(log_path(dir)).unwrap_or_default();
    let all: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

pub fn last_error() -> Option<String> {
    LAST_ERROR.lock().unwrap().clone()
}

/// С какого порта начинаем раздавать входы по странам.
pub const FIRST_PORT: u16 = 20800;

const RELEASES: &str = "https://api.github.com/repos/XTLS/Xray-core/releases/latest";

/// Имя файла в выпуске под текущую систему.
fn asset_name() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => Some("Xray-windows-64.zip"),
        ("windows", "aarch64") => Some("Xray-windows-arm64-v8a.zip"),
        ("macos", "x86_64") => Some("Xray-macos-64.zip"),
        ("macos", "aarch64") => Some("Xray-macos-arm64-v8a.zip"),
        ("linux", "x86_64") => Some("Xray-linux-64.zip"),
        ("linux", "aarch64") => Some("Xray-linux-arm64-v8a.zip"),
        _ => None,
    }
}

fn exe_name() -> &'static str {
    if cfg!(windows) { "xray.exe" } else { "xray" }
}

pub fn binary_path(dir: &Path) -> PathBuf {
    dir.join(exe_name())
}

pub fn is_installed(dir: &Path) -> bool {
    binary_path(dir).is_file()
}

/// Скачать xray в указанную папку. Возвращает версию.
pub fn download(dir: &Path) -> Result<String, String> {
    let asset = asset_name().ok_or("для этой системы готовой сборки xray нет")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("не создать папку: {e}"))?;

    let meta: serde_json::Value = ureq::get(RELEASES)
        .header("User-Agent", "NexusProxy")
        .call()
        .map_err(|e| format!("не получить список выпусков: {e}"))?
        .body_mut()
        .read_json()
        .map_err(|e| format!("испорченный ответ: {e}"))?;

    let version = meta["tag_name"].as_str().unwrap_or("неизвестно").to_string();
    let url = meta["assets"].as_array().ok_or("в выпуске нет файлов")?
        .iter()
        .find(|a| a["name"].as_str() == Some(asset))
        .and_then(|a| a["browser_download_url"].as_str())
        .ok_or_else(|| format!("в выпуске нет файла {asset}"))?
        .to_string();

    let body: Vec<u8> = ureq::get(&url)
        .header("User-Agent", "NexusProxy")
        .call()
        .map_err(|e| format!("не скачать {asset}: {e}"))?
        .body_mut()
        // выпуск весит десятки мегабайт, поднимаем ограничение
        .with_config()
        .limit(80 * 1024 * 1024)
        .read_to_vec()
        .map_err(|e| format!("обрыв при скачивании: {e}"))?;

    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(body))
        .map_err(|e| format!("архив не читается: {e}"))?;
    let mut found = false;
    for i in 0..zip.len() {
        let mut f = zip.by_index(i).map_err(|e| e.to_string())?;
        let name = f.name().rsplit('/').next().unwrap_or("").to_string();
        if name == exe_name() || name == "geoip.dat" || name == "geosite.dat" {
            let dest = dir.join(&name);
            let mut out = std::fs::File::create(&dest)
                .map_err(|e| format!("не записать {name}: {e}"))?;
            std::io::copy(&mut f, &mut out).map_err(|e| format!("не записать {name}: {e}"))?;
            if name == exe_name() {
                found = true;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755));
                }
            }
        }
    }
    if !found {
        return Err("в архиве не оказалось самого xray".into());
    }
    Ok(version)
}

/// Настройки: по одному входу на страну, каждый — в свой выход.
pub fn build_config(profiles: &[Profile]) -> serde_json::Value {
    let mut inbounds = Vec::new();
    let mut outbounds = Vec::new();
    let mut rules = Vec::new();

    for (i, p) in profiles.iter().enumerate() {
        let tag = format!("p{i}");
        let port = FIRST_PORT + i as u16;
        inbounds.push(json!({
            "tag": format!("in{i}"),
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": { "udp": true, "auth": "noauth" },
            "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
        }));
        let mut ob = p.outbound.clone();
        ob["tag"] = json!(tag);
        outbounds.push(ob);
        rules.push(json!({ "type": "field", "inboundTag": [format!("in{i}")], "outboundTag": tag }));
    }
    outbounds.push(json!({ "tag": "direct", "protocol": "freedom" }));

    json!({
        "log": { "loglevel": "warning" },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": { "domainStrategy": "AsIs", "rules": rules }
    })
}

/// Порт, на котором слушает страна с этим номером.
pub fn port_for(index: usize) -> u16 {
    FIRST_PORT + index as u16
}

static CHILD: Mutex<Option<Child>> = Mutex::new(None);

/// Запустить xray с настройками под список стран.
/// Запуск не должен идти в два голоса: сторож раз в 15 секунд видит, что
/// ядра нет, и лезет поднимать — а поднятие уже идёт. Два ядра дерутся
/// за одни порты, и оба падают.
static STARTING: Mutex<()> = Mutex::new(());

pub fn start(dir: &Path, profiles: &[Profile]) -> Result<(), String> {
    let _one_at_a_time = STARTING.lock().unwrap_or_else(|e| e.into_inner());
    stop();
    if profiles.is_empty() {
        return Err("список стран пуст".into());
    }
    let bin = binary_path(dir);
    if !bin.is_file() {
        return Err("xray ещё не скачан".into());
    }
    // Осиротевшее ядро от прошлого запуска держит порты — новое их не займёт
    let orphans = kill_orphans(&bin);
    if orphans > 0 {
        crate::logfile::line(&crate::logfile::now_stamp(),
            &format!("осталось ядер от прошлого запуска: {orphans}, остановлены"));
        // порту нужно время освободиться
        std::thread::sleep(std::time::Duration::from_millis(400));
    }

    let cfg_path = dir.join("xray-config.json");
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&build_config(profiles)).unwrap())
        .map_err(|e| format!("не записать настройки: {e}"))?;

    // ⛔ Вывод ядра обязан куда-то писаться. Без этого его падение —
    // немая красная точка в списке прокси: порт не слушается, а почему —
    // узнать неоткуда.
    let log = std::fs::File::create(log_path(dir))
        .map_err(|e| format!("не создать журнал ядра: {e}"))?;
    let log_err = log.try_clone().map_err(|e| format!("не создать журнал ядра: {e}"))?;

    let mut cmd = Command::new(&bin);
    cmd.arg("run").arg("-c").arg(&cfg_path).current_dir(dir)
        .stdout(Stdio::from(log)).stderr(Stdio::from(log_err));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // без окна консоли
    }
    let mut child = cmd.spawn().map_err(|e| {
        let m = format!("не запустить xray: {e}");
        *LAST_ERROR.lock().unwrap() = Some(m.clone());
        m
    })?;

    // ⛔ Мало запустить — надо убедиться, что ядро не умерло сразу.
    // Битые настройки, снесённый антивирусом файл, занятый порт: всё это
    // раньше выглядело как успешный запуск, потому что spawn отработал.
    std::thread::sleep(std::time::Duration::from_millis(900));
    if let Ok(Some(status)) = child.try_wait() {
        let tail = log_tail(dir, 6);
        let m = if tail.is_empty() {
            format!("ядро xray сразу завершилось ({status}) и ничего не сказало. \
                     Так ведёт себя файл, удалённый антивирусом")
        } else {
            format!("ядро xray сразу завершилось ({status}):\n{tail}")
        };
        *LAST_ERROR.lock().unwrap() = Some(m.clone());
        return Err(m);
    }

    #[cfg(windows)]
    assign_to_job(&child);

    *LAST_ERROR.lock().unwrap() = None;
    *CHILD.lock().unwrap() = Some(child);
    Ok(())
}

/// ⛔ Windows: без Job Object дочерний процесс переживает родителя.
/// Программу закрыли, а ядро осталось держать порты — и следующий запуск
/// падает с «Only one usage of each socket address». Привязка к заданию
/// с KILL_ON_JOB_CLOSE решает это в корне.
#[cfg(windows)]
fn assign_to_job(child: &Child) {
    use std::sync::OnceLock;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
        JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
    };

    struct Job(HANDLE);
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}
    static JOB: OnceLock<Job> = OnceLock::new();

    let job = JOB.get_or_init(|| unsafe {
        let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if !h.is_null() {
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                h, JobObjectExtendedLimitInformation,
                &info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
        }
        Job(h)
    });
    if job.0.is_null() {
        return;
    }
    unsafe {
        let h = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, child.id());
        if !h.is_null() {
            AssignProcessToJobObject(job.0, h);
            CloseHandle(h);
        }
    }
}

pub fn stop() {
    if let Some(mut c) = CHILD.lock().unwrap().take() {
        let _ = c.kill();
        let _ = c.wait();
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subscription;

    fn profiles() -> Vec<Profile> {
        subscription::parse(
            "vless://u1@a.example:443?type=tcp#Германия\nvless://u2@b.example:443?type=ws#Франция",
        )
        .unwrap()
    }

    #[test]
    fn each_country_gets_its_own_entry() {
        let c = build_config(&profiles());
        let ins = c["inbounds"].as_array().unwrap();
        assert_eq!(ins.len(), 2, "по входу на страну");
        assert_eq!(ins[0]["port"], FIRST_PORT);
        assert_eq!(ins[1]["port"], FIRST_PORT + 1);
    }

    #[test]
    fn entry_leads_to_its_own_country() {
        let c = build_config(&profiles());
        let rules = c["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        // вход №1 обязан вести в выход №1, иначе страны перепутаются
        assert_eq!(rules[0]["inboundTag"][0], "in0");
        assert_eq!(rules[0]["outboundTag"], "p0");
        assert_eq!(rules[1]["inboundTag"][0], "in1");
        assert_eq!(rules[1]["outboundTag"], "p1");
        let obs = c["outbounds"].as_array().unwrap();
        assert_eq!(obs[0]["settings"]["vnext"][0]["address"], "a.example");
        assert_eq!(obs[1]["settings"]["vnext"][0]["address"], "b.example");
    }

    #[test]
    fn config_is_valid_json_with_direct_fallback() {
        let c = build_config(&profiles());
        let obs = c["outbounds"].as_array().unwrap();
        assert_eq!(obs.last().unwrap()["protocol"], "freedom");
    }

    /// Настоящее скачивание. Обычным прогоном не идёт — сеть и десятки
    /// мегабайт. Запускать вручную: cargo test -- --ignored скачивание
    #[test]
    #[ignore]
    fn real_download_works() {
        let dir = std::env::temp_dir().join("np-xray-test");
        let _ = std::fs::remove_dir_all(&dir);
        let ver = download(&dir).expect("скачивание");
        println!("скачана версия {ver}");
        assert!(is_installed(&dir), "исполняемый файл должен появиться");
        let size = std::fs::metadata(binary_path(&dir)).unwrap().len();
        assert!(size > 1_000_000, "слишком маленький файл: {size}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_list_is_refused() {
        let dir = std::env::temp_dir();
        assert!(start(&dir, &[]).is_err());
    }
}

// ── Осиротевшее ядро ────────────────────────────────────────────────────
// ⛔ Самая частая причина «страны недоступны»: от прошлого запуска остался
// живой xray и держит порты 20800+, а новый не может их занять и умирает
// с «Only one usage of each socket address». На Windows дочерний процесс
// переживает родителя, если его не привязать к Job Object, — вот и копятся.
//
// Убиваем СТРОГО по полному пути своего файла: у Happ и других клиентов
// свой xray.exe, трогать его нельзя. [[feedback-no-broad-process-kill]]

#[cfg(windows)]
pub fn kill_orphans(bin: &Path) -> usize {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::ProcessStatus::EnumProcesses;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    };

    let want = bin.to_string_lossy().to_lowercase();
    let mut pids = vec![0u32; 4096];
    let mut needed = 0u32;
    let mut killed = 0;
    unsafe {
        if EnumProcesses(pids.as_mut_ptr(), (pids.len() * 4) as u32, &mut needed) == 0 {
            return 0;
        }
        let count = needed as usize / 4;
        let me = std::process::id();
        for &pid in pids.iter().take(count) {
            if pid == 0 || pid == me {
                continue;
            }
            match crate::proc::path_of_pid(pid) {
                Some(p) if p.to_lowercase() == want => {
                    let h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                    if !h.is_null() {
                        if TerminateProcess(h, 1) != 0 {
                            killed += 1;
                        }
                        CloseHandle(h);
                    }
                }
                _ => {}
            }
        }
    }
    killed
}

#[cfg(not(windows))]
pub fn kill_orphans(bin: &Path) -> usize {
    let out = Command::new("pgrep").arg("-f").arg(bin.to_string_lossy().as_ref()).output();
    let Ok(out) = out else { return 0 };
    let me = std::process::id().to_string();
    let mut killed = 0;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let pid = line.trim();
        if pid.is_empty() || pid == me {
            continue;
        }
        if Command::new("kill").arg("-9").arg(pid).status().map(|s| s.success()).unwrap_or(false) {
            killed += 1;
        }
    }
    killed
}
