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
use std::process::{Child, Command};
use std::sync::Mutex;

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
pub fn start(dir: &Path, profiles: &[Profile]) -> Result<(), String> {
    stop();
    if profiles.is_empty() {
        return Err("список стран пуст".into());
    }
    let bin = binary_path(dir);
    if !bin.is_file() {
        return Err("xray ещё не скачан".into());
    }
    let cfg_path = dir.join("xray-config.json");
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&build_config(profiles)).unwrap())
        .map_err(|e| format!("не записать настройки: {e}"))?;

    let mut cmd = Command::new(&bin);
    cmd.arg("run").arg("-c").arg(&cfg_path).current_dir(dir);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // без окна консоли
    }
    let child = cmd.spawn().map_err(|e| format!("не запустить xray: {e}"))?;
    *CHILD.lock().unwrap() = Some(child);
    Ok(())
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
