//! Служба, поднимающая перехват, — своя на каждой системе.
//!
//! ⛔ Зачем она. Сетевой интерфейс создаётся только с правами
//! администратора. Просить их при каждом включении — ровно то, чем
//! людей раздражает Proxifier. Поэтому права спрашиваются ОДИН раз, при
//! установке службы; дальше перехват включается без единого вопроса.
//! Само окно программы прав не имеет и иметь не должно.
//!
//! Побочная польза: служба переживает перезапуск программы, поэтому
//! перехват не отваливается, когда человек закрыл и открыл окно.

use std::path::Path;

pub const NAME: &str = "NexusProxyTunnel";

/// Что сейчас со службой.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub enum State {
    /// Не установлена — нужен один запрос прав.
    Absent,
    /// Установлена, но перехват выключен.
    Stopped,
    /// Перехват работает.
    Running,
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::process::Command;

    /// Права на службу: система и администраторы — полностью, вошедший
    /// пользователь — запуск, остановка и чтение состояния.
    ///
    /// ⛔ Без последней части включение перехвата снова требовало бы
    /// администратора, и вся затея теряла бы смысл.
    const RIGHTS: &str = concat!(
        "D:",
        "(A;;CCLCSWRPWPDTLOCRRC;;;SY)",
        "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)",
        "(A;;CCLCSWRPWPLORC;;;IU)",
    );

    fn sc(args: &[&str]) -> Result<String, String> {
        let out = Command::new("sc.exe").args(args).output()
            .map_err(|e| format!("не вызвать sc: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr);
        if out.status.success() { Ok(text) } else { Err(text.trim().to_string()) }
    }

    pub fn state() -> State {
        match sc(&["query", NAME]) {
            Err(_) => State::Absent,
            Ok(t) if t.contains("RUNNING") => State::Running,
            Ok(_) => State::Stopped,
        }
    }

    /// Команда установки — выполняется один раз с повышением прав.
    ///
    /// ⛔ Кавычки обязательны: в путях бывают пробелы («Program Files»,
    /// имя пользователя). Без них служба получит обрезанный путь и молча
    /// не запустится — перехват «не работает», а почему, не видно.
    pub fn install_command(exe: &Path, config: &Path) -> String {
        format!(
            "sc.exe create {NAME} binPath= \"\\\"{}\\\" run -c \\\"{}\\\"\" start= demand \
             DisplayName= \"NexusProxy: перехват трафика\" && \
             sc.exe sdset {NAME} \"{RIGHTS}\"",
            exe.display(), config.display()
        )
    }

    pub fn uninstall_command() -> String {
        format!("sc.exe stop {NAME} & sc.exe delete {NAME}")
    }

    pub fn start() -> Result<(), String> {
        match sc(&["start", NAME]) {
            Ok(_) => Ok(()),
            // 1056 — уже работает, это не беда
            Err(e) if e.contains("1056") => Ok(()),
            Err(e) => Err(format!("перехват не включился: {e}")),
        }
    }

    pub fn stop() -> Result<(), String> {
        match sc(&["stop", NAME]) {
            Ok(_) => Ok(()),
            // 1062 — и так не запущена
            Err(e) if e.contains("1062") => Ok(()),
            Err(e) => Err(format!("перехват не выключился: {e}")),
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use std::process::Command;

    /// Где живёт описание службы. Каталог системный — туда кладут то,
    /// что должно работать от имени системы и переживать выход из неё.
    pub fn plist_path() -> std::path::PathBuf {
        std::path::PathBuf::from(format!("/Library/LaunchDaemons/{NAME}.plist"))
    }

    fn launchctl(args: &[&str]) -> Result<String, String> {
        let out = Command::new("launchctl").args(args).output()
            .map_err(|e| format!("не вызвать launchctl: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr);
        if out.status.success() { Ok(text) } else { Err(text.trim().to_string()) }
    }

    pub fn state() -> State {
        if !plist_path().exists() {
            return State::Absent;
        }
        match launchctl(&["print", &format!("system/{NAME}")]) {
            Ok(t) if t.contains("state = running") => State::Running,
            _ => State::Stopped,
        }
    }

    /// Описание службы для launchd.
    ///
    /// ⛔ `RunAtLoad` выключен: перехват включает человек, а не система
    /// при каждой загрузке. Иначе он поднимался бы сам, и человек не мог
    /// бы понять, почему трафик куда-то заворачивается.
    pub fn plist(exe: &Path, config: &Path) -> String {
        format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{NAME}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>run</string>
    <string>-c</string>
    <string>{}</string>
  </array>
  <key>RunAtLoad</key><false/>
  <key>KeepAlive</key><false/>
</dict>
</plist>
"#, exe.display(), config.display())
    }

    /// Ставится один раз с правами: положить описание и зарегистрировать.
    pub fn install_command(exe: &Path, config: &Path) -> String {
        let p = plist_path();
        // Пишем через здесь-документ: в путях бывают пробелы, а кавычки
        // внутри xml пришлось бы экранировать дважды.
        format!(
            "cat > '{}' <<'NEXUSPROXY_PLIST'\n{}NEXUSPROXY_PLIST\n\
             chown root:wheel '{}' && chmod 644 '{}' && \
             launchctl bootstrap system '{}'",
            p.display(), plist(exe, config), p.display(), p.display(), p.display()
        )
    }

    pub fn uninstall_command() -> String {
        let p = plist_path();
        format!("launchctl bootout system/{NAME}; rm -f '{}'", p.display())
    }

    pub fn start() -> Result<(), String> {
        launchctl(&["kickstart", &format!("system/{NAME}")])
            .map(|_| ())
            .map_err(|e| format!("перехват не включился: {e}"))
    }

    pub fn stop() -> Result<(), String> {
        launchctl(&["kill", "SIGTERM", &format!("system/{NAME}")])
            .map(|_| ())
            .map_err(|e| format!("перехват не выключился: {e}"))
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod imp {
    use super::*;
    pub fn state() -> State { State::Absent }
    pub fn install_command(_e: &Path, _c: &Path) -> String { String::new() }
    pub fn uninstall_command() -> String { String::new() }
    pub fn start() -> Result<(), String> { Err("перехват на этой системе не поддерживается".into()) }
    pub fn stop() -> Result<(), String> { Ok(()) }
}

pub use imp::{install_command, start, state, stop, uninstall_command};

// ⛔ Механизма нет на Linux, и проверять там нечего: заглушка отдаёт
// пустую строку. Тесты идут только там, где перехват работает.
#[cfg(all(test, any(windows, target_os = "macos")))]
mod tests {
    use super::*;

    /// ⛔ В путях бывают пробелы — и в «Program Files», и в имени
    /// пользователя. Потеряв часть пути, служба молча не запустится.
    #[test]
    fn путь_с_пробелами_не_теряется() {
        let c = install_command(
            Path::new("/Applications/Nexus Proxy/sing-box"),
            Path::new("/Users/Иван Петров/cfg.json"),
        );
        assert!(c.contains("Nexus Proxy"), "{c}");
        assert!(c.contains("Иван Петров"), "{c}");
    }

    /// Перехват включает человек, а не система при загрузке: иначе
    /// трафик начал бы заворачиваться сам, без спросу.
    #[test]
    fn сама_по_себе_служба_не_поднимается() {
        let c = install_command(Path::new("a"), Path::new("b"));
        #[cfg(windows)]
        assert!(c.contains("start= demand"), "{c}");
        #[cfg(target_os = "macos")]
        assert!(c.contains("<key>RunAtLoad</key><false/>"), "{c}");
        let _ = c;
    }
}

/// Поставить службу — один запрос прав у системы.
///
/// ⛔ Это единственное место, где программа просит администратора.
/// Дальше перехват включается и выключается без вопросов: службе при
/// установке выдаётся право на запуск и остановку обычным пользователем.
pub fn install(dir: &Path) -> Result<(), String> {
    let exe = crate::tunnel::binary_path(dir);
    if !exe.is_file() {
        return Err("движок перехвата ещё не скачан".into());
    }
    let cfg = crate::tunnel::config_path(dir);
    let cmd = install_command(&exe, &cfg);
    run_elevated(&cmd)
}

/// Убрать службу — тоже с запросом прав.
pub fn uninstall() -> Result<(), String> {
    run_elevated(&uninstall_command())
}

#[cfg(windows)]
fn run_elevated(cmd: &str) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    use windows_sys::Win32::Foundation::CloseHandle;

    let wide = |s: &str| -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    };
    let verb = wide("runas");
    let file = wide("cmd.exe");
    let args = wide(&format!("/c {cmd}"));

    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = args.as_ptr();
    info.nShow = 0;

    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok == 0 {
        // Человек мог нажать «Нет» — это его решение, а не наша поломка.
        return Err("права администратора не выданы".into());
    }
    unsafe {
        WaitForSingleObject(info.hProcess, 60_000);
        CloseHandle(info.hProcess);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_elevated(cmd: &str) -> Result<(), String> {
    // ⛔ Кавычки внутри скрипта нужно удвоить: osascript отдаёт строку
    // оболочке, и одиночная кавычка оборвала бы команду на середине.
    let escaped = cmd.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!(
        "do shell script \"{escaped}\" with administrator privileges"
    );
    let out = std::process::Command::new("osascript")
        .arg("-e").arg(&script)
        .output()
        .map_err(|e| format!("не вызвать osascript: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("-128") {
            Err("права администратора не выданы".into())
        } else {
            Err(format!("не поставить службу перехвата: {}", err.trim()))
        }
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn run_elevated(_cmd: &str) -> Result<(), String> {
    Err("перехват на этой системе не поддерживается".into())
}
