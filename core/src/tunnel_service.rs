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

    /// ⛔ Службой Windows может быть только программа, умеющая отчитаться
    /// диспетчеру о запуске. sing-box этого не умеет и не должен:
    /// диспетчер ждёт ответа и снимает её с ошибкой 1053.
    ///
    /// Поэтому берём задачу планировщика с повышенными правами: ставится
    /// один раз с подтверждением, запускается потом без него — ровно то,
    /// что нужно, администратор спрашивается единожды.
    fn schtasks(args: &[&str]) -> Result<String, String> {
        use std::os::windows::process::CommandExt;
        let out = Command::new("schtasks.exe")
            .args(args)
            // ⛔ Без этого флага при каждой проверке состояния мигает
            // чёрное окно консоли — а состояние мы спрашиваем постоянно.
            .creation_flags(0x0800_0000)
            .output()
            .map_err(|e| format!("не вызвать планировщик: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout).to_string()
            + &String::from_utf8_lossy(&out.stderr);
        if out.status.success() { Ok(text) } else { Err(text.trim().to_string()) }
    }

    pub fn state() -> State {
        match schtasks(&["/query", "/tn", NAME, "/fo", "list"]) {
            Err(_) => State::Absent,
            Ok(t) if t.contains("Running") || t.contains("Выполняется") => State::Running,
            Ok(_) => State::Stopped,
        }
    }

    /// ⛔ Кавычки обязательны: в путях бывают пробелы («Program Files»,
    /// имя пользователя). Без них задача получит обрезанный путь и молча
    /// не запустится — перехват «не работает», а почему, не видно.
    /// ⛔ Задача запускает НАС, а не движок напрямую: сама она окно
    /// консоли спрятать не умеет, и у человека висело бы чёрное окно с
    /// журналом. Движок поднимаем мы, уже без окна.
    pub fn install_command(exe: &Path, dir: &Path) -> String {
        format!(
            "schtasks.exe /create /tn {NAME} /f /sc once /st 00:00 /rl highest \
             /tr \"\\\"{}\\\" --run-tunnel \\\"{}\\\"\"",
            exe.display(), dir.display()
        )
    }

    pub fn uninstall_command() -> String {
        format!("schtasks.exe /end /tn {NAME} & schtasks.exe /delete /tn {NAME} /f")
    }

    pub fn start() -> Result<(), String> {
        schtasks(&["/run", "/tn", NAME]).map(|_| ())
            .map_err(|e| format!("перехват не включился: {e}"))
    }

    pub fn stop() -> Result<(), String> {
        match schtasks(&["/end", "/tn", NAME]) {
            Ok(_) => Ok(()),
            Err(e) if e.contains("267011") || e.to_lowercase().contains("not running") => Ok(()),
            Err(e) => Err(format!("перехват не выключился: {e}")),
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    /// ⛔ Системным демоном на macOS может управлять только root. Если
    /// включать и выключать его через launchctl, пароль спрашивался бы
    /// каждый раз — ровно то, чего мы избегаем.
    ///
    /// Поэтому демон следит за файлом-признаком: файл появился — launchd
    /// поднял перехват, файл удалён — остановил. Создать и удалить файл
    /// в своей папке может обычный пользователь, без всяких прав.
    /// Администратор нужен один раз, чтобы положить описание демона.
    pub fn flag_path(dir: &Path) -> std::path::PathBuf {
        dir.join("enabled")
    }

    pub fn plist_path() -> std::path::PathBuf {
        std::path::PathBuf::from(format!("/Library/LaunchDaemons/{NAME}.plist"))
    }

    pub fn state_in(dir: &Path) -> State {
        if !plist_path().exists() {
            return State::Absent;
        }
        if flag_path(dir).exists() { State::Running } else { State::Stopped }
    }

    pub fn state() -> State {
        if plist_path().exists() { State::Stopped } else { State::Absent }
    }

    /// Описание демона.
    ///
    /// ⛔ `RunAtLoad` выключен, а `KeepAlive` привязан к файлу: перехват
    /// включает человек, а не система при каждой загрузке. Иначе трафик
    /// начал бы заворачиваться сам, без спросу.
    pub fn plist(exe: &Path, dir: &Path) -> String {
        format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{NAME}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>--run-tunnel</string>
    <string>{}</string>
  </array>
  <key>RunAtLoad</key><false/>
  <key>KeepAlive</key>
  <dict>
    <key>PathState</key>
    <dict><key>{}</key><true/></dict>
  </dict>
  <key>StandardErrorPath</key><string>{}</string>
</dict>
</plist>
"#, exe.display(), dir.display(), flag_path(dir).display(),
    dir.join("daemon.log").display())
    }

    pub fn install_command(exe: &Path, dir: &Path) -> String {
        let p = plist_path();
        // Здесь-документ: в путях бывают пробелы, а кавычки внутри xml
        // пришлось бы экранировать дважды.
        format!(
            "cat > '{}' <<'NEXUSPROXY_PLIST'\n{}NEXUSPROXY_PLIST\n\
             chown root:wheel '{}' && chmod 644 '{}' && \
             launchctl bootstrap system '{}' 2>/dev/null; true",
            p.display(), plist(exe, dir), p.display(), p.display(), p.display()
        )
    }

    pub fn uninstall_command() -> String {
        let p = plist_path();
        format!("launchctl bootout system/{NAME} 2>/dev/null; rm -f '{}'", p.display())
    }

    /// Включение и выключение — просто файл. Прав не требует.
    pub fn start_in(dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("не создать папку: {e}"))?;
        std::fs::write(flag_path(dir), b"on")
            .map_err(|e| format!("перехват не включился: {e}"))
    }

    pub fn stop_in(dir: &Path) -> Result<(), String> {
        match std::fs::remove_file(flag_path(dir)) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("перехват не выключился: {e}")),
        }
    }

    pub fn start() -> Result<(), String> {
        Err("не указана папка перехвата".into())
    }
    pub fn stop() -> Result<(), String> { Ok(()) }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod imp {
    use super::*;
    pub fn state() -> State { State::Absent }
    pub fn install_command(_e: &Path, _d: &Path) -> String { String::new() }
    pub fn uninstall_command() -> String { String::new() }
    pub fn start() -> Result<(), String> { Err("перехват на этой системе не поддерживается".into()) }
    pub fn stop() -> Result<(), String> { Ok(()) }
}

pub use imp::{install_command, uninstall_command};

/// Что сейчас с перехватом.
pub fn state_in(dir: &Path) -> State {
    #[cfg(target_os = "macos")]
    { imp::state_in(dir) }
    #[cfg(not(target_os = "macos"))]
    { let _ = dir; imp::state() }
}

/// Включить. На macOS — создать файл-признак, на Windows — запустить задачу.
pub fn start_in(dir: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    { imp::start_in(dir) }
    #[cfg(not(target_os = "macos"))]
    { let _ = dir; imp::start() }
}

/// Выключить.
pub fn stop_in(dir: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    { imp::stop_in(dir) }
    #[cfg(not(target_os = "macos"))]
    { let _ = dir; imp::stop() }
}

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
        assert!(c.contains("/sc once"), "задача не должна запускаться сама: {c}");
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
    if !crate::tunnel::binary_path(dir).is_file() {
        return Err("движок перехвата ещё не скачан".into());
    }
    // Задача запускает нас же — мы поднимем движок без окна.
    let me = std::env::current_exe()
        .map_err(|e| format!("не найти себя: {e}"))?;
    run_elevated(&install_command(&me, dir))
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
