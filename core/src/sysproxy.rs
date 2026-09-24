//! Системные настройки прокси — одна дверь для всех систем.
//!
//! Внутри у каждой своя механика: в Windows ветка реестра пользователя,
//! в macOS утилита networksetup по каждой сетевой службе.

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub enum Saved {
    #[default]
    None,
    #[cfg(windows)]
    Windows(crate::winproxy::Saved),
    #[cfg(target_os = "macos")]
    Mac(crate::macproxy::Saved),
}

pub fn apply(proxy: &str, no_proxy: &str) -> std::io::Result<Saved> {
    #[cfg(windows)]
    { return crate::winproxy::apply(proxy, no_proxy).map(Saved::Windows); }
    #[cfg(target_os = "macos")]
    { return crate::macproxy::apply(proxy, no_proxy).map(Saved::Mac); }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (proxy, no_proxy);
        Err(std::io::Error::other(
            "переключение системного прокси есть в версиях для Windows и macOS",
        ))
    }
}

pub fn restore(s: &Saved) {
    match s {
        Saved::None => {}
        #[cfg(windows)]
        Saved::Windows(x) => crate::winproxy::restore(x),
        #[cfg(target_os = "macos")]
        Saved::Mac(x) => crate::macproxy::restore(x),
    }
}

/// Убрать за версиями до 0.9.16, которые писали переменные окружения
/// пользователя. Возвращает имена убранных — их стоит записать в журнал.
pub fn sweep_stale_env() -> Vec<String> {
    crate::winproxy::sweep_stale_env()
}

pub fn current() -> String {
    #[cfg(windows)]
    { return crate::winproxy::current(); }
    #[cfg(target_os = "macos")]
    { return crate::macproxy::current(); }
    #[cfg(not(any(windows, target_os = "macos")))]
    { "не поддерживается на этой системе".to_string() }
}

/// Куда кладём «что было до нас».
///
/// ⛔ Держать это только в памяти нельзя. Программа может уйти не через
/// своё меню — упасть, быть снятой из диспетчера, пережить перезагрузку
/// при включённом перехвате. Тогда системный прокси остаётся указывать
/// на несуществующую программу, и у человека молча отваливается всё,
/// включая почту. Файл на диске позволяет прибраться при следующем
/// запуске.
fn memo_path(config_path: &str) -> std::path::PathBuf {
    std::path::Path::new(config_path)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("system-proxy-was.json")
}

/// Запомнить на диск, что мы тронули системные настройки.
pub fn remember(config_path: &str, s: &Saved) {
    let p = memo_path(config_path);
    if let Ok(text) = serde_json::to_string_pretty(s) {
        let _ = std::fs::write(&p, text);
    }
}

/// Мы прибрались — записка больше не нужна.
pub fn forget(config_path: &str) {
    let _ = std::fs::remove_file(memo_path(config_path));
}

/// Прибраться за прошлым сеансом, если он не успел сам.
///
/// Возвращает true, если что-то пришлось возвращать — это стоит
/// записать в журнал: человек должен понимать, почему настройки
/// изменились сами.
pub fn restore_leftovers(config_path: &str) -> bool {
    let p = memo_path(config_path);
    let Ok(text) = std::fs::read_to_string(&p) else { return false };
    match serde_json::from_str::<Saved>(&text) {
        Ok(s) => {
            restore(&s);
            let _ = std::fs::remove_file(&p);
            true
        }
        // Записка испорчена — толку от неё нет, но и держать незачем.
        Err(_) => {
            let _ = std::fs::remove_file(&p);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⛔ У каждого теста свой каталог: они бегут параллельно, а записка
    /// лежит в файле с одним и тем же именем — соседний тест удалял её
    /// под ногами.
    fn tmp(who: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir()
            .join(format!("np-sysproxy-{}-{who}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.join("config.json")
    }

    /// Прошлый сеанс не прибрался — записка должна пережить перезапуск
    /// и сработать, иначе у человека остаётся системный прокси в никуда.
    #[test]
    fn записка_переживает_перезапуск() {
        let cfg = tmp("restart");
        let _ = forget(cfg.to_str().unwrap());
        remember(cfg.to_str().unwrap(), &Saved::None);
        assert!(restore_leftovers(cfg.to_str().unwrap()),
                "записка должна найтись и сработать");
        assert!(!restore_leftovers(cfg.to_str().unwrap()),
                "второй раз возвращать нечего");
    }

    #[test]
    fn после_обычного_выключения_записки_нет() {
        let cfg = tmp("normal-off");
        remember(cfg.to_str().unwrap(), &Saved::None);
        forget(cfg.to_str().unwrap());
        assert!(!restore_leftovers(cfg.to_str().unwrap()));
    }

    /// Испорченный файл не должен мешать запуску.
    #[test]
    fn испорченная_записка_не_ломает_запуск() {
        let cfg = tmp("broken");
        let memo = cfg.parent().unwrap().join("system-proxy-was.json");
        std::fs::write(&memo, "не json вовсе").unwrap();
        assert!(!restore_leftovers(cfg.to_str().unwrap()));
        assert!(!memo.exists(), "мусор должен убираться");
    }
}

/// Сторож: возвращает системные настройки, когда программа исчезла.
///
/// ⛔ Полагаться на её собственный выход нельзя. Обновление, падение,
/// снятие через диспетчер, выключение питания — любой из этих путей
/// оставляет системный прокси указывать на программу, которой больше
/// нет, и человек остаётся без сети, не понимая почему. Записка на
/// диске чинит это при следующем запуске, но до него может пройти день.
///
/// Поэтому рядом с программой живёт отдельный маленький процесс. Он
/// ничего не делает, только ждёт её завершения. Ушла по-хорошему —
/// записки уже нет, и сторож молча выходит. Ушла иначе — записка на
/// месте, и он возвращает настройки сам.
pub fn guard(parent_pid: u32, config_path: &str) {
    wait_for_exit(parent_pid);
    // Записка осталась — значит прибраться за собой она не успела.
    if restore_leftovers(config_path) {
        crate::logfile::line(&crate::logfile::now_stamp(),
            "системные настройки прокси возвращены сторожем: программа завершилась неожиданно");
    }
}

#[cfg(windows)]
fn wait_for_exit(pid: u32) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Foundation::WAIT_FAILED;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, WaitForSingleObject, INFINITE, PROCESS_SYNCHRONIZE,
    };
    let _ = WAIT_FAILED;
    unsafe {
        let h = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
        if h.is_null() {
            return; // процесса уже нет — проверим записку и выйдем
        }
        WaitForSingleObject(h, INFINITE);
        CloseHandle(h);
    }
}

#[cfg(not(windows))]
fn wait_for_exit(pid: u32) {
    // Ждём, пока процесс не перестанет отвечать на проверку существования.
    loop {
        let alive = std::process::Command::new("kill")
            .arg("-0").arg(pid.to_string())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !alive {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

/// Запустить сторожа рядом с собой.
pub fn spawn_guard(config_path: &str) {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("--restore-guard")
       .arg(std::process::id().to_string())
       .arg(config_path);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // без чёрного окна и отдельной группой, чтобы пережить нас
        cmd.creation_flags(0x0800_0000 | 0x0000_0200);
    }
    let _ = cmd.spawn();
}

/// Указывают ли системные настройки на нас.
///
/// ⛔ Только на себя и смотрим: чужие настройки — не наше дело, снести
/// их значило бы оставить человека без чужого прокси, который ему нужен.
pub fn points_to_us() -> bool {
    let now = current();
    now.contains("127.0.0.1") || now.contains("localhost")
}

/// Снять настройки прокси начисто.
pub fn clear() {
    #[cfg(windows)]
    crate::winproxy::clear();
    #[cfg(target_os = "macos")]
    crate::macproxy::clear();
}
