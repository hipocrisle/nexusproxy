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
