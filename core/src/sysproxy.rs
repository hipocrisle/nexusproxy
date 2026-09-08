//! Системные настройки прокси — одна дверь для всех систем.
//!
//! Внутри у каждой своя механика: в Windows ветка реестра пользователя,
//! в macOS утилита networksetup по каждой сетевой службе.

#[derive(Debug, Default, Clone)]
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
