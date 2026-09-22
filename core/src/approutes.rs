//! Куда отправлять трафик конкретной программы.
//!
//! Правила по доменам отвечают на вопрос «куда идёт этот адрес».
//! Здесь — другой вопрос: «куда идёт всё, что делает эта программа».
//! Второй сильнее: если человек велел вести Vivaldi через корпоративный
//! прокси, туда идёт весь Vivaldi, а не та часть, что совпала с доменным
//! правилом.

use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct AppRoutes {
    /// Полный путь программы (в нижнем регистре) → имя прокси.
    by_path: HashMap<String, String>,
    /// Имя файла → имя прокси. Запасной путь: программу могли
    /// перенести или запустить не оттуда, откуда добавляли.
    by_name: HashMap<String, String>,
}

impl AppRoutes {
    pub fn build(apps: &[crate::launch::App]) -> Self {
        let mut r = Self::default();
        for a in apps {
            if a.via.trim().is_empty() {
                continue;
            }
            let path = a.path.to_lowercase().replace('\\', "/");
            r.by_path.insert(path.clone(), a.via.clone());
            if let Some(file) = path.rsplit('/').next() {
                r.by_name.insert(file.to_string(), a.via.clone());
            }
        }
        r
    }

    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }

    /// Имя прокси для программы, открывшей соединение.
    pub fn route_for(&self, app: &crate::proc::AppInfo) -> Option<&str> {
        let path = app.path.to_lowercase().replace('\\', "/");
        if let Some(v) = self.by_path.get(&path) {
            return Some(v);
        }
        let name = app.name.to_lowercase();
        // на macOS процесс зовётся по файлу внутри бандла, а добавляют
        // саму папку .app — поэтому сверяем ещё и по имени файла
        self.by_name.get(&name).map(|s| s.as_str())
            .or_else(|| path.rsplit('/').next().and_then(|f| self.by_name.get(f)).map(|s| s.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::launch::{App, Kind};
    use crate::proc::AppInfo;

    fn app(path: &str, via: &str) -> App {
        App { name: "x".into(), path: path.into(), kind: Kind::Auto,
              via: via.into() }
    }

    #[test]
    fn весь_трафик_программы_идёт_в_её_прокси() {
        let r = AppRoutes::build(&[app(r"C:\Vivaldi\vivaldi.exe", "офис")]);
        let who = AppInfo { name: "vivaldi.exe".into(),
                            path: r"C:\Vivaldi\vivaldi.exe".into(), pid: 1 };
        assert_eq!(r.route_for(&who), Some("офис"));
    }

    #[test]
    fn регистр_и_косые_не_мешают() {
        let r = AppRoutes::build(&[app(r"C:\Vivaldi\vivaldi.exe", "офис")]);
        let who = AppInfo { name: "Vivaldi.exe".into(),
                            path: r"c:/VIVALDI/Vivaldi.exe".into(), pid: 1 };
        assert_eq!(r.route_for(&who), Some("офис"));
    }

    /// Программу могли запустить не из той папки, откуда добавляли.
    #[test]
    fn узнаём_по_имени_если_путь_другой() {
        let r = AppRoutes::build(&[app(r"C:\Старое\vivaldi.exe", "офис")]);
        let who = AppInfo { name: "vivaldi.exe".into(),
                            path: r"D:\Новое\vivaldi.exe".into(), pid: 1 };
        assert_eq!(r.route_for(&who), Some("офис"));
    }

    #[test]
    fn без_прокси_программа_идёт_по_общим_правилам() {
        let r = AppRoutes::build(&[app(r"C:\Vivaldi\vivaldi.exe", "")]);
        let who = AppInfo { name: "vivaldi.exe".into(),
                            path: r"C:\Vivaldi\vivaldi.exe".into(), pid: 1 };
        assert_eq!(r.route_for(&who), None);
        assert!(r.is_empty());
    }

    #[test]
    fn чужая_программа_не_задета() {
        let r = AppRoutes::build(&[app(r"C:\Vivaldi\vivaldi.exe", "офис")]);
        let who = AppInfo { name: "chrome.exe".into(),
                            path: r"C:\Chrome\chrome.exe".into(), pid: 2 };
        assert_eq!(r.route_for(&who), None);
    }
}
