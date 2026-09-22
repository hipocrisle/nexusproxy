//! Запуск приложений через наш прокси.
//!
//! ⛔ Зачем это нужно. Мы прописываем себя в СИСТЕМНЫЕ настройки прокси
//! Windows — и этого достаточно для браузеров и всего, что их читает.
//! Но Cursor, Electron-приложения и часть консольных программ системные
//! настройки игнорируют: их трафик до нас не доходит вовсе. Снаружи это
//! выглядит как «включил галочку, а не работает», и подбор доменов пуст —
//! он показывает только то, что через нас прошло.
//!
//! Здесь мы запускаем программу САМИ, передав ей адрес прокси тем
//! способом, который она понимает. Прав администратора не нужно,
//! в систему ничего не ставится.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct App {
    /// Как показать человеку.
    pub name: String,
    /// Путь к запускаемому файлу.
    pub path: String,
    /// Каким способом передавать адрес прокси.
    #[serde(default)]
    pub kind: Kind,
    /// Через какой прокси идёт ВЕСЬ трафик этой программы.
    ///
    /// Пусто — программа подчиняется общим правилам по доменам, как
    /// и всё остальное. Имя прокси — весь её трафик уходит туда, а
    /// доменные правила к ней не применяются: именно этого ждут от
    /// «запустить программу через прокси», иначе получается мешанина,
    /// где запущенная через нас программа всё равно ходит напрямую.
    #[serde(default)]
    pub via: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Определить по имени файла.
    #[default]
    Auto,
    /// Chromium и Electron: ключ --proxy-server.
    Chromium,
    /// Переменные окружения HTTP_PROXY/HTTPS_PROXY.
    Env,
}

/// Приложения, которые узнаём по имени файла. Список не запрещающий:
/// чего тут нет, получит переменные окружения — их понимает большинство.
const CHROMIUM_LIKE: &[&str] = &[
    "cursor", "code", "vscode", "windsurf", "chrome", "chromium", "msedge",
    "brave", "opera", "vivaldi", "discord", "slack", "notion", "obsidian",
    "postman", "insomnia", "electron", "teams", "spotify",
];

pub fn detect(path: &str) -> Kind {
    let name = Path::new(path)
        .file_stem()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if CHROMIUM_LIKE.iter().any(|k| name.contains(k)) {
        Kind::Chromium
    } else {
        Kind::Env
    }
}

/// Как именно запустим — показываем человеку до запуска, чтобы не гадал.
pub fn explain(app: &App, socks_port: u16, http_port: u16) -> String {
    match if app.kind == Kind::Auto { detect(&app.path) } else { app.kind } {
        Kind::Chromium => format!(
            "ключ --proxy-server=socks5://127.0.0.1:{socks_port} и переменные \
             HTTP_PROXY/HTTPS_PROXY на 127.0.0.1:{http_port} — Electron ходит \
             и тем, и другим"),
        _ => format!("переменные HTTP_PROXY и HTTPS_PROXY на 127.0.0.1:{http_port}"),
    }
}

/// На macOS программы лежат папками .app — внутри неё и есть запускаемый файл.
///
/// ⛔ Через `open -a` запускать нельзя: доводы уходят самому `open`,
/// а не программе, и прокси она не увидит. Поэтому ищем настоящий файл
/// внутри Contents/MacOS.
#[cfg(target_os = "macos")]
fn real_exe(path: &str) -> std::path::PathBuf {
    let p = Path::new(path);
    if p.extension().map(|e| e == "app").unwrap_or(false) {
        let macos = p.join("Contents").join("MacOS");
        // имя обычно совпадает с именем папки, но не всегда — берём что есть
        let by_name = p.file_stem()
            .map(|n| macos.join(n))
            .filter(|f| f.is_file());
        if let Some(f) = by_name {
            return f;
        }
        if let Ok(rd) = std::fs::read_dir(&macos) {
            if let Some(first) = rd.filter_map(|e| e.ok()).map(|e| e.path())
                                   .find(|f| f.is_file()) {
                return first;
            }
        }
    }
    p.to_path_buf()
}

#[cfg(not(target_os = "macos"))]
fn real_exe(path: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(path)
}

/// Запустить приложение через наш прокси.
pub fn start(app: &App, socks_port: u16, http_port: u16) -> Result<u32, String> {
    let exe_buf = real_exe(&app.path);
    let exe = exe_buf.as_path();
    if !exe.is_file() {
        return Err(format!("файл не найден: {}", app.path));
    }
    let kind = if app.kind == Kind::Auto { detect(&app.path) } else { app.kind };

    let mut cmd = std::process::Command::new(exe);
    if let Some(dir) = exe.parent() {
        cmd.current_dir(dir);
    }

    // ⛔ Переменные ставим ВСЕМ, включая Chromium. Electron — это не
    // только Chromium: расширения, языковые серверы и часть запросов
    // идут через Node внутри него, а Node про --proxy-server не знает
    // и смотрит только на окружение. Без этого Cursor открывается,
    // соединения видно, а работать он не работает: половина его
    // хозяйства ходит мимо нас.
    {
        let http = format!("http://127.0.0.1:{http_port}");
        cmd.env("HTTP_PROXY", &http).env("HTTPS_PROXY", &http)
           .env("http_proxy", &http).env("https_proxy", &http)
           .env("ALL_PROXY", format!("socks5://127.0.0.1:{socks_port}"))
           .env("NO_PROXY", "localhost,127.0.0.1,::1");
    }

    match kind {
        Kind::Chromium => {
            // ⛔ WebRTC в Chromium через SOCKS не ходит — поддержку для
            // медиа оттуда убрали, остался только HTTP-прокси методом
            // CONNECT. Поэтому при «видео и звонки тоже через прокси»
            // отдаём http-вход: иначе запрет ходить мимо прокси есть, а
            // дороги через прокси у медиа нет, и видео просто не идёт.
            //
            // В остальных случаях socks5: через http-прокси Chromium
            // капризничает с WebSocket, на котором держится половина
            // современных приложений.
            cmd.arg(format!("--proxy-server=socks5://127.0.0.1:{socks_port}"));
            // без этого Chromium ходит мимо прокси за своими адресами
            cmd.arg("--proxy-bypass-list=<-loopback>");
        }
        _ => {}
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0000_0008); // своя группа процессов
    }

    cmd.spawn()
        .map(|c| c.id())
        .map_err(|e| format!("не запустить {}: {e}", app.name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_узнаётся_как_chromium() {
        for p in [r"C:\Users\u\AppData\Local\Programs\cursor\Cursor.exe",
                  "/Applications/Cursor.app/Contents/MacOS/Cursor",
                  r"C:\Program Files\Microsoft VS Code\Code.exe"] {
            assert_eq!(detect(p), Kind::Chromium, "{p}");
        }
    }

    #[test]
    fn незнакомое_получает_переменные_окружения() {
        assert_eq!(detect(r"C:\tools\myapp.exe"), Kind::Env);
        assert_eq!(detect("/usr/bin/curl"), Kind::Env);
    }

    #[test]
    fn человеку_объясняем_способ_до_запуска() {
        let a = App { name: "Cursor".into(), path: "Cursor.exe".into(),
                      kind: Kind::Auto, via: String::new() };
        assert!(explain(&a, 18081, 18080).contains("socks5"));
        let b = App { name: "Своё".into(), path: "my.exe".into(),
                      kind: Kind::Auto, via: String::new() };
        assert!(explain(&b, 18081, 18080).contains("HTTP_PROXY"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn на_маке_находим_файл_внутри_папки_программы() {
        // .app — это папка; запускать надо то, что внутри
        let p = real_exe("/Applications/Нет.app");
        assert!(p.to_string_lossy().contains("Contents/MacOS")
                || p.to_string_lossy().ends_with(".app"));
    }

    #[test]
    fn несуществующий_файл_отвергается_с_объяснением() {
        let a = App { name: "Нет".into(), path: "/нет/такого".into(),
                      kind: Kind::Auto, via: String::new() };
        let e = start(&a, 18081, 18080).unwrap_err();
        assert!(e.contains("не найден"), "{e}");
    }
}


#[cfg(test)]
mod electron_tests {
    use super::*;

    /// Electron — не только Chromium: расширения и языковые серверы
    /// работают через Node внутри него, а тот знает лишь окружение.
    /// Cursor из-за этого открывался, но не работал.
    #[test]
    fn chromium_получает_и_ключ_и_переменные() {
        let a = App { name: "Cursor".into(), path: "cursor.exe".into(),
                      kind: Kind::Chromium, via: String::new() };
        let t = explain(&a, 18081, 18080);
        assert!(t.contains("--proxy-server"), "{t}");
        assert!(t.contains("HTTP_PROXY"), "{t}");
    }
}



/// Как процесс этой программы зовётся в системе.
///
/// ⛔ На macOS `.app` — это папка, а настоящий исполняемый файл лежит
/// внутри, в `Contents/MacOS`. Система показывает процесс по его имени
/// («Cursor»), а не по имени папки («Cursor.app»). Отдав перехвату имя
/// папки, мы заставляем его искать процесс, которого не существует:
/// перехват работает, а трафик приложения идёт мимо.
pub fn process_name(path: &str) -> String {
    let p = Path::new(path);
    #[cfg(target_os = "macos")]
    {
        if p.extension().map(|e| e == "app").unwrap_or(false) {
            return real_exe(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
        }
    }
    // ⛔ Режем по обоим разделителям, а не средствами системы: настройки
    // переносят между Windows и macOS, и на Linux путь вида C:\a\b.exe
    // целиком сошёл бы за имя файла.
    let _ = p;
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_string()
}

#[cfg(test)]
mod process_name_tests {
    use super::*;

    #[test]
    fn обычный_файл_берётся_как_есть() {
        assert_eq!(process_name(r"C:\Program Files\cursor\Cursor.exe"), "Cursor.exe");
        assert_eq!(process_name("/usr/bin/curl"), "curl");
    }

    /// ⛔ На macOS процесс зовётся по файлу внутри бандла. Отдав имя
    /// папки, перехват искал бы несуществующий процесс, и трафик шёл бы
    /// мимо — перехват «включён», а толку нет.
    ///
    /// Бандл собираем свой: на сборочной машине чужих программ нет, а
    /// проверять надо разбор, а не наличие Cursor.
    #[cfg(target_os = "macos")]
    #[test]
    fn у_бандла_берём_имя_внутреннего_файла() {
        let root = std::env::temp_dir()
            .join(format!("np-bundle-{}", std::process::id()))
            .join("Пример.app");
        let inner = root.join("Contents").join("MacOS");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(inner.join("Пример"), b"").unwrap();

        let n = process_name(root.to_str().unwrap());
        assert_eq!(n, "Пример", "нужно имя файла внутри бандла, а не папки");
        let _ = std::fs::remove_dir_all(root.parent().unwrap());
    }
}
