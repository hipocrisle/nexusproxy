//! Связка окна программы с ядром.

use nexusproxy_core as core;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{Manager, State, WindowEvent};

pub struct App {
    engine: Mutex<Option<Arc<core::Engine>>>,
    path: Mutex<String>,
}

#[derive(Serialize)]
pub struct Status {
    running: bool,
    upstream: String,
    http_port: u16,
    socks_port: u16,
    system_on: bool,
    discovering: bool,
    auto_reconnect: bool,
    minimize_to_tray: bool,
    rules_count: usize,
    upstream_up: bool,
    upstream_error: Option<String>,
    config_path: String,
    log_path: String,
    error: Option<String>,
}

fn engine(app: &State<App>) -> Result<Arc<core::Engine>, String> {
    app.engine.lock().unwrap().clone().ok_or_else(|| "движок не запущен".into())
}

#[tauri::command]
fn status(app: State<App>) -> Status {
    let path = app.path.lock().unwrap().clone();
    match app.engine.lock().unwrap().as_ref() {
        Some(e) => {
            let c = e.cfg.lock().unwrap();
            let h = core::health::get();
            Status {
                running: true,
                upstream: format!("{}:{}", c.upstream.address, c.upstream.port),
                http_port: c.listen.http,
                socks_port: c.listen.socks,
                system_on: e.system_proxy_is_ours(),
                discovering: core::report::session_active(),
                auto_reconnect: c.auto_reconnect,
                minimize_to_tray: c.minimize_to_tray,
                rules_count: c.through_proxy.iter().filter(|s| !s.starts_with('_')).count(),
                upstream_up: h.up,
                upstream_error: h.last_error,
                config_path: path,
                log_path: core::logfile::path().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
                error: None,
            }
        }
        None => Status {
            running: false, upstream: String::new(), http_port: 0, socks_port: 0,
            system_on: false, discovering: false,
            auto_reconnect: true, minimize_to_tray: true, rules_count: 0,
            upstream_up: false, upstream_error: None,
            config_path: path, log_path: String::new(),
            error: Some("движок не запущен".into()),
        },
    }
}

#[derive(Serialize)]
pub struct RuleLists {
    through_proxy: Vec<String>,
    direct: Vec<String>,
}

#[tauri::command]
fn rules_list(app: State<App>) -> Result<RuleLists, String> {
    let e = engine(&app)?;
    let c = e.cfg.lock().unwrap();
    Ok(RuleLists { through_proxy: c.through_proxy.clone(), direct: c.direct.clone() })
}

#[tauri::command]
fn rule_add(app: State<App>, text: String) -> Result<core::config::BulkResult, String> {
    let e = engine(&app)?;
    let r = { e.cfg.lock().unwrap().add_many(&text) };
    e.apply_and_save()?;
    Ok(r)
}

/// Заменить запись — правка вместо «убрать и добавить заново».
#[tauri::command]
fn rule_edit(app: State<App>, old: String, new: String) -> Result<core::config::BulkResult, String> {
    let e = engine(&app)?;
    let r = {
        let mut c = e.cfg.lock().unwrap();
        c.remove_proxy(&old);
        c.add_many(&new)
    };
    e.apply_and_save()?;
    Ok(r)
}

/// Загрузить список из файла — обычный текстовый, по строке на запись.
#[tauri::command]
fn rule_add_from_file(app: State<App>, path: String) -> Result<core::config::BulkResult, String> {
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("не читается {path}: {e}"))?;
    let e = engine(&app)?;
    let r = { e.cfg.lock().unwrap().add_many(&text) };
    e.apply_and_save()?;
    Ok(r)
}

/// Выгрузить список правил в файл — чтобы поделиться с коллегами.
#[tauri::command]
fn rules_export(app: State<App>, path: String) -> Result<usize, String> {
    let e = engine(&app)?;
    let c = e.cfg.lock().unwrap();
    let text = c.through_proxy.join("\n") + "\n";
    let n = c.through_proxy.iter().filter(|s| !s.starts_with('_')).count();
    std::fs::write(&path, text).map_err(|e| format!("не записать {path}: {e}"))?;
    Ok(n)
}

/// Готовые наборы доменов для ходовых сервисов.
#[tauri::command]
fn presets() -> Vec<core::presets::Preset> {
    core::presets::all()
}

#[tauri::command]
fn rule_remove(app: State<App>, pattern: String) -> Result<bool, String> {
    let e = engine(&app)?;
    let removed = { e.cfg.lock().unwrap().remove_proxy(&pattern) };
    if removed {
        e.apply_and_save()?;
    }
    Ok(removed)
}

#[derive(Serialize)]
pub struct Verdict {
    host: String,
    route: String,
}

#[tauri::command]
fn check(app: State<App>, hosts: Vec<String>) -> Result<Vec<Verdict>, String> {
    let e = engine(&app)?;
    let r = e.rules.read().unwrap();
    Ok(hosts
        .iter()
        .map(|h| Verdict {
            host: h.clone(),
            route: match r.decide(h) {
                core::rules::Route::Proxy => "proxy",
                core::rules::Route::Direct => "direct",
                core::rules::Route::Block => "block",
            }
            .into(),
        })
        .collect())
}

#[tauri::command]
fn journal_since(after: u64) -> Vec<core::journal::Entry> {
    core::journal::since(after)
}

/// Открыть папку с настройками и журналом в проводнике.
#[tauri::command]
fn open_folder(app: State<App>) -> Result<(), String> {
    let p = app.path.lock().unwrap().clone();
    let dir = std::path::Path::new(&p).parent().ok_or("папка не найдена")?;
    #[cfg(windows)]
    { std::process::Command::new("explorer").arg(dir).spawn().map_err(|e| e.to_string())?; }
    #[cfg(not(windows))]
    { let _ = dir; }
    Ok(())
}

#[tauri::command]
fn journal_clear() {
    core::journal::clear()
}

#[tauri::command]
fn discovery_start() {
    core::report::start_session()
}

#[tauri::command]
fn discovery_live() -> Vec<core::report::Candidate> {
    core::report::live_candidates()
}

#[tauri::command]
fn discovery_stop() -> Option<core::report::SessionResult> {
    core::report::finish_session()
}

#[tauri::command]
fn system_proxy(app: State<App>, on: bool) -> Result<(), String> {
    let e = engine(&app)?;
    if on { e.system_proxy_on() } else { e.system_proxy_off(); Ok(()) }
}

/// Переключатели, которые применяются сразу, без перезапуска движка.
#[tauri::command]
fn set_flag(app: State<App>, name: String, value: bool) -> Result<(), String> {
    let e = engine(&app)?;
    {
        let mut c = e.cfg.lock().unwrap();
        match name.as_str() {
            "auto_reconnect" => {
                c.auto_reconnect = value;
                core::upstream::AUTO_RECONNECT
                    .store(value, std::sync::atomic::Ordering::Relaxed);
            }
            "minimize_to_tray" => c.minimize_to_tray = value,
            other => return Err(format!("неизвестная настройка: {other}")),
        }
    }
    e.apply_and_save()
}

/// Полный выход: вернуть системные настройки и закрыться.
/// ⛔ Обязательно через это, а не через закрытие окна: иначе у пользователя
/// останется системный прокси, указывающий в никуда, и «пропадёт интернет».
#[tauri::command]
fn quit(app: tauri::AppHandle) {
    if let Some(e) = app.state::<App>().engine.lock().unwrap().as_ref() {
        e.shutdown();
    }
    app.exit(0);
}

#[derive(serde::Deserialize)]
pub struct Settings {
    address: String,
    port: u16,
    user: Option<String>,
    password: Option<String>,
    http_port: u16,
    socks_port: u16,
}

#[tauri::command]
async fn settings_save(app: tauri::AppHandle, s: Settings) -> Result<(), String> {
    let state = app.state::<App>();
    let path = state.path.lock().unwrap().clone();
    let old = engine(&state).ok();
    let mut cfg = match &old {
        Some(e) => e.cfg.lock().unwrap().clone(),
        None => core::config::Config::load(&path)?,
    };
    cfg.upstream.address = s.address;
    cfg.upstream.port = s.port;
    cfg.upstream.user = s.user.filter(|v| !v.is_empty());
    cfg.upstream.password = s.password.filter(|v| !v.is_empty());
    cfg.listen.http = s.http_port;
    cfg.listen.socks = s.socks_port;
    cfg.save(&path)?;

    // перезапуск: порты и адрес прокси читаются при старте
    let was_on = old.as_ref().map_or(false, |e| e.system_proxy_is_ours());
    if let Some(e) = old {
        e.shutdown();
    }
    *state.engine.lock().unwrap() = None;
    let fresh = core::Engine::start(cfg, &path).await?;
    if was_on {
        fresh.system_proxy_on()?;
    }
    *state.engine.lock().unwrap() = Some(fresh);
    Ok(())
}

fn default_config() -> core::config::Config {
    core::config::Config {
        upstream: core::upstream::Upstream {
            address: "127.0.0.1".into(), port: 1080, user: None, password: None,
        },
        listen: core::config::Listen { http: 18080, socks: 18081 },
        through_proxy: vec![],
        direct: vec![],
        auto_reconnect: true,
        minimize_to_tray: true,
        extra: Default::default(),
    }
}

/// Запуск свёрнутым. Нужен вместе с автозапуском: иначе при каждом входе
/// в систему окно лезет на передний план.
fn started_hidden() -> bool {
    std::env::args().any(|a| a == "--hidden" || a == "--minimized")
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            // при автозапуске окно не показываем — программа уходит в трей
            Some(vec!["--hidden"]),
        ))
        .manage(App { engine: Mutex::new(None), path: Mutex::new(String::new()) })
        .setup(|app| {
            // ── значок в области уведомлений ──
            let show = MenuItem::with_id(app, "show", "Показать окно", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit_item])?;
            TrayIconBuilder::with_id("main")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("NexusProxy")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "quit" => {
                        // системный прокси надо вернуть, иначе интернет «пропадёт»
                        if let Some(e) = app.state::<App>().engine.lock().unwrap().as_ref() {
                            e.shutdown();
                        }
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::Click {
                        button: tauri::tray::MouseButton::Left,
                        button_state: tauri::tray::MouseButtonState::Up,
                        ..
                    } = event
                    {
                        if let Some(w) = tray.app_handle().get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                })
                .build(app)?;

            let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
            std::fs::create_dir_all(&dir).ok();
            core::logfile::open(dir.join("nexusproxy.log")).ok();
            let path = dir.join("config.json");
            let path_s = path.to_string_lossy().to_string();
            if !path.exists() {
                default_config().save(&path_s).ok();
            }
            let cfg = core::config::Config::load(&path_s)
                .unwrap_or_else(|_| default_config());

            if started_hidden() {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }

            let state = app.state::<App>();
            *state.path.lock().unwrap() = path_s.clone();
            let rt = tokio::runtime::Runtime::new()?;
            match rt.block_on(core::Engine::start(cfg, &path_s)) {
                Ok(e) => *state.engine.lock().unwrap() = Some(e),
                Err(err) => eprintln!("движок не запустился: {err}"),
            }
            // среда выполнения должна жить, пока живёт программа
            std::mem::forget(rt);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status, rules_list, rule_add, rule_edit, rule_remove,
            rule_add_from_file, rules_export, presets, check,
            journal_since, journal_clear, open_folder,
            discovery_start, discovery_live, discovery_stop,
            system_proxy, settings_save, set_flag, quit
        ])
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                let app = window.app_handle();
                let to_tray = app
                    .state::<App>()
                    .engine
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|e| e.cfg.lock().unwrap().minimize_to_tray)
                    .unwrap_or(true);
                if to_tray {
                    api.prevent_close();
                    let _ = window.hide();
                } else if let Some(e) = app.state::<App>().engine.lock().unwrap().as_ref() {
                    e.shutdown();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("не удалось запустить окно");
}
