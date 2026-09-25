//! Связка окна программы с ядром.

use nexusproxy_core as core;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, State, WindowEvent};

pub struct App {
    engine: Mutex<Option<Arc<core::Engine>>>,
    path: Mutex<String>,
    /// Почему движок не поднялся — чтобы окно показало причину,
    /// а не пустые списки.
    start_error: Mutex<Option<String>>,
}

#[derive(Serialize)]
pub struct Status {
    running: bool,
    upstream: String,
    http_port: u16,
    socks_port: u16,
    system_on: bool,
    auto_reconnect: bool,
    minimize_to_tray: bool,
    enable_on_start: bool,
    tunnel_mode: bool,
    default_upstream: String,
    rules_count: usize,
    upstream_up: bool,
    upstream_error: Option<String>,
    config_path: String,
    log_path: String,
    error: Option<String>,
    os: String,
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
                upstream: c.default_proxy()
                    .map(|u| format!("{} · {}:{}", u.name, u.address, u.port))
                    .unwrap_or_else(|| "прокси не задан".into()),
                http_port: c.listen.http,
                socks_port: c.listen.socks,
                // ⛔ «Включено» зависит от выбранного способа. В TUN
                // режиме системные настройки не трогаются вовсе, и по
                // ним программа выглядела вечно выключенной: человек
                // жал «Включить» и не видел никакой реакции.
                system_on: if c.tunnel_mode {
                    core::tunnel_service::state_in(
                        &core::tunnel_dir(&app.path.lock().unwrap().clone())
                    ) == core::tunnel_service::State::Running
                } else {
                    e.system_proxy_is_ours()
                },
                auto_reconnect: c.auto_reconnect,
                minimize_to_tray: c.minimize_to_tray,
                enable_on_start: c.enable_on_start,
                tunnel_mode: c.tunnel_mode,
                os: std::env::consts::OS.to_string(),
                default_upstream: c.default_upstream.clone(),
                rules_count: c.through_proxy.iter().filter(|s| !s.starts_with('_')).count(),
                upstream_up: h.up,
                upstream_error: h.last_error,
                config_path: path,
                log_path: core::logfile::path().map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
                error: app.start_error.lock().unwrap().clone(),
            }
        }
        None => Status {
            running: false, upstream: String::new(), http_port: 0, socks_port: 0,
            system_on: false,
            auto_reconnect: true, minimize_to_tray: true, enable_on_start: true,
            tunnel_mode: false,
            os: std::env::consts::OS.to_string(),
            default_upstream: String::new(), rules_count: 0,
            upstream_up: false, upstream_error: None,
            config_path: path, log_path: String::new(),
            // ⛔ Показываем НАСТОЯЩУЮ причину. Она сохранялась при
            // запуске и не читалась никем: человек видел «движок не
            // запущен» и не мог узнать, что дело, скажем, в занятом
            // порте.
            error: Some(app.start_error.lock().unwrap().clone()
                .unwrap_or_else(|| "движок не запущен".into())),
        },
    }
}

/// Одно правило вместе с тем, через какой прокси оно идёт.
#[derive(Serialize)]
pub struct RuleItem {
    pattern: String,
    /// пустое — основной прокси
    via: String,
}

#[derive(Serialize)]
pub struct RuleLists {
    items: Vec<RuleItem>,
    direct: Vec<String>,
}

#[tauri::command]
fn rules_list(app: State<App>) -> Result<RuleLists, String> {
    let e = engine(&app)?;
    let c = e.cfg.lock().unwrap();
    let mut items: Vec<RuleItem> = c
        .through_proxy
        .iter()
        .map(|p| RuleItem { pattern: p.clone(), via: String::new() })
        .collect();
    for g in &c.groups {
        for p in &g.patterns {
            items.push(RuleItem { pattern: p.clone(), via: g.via.clone() });
        }
    }
    Ok(RuleLists { items, direct: c.direct.clone() })
}

/// Перевести сразу несколько правил. Нужно для наборов: переключать
/// их по одному значит на секунду оставлять маршрутизацию несогласованной.
#[tauri::command]
fn rules_set_via(app: State<App>, patterns: Vec<String>, via: String) -> Result<(), String> {
    let e = engine(&app)?;
    {
        let mut c = e.cfg.lock().unwrap();
        for pattern in &patterns {
            c.through_proxy.retain(|p| p != pattern);
            for g in c.groups.iter_mut() {
                g.patterns.retain(|p| p != pattern);
            }
        }
        c.groups.retain(|g| !g.patterns.is_empty());
        if via.is_empty() {
            c.through_proxy.extend(patterns);
        } else {
            match c.groups.iter_mut().find(|g| g.via == via) {
                Some(g) => g.patterns.extend(patterns),
                None => c.groups.push(core::config::RouteGroup {
                    via, enabled: true, patterns,
                }),
            }
        }
    }
    { e.apply_and_save()?; let _ = refresh_tunnel(&app); Ok(()) }
}

/// Перевести правило на другой прокси. Пустое имя — вернуть на основной.
#[tauri::command]
fn rule_set_via(app: State<App>, pattern: String, via: String) -> Result<(), String> {
    let e = engine(&app)?;
    {
        let mut c = e.cfg.lock().unwrap();
        // сначала убираем отовсюду
        c.through_proxy.retain(|p| p != &pattern);
        for g in c.groups.iter_mut() {
            g.patterns.retain(|p| p != &pattern);
        }
        c.groups.retain(|g| !g.patterns.is_empty());
        // затем кладём куда надо
        if via.is_empty() {
            c.through_proxy.push(pattern);
        } else {
            match c.groups.iter_mut().find(|g| g.via == via) {
                Some(g) => g.patterns.push(pattern),
                None => c.groups.push(core::config::RouteGroup {
                    via, enabled: true, patterns: vec![pattern],
                }),
            }
        }
    }
    e.apply_and_save()
}

/// Добавить правила. `via` — через какой прокси их пускать;
/// пусто или не указано — через основной.
#[tauri::command]
fn rule_add(
    app: State<App>,
    text: String,
    via: Option<String>,
) -> Result<core::config::BulkResult, String> {
    let e = engine(&app)?;
    let via = via.unwrap_or_default();
    let r = {
        let mut c = e.cfg.lock().unwrap();
        let r = c.add_many(&text);
        if !via.is_empty() {
            // добавленное сразу переносим в группу выбранного прокси
            for pat in &r.added {
                c.through_proxy.retain(|p| p != pat);
            }
            match c.groups.iter_mut().find(|g| g.via == via) {
                Some(g) => g.patterns.extend(r.added.iter().cloned()),
                None => c.groups.push(core::config::RouteGroup {
                    via: via.clone(), enabled: true, patterns: r.added.clone(),
                }),
            }
        }
        r
    };
    e.apply_and_save()?;
    let _ = refresh_tunnel(&app);
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
    let _ = refresh_tunnel(&app);
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
    let _ = refresh_tunnel(&app);
    Ok(r)
}

/// Выгрузить список правил в файл — чтобы поделиться с коллегами.
#[tauri::command]
fn rules_export(app: State<App>, path: String) -> Result<usize, String> {
    let e = engine(&app)?;
    let c = e.cfg.lock().unwrap();
    // ⛔ Выгружаем ВСЁ, что задаёт маршрутизацию: общие правила,
    // правила групп и исключения. Раньше уходили только общие, и у
    // того, кому отдали файл, пропадали и переведённые на отдельные
    // прокси домены, и исключения — а число в окне говорило другое.
    let mut lines: Vec<String> = Vec::new();
    lines.extend(c.through_proxy.iter().cloned());
    for g in &c.groups {
        if g.patterns.is_empty() {
            continue;
        }
        lines.push(format!("_через «{}»", g.via));
        lines.extend(g.patterns.iter().cloned());
    }
    if !c.direct.is_empty() {
        lines.push("_напрямую".into());
        lines.extend(c.direct.iter().map(|d| format!("!{d}")));
    }
    let text = lines.join("\n") + "\n";
    let n = lines.iter().filter(|s| !s.starts_with('_')).count();
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
    let _ = refresh_tunnel(&app);
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
            route: r.decide(h).tag().into(),
        })
        .collect())
}

/// Что открыто прямо сейчас — колонки как в Proxifier.
#[tauri::command]
fn conns_active(app: State<App>) -> Vec<core::conns::Conn> {
    // ⛔ В режиме перехвата программы обращаются не к нам, и свои записи
    // пусты: человек видел пустую вкладку при работающем туннеле.
    // Спрашиваем движок — он ведёт учёт сам.
    if tunnel_on(&app) {
        return core::engine_stats::active();
    }
    core::conns::active()
}

/// Сколько куда ушло, по доменам.
#[tauri::command]
fn conns_totals(app: State<App>) -> Vec<core::conns::DomainStat> {
    if tunnel_on(&app) {
        return core::engine_stats::totals();
    }
    core::conns::totals()
}

#[tauri::command]
fn conns_reset(app: State<App>) {
    core::engine_stats::reset();
    let _ = app;
    core::conns::reset_totals();
}

/// Сделать прокси основным — одним нажатием, без правки правил.
#[tauri::command]
fn upstream_set_default(app: State<App>, name: String) -> Result<(), String> {
    let e = engine(&app)?;
    { e.cfg.lock().unwrap().set_default(&name)?; }
    e.apply_and_save()
}

/// Отказы соединений за последние 10 минут — для подсказок.
#[tauri::command]
fn failures_recent() -> Vec<core::failures::Failure> {
    core::failures::recent(600)
}

#[tauri::command]
fn failures_clear() {
    core::failures::clear()
}

/// Временно увести правила одного прокси на другой.
#[tauri::command]
fn override_set(app: State<App>, from: String, to: String) -> Result<(), String> {
    engine(&app)?.set_override(&from, &to)
}

#[tauri::command]
fn override_clear(app: State<App>, from: String) -> Result<(), String> {
    engine(&app)?.clear_override(&from);
    Ok(())
}

#[derive(Serialize)]
pub struct Override {
    from: String,
    to: String,
}

#[tauri::command]
fn overrides_list(app: State<App>) -> Vec<Override> {
    match engine(&app) {
        Ok(e) => e.overrides().into_iter().map(|(from, to)| Override { from, to }).collect(),
        Err(_) => Vec::new(),
    }
}

/// Прокси, на которые ссылаются правила, — чтобы знать, чей отказ важен.
#[tauri::command]
fn proxies_in_use(app: State<App>) -> Result<Vec<String>, String> {
    let e = engine(&app)?;
    let c = e.cfg.lock().unwrap();
    let mut v: Vec<String> = c.groups.iter()
        .filter(|g| g.enabled && !g.patterns.is_empty())
        .map(|g| g.via.clone())
        .collect();
    if !c.through_proxy.is_empty() {
        v.push(c.default_upstream.clone());
    }
    v.sort();
    v.dedup();
    Ok(v)
}

/// Состояние подписки и xray.
#[derive(Serialize)]
pub struct SubState {
    /// скачан ли xray
    installed: bool,
    /// работает ли сейчас
    running: bool,
    /// адрес подписки, если брали по ссылке
    url: String,
    /// есть ли сохранённое содержимое
    has_text: bool,
    enabled: bool,
    countries: Vec<String>,
    dir: String,
    /// почему ядро не поднялось — если не поднялось
    error: Option<String>,
    /// последние строки, сказанные ядром
    log_tail: String,
}

#[tauri::command]
fn sub_state(app: State<App>) -> SubState {
    let path = app.path.lock().unwrap().clone();
    let dir = core::xray_dir(&path);
    let (url, has_text, enabled, countries) = match engine(&app) {
        Ok(e) => {
            let c = e.cfg.lock().unwrap();
            let s = c.subscription.clone();
            (
                s.as_ref().map(|s| s.url.clone()).unwrap_or_default(),
                s.as_ref().map(|s| !s.text.trim().is_empty()).unwrap_or(false),
                s.as_ref().map(|s| s.enabled).unwrap_or(false),
                c.upstreams.iter().filter(|u| u.from_subscription)
                    .map(|u| u.name.clone()).collect(),
            )
        }
        Err(_) => (String::new(), false, false, Vec::new()),
    };
    SubState {
        installed: core::xray::is_installed(&dir),
        running: core::xray::is_running(),
        error: core::xray::last_error(),
        log_tail: core::xray::log_tail(&dir, 8),
        url, has_text, enabled, countries,
        dir: dir.to_string_lossy().to_string(),
    }
}

/// Скачать xray. Отдельным действием и только по нажатию: в состав
/// программы он не входит, чтобы на рабочих машинах его не было вовсе.
#[tauri::command]
async fn sub_install(app: tauri::AppHandle) -> Result<String, String> {
    let path = app.state::<App>().path.lock().unwrap().clone();
    let dir = core::xray_dir(&path);
    tauri::async_runtime::spawn_blocking(move || core::xray::download(&dir))
        .await
        .map_err(|e| e.to_string())?
}

/// Загрузить подписку: из текста или по ссылке. Возвращает список стран.
#[tauri::command]
async fn sub_load(app: tauri::AppHandle, source: String) -> Result<Vec<String>, String> {
    let source = source.trim().to_string();
    if source.is_empty() {
        return Err("не указана подписка".into());
    }
    let by_url = source.starts_with("http://") || source.starts_with("https://");
    let (url, text) = if by_url {
        let u = source.clone();
        let body = tauri::async_runtime::spawn_blocking(move || {
            ureq::get(&u)
                .header("User-Agent", "NexusProxy")
                .call()
                .map_err(|e| format!("не скачать подписку: {e}"))?
                .body_mut()
                .read_to_string()
                .map_err(|e| format!("испорченный ответ: {e}"))
        })
        .await
        .map_err(|e| e.to_string())??;
        (source, body)
    } else {
        (String::new(), source)
    };

    // разбираем сразу, чтобы не сохранять заведомо негодное
    let profiles = core::subscription::parse(&text)?;
    let names: Vec<String> = profiles.iter().map(|p| p.name.clone()).collect();

    let state = app.state::<App>();
    let e = engine(&state)?;
    {
        let mut c = e.cfg.lock().unwrap();
        c.subscription = Some(core::config::Subscription { url, text, enabled: true });
    }
    e.apply_and_save()?;
    Ok(names)
}

/// Поднять страны из подписки.
#[tauri::command]
async fn sub_apply(app: tauri::AppHandle) -> Result<Vec<String>, String> {
    let state = app.state::<App>();
    let e = engine(&state)?;
    tauri::async_runtime::spawn_blocking(move || e.apply_subscription())
        .await
        .map_err(|e| e.to_string())?
}

/// Выключить подписку: остановить xray и убрать страны из списка.
#[tauri::command]
async fn sub_disable(app: tauri::AppHandle) -> Result<(), String> {
    let state = app.state::<App>();
    let e = engine(&state)?;
    {
        let mut c = e.cfg.lock().unwrap();
        if let Some(s) = c.subscription.as_mut() {
            s.enabled = false;
        }
    }
    tauri::async_runtime::spawn_blocking(move || e.apply_subscription())
        .await
        .map_err(|e| e.to_string())??;
    Ok(())
}

/// Доступность каждого прокси.
#[tauri::command]
fn proxies_health() -> Vec<core::health::ProxyHealth> {
    core::health::proxies()
}

/// Список прокси и группы правил.
#[tauri::command]
fn upstreams_list(app: State<App>) -> Result<serde_json::Value, String> {
    let e = engine(&app)?;
    let c = e.cfg.lock().unwrap();
    Ok(serde_json::json!({
        "upstreams": c.all_upstreams(),
        "groups": c.groups,
    }))
}

/// Добавить, изменить или переименовать прокси.
/// `old_name` — как он назывался до правки; пусто, если это новый.
///
/// Переименование обязано тянуть за собой группы правил: иначе они
/// останутся ссылаться на исчезнувшее имя, и трафик молча пойдёт мимо.
#[tauri::command]
fn upstream_save(
    app: State<App>,
    up: core::upstream::Upstream,
    old_name: Option<String>,
) -> Result<(), String> {
    if up.address.trim().is_empty() {
        return Err("не указан адрес".into());
    }
    if up.name.trim().is_empty() {
        return Err("не указано имя".into());
    }
    let mut up = up;
    // пустые поля входа не должны попадать в настройки как пустые строки:
    // прокси тогда предлагается вход по логину, а отправлять нечего
    if up.user.as_deref().is_some_and(|v| v.trim().is_empty()) { up.user = None; }
    if up.password.as_deref().is_some_and(|v| v.trim().is_empty()) { up.password = None; }
    let e = engine(&app)?;
    {
        let mut c = e.cfg.lock().unwrap();
        let old = old_name.unwrap_or_default();

        // имя должно быть свободно
        if up.name != old && c.upstreams.iter().any(|x| x.name == up.name) {
            return Err(format!("прокси с именем «{}» уже есть", up.name));
        }

        match c.upstreams.iter_mut().find(|x| x.name == old) {
            Some(x) => {
                *x = up.clone();
                // ⛔ Переименование тянет за собой ВСЕ ссылки: группы,
                // список программ и «основной». Раньше список программ
                // забывали, и весь их трафик уходил на несуществующее
                // имя — со стороны это «программа перестала ходить через
                // прокси», без единого объяснения.
                c.rename_upstream(&old, &up.name.clone());
            }
            None => {
                c.upstreams.push(up.clone());
                if c.default_upstream.is_empty() {
                    c.default_upstream = up.name.clone();
                }
            }
        }
    }
    e.apply_and_save()
}

/// Убрать прокси. Нельзя убрать последний и тот, на который ещё
/// ссылается группа правил. Основной убрать можно — роль перейдёт
/// к оставшемуся.
#[tauri::command]
fn upstream_remove(app: State<App>, name: String) -> Result<(), String> {
    let e = engine(&app)?;
    {
        let mut c = e.cfg.lock().unwrap();
        c.remove_upstream(&name)?;
    }
    e.apply_and_save()
}

/// Создать или обновить группу правил, идущих через отдельный прокси.
#[tauri::command]
fn group_save(app: State<App>, group: core::config::RouteGroup) -> Result<(), String> {
    let e = engine(&app)?;
    {
        let mut c = e.cfg.lock().unwrap();
        match c.groups.iter_mut().find(|g| g.via == group.via) {
            Some(g) => *g = group,
            None => c.groups.push(group),
        }
    }
    e.apply_and_save()
}

#[tauri::command]
fn group_remove(app: State<App>, via: String) -> Result<(), String> {
    let e = engine(&app)?;
    { e.cfg.lock().unwrap().groups.retain(|g| g.via != via); }
    e.apply_and_save()
}

#[tauri::command]
fn journal_since(after: u64) -> Vec<core::journal::Entry> {
    core::journal::since(after)
}

/// Откуда запущена программа и какая это версия.
///
/// Нужно, потому что обновление у Tauri всегда идёт через установщик:
/// он ставит программу в профиль пользователя, а запущенный портативный
/// файл остаётся старым. Без пояснения человек ищет «куда делась новая
/// версия» и снова запускает старый файл.
#[derive(Serialize)]
pub struct Install {
    version: String,
    portable: bool,
    exe_dir: String,
    installed_dir: String,
}

#[tauri::command]
fn install_info(app: tauri::AppHandle) -> Install {
    let exe = std::env::current_exe().unwrap_or_default();
    let exe_dir = exe.parent().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
    let installed_dir = std::env::var("LOCALAPPDATA")
        .map(|d| format!("{d}\\NexusProxy"))
        .unwrap_or_default();
    let portable = !installed_dir.is_empty()
        && !exe_dir.eq_ignore_ascii_case(&installed_dir);
    Install {
        version: app.package_info().version.to_string(),
        portable,
        exe_dir,
        installed_dir,
    }
}

/// Показать папку человеку — своим проводником на каждой системе.
///
/// ⛔ Раньше на macOS здесь была пустая ветка: кнопка нажималась и не
/// делала ничего. Молчаливое бездействие хуже отказа — человек считает,
/// что сломалась программа, а не кнопка.
fn reveal(dir: &std::path::Path) -> Result<(), String> {
    let program = if cfg!(windows) {
        "explorer"
    } else if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    std::process::Command::new(program)
        .arg(dir)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("не открыть папку: {e}"))
}

/// Открыть папку, куда установщик кладёт программу.
#[tauri::command]
fn open_installed(_app: tauri::AppHandle) -> Result<(), String> {
    let dir: std::path::PathBuf = if cfg!(windows) {
        std::env::var("LOCALAPPDATA")
            .map(|d| std::path::PathBuf::from(d).join("NexusProxy"))
            .map_err(|_| "не удалось определить папку профиля")?
    } else {
        // на macOS программа лежит в бандле — показываем его самого
        std::env::current_exe()
            .map_err(|e| e.to_string())?
            .ancestors()
            .find(|p| p.extension().map(|e| e == "app").unwrap_or(false))
            .map(|p| p.to_path_buf())
            .or_else(|| std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())))
            .ok_or("папка не найдена")?
    };
    reveal(&dir)
}

/// Открыть папку с настройками и журналом.
#[tauri::command]
fn open_folder(app: State<App>) -> Result<(), String> {
    let p = app.path.lock().unwrap().clone();
    let dir = std::path::Path::new(&p).parent().ok_or("папка не найдена")?;
    reveal(dir)
}

#[tauri::command]
fn journal_clear() {
    core::journal::clear()
}




#[tauri::command]
fn system_proxy(app: State<App>, on: bool) -> Result<(), String> {
    let e = engine(&app)?;
    // ⛔ Одна кнопка на всё. Способ выбран в настройках, здесь только
    // «работает / не работает»: два независимых выключателя человеку не
    // объяснить, и перехват однажды остался включённым при выключенной
    // программе.
    let tunnel = e.cfg.lock().unwrap().tunnel_mode;
    if on {
        if tunnel {
            let path = app.path.lock().unwrap().clone();
            let dir = core::tunnel_dir(&path);
            // системные настройки перехвату не нужны и только мешают:
            // браузеры читают их и уходят на локальный адрес мимо туннеля
            e.system_proxy_drop();
            core::tunnel_service::start_in(&dir)
        } else {
            e.tunnel_off();
            e.system_proxy_on()
        }
    } else {
        e.tunnel_off();
        e.system_proxy_off();
        Ok(())
    }
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
            "enable_on_start" => c.enable_on_start = value,
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
    http_port: u16,
    socks_port: u16,
}

/// Сохранить наши порты. Порты читаются при запуске, поэтому движок
/// перезапускается; прокси и правила при этом сохраняются.
#[tauri::command]
async fn settings_save(app: tauri::AppHandle, s: Settings) -> Result<(), String> {
    let state = app.state::<App>();
    let path = state.path.lock().unwrap().clone();
    let old = engine(&state).ok();
    let mut cfg = match &old {
        Some(e) => e.cfg.lock().unwrap().clone(),
        None => core::config::Config::load(&path)?,
    };
    // ⛔ Порты проверяем ДО того, как что-то трогать. Ноль или два
    // одинаковых означают, что движок не поднимется, — и раньше это
    // выяснялось уже после остановки прежнего.
    if s.http_port == 0 || s.socks_port == 0 {
        return Err("порт не может быть нулевым".into());
    }
    if s.http_port == s.socks_port {
        return Err("у входов должны быть разные порты".into());
    }

    let было = cfg.clone();
    cfg.listen.http = s.http_port;
    cfg.listen.socks = s.socks_port;
    cfg.save(&path)?;

    // перезапуск: порты и адрес прокси читаются при старте
    let was_on = old.as_ref().map_or(false, |e| e.system_proxy_is_ours());
    if let Some(e) = old {
        e.shutdown();
    }
    *state.engine.lock().unwrap() = None;
    let fresh = match core::Engine::start(cfg, &path).await {
        Ok(e) => e,
        Err(err) => {
            // ⛔ Возвращаем как было. Иначе программа остаётся без
            // движка НАВСЕГДА: негодные порты уже записаны в файл, и
            // перезапуск не помогает — человеку остаётся править
            // настройки руками в блокноте.
            let _ = было.save(&path);
            match core::Engine::start(было, &path).await {
                Ok(back) => {
                    if was_on {
                        let _ = back.system_proxy_on();
                    }
                    *state.engine.lock().unwrap() = Some(back);
                    return Err(format!("{err}. Прежние настройки возвращены"));
                }
                Err(worse) => {
                    *state.start_error.lock().unwrap() = Some(worse.clone());
                    return Err(format!("{err}. Вернуть прежние тоже не вышло: {worse}"));
                }
            }
        }
    };
    if was_on {
        fresh.system_proxy_on()?;
    }
    *state.engine.lock().unwrap() = Some(fresh);
    Ok(())
}

fn default_config() -> core::config::Config {
    core::config::Config {
        upstream: None,
        upstreams: vec![core::upstream::Upstream {
            name: "основной".into(),
            kind: core::upstream::Kind::Socks5,
            address: "127.0.0.1".into(), port: 1080, user: None, password: None,
            from_subscription: false,
        }],
        default_upstream: "основной".into(),
        groups: vec![],
        listen: core::config::Listen { http: 18080, socks: 18081 },
        through_proxy: vec![],
        direct: vec![],
        auto_reconnect: true,
        minimize_to_tray: true,
        enable_on_start: true,
        defaults_applied: false,
        subscription: None,
        apps: vec![],
        tunnel_mode: false,
        extra: Default::default(),
    }
}

/// Запуск свёрнутым. Нужен вместе с автозапуском: иначе при каждом входе
/// в систему окно лезет на передний план.
fn started_hidden() -> bool {
    std::env::args().any(|a| a == "--hidden" || a == "--minimized")
}

/// Список приложений, запускаемых через нас.
///
/// ⛔ Нужно тем, кто НЕ читает системные настройки прокси: Cursor,
/// Electron и часть консольных программ. Их трафик до нас не доходит
/// вовсе, поэтому и подбор доменов для них пуст — он показывает только
/// то, что через нас прошло.
#[tauri::command]
fn apps_list(app: State<App>) -> Vec<core::launch::App> {
    match engine(&app) {
        Ok(e) => e.cfg.lock().unwrap().apps.clone(),
        Err(_) => Vec::new(),
    }
}

#[tauri::command]
fn app_save(state: State<App>, item: core::launch::App) -> Result<String, String> {
    if item.path.trim().is_empty() {
        return Err("не указан путь к программе".into());
    }
    let e = engine(&state)?;
    // Прокси у приложения обязателен: ради него его сюда и добавляют.
    // Пустое значение оставляло бы приложение жить по общим правилам —
    // ровно то, что было бы и без записи в списке.
    let mut item = item;
    if item.via.trim().is_empty() {
        item.via = e.cfg.lock().unwrap().default_upstream.clone();
    }
    {
        let mut c = e.cfg.lock().unwrap();
        match c.apps.iter_mut().find(|a| a.path == item.path) {
            Some(x) => *x = item,
            None => c.apps.push(item),
        }
    }
    e.apply_and_save()?;
    // ⛔ Иначе движок останется со старым списком: приложение в окне
    // есть, а трафик его идёт мимо.
    //
    // ⛔ Но НЕ ценой самой записи. Приложение уже сохранено, и падать
    // здесь нельзя: человек видел бы «не добавилось», хотя добавилось.
    // Про неудачу говорим отдельно — записи это не отменяет.
    Ok(match refresh_tunnel(&state) {
        Ok(()) => String::new(),
        Err(e) => format!("Приложение добавлено, но перехват не обновился: {e}"),
    })
}

#[tauri::command]
fn app_remove(state: State<App>, path: String) -> Result<String, String> {
    let e = engine(&state)?;
    e.cfg.lock().unwrap().apps.retain(|a| a.path != path);
    e.apply_and_save()?;
    Ok(match refresh_tunnel(&state) {
        Ok(()) => String::new(),
        Err(e) => format!("Приложение убрано, но перехват не обновился: {e}"),
    })
}

/// На каких портах мы слушаем — берём из живого движка.
fn ports(state: &State<App>) -> (u16, u16) {
    match engine(state) {
        Ok(e) => { let c = e.cfg.lock().unwrap(); (c.listen.socks, c.listen.http) }
        Err(_) => (18081, 18080),
    }
}

#[tauri::command]
fn app_launch(state: State<App>, path: String) -> Result<String, String> {
    let item = {
        let e = engine(&state)?;
        let c = e.cfg.lock().unwrap();
        c.apps.iter().find(|a| a.path == path).cloned()
    }.ok_or("такого приложения нет в списке")?;
    let (socks, http) = ports(&state);
    let pid = core::launch::start(&item, socks, http)?;
    Ok(format!("{} запущен через прокси ({}), процесс {pid}",
               item.name, core::launch::explain(&item, socks, http)))
}

/// Переписать настройки туннеля по текущему состоянию программы.
///
/// ⛔ Вызывать при ЛЮБОМ изменении списка приложений и правил. Движок
/// читает настройки при запуске: не обновив их, мы оставляем его со
/// старым списком — человек добавляет приложение, видит его в окне, а
/// трафик идёт мимо. Так и было: добавленный браузер в туннель не
/// попадал вовсе.
/// Работает ли сейчас перехват — от этого зависит, чьи счётчики верны.
fn tunnel_on(app: &State<App>) -> bool {
    match engine(app) {
        Ok(e) => { let m = e.cfg.lock().unwrap().tunnel_mode; m }
        Err(_) => false,
    }
}

fn refresh_tunnel(app: &State<App>) -> Result<(), String> {
    let path = app.path.lock().unwrap().clone();
    let dir = core::tunnel_dir(&path);
    let e = engine(app)?;
    if !e.cfg.lock().unwrap().tunnel_mode {
        return Ok(());
    }
    // ⛔ В режиме перехвата системные настройки прокси обязаны быть
    // сняты: иначе браузеры идут по ним на наш вход, мимо туннеля.
    e.system_proxy_drop();
    // Сами настройки движка перекладывает движок программы — так это
    // делает КАЖДОЕ сохранение, а не только часть команд.
    e.sync_tunnel()?;
    // ⛔ Служба тоже могла устареть: способ запуска меняется вместе с
    // программой, а ставится он один раз. Без проверки после обновления
    // продолжает работать прежний — со старыми повадками.
    if core::tunnel_service::needs_reinstall(&dir) {
        core::tunnel_service::install(&dir)?;
    }
    core::tunnel_service::start_in(&dir)
}

/// Что сейчас с перехватом: скачан ли движок, работает ли, почему нет.
#[tauri::command]
fn tunnel_state(app: State<App>) -> serde_json::Value {
    let path = app.path.lock().unwrap().clone();
    let dir = core::tunnel_dir(&path);
    let (mode, apps) = match engine(&app) {
        Ok(e) => { let c = e.cfg.lock().unwrap(); (c.tunnel_mode, c.apps.len()) }
        Err(_) => (false, 0),
    };
    let svc = core::tunnel_service::state_in(&dir);
    serde_json::json!({
        "installed": core::tunnel::is_installed(&dir),
        "service": svc,
        // ⛔ Показываем, что происходит НА САМОМ ДЕЛЕ, а не сохранённую
        // настройку: после перезапуска программы галка стояла, а перехват
        // был снят — человек считал, что всё работает.
        // ⛔ Движок поднимает служба от имени системы — нашим дочерним
        // процессом он не является. Смотрим, жив ли он в системе вообще,
        // иначе в окне «перехват выключен» при работающем туннеле.
        "running": svc == core::tunnel_service::State::Running
                   || core::tunnel::is_alive(&dir),
        "mode": mode,
        "apps": apps,
        "error": core::tunnel::last_error(),
    })
}

/// Последние строки журнала движка — показываем при неудаче.
#[tauri::command]
fn tunnel_log(app: State<App>) -> String {
    let path = app.path.lock().unwrap().clone();
    core::tunnel::diagnosis(&core::tunnel_dir(&path))
}

/// Скачать движок перехвата — он не входит в состав программы.
#[tauri::command]
async fn tunnel_install(app: AppHandle) -> Result<String, String> {
    let dir = {
        let s = app.state::<App>();
        let path = s.path.lock().unwrap().clone();
        core::tunnel_dir(&path)
    };
    tokio::task::spawn_blocking(move || core::tunnel::download(&dir))
        .await
        .map_err(|e| e.to_string())?
}

/// Включить или выключить перехват.
#[tauri::command]
async fn tunnel_set(app: AppHandle, on: bool) -> Result<(), String> {
    let (dir, routes, domains, ups) = {
        let state = app.state::<App>();
        let path = state.path.lock().unwrap().clone();
        let dir = core::tunnel_dir(&path);
        let e = engine(&state)?;
        let mut c = e.cfg.lock().unwrap();
        c.tunnel_mode = on;
        let routes: Vec<core::tunnel::Route> = c.apps.iter()
            .filter(|a| !a.via.trim().is_empty())
            .map(|a| core::tunnel::Route {
                process: core::launch::process_name(&a.path),
                path: a.path.clone(),
                via: a.via.clone(),
            })
            .collect();
        let ups: Vec<core::tunnel::Upstream> = c.all_upstreams().into_iter()
            .map(|u| core::tunnel::Upstream {
                tag: u.name.clone(),
                kind: match u.kind {
                    core::upstream::Kind::Socks5 => core::tunnel::Kind::Socks5,
                    core::upstream::Kind::Http => core::tunnel::Kind::Http,
                },
                address: u.address.clone(), port: u.port,
                user: u.user.clone(), password: u.password.clone(),
            })
            .collect();
        // ⛔ Правила по доменам обязаны попасть в туннель: системные
        // настройки при нём не трогаются, и без них всё, кроме
        // приложений, пойдёт напрямую.
        let domains: Vec<core::tunnel::DomainRule> = c.through_proxy.iter()
            .map(|p| core::tunnel::DomainRule { pattern: p.clone(), via: String::new() })
            .chain(c.groups.iter().filter(|g| g.enabled).flat_map(|g| {
                g.patterns.iter().map(move |p| core::tunnel::DomainRule {
                    pattern: p.clone(), via: g.via.clone(),
                })
            }))
            .map(|mut d| {
                if d.via.trim().is_empty() {
                    d.via = c.default_upstream.clone();
                }
                d
            })
            .collect();
        (dir, routes, domains, ups)
    };
    { let s = app.state::<App>(); engine(&s)?.apply_and_save()?; }

    tokio::task::spawn_blocking(move || {
        if !on {
            // ⛔ Переключение способа обязано его СРАЗУ применить, а не
            // просто запомнить. Человек выбрал режим прокси — значит
            // системные настройки должны прописаться тут же, без похода
            // к кнопке в шапке: «включил — прописались, выключил —
            // убрались», как на Windows.
            let _ = core::tunnel_service::stop_in(&dir);
            core::tunnel::stop_elevated();
            core::tunnel::stop();
            return Ok(());
        }
        // Настройки пишем всегда: служба читает их при запуске.
        core::tunnel::write_config(&dir, &routes, &domains, &ups)?;
        // ⛔ Проверяем не только наличие, но и чем служба поставлена:
        // после обновления программы старая запись продолжает работать
        // по-старому, и человек не видит никаких изменений.
        let stale = core::tunnel_service::needs_reinstall(&dir);
        match core::tunnel_service::state_in(&dir) {
            _ if stale => {
                core::tunnel_service::install(&dir)?;
                core::tunnel_service::start_in(&dir)
            }
            core::tunnel_service::State::Stopped
            | core::tunnel_service::State::Running => core::tunnel_service::start_in(&dir),
            core::tunnel_service::State::Absent => {
                core::tunnel_service::install(&dir)?;
                core::tunnel_service::start_in(&dir)
            }
        }
    })
    .await
    .map_err(|e| e.to_string())??;

    // Способ выбран — применяем его сразу.
    let state = app.state::<App>();
    let e = engine(&state)?;
    if on {
        e.system_proxy_drop();
    } else {
        e.system_proxy_on()?;
    }
    Ok(())
}

/// Сохранить настройки в файл — чтобы перенести на другую машину.
#[tauri::command]
fn settings_export(app: State<App>, path: String) -> Result<(), String> {
    let e = engine(&app)?;
    let data = e.cfg.lock().unwrap().export();
    let text = serde_json::to_string_pretty(&data)
        .map_err(|e| format!("не собрать настройки: {e}"))?;
    std::fs::write(&path, text).map_err(|e| format!("не записать файл: {e}"))
}

/// Принять настройки из файла.
///
/// Возвращает список приложений, которых на этой машине нет: пути у
/// разных людей отличаются, и человек должен увидеть это сразу, а не
/// гадать, почему перехват их не ловит.
#[tauri::command]
async fn settings_import(app: AppHandle, path: String) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("не прочитать файл: {e}"))?;
    let data: core::config::Portable = serde_json::from_str(&text)
        .map_err(|_| "это не файл настроек NexusProxy".to_string())?;

    let missing = {
        let state = app.state::<App>();
        let e = engine(&state)?;
        let missing = e.cfg.lock().unwrap().import(data);
        e.apply_and_save()?;
        missing
    };
    // применяем выбранный способ сразу, как при переключении вручную
    let on = { let s = app.state::<App>(); let e = engine(&s)?; let m = e.cfg.lock().unwrap().tunnel_mode; m };
    tunnel_set(app, on).await?;
    Ok(missing)
}


#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // Вторая копия не должна занимать порты и показывать пустое окно —
        // вместо запуска показываем уже работающую.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            // при автозапуске окно не показываем — программа уходит в трей
            Some(vec!["--hidden"]),
        ))
        .manage(App {
            engine: Mutex::new(None),
            path: Mutex::new(String::new()),
            start_error: Mutex::new(None),
        })
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
            // ⛔ Испорченные настройки НЕ заменяем умолчаниями. Любая
            // неудача чтения — оборванная запись, файл занят проверяющей
            // программой, отказ доступа — раньше означала, что человек
            // молча теряет все прокси, правила и список программ, а
            // поверх тут же записываются пустые настройки.
            let mut cfg = match core::config::Config::load_or_backup(&path_s) {
                Ok((c, note)) => {
                    if let Some(note) = note {
                        core::logfile::line(&core::logfile::now_stamp(), &note);
                        *app.state::<App>().start_error.lock().unwrap() = Some(note);
                    }
                    c
                }
                Err(e) => {
                    // Ничего не портим: откладываем нечитаемый файл в
                    // сторону, чтобы человек мог его посмотреть, и
                    // говорим об этом прямо.
                    let kept = format!("{path_s}.испорчен");
                    let _ = std::fs::rename(&path_s, &kept);
                    let note = format!("{e}. Прежний файл отложен: {kept}");
                    core::logfile::line(&core::logfile::now_stamp(), &note);
                    *app.state::<App>().start_error.lock().unwrap() = Some(note);
                    default_config()
                }
            };

            // ── Базовые галки поведения: все четыре включены ──
            // Ставим один раз и запоминаем это в настройках: иначе снятая
            // вручную галка возвращалась бы при каждом запуске.
            if !cfg.defaults_applied {
                cfg.defaults_applied = true;
                cfg.enable_on_start = true;
                cfg.minimize_to_tray = true;
                cfg.auto_reconnect = true;
                cfg.save(&path_s).ok();
                use tauri_plugin_autostart::ManagerExt;
                match app.autolaunch().enable() {
                    Ok(_) => core::logfile::line(&core::logfile::now_stamp(),
                        "запуск вместе с системой включён по умолчанию"),
                    Err(err) => core::logfile::line(&core::logfile::now_stamp(),
                        &format!("автозапуск не включился: {err}")),
                }
            }

            if started_hidden() {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }

            let state = app.state::<App>();
            *state.path.lock().unwrap() = path_s.clone();

            // ⛔ Статистику перехвата забираем в СВОЁМ потоке, раз в две
            // секунды. Спрашивать движок из окна нельзя: это обращение по
            // сети, и окно на нём замирает.
            {
                let dir = core::tunnel_dir(&path_s);
                std::thread::spawn(move || loop {
                    if core::tunnel::is_alive(&dir) {
                        let _ = core::engine_stats::refresh(&dir);
                    }
                    // ⛔ Раз в секунду, а не раз в две: движок отдаёт
                    // только открытые сейчас соединения, и всё, что
                    // успело открыться и закрыться между опросами, в
                    // учёт по доменам не попадает вовсе. Общий итог при
                    // этом точный — его ведёт сам движок.
                    std::thread::sleep(std::time::Duration::from_secs(1));
                });
            }

            let rt = tokio::runtime::Runtime::new()?;
            match rt.block_on(core::Engine::start(cfg, &path_s)) {
                Ok(e) => {
                    *state.engine.lock().unwrap() = Some(e);
                    // ⛔ Настройки туннеля обновляем при каждом запуске:
                    // иначе движок работает с тем списком, что был при
                    // последнем переключении режима, а всё добавленное
                    // после него в туннель не попадает.
                    let _ = refresh_tunnel(&state);
                }
                Err(err) => {
                    eprintln!("движок не запустился: {err}");
                    *state.start_error.lock().unwrap() = Some(err);
                }
            }

            {
                let e = app.state::<App>().engine.lock().unwrap().clone();
                if let Some(e) = e {
                    // страны из подписки поднимаем при запуске, иначе правила,
                    // на них ссылающиеся, будут вести в никуда
                    if let Err(err) = e.apply_subscription() {
                        core::logfile::line(&core::logfile::now_stamp(),
                            &format!("подписка не поднялась: {err}"));
                    }
                }
            }

            // ⛔ Только ПОСЛЕ запуска движка: раньше этот блок стоял выше,
            // движка ещё не было, и галка «включать при запуске» молча
            // ничего не делала.
            {
                let e = app.state::<App>().engine.lock().unwrap().clone();
                if let Some(e) = e {
                    let (want, tunnel) = {
                        let c = e.cfg.lock().unwrap();
                        (c.enable_on_start, c.tunnel_mode)
                    };
                    if want && !tunnel {
                        match e.system_proxy_on() {
                            Ok(_) => core::logfile::line(&core::logfile::now_stamp(),
                                                        "режим прокси включён при запуске"),
                            Err(err) => core::logfile::line(&core::logfile::now_stamp(),
                                &format!("не удалось включить режим прокси: {err}")),
                        }
                    } else if want && tunnel {
                        // ⛔ В TUN режиме системные настройки прокси ставить
                        // НЕЛЬЗЯ. Браузеры (кроме Firefox) их читают и идут
                        // на наш локальный адрес — а туда туннель не смотрит,
                        // это петля внутри машины. Их соединений не видно
                        // вовсе, и выглядит как «перехват их не ловит».
                        e.system_proxy_drop();
                        core::logfile::line(&core::logfile::now_stamp(),
                            "TUN режим: системные настройки прокси сняты");
                    }
                }
            }

            // среда выполнения должна жить, пока живёт программа
            std::mem::forget(rt);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status, rules_list, rule_add, rule_edit, rule_remove, rule_set_via, rules_set_via,
            rule_add_from_file, rules_export, presets, check,
            journal_since, journal_clear, open_folder, install_info, open_installed,
            conns_active, conns_totals, conns_reset,
            upstreams_list, upstream_save, upstream_remove, group_save, group_remove,
            proxies_health, upstream_set_default, failures_recent, failures_clear,
            override_set, override_clear, overrides_list, proxies_in_use,
            sub_state, sub_install, sub_load, sub_apply, sub_disable,
            system_proxy, settings_save, set_flag, quit,
            apps_list, app_save, app_remove, app_launch,
            tunnel_state, tunnel_install, tunnel_set, tunnel_log,
            settings_export, settings_import
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
