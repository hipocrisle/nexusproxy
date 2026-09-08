//! Ядро NexusProxy: локальный прокси с правилами.
//! Отдельно от интерфейса, чтобы им пользовались и окно программы, и консоль.

pub mod config;
pub mod conns;
pub mod domain;
pub mod http_in;
pub mod health;
pub mod journal;
pub mod logfile;
pub mod presets;
pub mod proc;
pub mod pump;
pub mod report;
pub mod rules;
pub mod socks_in;
pub mod upstream;
pub mod winproxy;

use std::sync::{Arc, Mutex, RwLock};

use tokio::net::TcpListener;

pub struct Engine {
    pub cfg: Arc<Mutex<config::Config>>,
    pub rules: Arc<RwLock<rules::Rules>>,
    /// Доступные прокси: имя → описание. Меняется вместе с настройками.
    pub pool: Arc<RwLock<upstream::Pool>>,
    /// Пинок сторожу: проверить прокси немедленно, не дожидаясь очередного круга.
    /// Без этого добавленный прокси до пятнадцати секунд оставался серым.
    recheck: Arc<tokio::sync::Notify>,
    pub path: String,
    saved: Mutex<Option<winproxy::Saved>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

pub const NO_PROXY: &str = "localhost,127.0.0.1,::1";

/// Собрать набор прокси из настроек: основной под пустым именем плюс
/// каждый под своим.
fn build_pool(cfg: &config::Config) -> upstream::Pool {
    let mut m = upstream::Pool::new();
    m.insert(String::new(), cfg.upstream.clone());
    if !cfg.upstream.name.is_empty() {
        m.insert(cfg.upstream.name.clone(), cfg.upstream.clone());
    }
    for u in &cfg.upstreams {
        m.insert(u.name.clone(), u.clone());
    }
    m
}

impl Engine {
    /// Поднимает оба входа. Системный прокси НЕ трогает — это отдельным шагом.
    pub async fn start(cfg: config::Config, path: &str) -> Result<Arc<Self>, String> {
        journal::enable();
        report::enable();
        health::enable();
        conns::enable();
        upstream::AUTO_RECONNECT.store(cfg.auto_reconnect, std::sync::atomic::Ordering::Relaxed);
        cfg.check_links()?;
        let rules = Arc::new(RwLock::new(cfg.rules()?));
        let pool = Arc::new(RwLock::new(build_pool(&cfg)));
        let recheck = Arc::new(tokio::sync::Notify::new());
        let up = Arc::new(cfg.upstream.clone());
        let (hp, sp) = (cfg.listen.http, cfg.listen.socks);

        let http = TcpListener::bind(("127.0.0.1", hp)).await
            .map_err(|e| format!("порт {hp} занят: {e}"))?;
        let socks = TcpListener::bind(("127.0.0.1", sp)).await
            .map_err(|e| format!("порт {sp} занят: {e}"))?;

        let e = Arc::new(Engine {
            cfg: Arc::new(Mutex::new(cfg)),
            rules: rules.clone(),
            pool: pool.clone(),
            recheck: recheck.clone(),
            path: path.to_string(),
            saved: Mutex::new(None),
            tasks: Mutex::new(Vec::new()),
        });

        // ⛔ Раньше здесь было `while let Ok(...) = accept()`, и любая
        // случайная ошибка приёма навсегда убивала вход — молча, без следа.
        // Теперь ошибка только записывается, а цикл продолжается.
        let (u1, r1) = (pool.clone(), rules.clone());
        let t1 = tokio::spawn(async move {
            loop {
                match http.accept().await {
                    Ok((c, _)) => {
                        let (u, r) = (u1.clone(), r1.clone());
                        tokio::spawn(async move { let _ = http_in::handle(c, u, r).await; });
                    }
                    Err(e) => {
                        logfile::line(&logfile::now_stamp(), &format!("вход HTTP: {e}"));
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    }
                }
            }
        });
        let (u2, r2) = (pool.clone(), rules.clone());
        let t2 = tokio::spawn(async move {
            loop {
                match socks.accept().await {
                    Ok((c, _)) => {
                        let (u, r) = (u2.clone(), r2.clone());
                        tokio::spawn(async move { let _ = socks_in::handle(c, u, r).await; });
                    }
                    Err(e) => {
                        logfile::line(&logfile::now_stamp(), &format!("вход SOCKS: {e}"));
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    }
                }
            }
        });

        // Сторож проверяет КАЖДЫЙ прокси из настроек, а не только основной:
        // иначе о том, что запасной лёг, узнаёшь только когда он понадобился.
        let watch_pool = pool.clone();
        let watch_recheck = recheck.clone();
        let main_name = up.title();
        let t3 = tokio::spawn(async move {
            // первая проверка сразу: иначе список прокси до четверти минуты
            // стоит серым и выглядит сломанным
            let mut first = true;
            loop {
                if !first {
                    tokio::select! {
                        _ = tokio::time::sleep(std::time::Duration::from_secs(15)) => {}
                        _ = watch_recheck.notified() => {}
                    }
                }
                first = false;
                let list: Vec<upstream::Upstream> = {
                    let p = watch_pool.read().unwrap();
                    // пустое имя дублирует основной — его пропускаем
                    p.iter().filter(|(k, _)| !k.is_empty()).map(|(_, v)| v.clone())
                        .chain(p.get("").cloned())
                        .collect()
                };
                let mut main_ok = true;
                for u in list {
                    let started = std::time::Instant::now();
                    let ok = tokio::time::timeout(
                        std::time::Duration::from_secs(6),
                        tokio::net::TcpStream::connect((u.address.as_str(), u.port)),
                    )
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false);
                    let ms = started.elapsed().as_millis() as u64;
                    let first_time = !health::proxies().iter().any(|p| p.name == u.title());
                    health::set_proxy(&u.title(), ok, ms);
                    if first_time {
                        logfile::line(&logfile::now_stamp(),
                                      &format!("прокси «{}» взят под наблюдение: {}",
                                               u.title(),
                                               if ok { format!("отвечает, {ms} мс") }
                                               else { "не отвечает".into() }));
                    }
                    if u.title() == main_name {
                        main_ok = ok;
                    }
                    if !ok {
                        logfile::line(&logfile::now_stamp(),
                                      &format!("прокси «{}» не отвечает", u.title()));
                    }
                }
                if !upstream::AUTO_RECONNECT.load(std::sync::atomic::Ordering::Relaxed) {
                    continue;
                }
                let was = health::get().up;
                if main_ok {
                    if !was {
                        logfile::line(&logfile::now_stamp(), "основной прокси снова доступен");
                    }
                    health::mark_up();
                } else {
                    health::mark_down("не отвечает на проверке связи");
                }
            }
        });

        e.tasks.lock().unwrap().extend([t1, t2, t3]);
        Ok(e)
    }

    /// Перечитать правила и список прокси из настроек, затем сохранить файл.
    pub fn apply_and_save(&self) -> Result<(), String> {
        let c = self.cfg.lock().unwrap();
        c.check_links()?;
        *self.rules.write().unwrap() = c.rules()?;
        let pool = build_pool(&c);
        // пишем состав в журнал: если прокси не появился, здесь будет видно,
        // дошёл он до движка или потерялся раньше
        let names: Vec<String> = pool.iter()
            .filter(|(k, _)| !k.is_empty())
            .map(|(k, v)| format!("{k} → {}:{}", v.address, v.port))
            .collect();
        logfile::line(&logfile::now_stamp(),
                      &format!("список прокси обновлён: основной {}:{}{}",
                               c.upstream.address, c.upstream.port,
                               if names.is_empty() { String::new() }
                               else { format!(", ещё {}", names.join(", ")) }));
        *self.pool.write().unwrap() = pool;
        // сторож должен сразу проверить изменившийся список прокси
        self.recheck.notify_waiters();
        // рвём то, что теперь должно идти иначе, иначе правка не подействует
        let dropped = conns::drop_changed(&self.rules);
        if dropped > 0 {
            logfile::line(&logfile::now_stamp(),
                          &format!("правила изменены, разорвано соединений: {dropped}"));
        }
        c.save(&self.path)
    }

    pub fn system_proxy_on(&self) -> Result<(), String> {
        let port = self.cfg.lock().unwrap().listen.http;
        let s = winproxy::apply(&format!("127.0.0.1:{port}"), NO_PROXY)
            .map_err(|e| e.to_string())?;
        *self.saved.lock().unwrap() = Some(s);
        Ok(())
    }

    pub fn system_proxy_off(&self) {
        if let Some(s) = self.saved.lock().unwrap().take() {
            winproxy::restore(&s);
        }
    }

    pub fn system_proxy_is_ours(&self) -> bool {
        self.saved.lock().unwrap().is_some()
    }

    pub fn shutdown(&self) {
        self.system_proxy_off();
        for t in self.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
    }
}
