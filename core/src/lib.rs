//! Ядро NexusProxy: локальный прокси с правилами.
//! Отдельно от интерфейса, чтобы им пользовались и окно программы, и консоль.

pub mod config;
pub mod conns;
pub mod domain;
pub mod http_in;
pub mod failures;
pub mod health;
pub mod journal;
pub mod logfile;
pub mod macproxy;
pub mod presets;
pub mod proc;
pub mod pump;
pub mod report;
pub mod rules;
pub mod socks_in;
pub mod subscription;
pub mod sysproxy;
pub mod upstream;
pub mod winproxy;
pub mod xray;

use std::sync::{Arc, Mutex, RwLock};

use tokio::net::TcpListener;

pub struct Engine {
    pub cfg: Arc<Mutex<config::Config>>,
    pub rules: Arc<RwLock<rules::Rules>>,
    /// Куда идти: список прокси и временные подмены.
    pub routing: Arc<RwLock<upstream::Routing>>,
    /// Пинок сторожу: проверить прокси немедленно, не дожидаясь очередного круга.
    /// Без этого добавленный прокси до пятнадцати секунд оставался серым.
    recheck: Arc<tokio::sync::Notify>,
    pub path: String,
    saved: Mutex<Option<sysproxy::Saved>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

pub const NO_PROXY: &str = "localhost,127.0.0.1,::1";

/// Папка, куда кладём скачанный xray и его настройки.
pub fn xray_dir(config_path: &str) -> std::path::PathBuf {
    std::path::Path::new(config_path)
        .parent()
        .map(|p| p.join("xray"))
        .unwrap_or_else(|| std::path::PathBuf::from("xray"))
}

/// Собрать набор прокси из настроек: основной под пустым именем плюс
/// каждый под своим.
fn build_pool(cfg: &config::Config) -> upstream::Pool {
    let mut m = upstream::Pool::new();
    for u in &cfg.upstreams {
        m.insert(u.name.clone(), u.clone());
    }
    // пустое имя — «через тот, что по умолчанию»
    if let Some(d) = cfg.default_proxy() {
        m.insert(String::new(), d.clone());
    }
    m
}

impl Engine {
    /// Поднимает оба входа. Системный прокси НЕ трогает — это отдельным шагом.
    pub async fn start(mut cfg: config::Config, path: &str) -> Result<Arc<Self>, String> {
        journal::enable();
        report::enable();
        health::enable();
        conns::enable();
        failures::enable();
        upstream::AUTO_RECONNECT.store(cfg.auto_reconnect, std::sync::atomic::Ordering::Relaxed);
        cfg.migrate();
        cfg.check_links()?;
        let rules = Arc::new(RwLock::new(cfg.rules()?));
        let routing = Arc::new(RwLock::new(upstream::Routing {
            pool: build_pool(&cfg),
            overrides: Default::default(),
        }));
        let recheck = Arc::new(tokio::sync::Notify::new());
        let default_name = cfg.default_proxy().map(|u| u.name.clone()).unwrap_or_default();
        let (hp, sp) = (cfg.listen.http, cfg.listen.socks);

        let http = TcpListener::bind(("127.0.0.1", hp)).await
            .map_err(|e| format!("порт {hp} занят: {e}"))?;
        let socks = TcpListener::bind(("127.0.0.1", sp)).await
            .map_err(|e| format!("порт {sp} занят: {e}"))?;

        let e = Arc::new(Engine {
            cfg: Arc::new(Mutex::new(cfg)),
            rules: rules.clone(),
            routing: routing.clone(),
            recheck: recheck.clone(),
            path: path.to_string(),
            saved: Mutex::new(None),
            tasks: Mutex::new(Vec::new()),
        });

        // ⛔ Раньше здесь было `while let Ok(...) = accept()`, и любая
        // случайная ошибка приёма навсегда убивала вход — молча, без следа.
        // Теперь ошибка только записывается, а цикл продолжается.
        let (u1, r1) = (routing.clone(), rules.clone());
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
        let (u2, r2) = (routing.clone(), rules.clone());
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
        let watch_routing = routing.clone();
        let watch_recheck = recheck.clone();
        let main_name = default_name.clone();
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
                    let r = watch_routing.read().unwrap();
                    // пустое имя — дубль основного, его пропускаем
                    r.pool.iter().filter(|(k, _)| !k.is_empty()).map(|(_, v)| v.clone()).collect()
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
                    } else {
                        // вернулся — снимаем временную подмену сами
                        let had = { watch_routing.write().unwrap().overrides.remove(&u.name).is_some() };
                        if had {
                            logfile::line(&logfile::now_stamp(),
                                &format!("прокси «{}» снова доступен, подмена снята", u.title()));
                        }
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

    /// Поднять страны из подписки: разобрать, запустить xray, вписать их
    /// в список прокси. Возвращает названия стран.
    ///
    /// Прокси из подписки помечены особо: при следующем применении старые
    /// убираются целиком, иначе от прежней подписки оставались бы хвосты,
    /// на которые ссылаются правила.
    pub fn apply_subscription(&self) -> Result<Vec<String>, String> {
        let (text, enabled) = {
            let c = self.cfg.lock().unwrap();
            match &c.subscription {
                Some(s) => (s.text.clone(), s.enabled),
                None => return Ok(Vec::new()),
            }
        };
        if !enabled || text.trim().is_empty() {
            xray::stop();
            self.drop_subscription_upstreams()?;
            return Ok(Vec::new());
        }

        let profiles = subscription::parse(&text)?;
        let dir = xray_dir(&self.path);
        xray::start(&dir, &profiles)?;

        let names: Vec<String> = profiles.iter().map(|p| p.name.clone()).collect();
        {
            let mut c = self.cfg.lock().unwrap();
            c.upstreams.retain(|u| !u.from_subscription);
            for (i, p) in profiles.iter().enumerate() {
                // имя может совпасть с уже заведённым вручную — не затираем чужое
                let name = if c.upstreams.iter().any(|u| u.name == p.name) {
                    format!("{} (подписка)", p.name)
                } else {
                    p.name.clone()
                };
                c.upstreams.push(upstream::Upstream {
                    name,
                    kind: upstream::Kind::Socks5,
                    address: "127.0.0.1".into(),
                    port: xray::port_for(i),
                    user: None,
                    password: None,
                    from_subscription: true,
                });
            }
        }
        self.apply_and_save()?;
        logfile::line(&logfile::now_stamp(),
                      &format!("подписка поднята, стран: {}", names.len()));
        Ok(names)
    }

    /// Убрать страны прежней подписки из списка прокси.
    fn drop_subscription_upstreams(&self) -> Result<(), String> {
        {
            let mut c = self.cfg.lock().unwrap();
            let gone: Vec<String> = c.upstreams.iter()
                .filter(|u| u.from_subscription)
                .map(|u| u.name.clone())
                .collect();
            c.upstreams.retain(|u| !u.from_subscription);
            // правила, ссылавшиеся на исчезнувшие страны, возвращаем на основной
            for name in &gone {
                if let Some(g) = c.groups.iter().find(|g| &g.via == name) {
                    let pats = g.patterns.clone();
                    c.through_proxy.extend(pats);
                }
                c.groups.retain(|g| &g.via != name);
                if &c.default_upstream == name {
                    c.default_upstream =
                        c.upstreams.first().map(|u| u.name.clone()).unwrap_or_default();
                }
            }
        }
        self.apply_and_save()
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
                      &format!("список прокси обновлён: по умолчанию «{}», всего {} — {}",
                               c.default_upstream, c.upstreams.len(), names.join(", ")));
        self.routing.write().unwrap().pool = pool;
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

    /// Временно увести правила одного прокси на другой.
    /// Файл настроек не трогаем: подмена живёт до возврата или до
    /// перезапуска, иначе человек получит не ту маршрутизацию, что помнит.
    pub fn set_override(&self, from: &str, to: &str) -> Result<(), String> {
        {
            let mut r = self.routing.write().unwrap();
            if !r.pool.contains_key(to) {
                return Err(format!("прокси «{to}» не найден"));
            }
            if from == to {
                return Err("нельзя заменить прокси им же".into());
            }
            r.overrides.insert(from.to_string(), to.to_string());
        }
        logfile::line(&logfile::now_stamp(),
                      &format!("правила «{from}» временно идут через «{to}»"));
        conns::drop_changed_all(&self.rules);
        Ok(())
    }

    pub fn clear_override(&self, from: &str) {
        let had = self.routing.write().unwrap().overrides.remove(from).is_some();
        if had {
            logfile::line(&logfile::now_stamp(),
                          &format!("правила «{from}» вернулись на свой прокси"));
            conns::drop_changed_all(&self.rules);
        }
    }

    /// Какие подмены сейчас действуют.
    pub fn overrides(&self) -> Vec<(String, String)> {
        self.routing.read().unwrap().overrides.iter()
            .map(|(a, b)| (a.clone(), b.clone())).collect()
    }

    pub fn system_proxy_on(&self) -> Result<(), String> {
        let port = self.cfg.lock().unwrap().listen.http;
        let s = sysproxy::apply(&format!("127.0.0.1:{port}"), NO_PROXY)
            .map_err(|e| e.to_string())?;
        *self.saved.lock().unwrap() = Some(s);
        Ok(())
    }

    pub fn system_proxy_off(&self) {
        if let Some(s) = self.saved.lock().unwrap().take() {
            sysproxy::restore(&s);
        }
    }

    pub fn system_proxy_is_ours(&self) -> bool {
        self.saved.lock().unwrap().is_some()
    }

    pub fn shutdown(&self) {
        xray::stop();
        self.system_proxy_off();
        for t in self.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
    }
}
