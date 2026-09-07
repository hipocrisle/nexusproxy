//! Ядро NexusProxy: локальный прокси с правилами.
//! Отдельно от интерфейса, чтобы им пользовались и окно программы, и консоль.

pub mod config;
pub mod domain;
pub mod http_in;
pub mod health;
pub mod journal;
pub mod logfile;
pub mod presets;
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
    pub path: String,
    saved: Mutex<Option<winproxy::Saved>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

pub const NO_PROXY: &str = "localhost,127.0.0.1,::1";

impl Engine {
    /// Поднимает оба входа. Системный прокси НЕ трогает — это отдельным шагом.
    pub async fn start(cfg: config::Config, path: &str) -> Result<Arc<Self>, String> {
        journal::enable();
        report::enable();
        health::enable();
        upstream::AUTO_RECONNECT.store(cfg.auto_reconnect, std::sync::atomic::Ordering::Relaxed);
        let rules = Arc::new(RwLock::new(cfg.rules()?));
        let up = Arc::new(cfg.upstream.clone());
        let (hp, sp) = (cfg.listen.http, cfg.listen.socks);

        let http = TcpListener::bind(("127.0.0.1", hp)).await
            .map_err(|e| format!("порт {hp} занят: {e}"))?;
        let socks = TcpListener::bind(("127.0.0.1", sp)).await
            .map_err(|e| format!("порт {sp} занят: {e}"))?;

        let e = Arc::new(Engine {
            cfg: Arc::new(Mutex::new(cfg)),
            rules: rules.clone(),
            path: path.to_string(),
            saved: Mutex::new(None),
            tasks: Mutex::new(Vec::new()),
        });

        // ⛔ Раньше здесь было `while let Ok(...) = accept()`, и любая
        // случайная ошибка приёма навсегда убивала вход — молча, без следа.
        // Теперь ошибка только записывается, а цикл продолжается.
        let (u1, r1) = (up.clone(), rules.clone());
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
        let (u2, r2) = (up.clone(), rules.clone());
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

        // Сторож: раз в 15 секунд проверяет, жив ли вышестоящий прокси,
        // и сам отмечает восстановление. Ничего не «чинит» силой —
        // соединения и так пробуются повторно.
        let watch_up = up.clone();
        let t3 = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                if !upstream::AUTO_RECONNECT.load(std::sync::atomic::Ordering::Relaxed) {
                    continue;
                }
                let addr = (watch_up.address.as_str(), watch_up.port);
                let ok = tokio::time::timeout(
                    std::time::Duration::from_secs(6),
                    tokio::net::TcpStream::connect(addr),
                )
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);
                let was = health::get().up;
                if ok {
                    if !was {
                        logfile::line(&logfile::now_stamp(), "вышестоящий прокси снова доступен");
                    }
                    health::mark_up();
                } else {
                    if was {
                        logfile::line(&logfile::now_stamp(), "вышестоящий прокси недоступен");
                    }
                    health::mark_down("не отвечает на проверке связи");
                }
            }
        });

        e.tasks.lock().unwrap().extend([t1, t2, t3]);
        Ok(e)
    }

    /// Перечитать правила из настроек и сохранить файл.
    pub fn apply_and_save(&self) -> Result<(), String> {
        let c = self.cfg.lock().unwrap();
        *self.rules.write().unwrap() = c.rules()?;
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
