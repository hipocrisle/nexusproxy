//! NexusProxy — выбранные ресурсы идут через вышестоящий SOCKS5,
//! всё остальное напрямую. Прав администратора не требует.

mod config;
mod domain;
mod http_in;
mod health;
mod journal;
mod logfile;
mod presets;
mod report;
mod rules;
mod socks_in;
mod upstream;
mod winproxy;

use std::sync::{Arc, Mutex, RwLock};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;

const NO_PROXY: &str = "localhost,127.0.0.1,::1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let verbose = args.iter().any(|a| a == "--verbose" || a == "-v");
    let no_system = args.iter().any(|a| a == "--no-system");
    let path = args.iter().find(|a| !a.starts_with('-'))
        .cloned().unwrap_or_else(|| "config.json".to_string());

    let cfg = config::Config::load(&path)?;

    // разовая проверка имени, без запуска
    if let Some(i) = args.iter().position(|a| a == "--check") {
        let r = cfg.rules()?;
        let hosts: Vec<&String> = args[i + 1..].iter().filter(|a| !a.starts_with('-')).collect();
        if hosts.is_empty() {
            eprintln!("после --check укажи одно или несколько имён");
            std::process::exit(2);
        }
        for h in hosts {
            println!("  {:44} {}", h, verdict(&r, h));
        }
        return Ok(());
    }

    if verbose {
        upstream::VERBOSE.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    report::enable();

    let rules = Arc::new(RwLock::new(cfg.rules()?));
    let up = Arc::new(cfg.upstream.clone());
    let cfg = Arc::new(Mutex::new(cfg));
    let http_port = cfg.lock().unwrap().listen.http;
    let socks_port = cfg.lock().unwrap().listen.socks;

    let http = TcpListener::bind(("127.0.0.1", http_port)).await
        .map_err(|e| format!("порт {http_port} занят: {e}"))?;
    let socks = TcpListener::bind(("127.0.0.1", socks_port)).await
        .map_err(|e| format!("порт {socks_port} занят: {e}"))?;

    spawn_http(http, up.clone(), rules.clone());
    spawn_socks(socks, up.clone(), rules.clone());

    println!("NexusProxy");
    println!("  вышестоящий прокси : {}:{}", up.address, up.port);
    println!("  HTTP-прокси        : 127.0.0.1:{http_port}");
    println!("  SOCKS5-прокси      : 127.0.0.1:{socks_port}");
    println!("  правил «через прокси»: {}", cfg.lock().unwrap().through_proxy.len());

    let saved = if no_system {
        println!("  системный прокси   : не трогаем (запущено с --no-system)");
        None
    } else {
        match winproxy::apply(&format!("127.0.0.1:{http_port}"), NO_PROXY) {
            Ok(s) => {
                println!("  системный прокси   : включён на нас");
                println!("\n⚠ Уже запущенные приложения читают настройки при старте — перезапусти их.");
                Some(s)
            }
            Err(e) => {
                println!("  системный прокси   : НЕ включён — {e}");
                None
            }
        }
    };

    help();
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            line = lines.next_line() => {
                match line {
                    Ok(Some(l)) => {
                        if command(&l, &cfg, &rules, &path) { break; }
                    }
                    _ => break,
                }
            }
        }
    }

    if let Some(s) = &saved {
        winproxy::restore(s);
        println!("системный прокси возвращён как было");
    }
    println!("остановлено");
    Ok(())
}

fn verdict(r: &rules::Rules, host: &str) -> &'static str {
    match r.decide(host) {
        rules::Route::Proxy => "через прокси",
        rules::Route::Direct => "напрямую",
        rules::Route::Block => "запрещено",
    }
}

fn help() {
    println!("\nКоманды (просто набери и нажми Enter):");
    println!("  + имя      добавить ресурс в список «через прокси»");
    println!("  - имя      убрать из списка");
    println!("  ? имя      проверить, каким путём пойдёт");
    println!("  список     показать все правила");
    println!("  подбор     начать подбор доменов для сервиса");
    println!("  стоп       закончить подбор и показать найденное");
    println!("  прокси     состояние системного прокси");
    println!("  выход      вернуть настройки и закрыть\n");
}

/// Возвращает true, если пора завершаться.
fn command(
    line: &str,
    cfg: &Arc<Mutex<config::Config>>,
    rules: &Arc<RwLock<rules::Rules>>,
    path: &str,
) -> bool {
    let line = line.trim();
    if line.is_empty() {
        return false;
    }
    let (cmd, arg) = match line.split_once(char::is_whitespace) {
        Some((c, a)) => (c, a.trim()),
        None => (line, ""),
    };

    match cmd {
        "+" | "add" | "добавить" => {
            if arg.is_empty() {
                println!("  что добавить? например:  + openai.com");
                return false;
            }
            let mut c = cfg.lock().unwrap();
            for item in arg.split(|ch| ch == ',' || ch == ' ').filter(|s| !s.is_empty()) {
                if c.add_proxy(item) {
                    println!("  добавлено: {}", config::normalize(item));
                } else {
                    println!("  уже было: {}", config::normalize(item));
                }
            }
            apply_changes(&c, rules, path);
        }
        "-" | "del" | "убрать" => {
            if arg.is_empty() {
                println!("  что убрать? например:  - openai.com");
                return false;
            }
            let mut c = cfg.lock().unwrap();
            for item in arg.split(|ch| ch == ',' || ch == ' ').filter(|s| !s.is_empty()) {
                if c.remove_proxy(item) {
                    println!("  убрано: {}", config::normalize(item));
                } else {
                    println!("  такого нет: {}", config::normalize(item));
                }
            }
            apply_changes(&c, rules, path);
        }
        "?" | "check" | "проверить" => {
            if arg.is_empty() {
                println!("  что проверить? например:  ? api.openai.com");
                return false;
            }
            let r = rules.read().unwrap();
            for item in arg.split(|ch| ch == ',' || ch == ' ').filter(|s| !s.is_empty()) {
                println!("  {:44} {}", item, verdict(&r, item));
            }
        }
        "list" | "список" => {
            let c = cfg.lock().unwrap();
            println!("  через прокси ({}):", c.through_proxy.iter().filter(|s| !s.starts_with('_')).count());
            for p in &c.through_proxy {
                if p.starts_with('_') { println!("    {}", &p[1..]); } else { println!("      {p}"); }
            }
            if !c.direct.is_empty() {
                println!("  исключения ({}):", c.direct.len());
                for p in &c.direct { println!("      {p}"); }
            }
        }
        "подбор" => {
            report::start_session();
            println!("  подбор начат. Открой нужный сервис, потом набери «стоп».");
        }
        "стоп" => match report::finish_session() {
            Some(r) => {
                println!("  за {} с найдено нового: {} кандидатов", r.seconds, r.candidates.len());
                for c in &r.candidates {
                    match &c.triggered_by {
                        Some(t) => println!("    {} ×{}  (следом за {t})", c.domain, c.count),
                        None => println!("    {} ×{}", c.domain, c.count),
                    }
                }
                if !r.already_proxied.is_empty() {
                    println!("  уже шло через прокси: {}", r.already_proxied.len());
                }
            }
            None => println!("  подбор не запускался"),
        },
        "прокси" | "proxy" | "status" => println!("  системный прокси: {}", winproxy::current()),
        "help" | "?h" | "помощь" => help(),
        "выход" | "quit" | "exit" | "q" => return true,
        _ => println!("  не понял «{cmd}». Набери «помощь»."),
    }
    false
}

fn apply_changes(c: &config::Config, rules: &Arc<RwLock<rules::Rules>>, path: &str) {
    match c.rules() {
        Ok(new) => {
            *rules.write().unwrap() = new;
            match c.save(path) {
                Ok(_) => println!("  правила применены и сохранены в {path}"),
                Err(e) => println!("  правила применены, но НЕ сохранены: {e}"),
            }
        }
        Err(e) => println!("  правило не принято: {e}"),
    }
}

fn spawn_http(l: TcpListener, up: Arc<upstream::Upstream>, rules: Arc<RwLock<rules::Rules>>) {
    tokio::spawn(async move {
        loop {
            if let Ok((c, _)) = l.accept().await {
                let (u, r) = (up.clone(), rules.clone());
                tokio::spawn(async move { let _ = http_in::handle(c, u, r).await; });
            }
        }
    });
}

fn spawn_socks(l: TcpListener, up: Arc<upstream::Upstream>, rules: Arc<RwLock<rules::Rules>>) {
    tokio::spawn(async move {
        loop {
            if let Ok((c, _)) = l.accept().await {
                let (u, r) = (up.clone(), rules.clone());
                tokio::spawn(async move { let _ = socks_in::handle(c, u, r).await; });
            }
        }
    });
}
