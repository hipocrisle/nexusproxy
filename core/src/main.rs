//! Консольная версия NexusProxy — для быстрых проверок.
//! Вся работа в библиотеке, здесь только ввод-вывод.

use nexusproxy_core as core;
use core::config::Config;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let verbose = args.iter().any(|a| a == "--verbose" || a == "-v");
    let no_system = args.iter().any(|a| a == "--no-system");
    let path = args.iter().find(|a| !a.starts_with('-'))
        .cloned().unwrap_or_else(|| "config.json".to_string());

    let cfg = Config::load(&path)?;

    // разовая проверка имени, без запуска
    if let Some(i) = args.iter().position(|a| a == "--check") {
        let r = cfg.rules()?;
        let hosts: Vec<&String> = args[i + 1..].iter().filter(|a| !a.starts_with('-')).collect();
        if hosts.is_empty() {
            eprintln!("после --check укажи одно или несколько имён");
            std::process::exit(2);
        }
        for h in hosts {
            println!("  {:44} {}", h, r.decide(h).label());
        }
        return Ok(());
    }

    if verbose {
        core::upstream::VERBOSE.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    core::logfile::open(std::path::PathBuf::from("nexusproxy.log")).ok();

    let e = core::Engine::start(cfg, &path).await?;
    {
        let c = e.cfg.lock().unwrap();
        println!("NexusProxy");
        for u in c.all_upstreams() {
            println!("  прокси             : {} ({:?})", u.title(), u.kind);
        }
        println!("  HTTP-прокси        : 127.0.0.1:{}", c.listen.http);
        println!("  SOCKS5-прокси      : 127.0.0.1:{}", c.listen.socks);
        println!("  правил «через прокси»: {}", c.through_proxy.len());
    }

    if no_system {
        println!("  системный прокси   : не трогаем (запущено с --no-system)");
    } else {
        match e.system_proxy_on() {
            Ok(_) => println!("  системный прокси   : включён на нас\n\n⚠ Уже запущенные приложения нужно перезапустить."),
            Err(err) => println!("  системный прокси   : НЕ включён — {err}"),
        }
    }

    help();
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            line = lines.next_line() => match line {
                Ok(Some(l)) => { if command(&l, &e) { break; } }
                _ => break,
            }
        }
    }
    e.shutdown();
    println!("остановлено");
    Ok(())
}

fn help() {
    println!("\nКоманды:");
    println!("  + имя      добавить в список «через прокси»");
    println!("  - имя      убрать из списка");
    println!("  ? имя      проверить, каким путём пойдёт");
    println!("  список     показать правила");
    println!("  связи      что открыто прямо сейчас");
    println!("  трафик     сколько куда ушло");
    println!("  подбор     начать подбор доменов");
    println!("  стоп       закончить подбор и показать найденное");
    println!("  выход      вернуть настройки и закрыть\n");
}

fn command(line: &str, e: &Arc<core::Engine>) -> bool {
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
            let r = { e.cfg.lock().unwrap().add_many(arg) };
            println!("  принято {}, уже было {}, не разобрано {}",
                     r.added.len(), r.skipped.len(), r.invalid.len());
            apply(e);
        }
        "-" | "del" | "убрать" => {
            let ok = { e.cfg.lock().unwrap().remove_proxy(arg) };
            println!("{}", if ok { "  убрано" } else { "  такого нет" });
            apply(e);
        }
        "?" | "check" | "проверить" => {
            let r = e.rules.read().unwrap();
            for item in arg.split_whitespace() {
                println!("  {item:44} {}", r.decide(item).label());
            }
        }
        "list" | "список" => {
            let c = e.cfg.lock().unwrap();
            for p in &c.through_proxy {
                println!("    {p}");
            }
        }
        "связи" | "conns" => {
            let v = core::conns::active();
            if v.is_empty() { println!("  сейчас ничего не открыто"); }
            for c in v {
                println!("  {:34} {:>4}с  {:12} отдано {:>9} получено {:>9}  {}",
                         format!("{}:{}", c.host, c.port), c.seconds, c.via,
                         human(c.sent), human(c.received), c.app);
            }
        }
        "трафик" | "traffic" => {
            let v = core::conns::totals();
            if v.is_empty() { println!("  пока пусто"); }
            for t in v.iter().take(25) {
                println!("  {:36} связей {:>4}  отдано {:>9} получено {:>9}",
                         t.domain, t.conns, human(t.sent), human(t.received));
            }
        }
        "подбор" => {
            core::report::start_session();
            println!("  подбор начат. Открой сервис, потом «стоп».");
        }
        "стоп" => match core::report::finish_session() {
            Some(r) => {
                println!("  за {} с найдено доменов: {}", r.seconds, r.candidates.len());
                for c in &r.candidates {
                    match &c.triggered_by {
                        Some(t) => println!("    {} ×{} ({} имён, следом за {t})", c.domain, c.count, c.hosts_count),
                        None => println!("    {} ×{}", c.domain, c.count),
                    }
                }
            }
            None => println!("  подбор не запускался"),
        },
        "help" | "помощь" => help(),
        "выход" | "quit" | "exit" | "q" => return true,
        _ => println!("  не понял «{cmd}». Набери «помощь»."),
    }
    false
}

fn apply(e: &Arc<core::Engine>) {
    match e.apply_and_save() {
        Ok(_) => println!("  правила применены и сохранены"),
        Err(err) => println!("  не сохранено: {err}"),
    }
}

fn human(b: u64) -> String {
    const U: [&str; 4] = ["Б", "КБ", "МБ", "ГБ"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{b} {}", U[0]) } else { format!("{v:.1} {}", U[i]) }
}
