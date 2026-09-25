//! Проверка при запуске: что в порядке, а что нет.
//!
//! ⛔ Пишется в журнал целиком, одним блоком, при каждом запуске. Без
//! неё разбор любой поломки начинался с переписки: «пришли журнал»,
//! «выполни вот эту команду», «а теперь эту». Здесь сразу видно
//! состояние всего, что должно работать, — и то, чего не хватает.

use std::path::Path;

/// Одна строка отчёта.
struct Item {
    name: String,
    ok: bool,
    note: String,
}

fn ok(name: &str, note: impl Into<String>) -> Item {
    Item { name: name.into(), ok: true, note: note.into() }
}

fn bad(name: &str, note: impl Into<String>) -> Item {
    Item { name: name.into(), ok: false, note: note.into() }
}

/// Собрать отчёт и записать его в журнал.
pub fn run(cfg: &crate::config::Config, path: &str, version: &str) {
    let dir = crate::tunnel_dir(path);
    let mut items: Vec<Item> = Vec::new();

    items.push(ok("версия", format!("{version}, система {}", std::env::consts::OS)));
    items.push(ok("настройки", format!("{path}")));

    // ── прокси ──
    let ups = cfg.all_upstreams();
    if ups.is_empty() {
        items.push(bad("прокси", "не задан ни один — через прокси ничего не пойдёт"));
    } else {
        let list: Vec<String> = ups.iter()
            .map(|u| format!("{} = {}:{}{}", u.name, u.address, u.port,
                             if u.password.is_some() { " (с паролем)" } else { "" }))
            .collect();
        items.push(ok("прокси", format!("{} шт.: {}", ups.len(), list.join(", "))));
        match cfg.default_proxy() {
            Some(u) => items.push(ok("основной прокси", u.name.clone())),
            None => items.push(bad("основной прокси",
                format!("назначен «{}», но такого нет", cfg.default_upstream))),
        }
    }

    // ── правила ──
    let domains = cfg.through_proxy.iter().filter(|s| !s.starts_with('_')).count();
    let in_groups: usize = cfg.groups.iter().map(|g| g.patterns.len()).sum();
    if domains + in_groups == 0 && cfg.apps.is_empty() {
        items.push(bad("правила", "ни одного правила и ни одной программы — \
                                   весь трафик идёт напрямую"));
    } else {
        items.push(ok("правила", format!("по адресам {domains}, в наборах {in_groups}, программ {}", cfg.apps.len())));
    }
    if let Err(e) = cfg.check_links() {
        items.push(bad("связи правил", e));
    }

    // ── способ работы ──
    if !cfg.tunnel_mode {
        items.push(ok("способ работы", "режим прокси (через системные настройки)"));
        items.push(ok("входы", format!("HTTP {} · SOCKS5 {}", cfg.listen.http, cfg.listen.socks)));
    } else {
        items.push(ok("способ работы", "перехват"));
        // движок
        let downloaded = crate::tunnel::downloaded_engine(&dir);
        if downloaded.is_file() {
            let size = std::fs::metadata(&downloaded).map(|m| m.len()).unwrap_or(0);
            items.push(ok("движок скачан", format!("{} ({size} Б)", downloaded.display())));
        } else {
            items.push(bad("движок скачан", format!("нет файла {}", downloaded.display())));
        }
        // secure папка
        let secure = crate::tunnel_service::secure_dir(&dir);
        if secure.is_dir() {
            let inside = crate::tunnel::binary_path(&dir);
            items.push(if inside.is_file() {
                ok("закрытая папка", format!("{} — движок на месте", secure.display()))
            } else {
                bad("закрытая папка", format!("{} есть, но движка в ней нет", secure.display()))
            });
            // ⛔ Главное в защите прав: человек НЕ должен мочь туда писать.
            items.push(match can_write(&secure) {
                true => bad("защита закрытой папки",
                            "в неё удалось записать своими правами — защита не действует"),
                false => ok("защита закрытой папки", "запись своими правами запрещена"),
            });
        } else {
            items.push(bad("закрытая папка",
                format!("нет {} — служба поставлена по-старому", secure.display())));
        }
        // служба
        match crate::tunnel_service::state_in(&dir) {
            crate::tunnel_service::State::Absent =>
                items.push(bad("служба перехвата", "не установлена")),
            crate::tunnel_service::State::Stopped =>
                items.push(ok("служба перехвата", "установлена, перехват выключен")),
            crate::tunnel_service::State::Running =>
                items.push(ok("служба перехвата", "работает")),
        }
        if crate::tunnel_service::needs_reinstall(&dir) {
            // Различаем «ставилась другой версией» и «не ставилась вовсе»:
            // это разные поломки и чинятся по-разному.
            let ставилась = dir.join("service-signature").is_file();
            items.push(bad("свежесть службы", if ставилась {
                "поставлена прежней версией — нужна переустановка"
            } else {
                "отметки об установке нет — служба не ставилась этой программой"
            }));
        } else {
            items.push(ok("свежесть службы", "поставлена нынешней версией"));
        }
        // ⛔ Спрашиваем движок только когда служба СЧИТАЕТ перехват
        // включённым. Сразу после переустановки службы движок ещё не
        // поднялся — проверка пугала «не отвечает» там, где всё шло
        // своим чередом и через секунду уже работало.
        let включён = crate::tunnel_service::state_in(&dir)
            == crate::tunnel_service::State::Running;
        items.push(if crate::tunnel::is_alive(&dir) {
            ok("движок отвечает", "да")
        } else if включён {
            bad("движок отвечает", "нет — перехват не работает, хотя должен")
        } else {
            ok("движок отвечает", "ещё не поднят — служба поднимет его сама")
        });
        // cfg_file движка
        let cfg_file = crate::tunnel::config_path(&dir);
        items.push(if cfg_file.is_file() {
            ok("настройки движка", cfg_file.display().to_string())
        } else {
            bad("настройки движка", format!("нет файла {}", cfg_file.display()))
        });
    }

    // ── что показывается человеку ──
    let bad_count = items.iter().filter(|i| !i.ok).count();
    let mut out = String::from("\n── проверка при запуске ──\n");
    for i in &items {
        out.push_str(&format!("  {} {}: {}\n",
                              if i.ok { "ок  " } else { "ПЛОХО" }, i.name, i.note));
    }
    out.push_str(&if bad_count == 0 {
        "  всё в порядке\n".to_string()
    } else {
        format!("  неладно: {bad_count}\n")
    });
    crate::logfile::line(&crate::logfile::now_stamp(), &out);
}

/// Можно ли писать в эту папку своими правами.
fn can_write(dir: &Path) -> bool {
    let probe = dir.join(format!("probe-{}.tmp", crate::tunnel::random_tag()));
    match std::fs::write(&probe, b"x") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⛔ Отчёт обязан называть то, чего не хватает: ради этого он и
    /// заведён. Проверяем на пустых настройках — ни прокси, ни правил.
    #[test]
    fn отчёт_называет_нехватку() {
        let dir = std::env::temp_dir().join(format!("np-check-{}", crate::tunnel::random_tag()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        crate::logfile::open(dir.join("nexusproxy.log")).unwrap();

        let cfg: crate::config::Config = serde_json::from_str("{}").unwrap();
        run(&cfg, &path.display().to_string(), "1.2.3");

        let текст = std::fs::read_to_string(dir.join("nexusproxy.log")).unwrap();
        assert!(текст.contains("проверка при запуске"), "отчёта нет: {текст}");
        assert!(текст.contains("не задан ни один"), "не сказано про отсутствие прокси: {текст}");
        assert!(текст.contains("весь трафик идёт напрямую"), "не сказано про отсутствие правил");
        assert!(текст.contains("неладно:"), "итог не подведён");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
