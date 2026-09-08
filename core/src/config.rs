//! Настройки приложения.

use crate::rules::{Route, Rules};
use crate::upstream::Upstream;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listen {
    #[serde(default = "default_http")]
    pub http: u16,
    #[serde(default = "default_socks")]
    pub socks: u16,
}
fn yes() -> bool { true }
fn default_http() -> u16 { 18080 }
fn default_socks() -> u16 { 18081 }

impl Default for Listen {
    fn default() -> Self {
        Self { http: default_http(), socks: default_socks() }
    }
}

/// Похоже ли на подсеть: адрес, косая черта, длина префикса.
fn is_cidr(s: &str) -> bool {
    let body = s.strip_prefix("ip:").unwrap_or(s);
    match body.split_once('/') {
        Some((a, p)) => a.parse::<std::net::IpAddr>().is_ok() && p.parse::<u8>().is_ok(),
        None => false,
    }
}

/// Приводим запись к единому виду: голое имя означает домен с поддоменами.
pub fn normalize(pattern: &str) -> String {
    let p = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    if p.is_empty() || p.starts_with('_') || p.starts_with('#') {
        return p;
    }
    // уже с приставкой — оставляем как есть
    for pref in ["domain:", "full:", "keyword:", "ip:"] {
        if p.starts_with(pref) {
            return p;
        }
    }
    // подсеть или голый адрес — это правило по адресу
    if p.contains('/') || p.parse::<std::net::IpAddr>().is_ok() {
        return format!("ip:{p}");
    }
    format!("domain:{p}")
}

/// Подписка: откуда взяли и что в ней было.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    /// адрес, если подписку берут по ссылке — чтобы обновлять
    #[serde(default)]
    pub url: String,
    /// содержимое: по нему поднимаются страны при запуске
    #[serde(default)]
    pub text: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

/// Итог добавления списком — что принято, что уже было, что не разобрано.
#[derive(Debug, Default, Clone, Serialize)]
pub struct BulkResult {
    pub added: Vec<String>,
    pub skipped: Vec<String>,
    pub invalid: Vec<String>,
}

/// Группа правил, идущих через один и тот же прокси.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteGroup {
    /// Имя прокси из списка upstreams.
    pub via: String,
    /// Можно выключить группу целиком, не удаляя правил.
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Старый формат: единственный прокси отдельным полем.
    /// Читается ради совместимости и при загрузке переносится в список.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<Upstream>,
    /// Все прокси одним списком. У каждого есть имя — иначе его не показать
    /// ни в журнале, ни в таблице соединений.
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    /// Имя прокси, через который идут правила без явного назначения.
    #[serde(default)]
    pub default_upstream: String,
    /// Правила, идущие через отдельные прокси.
    #[serde(default)]
    pub groups: Vec<RouteGroup>,
    #[serde(default)]
    pub listen: Listen,
    /// Ресурсы, которые идут ЧЕРЕЗ вышестоящий прокси. Всё остальное — напрямую.
    #[serde(default)]
    pub through_proxy: Vec<String>,
    /// Исключения: идут напрямую, даже если попали под правило выше.
    #[serde(default)]
    pub direct: Vec<String>,
    /// Повторять подключение, если вышестоящий прокси на мгновение отвалился,
    /// и следить за его доступностью. Выключается, если мешает.
    #[serde(default = "yes")]
    pub auto_reconnect: bool,
    /// Закрытие окна сворачивает в трей, а не завершает программу.
    #[serde(default = "yes")]
    pub minimize_to_tray: bool,
    /// Включать перехват сразу при запуске программы.
    #[serde(default = "yes")]
    pub enable_on_start: bool,
    /// Отметка, что базовые галки поведения уже расставлены один раз.
    /// Нужна, чтобы разовая простановка не повторялась после того,
    /// как галки сняли вручную.
    #[serde(default)]
    pub defaults_applied: bool,
    /// Подписка со странами. Хранится, чтобы поднимать их при запуске.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscription: Option<Subscription>,
    /// Всё прочее из файла — чтобы при перезаписи не потерять
    /// комментарии и поля, которых мы не знаем.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Config {
    pub fn load(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("не читается {path}: {e}"))?;
        let mut c: Config =
            serde_json::from_str(&text).map_err(|e| format!("испорченный {path}: {e}"))?;
        c.migrate();
        Ok(c)
    }

    /// Переносит старое поле `upstream` в общий список и следит,
    /// чтобы у каждого прокси было имя, а «по умолчанию» указывал
    /// на существующую запись.
    pub fn migrate(&mut self) {
        if let Some(mut u) = self.upstream.take() {
            if u.name.is_empty() {
                u.name = "основной".into();
            }
            if !self.upstreams.iter().any(|x| x.name == u.name) {
                self.upstreams.insert(0, u.clone());
            }
            if self.default_upstream.is_empty() {
                self.default_upstream = u.name;
            }
        }
        // пустая строка в логине или пароле — это «их нет». Иначе прокси
        // предлагается вход по логину, а отправлять нечего.
        for u in self.upstreams.iter_mut() {
            if u.user.as_deref().is_some_and(|v| v.is_empty()) { u.user = None; }
            if u.password.as_deref().is_some_and(|v| v.is_empty()) { u.password = None; }
        }
        // имена обязательны: безымянный прокси не показать и не выбрать
        let mut n = 1;
        for u in self.upstreams.iter_mut() {
            if u.name.is_empty() {
                u.name = format!("прокси {n}");
                n += 1;
            }
        }
        if self.upstreams.iter().all(|u| u.name != self.default_upstream) {
            self.default_upstream =
                self.upstreams.first().map(|u| u.name.clone()).unwrap_or_default();
        }
    }

    /// Убрать прокси из настроек. Если убирают основной, основным
    /// становится первый из оставшихся: раньше приходилось сначала
    /// вручную назначить другой основным и только потом удалять,
    /// и это на ровном месте выглядело поломкой.
    pub fn remove_upstream(&mut self, name: &str) -> Result<(), String> {
        if self.upstreams.len() <= 1 {
            return Err("это последний прокси, убрать его нельзя".into());
        }
        if let Some(g) = self.groups.iter().find(|g| g.via == name) {
            return Err(format!(
                "на него ссылаются {} правил — сначала переключите их на другой прокси",
                g.patterns.len()
            ));
        }
        self.upstreams.retain(|u| u.name != name);
        if self.default_upstream == name {
            self.default_upstream =
                self.upstreams.first().map(|u| u.name.clone()).unwrap_or_default();
        }
        Ok(())
    }

    /// Прокси, через который идут правила без явного назначения.
    pub fn default_proxy(&self) -> Option<&Upstream> {
        self.upstreams.iter().find(|u| u.name == self.default_upstream)
            .or_else(|| self.upstreams.first())
    }

    /// Сделать указанный прокси основным.
    pub fn set_default(&mut self, name: &str) -> Result<(), String> {
        if !self.upstreams.iter().any(|u| u.name == name) {
            return Err(format!("прокси «{name}» не найден"));
        }
        self.default_upstream = name.to_string();
        Ok(())
    }

    /// Пишем через временный файл: если запись оборвётся, старый конфиг цел.
    pub fn save(&self, path: &str) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        let tmp = format!("{path}.tmp");
        std::fs::write(&tmp, text.as_bytes()).map_err(|e| format!("не пишется {tmp}: {e}"))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("не переименовать в {path}: {e}"))
    }

    /// Добавить ресурс в список «через прокси». Возвращает false, если он уже был.
    pub fn add_proxy(&mut self, pattern: &str) -> bool {
        let p = normalize(pattern);
        if self.through_proxy.iter().any(|x| normalize(x) == p) {
            return false;
        }
        self.through_proxy.push(p);
        true
    }

    /// Добавить сразу список: домены, адреса и диапазоны вперемешку,
    /// разделённые переводами строк, запятыми или пробелами.
    /// Строки-комментарии и мусор не роняют разбор — просто отбрасываются.
    pub fn add_many(&mut self, text: &str) -> BulkResult {
        let mut r = BulkResult::default();
        for raw in text.split(|c: char| c == '\n' || c == '\r' || c == ',' || c == ';' || c == ' ' || c == '\t') {
            let item = raw.trim();
            if item.is_empty() {
                continue;
            }
            if item.starts_with('#') || item.starts_with("//") {
                continue;
            }
            // Отсекаем путь, если вставили ссылку целиком. Но осторожно:
            // у подсети косая черта — часть записи, её резать нельзя.
            let body = item.trim_start_matches("https://").trim_start_matches("http://");
            let item = if is_cidr(body) {
                body
            } else {
                body.split('/').next().unwrap_or(body)
            }
            .trim_matches('.');
            if item.is_empty() {
                continue;
            }
            let normalized = normalize(item);
            // проверяем, что запись вообще осмысленная
            let mut probe = crate::rules::Rules::new(crate::rules::Route::Direct);
            if let Err(e) = probe.add(&normalized, crate::rules::Route::proxy()) {
                r.invalid.push(format!("{item} — {e}"));
                continue;
            }
            if self.add_proxy(item) {
                r.added.push(normalized);
            } else {
                r.skipped.push(normalized);
            }
        }
        r
    }

    /// Убрать ресурс отовсюду: и из общего списка, и из групп.
    /// ⛔ Раньше чистился только общий список, и правило, переведённое
    /// на другой прокси, удалить было нельзя — оно молча оставалось.
    pub fn remove_proxy(&mut self, pattern: &str) -> bool {
        let p = normalize(pattern);
        let before = self.through_proxy.len()
            + self.groups.iter().map(|g| g.patterns.len()).sum::<usize>();
        self.through_proxy.retain(|x| normalize(x) != p);
        for g in self.groups.iter_mut() {
            g.patterns.retain(|x| normalize(x) != p);
        }
        self.groups.retain(|g| !g.patterns.is_empty());
        let after = self.through_proxy.len()
            + self.groups.iter().map(|g| g.patterns.len()).sum::<usize>();
        after != before
    }

    pub fn rules(&self) -> Result<Rules, String> {
        let mut r = Rules::new(Route::Direct);
        // исключения проверяются раньше — первое совпадение побеждает
        for p in &self.direct {
            r.add(p, Route::Direct)?;
        }
        // затем группы: они адреснее общего списка
        for g in &self.groups {
            if !g.enabled {
                continue;
            }
            for p in &g.patterns {
                r.add(p, Route::Proxy(g.via.clone()))?;
            }
        }
        for p in &self.through_proxy {
            r.add(p, Route::proxy())?;
        }
        Ok(r)
    }

    /// Найти прокси по имени. Пустое имя — тот, что по умолчанию.
    pub fn upstream_by_name(&self, name: &str) -> Option<&Upstream> {
        if name.is_empty() {
            return self.default_proxy();
        }
        self.upstreams.iter().find(|u| u.name == name)
    }

    /// Все прокси одним списком — для показа и для проверки ссылок.
    pub fn all_upstreams(&self) -> Vec<Upstream> {
        self.upstreams.clone()
    }

    /// Группы не должны ссылаться на несуществующий прокси —
    /// иначе трафик молча никуда не пойдёт.
    pub fn check_links(&self) -> Result<(), String> {
        for g in &self.groups {
            if self.upstream_by_name(&g.via).is_none() {
                return Err(format!("группа ссылается на неизвестный прокси «{}»", g.via));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn cfg(through: &[&str], direct: &[&str]) -> Config {
        Config {
            upstream: None,
            listen: Listen::default(),
            upstreams: vec![Upstream {
                name: "основной".into(), kind: Default::default(),
                address: "127.0.0.1".into(), port: 1080, user: None, password: None,
                from_subscription: false,
            }],
            default_upstream: "основной".into(),
            groups: vec![],
            through_proxy: through.iter().map(|s| s.to_string()).collect(),
            direct: direct.iter().map(|s| s.to_string()).collect(),
            auto_reconnect: true,
            minimize_to_tray: true,
            enable_on_start: true,
            defaults_applied: false,
            subscription: None,
            extra: Default::default(),
        }
    }

    #[test]
    fn exception_beats_proxy_rule() {
        // весь домен через прокси, но один поддомен — напрямую
        let r = cfg(&["domain:corp.example"], &["domain:cdn.corp.example"]).rules().unwrap();
        assert_eq!(r.decide("api.corp.example"), Route::proxy());
        assert_eq!(r.decide("cdn.corp.example"), Route::Direct);
        assert_eq!(r.decide("a.cdn.corp.example"), Route::Direct);
    }

    #[test]
    fn nothing_listed_means_everything_direct() {
        let r = cfg(&[], &[]).rules().unwrap();
        assert_eq!(r.decide("anything.example"), Route::Direct);
        assert_eq!(r.decide("8.8.8.8"), Route::Direct);
    }

    #[test]
    fn normalizing_bare_names() {
        assert_eq!(normalize("2ip.io"), "domain:2ip.io");
        assert_eq!(normalize("  OpenAI.COM. "), "domain:openai.com");
        assert_eq!(normalize("domain:openai.com"), "domain:openai.com");
        assert_eq!(normalize("full:a.b"), "full:a.b");
        assert_eq!(normalize("10.0.0.0/8"), "ip:10.0.0.0/8");
        assert_eq!(normalize("ip:10.0.0.0/8"), "ip:10.0.0.0/8");
        assert_eq!(normalize("8.8.8.8"), "ip:8.8.8.8");
        assert_eq!(normalize("ip:2001:db8::/32"), "ip:2001:db8::/32");
        assert_eq!(normalize("2001:db8::/32"), "ip:2001:db8::/32");
    }

    #[test]
    fn adding_is_idempotent() {
        let mut c = cfg(&["domain:openai.com"], &[]);
        assert!(!c.add_proxy("openai.com"), "то же самое в другой записи — не дубль");
        assert!(c.add_proxy("2ip.io"));
        assert_eq!(c.through_proxy.len(), 2);
        assert!(c.remove_proxy("2IP.IO"));
        assert!(!c.remove_proxy("2ip.io"));
    }

    fn up(name: &str, port: u16) -> Upstream {
        Upstream {
            name: name.into(), kind: Default::default(),
            address: "127.0.0.1".into(), port, user: None, password: None,
            from_subscription: false,
        }
    }

    #[test]
    fn group_routes_to_its_own_proxy() {
        let mut c = cfg(&["domain:openai.com"], &[]);
        c.upstreams.push(up("vpn", 10808));
        c.groups = vec![RouteGroup {
            via: "vpn".into(), enabled: true,
            patterns: vec!["domain:youtube.com".into()],
        }];
        let r = c.rules().unwrap();
        assert_eq!(r.decide("api.openai.com"), Route::proxy(), "общий список — основной прокси");
        assert_eq!(r.decide("www.youtube.com"), Route::Proxy("vpn".into()), "группа — свой прокси");
        assert!(c.check_links().is_ok());
    }

    #[test]
    fn removing_cleans_groups_too() {
        let mut c = cfg(&[], &[]);
        c.upstreams.push(up("vpn", 10808));
        c.groups = vec![RouteGroup {
            via: "vpn".into(), enabled: true,
            patterns: vec!["domain:youtube.com".into(), "domain:ytimg.com".into()],
        }];
        assert!(c.remove_proxy("youtube.com"), "правило из группы должно удаляться");
        assert_eq!(c.groups[0].patterns, vec!["domain:ytimg.com"]);
        assert!(c.remove_proxy("ytimg.com"));
        assert!(c.groups.is_empty(), "опустевшая группа убирается");
        assert!(!c.remove_proxy("ytimg.com"), "повторное удаление — уже нечего");
    }

    #[test]
    fn disabled_group_falls_back() {
        let mut c = cfg(&[], &[]);
        c.upstreams.push(up("vpn", 10808));
        c.groups = vec![RouteGroup {
            via: "vpn".into(), enabled: false,
            patterns: vec!["domain:youtube.com".into()],
        }];
        // выключенная группа не должна ничего заворачивать
        assert_eq!(c.rules().unwrap().decide("youtube.com"), Route::Direct);
    }

    #[test]
    fn broken_link_is_reported() {
        let mut c = cfg(&[], &[]);
        c.groups = vec![RouteGroup {
            via: "нет-такого".into(), enabled: true, patterns: vec!["a.example".into()],
        }];
        // иначе трафик молча никуда не пойдёт
        assert!(c.check_links().is_err());
    }

    #[test]
    fn flags_survive_save_and_load() {
        // галка «включать при запуске» не срабатывала — проверяем,
        // что она вообще доезжает до файла и обратно
        let dir = std::env::temp_dir().join(format!("np-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        let p = path.to_string_lossy().to_string();

        let mut c = cfg(&["domain:a.example"], &[]);
        c.enable_on_start = true;
        c.minimize_to_tray = false;
        c.defaults_applied = true;
        c.save(&p).unwrap();

        let back = Config::load(&p).unwrap();
        assert!(back.enable_on_start, "флаг должен пережить запись и чтение");
        assert!(!back.minimize_to_tray);
        assert!(back.defaults_applied, "отметка о разовой простановке галок должна сохраняться");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn old_config_is_migrated() {
        // старый файл: единственный прокси отдельным полем, без имени
        let old = r#"{"upstream":{"address":"10.0.0.1","port":1080},
                      "through_proxy":["domain:a.example"]}"#;
        let mut c: Config = serde_json::from_str(old).unwrap();
        c.migrate();
        assert!(c.upstream.is_none(), "старое поле должно опустеть");
        assert_eq!(c.upstreams.len(), 1);
        assert_eq!(c.upstreams[0].name, "основной", "безымянному даётся имя");
        assert_eq!(c.default_upstream, "основной");
        assert_eq!(c.default_proxy().unwrap().address, "10.0.0.1");
    }

    #[test]
    fn default_can_be_switched() {
        let mut c = cfg(&[], &[]);
        c.upstreams.push(up("vpn", 10808));
        assert!(c.set_default("vpn").is_ok());
        assert_eq!(c.default_proxy().unwrap().name, "vpn");
        assert!(c.set_default("нет-такого").is_err(), "несуществующий выбрать нельзя");
    }

    #[test]
    fn bulk_add_mixed_list() {
        let mut c = cfg(&["domain:openai.com"], &[]);
        let r = c.add_many("
            openai.com
            chatgpt.com, oaistatic.com
            10.0.0.0/8
            192.168.1.10
            # это комментарий
            https://sub.example.org/path?x=1
            2001:db8::/32
        ");
        assert!(r.added.contains(&"domain:chatgpt.com".to_string()));
        assert!(r.added.contains(&"ip:10.0.0.0/8".to_string()));
        assert!(r.added.contains(&"ip:192.168.1.10".to_string()));
        assert!(r.added.contains(&"ip:2001:db8::/32".to_string()));
        assert!(r.added.contains(&"domain:sub.example.org".to_string()),
                "из ссылки должно остаться только имя узла");
        assert_eq!(r.skipped, vec!["domain:openai.com"], "повтор — в пропущенные");
        assert!(r.invalid.is_empty(), "мусора быть не должно: {:?}", r.invalid);
    }

    #[test]
    fn bulk_add_reports_broken_entries() {
        let mut c = cfg(&[], &[]);
        let r = c.add_many("good.example\n10.0.0.0/99");
        assert_eq!(r.added, vec!["domain:good.example"]);
        assert_eq!(r.invalid.len(), 1);
        assert!(r.invalid[0].contains("10.0.0.0/99"));
    }

    #[test]
    fn bad_pattern_is_reported() {
        assert!(cfg(&["ip:999.1.1.1/8"], &[]).rules().is_err());
    }
}

#[cfg(test)]
mod remove_tests {
    use super::*;

    fn up(name: &str) -> crate::upstream::Upstream {
        crate::upstream::Upstream {
            name: name.into(), kind: Default::default(), address: "127.0.0.1".into(),
            port: 1080, user: None, password: None, from_subscription: false,
        }
    }

    #[test]
    fn убранный_основной_передаёт_роль_оставшемуся() {
        let mut c = super::tests::cfg(&[], &[]);
        c.upstreams = vec![up("основной"), up("WL")];
        c.default_upstream = "основной".into();
        c.remove_upstream("основной").unwrap();
        assert_eq!(c.upstreams.len(), 1);
        assert_eq!(c.default_upstream, "WL", "основным должен стать оставшийся");
    }

    #[test]
    fn последний_прокси_убрать_нельзя() {
        let mut c = super::tests::cfg(&[], &[]);
        c.upstreams = vec![up("основной")];
        assert!(c.remove_upstream("основной").is_err());
    }

    #[test]
    fn прокси_под_ссылкой_группы_не_убрать() {
        let mut c = super::tests::cfg(&[], &[]);
        c.upstreams = vec![up("основной"), up("WL")];
        c.groups = vec![RouteGroup {
            via: "WL".into(), enabled: true,
            patterns: vec!["domain:example.com".into()],
        }];
        assert!(c.remove_upstream("WL").is_err());
    }
}
