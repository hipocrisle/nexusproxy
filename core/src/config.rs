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
    /// Приложения, запускаемые через нас.
    ///
    /// ⛔ Для тех, кто НЕ читает системные настройки прокси: Cursor,
    /// Electron и часть консольных программ. Их трафик до нас не доходит
    /// вовсе, поэтому и подбор доменов для них пуст.
    #[serde(default)]
    pub apps: Vec<crate::launch::App>,
    /// Каким способом ведём трафик: перехватом или системными настройками.
    ///
    /// ⛔ Это именно ВЫБОР способа, а не второй выключатель. Включает и
    /// выключает программу одна кнопка в шапке; раньше здесь была
    /// отдельная галка, и получалось два независимых переключателя —
    /// перехват работал при выключенной программе, и никто не мог
    /// понять, что чем управляет.
    #[serde(default)]
    pub tunnel_mode: bool,
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
    /// ⛔ Сохранение обязано быть либо полным, либо никаким. Внезапное
    /// отключение сразу после записи оставляло на месте настроек файл
    /// нулевой длины: содержимое ещё не дошло до диска, а имя уже
    /// переставлено. Дальше программа не могла его прочесть и заменяла
    /// настройки человека умолчаниями.
    pub fn save(&self, path: &str) -> Result<(), String> {
        use std::io::Write;
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        // Имя временного файла своё у каждой записи: две одновременные
        // записи иначе портят друг другу содержимое.
        let tmp = format!("{path}.{}.tmp", crate::tunnel::random_tag());
        {
            let mut f = std::fs::File::create(&tmp)
                .map_err(|e| format!("не пишется {tmp}: {e}"))?;
            f.write_all(text.as_bytes()).map_err(|e| format!("не пишется {tmp}: {e}"))?;
            f.sync_all().map_err(|e| format!("не сбросить на диск {tmp}: {e}"))?;
        }
        // Прежние настройки держим рядом: если новые окажутся негодными,
        // человеку будет что вернуть.
        if std::path::Path::new(path).is_file() {
            let _ = std::fs::copy(path, format!("{path}.bak"));
        }
        std::fs::rename(&tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("не переименовать в {path}: {e}")
        })
    }

    /// Прочитать настройки, а если они испорчены — взять вчерашние.
    ///
    /// ⛔ Возвращаем ошибку, а не умолчания. Прежде любая неудача чтения
    /// — оборванная запись, файл занят проверяющей программой, отказ
    /// доступа — приводила к тому, что человек молча терял все прокси,
    /// правила и список программ, и поверх тут же записывались пустые
    /// настройки.
    pub fn load_or_backup(path: &str) -> Result<(Self, Option<String>), String> {
        match Self::load(path) {
            Ok(c) => Ok((c, None)),
            Err(first) => {
                let bak = format!("{path}.bak");
                match Self::load(&bak) {
                    Ok(c) => Ok((c, Some(format!(
                        "настройки не читались ({first}), взяты последние сохранённые")))),
                    Err(_) => Err(first),
                }
            }
        }
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
        // ⛔ Приложения ссылаются на прокси по имени так же, как группы.
        // Без проверки переименование прокси уводило весь их трафик на
        // несуществующий адрес, и человек видел только, что программа
        // «перестала ходить через прокси».
        for a in &self.apps {
            if !a.via.trim().is_empty() && self.upstream_by_name(&a.via).is_none() {
                return Err(format!("приложение «{}» ссылается на неизвестный прокси «{}»",
                                   a.name, a.via));
            }
        }
        if !self.default_upstream.is_empty()
            && self.upstream_by_name(&self.default_upstream).is_none()
        {
            return Err(format!("основным назначен неизвестный прокси «{}»",
                               self.default_upstream));
        }
        Ok(())
    }

    /// Переименование прокси — во всех местах, где на него ссылаются.
    ///
    /// ⛔ Ссылки живут по имени в трёх местах: группы, приложения и
    /// «основной». Раньше обновлялись только первые два, и список
    /// программ оставался указывать в пустоту.
    pub fn rename_upstream(&mut self, from: &str, to: &str) {
        if from == to {
            return;
        }
        for g in &mut self.groups {
            if g.via == from {
                g.via = to.to_string();
            }
        }
        for a in &mut self.apps {
            if a.via == from {
                a.via = to.to_string();
            }
        }
        if self.default_upstream == from {
            self.default_upstream = to.to_string();
        }
    }
}

#[cfg(test)]
mod links_tests {
    use super::*;

    fn with_app() -> Config {
        let mut c = tests::cfg(&[], &[]);
        c.apps.push(crate::launch::App {
            name: "Cursor".into(),
            path: "C:\\Cursor.exe".into(),
            kind: crate::launch::Kind::Auto,
            via: "основной".into(),
        });
        c.groups.push(RouteGroup {
            via: "основной".into(),
            patterns: vec!["example.com".into()],
            enabled: true,
        });
        c
    }

    /// ⛔ Переименование прокси обязано тянуть за собой список программ:
    /// иначе весь их трафик уходит на несуществующее имя, и со стороны
    /// это «программа перестала ходить через прокси».
    #[test]
    fn переименование_тянет_за_собой_программы() {
        let mut c = with_app();
        c.upstreams[0].name = "офис".into();
        c.rename_upstream("основной", "офис");
        assert_eq!(c.apps[0].via, "офис");
        assert_eq!(c.groups[0].via, "офис");
        assert_eq!(c.default_upstream, "офис");
        assert!(c.check_links().is_ok(), "{:?}", c.check_links());
    }

    /// Ссылка в пустоту должна обнаруживаться, а не работать молча.
    #[test]
    fn ссылка_программы_в_пустоту_видна() {
        let mut c = with_app();
        c.apps[0].via = "которого-нет".into();
        assert!(c.check_links().is_err(), "битая ссылка программы не замечена");
    }

    /// ⛔ Негодный файл не должен уничтожать то, что уже настроено.
    #[test]
    fn негодные_принесённые_настройки_не_рушат_свои() {
        let mut c = with_app();
        let before = c.through_proxy.clone();
        let mut incoming = c.export();
        incoming.upstreams.clear();           // прокси в файле нет вовсе
        incoming.through_proxy = vec!["новое.com".into()];
        let complaints = c.import(incoming);
        assert!(!complaints.is_empty(), "негодный файл принят молча");
        assert_eq!(c.through_proxy, before, "свои правила затёрты");
        assert_eq!(c.apps.len(), 1, "свой список программ затёрт");
    }
}

#[cfg(test)]
mod save_tests {
    use super::*;

    /// ⛔ Испорченные настройки не должны превращаться в пустые: за ними
    /// весь труд человека — прокси, правила, список программ.
    #[test]
    fn испорченные_настройки_берутся_из_запасной_копии() {
        let dir = std::env::temp_dir().join(format!("np-cfg-{}", crate::tunnel::random_tag()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json").display().to_string();

        let mut c = tests::cfg(&["example.com"], &[]);
        c.save(&path).unwrap();
        // второе сохранение кладёт первое в запасную копию
        c.through_proxy.push("second.com".into());
        c.save(&path).unwrap();

        std::fs::write(&path, "{ это не настройки").unwrap();
        let (back, note) = Config::load_or_backup(&path).unwrap();
        assert!(note.is_some(), "человеку не сказали, что взяли запасную копию");
        assert!(back.through_proxy.contains(&"example.com".to_string()),
                "правила потеряны: {:?}", back.through_proxy);

        // а когда и запасной копии нет — честная ошибка, а не умолчания
        std::fs::remove_file(format!("{path}.bak")).unwrap();
        assert!(Config::load_or_backup(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// После записи содержимое обязано быть на диске целиком.
    #[test]
    fn сохранение_доходит_до_диска_целиком() {
        let dir = std::env::temp_dir().join(format!("np-cfg2-{}", crate::tunnel::random_tag()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json").display().to_string();
        let c = tests::cfg(&["a.com", "b.com"], &["c.com"]);
        c.save(&path).unwrap();
        let back = Config::load(&path).unwrap();
        assert_eq!(back.through_proxy.len(), 2);
        assert_eq!(back.direct.len(), 1);
        // временных огрызков после себя не оставляем
        let left: Vec<_> = std::fs::read_dir(&dir).unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(left.is_empty(), "остались временные файлы: {left:?}");
        let _ = std::fs::remove_dir_all(&dir);
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
            tunnel_mode: false,
            auto_reconnect: true,
            minimize_to_tray: true,
            enable_on_start: true,
            defaults_applied: false,
            apps: Vec::new(),
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


/// Что можно перенести на другую машину.
///
/// ⛔ Переносим только то, что человек настраивал руками: прокси,
/// правила, приложения, способ работы. Всё, что привязано к машине —
/// пути, состояние, признак первого запуска — остаётся своим. Иначе
/// настройки одного человека утащат за собой чужие пути, и у второго
/// ничего не заработает.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Portable {
    /// Чтобы старая программа не подавилась новым файлом.
    pub version: u32,
    pub upstreams: Vec<Upstream>,
    pub default_upstream: String,
    pub groups: Vec<RouteGroup>,
    pub through_proxy: Vec<String>,
    pub direct: Vec<String>,
    pub tunnel_mode: bool,
}

impl Config {
    /// Собрать настройки для переноса.
    ///
    /// ⛔ Пароли прокси в файл НЕ попадают. Этот файл заводят ровно
    /// затем, чтобы отдать его коллеге или положить в общую папку, — а
    /// пароль к корпоративному прокси это пароль доменной учётной
    /// записи. Человек на той стороне впишет свой сам.
    pub fn export(&self) -> Portable {
        Portable {
            version: 1,
            upstreams: self.all_upstreams().into_iter()
                .map(|mut u| { u.password = None; u })
                .collect(),
            default_upstream: self.default_upstream.clone(),
            groups: self.groups.clone(),
            through_proxy: self.through_proxy.clone(),
            direct: self.direct.clone(),
            tunnel_mode: self.tunnel_mode,
        }
    }

    /// Принять перенесённые настройки.
    ///
    /// ⛔ Приложения НЕ переносим. Пути к ним у каждого свои: имя
    /// пользователя в пути отличается, программа может стоять в другом
    /// месте или не стоять вовсе. Перенесённый список был бы набором
    /// чужих путей, от которых нет никакой пользы, — их всё равно
    /// пришлось бы задавать заново, только сперва разобравшись, почему
    /// перехват не работает.
    pub fn import(&mut self, p: Portable) -> Vec<String> {
        // ⛔ Свои пароли сохраняем: в перенесённом файле их нет, и без
        // этого приём чужих настроек молча обнулял бы вход в прокси,
        // который до того работал.
        let mut kept: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for u in self.all_upstreams() {
            if let Some(pw) = u.password.clone() {
                kept.insert(u.name.clone(), pw);
            }
        }
        // ⛔ Сначала собираем, потом проверяем, и только потом меняем
        // своё. Раньше негодный файл (пустой список прокси, группа на
        // несуществующий) уничтожал настройки человека ещё до того, как
        // выяснялось, что принять его нельзя.
        let upstreams: Vec<_> = p.upstreams.into_iter()
            .map(|mut u| {
                if u.password.is_none() {
                    u.password = kept.get(&u.name).cloned();
                }
                u
            })
            .collect();

        let mut candidate = self.clone();
        candidate.upstreams = upstreams;
        candidate.default_upstream = p.default_upstream;
        candidate.groups = p.groups;
        candidate.through_proxy = p.through_proxy;
        candidate.direct = p.direct;
        candidate.tunnel_mode = p.tunnel_mode;
        candidate.upstream = None;
        candidate.migrate();

        if let Err(e) = candidate.check_links() {
            return vec![format!("настройки не приняты: {e}")];
        }
        if candidate.all_upstreams().is_empty() {
            return vec!["в файле нет ни одного прокси — настройки не приняты".into()];
        }
        *self = candidate;
        Vec::new()
    }
}

#[cfg(test)]
mod portable_tests {
    use super::*;

    /// ⛔ Пароль корпоративного прокси — это пароль доменной учётной
    /// записи. Файл переноса кладут в общую папку и шлют в переписке.
    #[test]
    fn пароли_не_попадают_в_файл_переноса() {
        let mut c = tests::cfg(&[], &[]);
        c.upstreams[0].name = "офис".into();
        c.upstreams[0].user = Some("ivan".into());
        c.upstreams[0].password = Some("очень-секретно".into());
        let text = serde_json::to_string(&c.export()).unwrap();
        assert!(!text.contains("очень-секретно"), "пароль уехал в файл: {text}");
        assert!(text.contains("офис"), "сам прокси перенестись обязан");
    }

    /// А свой пароль от приёма чужих настроек пропадать не должен.
    #[test]
    fn свой_пароль_переживает_приём_настроек() {
        let mut c = tests::cfg(&[], &[]);
        c.upstreams[0].name = "офис".into();
        c.upstreams[0].password = Some("мой-пароль".into());
        let brought = c.export();
        c.import(brought);
        assert_eq!(c.upstreams[0].password.as_deref(), Some("мой-пароль"));
    }

    /// ⛔ В перенос не должно попадать ничего, привязанного к машине:
    /// пути к журналу, состояние, порты. Иначе настройки одного человека
    /// утащат за собой принесённое, и у второго не заработает.
    #[test]
    fn переносим_только_настроенное_руками() {
        let c = tests::cfg(&["domain:grid.gg"], &[]);
        let p = c.export();
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("grid.gg"));
        assert!(!json.contains("config_path"), "путей к файлам тут не место");
        assert!(!json.contains("defaults_applied"), "состояние машины не переносим");
    }

    /// ⛔ Приложения переносить нельзя: пути у каждого свои. Свой
    /// список приложений при загрузке чужих настроек должен уцелеть.
    #[test]
    fn приложения_не_переносятся() {
        let from = tests::cfg(&[], &[]);
        let json = serde_json::to_string(&from.export()).unwrap();
        assert!(!json.contains("apps"), "путям к чужим программам тут не место");

        let mut to = tests::cfg(&[], &[]);
        to.apps = vec![crate::launch::App {
            name: "Cursor".into(), path: "/свой/Cursor".into(),
            kind: crate::launch::Kind::Auto, via: "основной".into(),
        }];
        to.import(from.export());
        assert_eq!(to.apps.len(), 1, "свои приложения должны остаться");
    }

    #[test]
    fn правила_и_прокси_переносятся() {
        let from = tests::cfg(&["domain:grid.gg", "10.0.0.0/8"], &["localhost"]);
        let mut to = tests::cfg(&[], &[]);
        to.import(from.export());
        assert!(to.through_proxy.contains(&"domain:grid.gg".to_string()));
        assert!(to.direct.contains(&"localhost".to_string()));
        assert_eq!(to.default_upstream, from.default_upstream);
    }
}
