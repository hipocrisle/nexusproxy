//! Клиент вышестоящего SOCKS5 и выбор способа подключения.
//! Имя узла отдаём прокси НЕразрешённым: корпоративные адреса часто
//! резолвятся только на его стороне.

use crate::rules::{Route, Rules};
use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Повторять ли подключение при обрыве. Ставится из настроек при запуске.
pub static AUTO_RECONNECT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

/// Каким протоколом говорить с вышестоящим прокси.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Socks5,
    /// Обычный HTTP-прокси: соединение открывается методом CONNECT.
    Http,
}
impl Default for Kind {
    fn default() -> Self { Kind::Socks5 }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Upstream {
    /// Имя, по которому на прокси ссылаются правила. Пустое — значит основной.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub kind: Kind,
    pub address: String,
    pub port: u16,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// Пришёл из подписки — такие обновляются и убираются целой пачкой,
    /// вручную их править незачем.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub from_subscription: bool,
}

impl Upstream {
    pub fn title(&self) -> String {
        if self.name.is_empty() {
            format!("{}:{}", self.address, self.port)
        } else {
            self.name.clone()
        }
    }
}

/// Печатать каждое решение. Включается ключом --verbose.
pub static VERBOSE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Набор доступных прокси: имя → описание. Пустое имя — основной.
pub type Pool = std::collections::HashMap<String, Upstream>;

/// Куда на самом деле идти. Кроме списка прокси хранит временные подмены:
/// когда назначенный прокси лёг, его правила по согласию пользователя
/// уводятся на другой. Подмена живёт только в памяти — файл настроек не
/// трогаем, иначе после перезапуска человек получит не ту маршрутизацию,
/// о которой помнит.
#[derive(Default)]
pub struct Routing {
    pub pool: Pool,
    /// имя прокси → имя того, кем его временно заменили
    pub overrides: std::collections::HashMap<String, String>,
}

impl Routing {
    /// Прокси с учётом временной подмены.
    pub fn resolve(&self, name: &str) -> Option<(&Upstream, bool)> {
        let real = self.pool.get(name)?;
        match self.overrides.get(real.name.as_str()) {
            Some(to) => self.pool.get(to).map(|u| (u, true)),
            None => Some((real, false)),
        }
    }
}

/// Куда пошло соединение — для журнала и таблицы соединений.
pub struct Decision {
    pub route: Route,
    pub via: String,
}

pub async fn dial(routing: &std::sync::RwLock<Routing>, rules: &std::sync::RwLock<Rules>,
                  host: &str, port: u16) -> io::Result<(TcpStream, Decision)> {
    let route = rules.read().unwrap().decide(host);
    if VERBOSE.load(std::sync::atomic::Ordering::Relaxed) {
        let mark = route.label();
        println!("  {mark}  {host}:{port}");
    }
    crate::report::note(host, &route);

    let (up, substituted) = match &route {
        Route::Proxy(name) => {
            let r = routing.read().unwrap();
            match r.resolve(name).or_else(|| r.resolve("")) {
                Some((u, sub)) => (Some(u.clone()), sub),
                None => {
                    return Err(bad(&format!("прокси «{name}» не найден в настройках")));
                }
            }
        }
        _ => (None, false),
    };
    let via = match (&up, substituted) {
        // видно, что идёт не туда, куда назначено, — иначе подмена незаметна
        (Some(u), true) => format!("{} (замена)", u.title()),
        (Some(u), false) => u.title(),
        (None, _) => String::new(),
    };
    crate::journal::push(host, port, &route, &via);
    let d = Decision { route: route.clone(), via: via.clone() };

    let stream = match route {
        Route::Block => Err(io::Error::new(io::ErrorKind::PermissionDenied, "запрещено правилом")),
        Route::Direct => TcpStream::connect((host, port)).await,
        Route::Proxy(_) => {
            let up = up.as_ref().expect("прокси выбран выше");
            // Прокси может моргнуть — сеть переключилась, он перезапустился.
            // Пробуем ещё раз, прежде чем отдавать ошибку приложению.
            match connect_through(up, host, port).await {
                Ok(s) => Ok(s),
                Err(first) if !AUTO_RECONNECT.load(std::sync::atomic::Ordering::Relaxed) => {
                    crate::health::mark_down(&first.to_string());
                    Err(first)
                }
                Err(first) => {
                    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                    match connect_through(up, host, port).await {
                        Ok(s) => {
                            crate::health::mark_up();
                            Ok(s)
                        }
                        Err(_) => {
                            crate::health::mark_down(&first.to_string());
                            Err(first)
                        }
                    }
                }
            }
        }
    };
    match &stream {
        Ok(_) => crate::failures::forget(host),
        Err(e) => crate::failures::note(host, &route, &d.via, &e.to_string()),
    }
    Ok((stream?, d))
}

/// Открыть соединение через указанный прокси — каким бы протоколом он ни говорил.
pub async fn connect_through(up: &Upstream, host: &str, port: u16) -> io::Result<TcpStream> {
    match up.kind {
        Kind::Socks5 => via_socks5(up, host, port).await,
        Kind::Http => via_http(up, host, port).await,
    }
}

/// HTTP-прокси: тот же метод CONNECT, который мы сами принимаем на входе.
async fn via_http(up: &Upstream, host: &str, port: u16) -> io::Result<TcpStream> {
    let mut s = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        TcpStream::connect((up.address.as_str(), up.port)),
    )
    .await
    .map_err(|_| bad("вышестоящий прокси не отвечает"))??;
    s.set_nodelay(true).ok();

    let mut req = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if let Some(user) = &up.user {
        let pass = up.password.clone().unwrap_or_default();
        req.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64(format!("{user}:{pass}").as_bytes())
        ));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;

    // читаем ответ до конца заголовка
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            return Err(bad("прокси закрыл соединение без ответа"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err(bad("прокси прислал слишком длинный ответ"));
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let first = head.lines().next().unwrap_or("");
    let code: u16 = first.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    match code {
        200 => Ok(s),
        407 => Err(bad("прокси требует логин и пароль")),
        403 => Err(bad("прокси: соединение запрещено правилами")),
        c => Err(bad(&format!("прокси ответил {c}"))),
    }
}

fn base64(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { A[n as usize & 63] as char } else { '=' });
    }
    out
}

async fn via_socks5(up: &Upstream, host: &str, port: u16) -> io::Result<TcpStream> {
    let mut s = tokio::time::timeout(
        std::time::Duration::from_secs(8),
        TcpStream::connect((up.address.as_str(), up.port)),
    )
    .await
    .map_err(|_| bad("вышестоящий прокси не отвечает"))??;
    s.set_nodelay(true).ok();

    let with_auth = up.user.is_some();
    // приветствие: предлагаем «без аутентификации» и, если задан логин, «логин/пароль»
    if with_auth {
        s.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        s.write_all(&[0x05, 0x01, 0x00]).await?;
    }

    let mut rep = [0u8; 2];
    s.read_exact(&mut rep).await?;
    if rep[0] != 0x05 {
        return Err(bad("вышестоящий прокси ответил не по SOCKS5"));
    }
    match rep[1] {
        0x00 => {}
        0x02 => {
            let user = up.user.clone().unwrap_or_default();
            let pass = up.password.clone().unwrap_or_default();
            if user.len() > 255 || pass.len() > 255 {
                return Err(bad("логин или пароль длиннее 255 байт"));
            }
            let mut buf = vec![0x01, user.len() as u8];
            buf.extend_from_slice(user.as_bytes());
            buf.push(pass.len() as u8);
            buf.extend_from_slice(pass.as_bytes());
            s.write_all(&buf).await?;
            let mut ar = [0u8; 2];
            s.read_exact(&mut ar).await?;
            if ar[1] != 0x00 {
                return Err(bad("вышестоящий прокси отверг логин или пароль"));
            }
        }
        0xFF => return Err(bad("вышестоящий прокси не принял ни один способ входа")),
        other => return Err(bad(&format!("неизвестный способ входа: {other}"))),
    }

    // запрос на соединение, адрес — доменным именем
    if host.len() > 255 {
        return Err(bad("слишком длинное имя узла"));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(bad(socks_error(head[1])));
    }
    // дочитываем адрес привязки, он нам не нужен, но его надо снять с потока
    match head[3] {
        0x01 => { let mut b = [0u8; 4]; s.read_exact(&mut b).await?; }
        0x04 => { let mut b = [0u8; 16]; s.read_exact(&mut b).await?; }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            let mut b = vec![0u8; l[0] as usize];
            s.read_exact(&mut b).await?;
        }
        other => return Err(bad(&format!("неизвестный тип адреса в ответе: {other}"))),
    }
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await?;
    Ok(s)
}

fn socks_error(code: u8) -> &'static str {
    match code {
        0x01 => "прокси: внутренняя ошибка",
        0x02 => "прокси: соединение запрещено правилами",
        0x03 => "прокси: сеть недоступна",
        0x04 => "прокси: узел недоступен",
        0x05 => "прокси: соединение отклонено",
        0x06 => "прокси: истекло время жизни пакета",
        0x07 => "прокси: команда не поддерживается",
        0x08 => "прокси: тип адреса не поддерживается",
        _ => "прокси: неизвестная ошибка",
    }
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg.to_string())
}


#[cfg(test)]
mod tests {
    use super::*;

    fn up(name: &str, port: u16) -> Upstream {
        Upstream {
            name: name.into(), kind: Kind::Socks5,
            address: "127.0.0.1".into(), port, user: None, password: None,
            from_subscription: false,
        }
    }

    fn routing() -> Routing {
        let mut pool = Pool::new();
        pool.insert("офис".into(), up("офис", 1081));
        pool.insert("vpn".into(), up("vpn", 10808));
        pool.insert(String::new(), up("офис", 1081));
        Routing { pool, overrides: Default::default() }
    }

    #[test]
    fn without_override_goes_where_assigned() {
        let r = routing();
        let (u, sub) = r.resolve("офис").unwrap();
        assert_eq!(u.port, 1081);
        assert!(!sub, "подмены нет");
    }

    #[test]
    fn override_redirects_and_is_visible() {
        let mut r = routing();
        r.overrides.insert("офис".into(), "vpn".into());
        let (u, sub) = r.resolve("офис").unwrap();
        assert_eq!(u.port, 10808, "должен уйти на замену");
        assert!(sub, "подмена обязана быть заметна — иначе она незаметно врёт");

        // и через пустое имя, то есть «по умолчанию», тоже
        let (u, sub) = r.resolve("").unwrap();
        assert_eq!(u.port, 10808);
        assert!(sub);
    }

    #[test]
    fn other_proxies_untouched() {
        let mut r = routing();
        r.overrides.insert("офис".into(), "vpn".into());
        let (u, sub) = r.resolve("vpn").unwrap();
        assert_eq!(u.port, 10808);
        assert!(!sub, "у vpn подмены нет, пометки быть не должно");
    }

    #[test]
    fn override_to_missing_proxy_is_not_silently_ignored() {
        let mut r = routing();
        r.overrides.insert("офис".into(), "нет-такого".into());
        // молча вернуть исходный нельзя: человек думает, что переключил
        assert!(r.resolve("офис").is_none());
    }
}
