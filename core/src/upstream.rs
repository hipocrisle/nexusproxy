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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Upstream {
    pub address: String,
    pub port: u16,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

/// Печатать каждое решение. Включается ключом --verbose.
pub static VERBOSE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub async fn dial(up: &Upstream, rules: &std::sync::RwLock<Rules>, host: &str, port: u16)
    -> io::Result<TcpStream>
{
    let route = rules.read().unwrap().decide(host);
    if VERBOSE.load(std::sync::atomic::Ordering::Relaxed) {
        let mark = match route {
            Route::Proxy => "через прокси",
            Route::Direct => "напрямую   ",
            Route::Block => "запрещено  ",
        };
        println!("  {mark}  {host}:{port}");
    }
    crate::report::note(host, &route);
    crate::journal::push(host, port, &route);
    match route {
        Route::Block => Err(io::Error::new(io::ErrorKind::PermissionDenied, "запрещено правилом")),
        Route::Direct => TcpStream::connect((host, port)).await,
        Route::Proxy => {
            // Прокси может моргнуть — сеть переключилась, он перезапустился.
            // Пробуем ещё раз, прежде чем отдавать ошибку приложению.
            match via_socks5(up, host, port).await {
                Ok(s) => Ok(s),
                Err(first) if !AUTO_RECONNECT.load(std::sync::atomic::Ordering::Relaxed) => {
                    crate::health::mark_down(&first.to_string());
                    Err(first)
                }
                Err(first) => {
                    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                    match via_socks5(up, host, port).await {
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
    }
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
