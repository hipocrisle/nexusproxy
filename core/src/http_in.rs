//! Входящий HTTP-прокси. Именно его понимают переменные окружения
//! HTTP_PROXY/HTTPS_PROXY — а Claude Code, например, работает ТОЛЬКО так:
//! SOCKS он не поддерживает.

use crate::rules::Rules;
use crate::upstream::{dial, Upstream};
use std::io;
use std::sync::Arc;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_HEAD: usize = 64 * 1024;

pub async fn handle(mut c: TcpStream, up: Arc<Upstream>, rules: Arc<std::sync::RwLock<Rules>>)
    -> io::Result<()>
{
    c.set_nodelay(true).ok();

    // читаем заголовок до пустой строки
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let head_end = loop {
        let n = c.read(&mut chunk).await?;
        if n == 0 {
            return Err(bad("клиент закрыл соединение до конца заголовка"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = find_head_end(&buf) {
            break p;
        }
        if buf.len() > MAX_HEAD {
            respond(&mut c, 431, "Request Header Fields Too Large").await.ok();
            return Err(bad("заголовок слишком велик"));
        }
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("").to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(&target, 443)?;
        return match dial(&up, &rules, &host, port).await {
            Ok(mut server) => {
                c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
                // всё, что клиент успел прислать после заголовка, — уже полезные данные
                let rest = &buf[head_end..];
                if !rest.is_empty() {
                    server.write_all(rest).await?;
                }
                let _ = copy_bidirectional(&mut c, &mut server).await;
                Ok(())
            }
            Err(e) => {
                respond(&mut c, 502, "Bad Gateway").await.ok();
                Err(e)
            }
        };
    }

    // обычный запрос в абсолютной форме: GET http://host/path
    let (host, port, path) = split_absolute(&target)?;
    let mut server = match dial(&up, &rules, &host, port).await {
        Ok(s) => s,
        Err(e) => {
            respond(&mut c, 502, "Bad Gateway").await.ok();
            return Err(e);
        }
    };

    let mut out = format!("{method} {path} {version}\r\n");
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let name = line.split(':').next().unwrap_or("").trim();
        // заголовки, адресованные самому прокси, дальше не передаём
        if name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("proxy-authorization")
        {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    server.write_all(out.as_bytes()).await?;

    let rest = &buf[head_end..];
    if !rest.is_empty() {
        server.write_all(rest).await?;
    }
    let _ = copy_bidirectional(&mut c, &mut server).await;
    Ok(())
}

fn find_head_end(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn split_host_port(t: &str, default: u16) -> io::Result<(String, u16)> {
    // [::1]:443 или host:443 или host
    if let Some(rest) = t.strip_prefix('[') {
        let (h, tail) = rest.split_once(']').ok_or_else(|| bad("испорченный адрес IPv6"))?;
        let port = tail.strip_prefix(':').map_or(Ok(default), |p| {
            p.parse::<u16>().map_err(|_| bad("плохой номер порта"))
        })?;
        return Ok((h.to_string(), port));
    }
    match t.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => {
            Ok((h.to_string(), p.parse::<u16>().map_err(|_| bad("плохой номер порта"))?))
        }
        _ => Ok((t.to_string(), default)),
    }
}

fn split_absolute(t: &str) -> io::Result<(String, u16, String)> {
    let (scheme_default, rest) = if let Some(r) = t.strip_prefix("http://") {
        (80u16, r)
    } else if let Some(r) = t.strip_prefix("https://") {
        (443u16, r)
    } else {
        return Err(bad("ожидался запрос в абсолютной форме"));
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    // логин в адресе прокси не пересылаем дальше
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    let (host, port) = split_host_port(authority, scheme_default)?;
    Ok((host, port, path.to_string()))
}

async fn respond(c: &mut TcpStream, code: u16, text: &str) -> io::Result<()> {
    let body = format!("HTTP/1.1 {code} {text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    c.write_all(body.as_bytes()).await
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_forms() {
        assert_eq!(split_host_port("example.com:8080", 443).unwrap(), ("example.com".into(), 8080));
        assert_eq!(split_host_port("example.com", 443).unwrap(), ("example.com".into(), 443));
        assert_eq!(split_host_port("[::1]:9050", 443).unwrap(), ("::1".into(), 9050));
        assert_eq!(split_host_port("[::1]", 443).unwrap(), ("::1".into(), 443));
    }

    #[test]
    fn absolute_forms() {
        let (h, p, path) = split_absolute("http://example.com/a?b=1").unwrap();
        assert_eq!((h.as_str(), p, path.as_str()), ("example.com", 80, "/a?b=1"));
        let (h, p, path) = split_absolute("http://example.com").unwrap();
        assert_eq!((h.as_str(), p, path.as_str()), ("example.com", 80, "/"));
        let (h, p, _) = split_absolute("https://example.com:8443/x").unwrap();
        assert_eq!((h.as_str(), p), ("example.com", 8443));
        let (h, _, _) = split_absolute("http://user:pw@example.com/x").unwrap();
        assert_eq!(h.as_str(), "example.com");
    }

    #[test]
    fn head_end_detection() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\nBODY"), Some(18));
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n"), None);
    }
}
