//! Входящий SOCKS5 — для приложений, которые умеют работать через SOCKS.

use crate::rules::Rules;
use crate::upstream::{dial, Upstream};
use std::io;
use std::sync::Arc;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn handle(mut c: TcpStream, up: Arc<Upstream>, rules: Arc<std::sync::RwLock<Rules>>)
    -> io::Result<()>
{
    c.set_nodelay(true).ok();

    // приветствие клиента
    let mut head = [0u8; 2];
    c.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(bad("клиент пришёл не по SOCKS5"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    c.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        c.write_all(&[0x05, 0xFF]).await.ok();
        return Err(bad("клиент не поддерживает вход без пароля"));
    }
    c.write_all(&[0x05, 0x00]).await?;

    // запрос
    let mut req = [0u8; 4];
    c.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Err(bad("испорченный запрос"));
    }
    if req[1] != 0x01 {
        // поддерживаем только CONNECT; UDP пока не проксируем
        reply(&mut c, 0x07).await.ok();
        return Err(bad("поддерживается только команда CONNECT"));
    }

    let host = match req[3] {
        0x01 => {
            let mut b = [0u8; 4];
            c.read_exact(&mut b).await?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        0x04 => {
            let mut b = [0u8; 16];
            c.read_exact(&mut b).await?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        0x03 => {
            let mut l = [0u8; 1];
            c.read_exact(&mut l).await?;
            let mut b = vec![0u8; l[0] as usize];
            c.read_exact(&mut b).await?;
            String::from_utf8(b).map_err(|_| bad("имя узла не в UTF-8"))?
        }
        _ => {
            reply(&mut c, 0x08).await.ok();
            return Err(bad("неизвестный тип адреса"));
        }
    };
    let mut pb = [0u8; 2];
    c.read_exact(&mut pb).await?;
    let port = u16::from_be_bytes(pb);

    match dial(&up, &rules, &host, port).await {
        Ok(mut server) => {
            reply(&mut c, 0x00).await?;
            let _ = copy_bidirectional(&mut c, &mut server).await;
            Ok(())
        }
        Err(e) => {
            let code = match e.kind() {
                io::ErrorKind::PermissionDenied => 0x02,
                io::ErrorKind::ConnectionRefused => 0x05,
                _ => 0x01,
            };
            reply(&mut c, code).await.ok();
            Err(e)
        }
    }
}

async fn reply(c: &mut TcpStream, code: u8) -> io::Result<()> {
    // отвечаем нулевым адресом привязки: клиентам этого достаточно
    c.write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}
