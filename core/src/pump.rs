//! Перекачка данных со счётчиками.
//!
//! Готовая `copy_bidirectional` отдаёт объём только когда соединение
//! закрылось. Из-за этого в таблице живых соединений всегда были нули:
//! пока соединение открыто — считать нечем, а как закрылось — строка
//! уже исчезла. Здесь счётчики обновляются по ходу.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Default, Debug)]
pub struct Counters {
    pub sent: AtomicU64,
    pub received: AtomicU64,
}

impl Counters {
    pub fn get(&self) -> (u64, u64) {
        (self.sent.load(Ordering::Relaxed), self.received.load(Ordering::Relaxed))
    }
}

/// Гонит данные в обе стороны, обновляя счётчики на каждом куске.
/// «Отдано» — от клиента наружу, «получено» — обратно.
pub async fn both_ways(client: TcpStream, server: TcpStream, c: Arc<Counters>) -> (u64, u64) {
    both_ways_until(client, server, c, Arc::new(tokio::sync::Notify::new())).await
}

/// То же, но соединение можно оборвать снаружи.
/// Нужно, когда правило поменялось: уже открытое соединение продолжало бы
/// идти через прежний прокси, и правка выглядела бы как «не работает».
pub async fn both_ways_until(
    client: TcpStream,
    server: TcpStream,
    c: Arc<Counters>,
    kill: Arc<tokio::sync::Notify>,
) -> (u64, u64) {
    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = server.into_split();

    let up = {
        let (c, kill) = (c.clone(), kill.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 32 * 1024];
            // ⛔ Подписываемся на обрыв ДО первого чтения и держим
            // подписку между витками. Создавая её заново на каждом
            // витке, мы пропускали сигнал: он будит только подписанных в
            // тот самый миг и разрешений не копит. Задача, сидящая в
            // записи — а на загруженном направлении она там почти
            // всегда, — сигнала не видела вовсе: соединение продолжало
            // идти через прежний прокси, хотя в журнал писалось
            // «разорвано соединений: N».
            let notified = kill.notified();
            tokio::pin!(notified);
            loop {
                let n = tokio::select! {
                    r = cr.read(&mut buf) => match r { Ok(0) | Err(_) => break, Ok(n) => n },
                    _ = &mut notified => break,
                };
                let ушло = tokio::select! {
                    w = sw.write_all(&buf[..n]) => w.is_ok(),
                    _ = &mut notified => false,
                };
                if !ушло {
                    break;
                }
                c.sent.fetch_add(n as u64, Ordering::Relaxed);
            }
            // ⛔ Закрываем с оглядкой на время. Вежливое закрытие ждёт,
            // пока та сторона заберёт остаток, — а если она перестала
            // читать, ожидание длится вечно, и оборванное соединение всё
            // равно не освобождается.
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2), sw.shutdown()).await;
        })
    };

    let down = {
        let (c, kill) = (c.clone(), kill.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 32 * 1024];
            let notified = kill.notified();
            tokio::pin!(notified);
            loop {
                let n = tokio::select! {
                    r = sr.read(&mut buf) => match r { Ok(0) | Err(_) => break, Ok(n) => n },
                    _ = &mut notified => break,
                };
                let ушло = tokio::select! {
                    w = cw.write_all(&buf[..n]) => w.is_ok(),
                    _ = &mut notified => false,
                };
                if !ушло {
                    break;
                }
                c.received.fetch_add(n as u64, Ordering::Relaxed);
            }
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2), cw.shutdown()).await;
        })
    };

    let _ = tokio::join!(up, down);
    c.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⛔ Обрыв обязан срабатывать, даже когда соединение в этот момент
    /// занято передачей. Подписка, создаваемая заново на каждом витке,
    /// сигнал пропускала: он будит только подписанных в тот самый миг.
    #[tokio::test]
    async fn обрыв_срабатывает_во_время_передачи() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let слушает = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let адрес = слушает.local_addr().unwrap();
        // та сторона принимает соединение и НЕ читает — запись упирается
        let держит = tokio::spawn(async move {
            let (s, _) = слушает.accept().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            drop(s);
        });

        let к_серверу = tokio::net::TcpStream::connect(адрес).await.unwrap();
        let наш = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let наш_адрес = наш.local_addr().unwrap();
        let клиент = tokio::spawn(async move {
            let mut c = tokio::net::TcpStream::connect(наш_адрес).await.unwrap();
            // шлём много, чтобы перекачка встала в записи
            let кусок = vec![7u8; 1024 * 1024];
            for _ in 0..40 {
                if c.write_all(&кусок).await.is_err() {
                    break;
                }
            }
        });
        let (со_стороны_клиента, _) = наш.accept().await.unwrap();

        let kill = std::sync::Arc::new(tokio::sync::Notify::new());
        let counters = std::sync::Arc::new(Counters::default());
        let перекачка = tokio::spawn(both_ways_until(
            со_стороны_клиента, к_серверу, counters, kill.clone()));

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        kill.notify_waiters();

        let начало = std::time::Instant::now();
        let итог = tokio::time::timeout(std::time::Duration::from_secs(10), перекачка).await;
        println!("перекачка завершилась за {:?}", начало.elapsed());
        assert!(итог.is_ok(), "обрыв не сработал — соединение осталось жить");
        assert!(начало.elapsed() < std::time::Duration::from_secs(5),
                "обрыв сработал слишком медленно: {:?}", начало.elapsed());

        держит.abort();
        клиент.abort();
    }
    use tokio::net::TcpListener;

    /// Эхо-сервер: возвращает вдвое больше, чем получил, — чтобы
    /// «отдано» и «получено» нельзя было перепутать местами.
    async fn echo_twice() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            while let Ok(n) = s.read(&mut buf).await {
                if n == 0 { break; }
                let doubled: Vec<u8> = buf[..n].iter().chain(buf[..n].iter()).copied().collect();
                if s.write_all(&doubled).await.is_err() { break; }
            }
        });
        port
    }

    #[tokio::test]
    async fn counts_both_directions() {
        let port = echo_twice().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = listener.local_addr().unwrap().port();
        let counters = Arc::new(Counters::default());
        let c2 = counters.clone();

        tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            let server = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            both_ways(client, server, c2).await;
        });

        let mut me = TcpStream::connect(("127.0.0.1", front)).await.unwrap();
        me.write_all(b"12345").await.unwrap();
        let mut got = [0u8; 10];
        me.read_exact(&mut got).await.unwrap();
        drop(me);
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let (sent, received) = counters.get();
        assert_eq!(sent, 5, "отдано — то, что ушло от клиента");
        assert_eq!(received, 10, "получено — то, что пришло обратно");
    }

    #[tokio::test]
    async fn counters_visible_before_close() {
        // ровно та беда, из-за которой в таблице были нули
        let port = echo_twice().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = listener.local_addr().unwrap().port();
        let counters = Arc::new(Counters::default());
        let c2 = counters.clone();
        tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            let server = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            both_ways(client, server, c2).await;
        });

        let mut me = TcpStream::connect(("127.0.0.1", front)).await.unwrap();
        me.write_all(b"abc").await.unwrap();
        let mut got = [0u8; 6];
        me.read_exact(&mut got).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let (sent, received) = counters.get();
        assert_eq!((sent, received), (3, 6), "счётчики должны быть видны, пока связь открыта");
        drop(me);
    }
}
