//! Запись журнала в файл. Пишем сразу, чтобы после падения или
//! перезапуска было что смотреть.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

/// Когда файл вырастает до этого размера, он становится .1, а запись
/// продолжается в чистый. Держим две штуки — этого хватает и место не ест.
const MAX_BYTES: u64 = 4 * 1024 * 1024;

struct Sink {
    path: PathBuf,
    file: File,
    written: u64,
}

static SINK: Mutex<Option<Sink>> = Mutex::new(None);

/// Журнал и файл журнала — общие на всю программу, поэтому тесты,
/// которые их трогают, выполняются по одному.
#[cfg(test)]
pub(crate) static TEST_LOCK: Mutex<()> = Mutex::new(());

pub fn open(path: PathBuf) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let file = OpenOptions::new().create(true).append(true).open(&path)?;
    let written = file.metadata().map(|m| m.len()).unwrap_or(0);
    *SINK.lock().unwrap() = Some(Sink { path, file, written });
    Ok(())
}

pub fn path() -> Option<PathBuf> {
    SINK.lock().unwrap().as_ref().map(|s| s.path.clone())
}

/// Отметка времени по местным часам — чтобы в логе было то же время,
/// что на часах у пользователя. На Windows берём системное местное,
/// в остальных случаях считаем от эпохи.
pub fn now_stamp() -> String {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::SystemInformation::GetLocalTime;
        let mut st = unsafe { std::mem::zeroed() };
        unsafe { GetLocalTime(&mut st) };
        return format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
        );
    }
    #[cfg(not(windows))]
    {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
        format!("{h:02}:{m:02}:{s:02}")
    }
}

/// Строка журнала. Время подставляет вызывающий: ядро не тянет
/// зависимостей ради форматирования даты.
pub fn line(stamp: &str, text: &str) {
    let mut g = SINK.lock().unwrap();
    let Some(s) = g.as_mut() else { return };
    let msg = format!("{stamp} {text}\n");
    if s.file.write_all(msg.as_bytes()).is_ok() {
        s.written += msg.len() as u64;
        let _ = s.file.flush();
    }
    if s.written >= MAX_BYTES {
        rotate(s);
    }
}

fn rotate(s: &mut Sink) {
    let old = s.path.with_extension("log.1");
    let _ = std::fs::rename(&s.path, &old);
    if let Ok(f) = OpenOptions::new().create(true).append(true).open(&s.path) {
        s.file = f;
        s.written = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_rotates() {
        let _guard = crate::logfile::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("np-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("nexusproxy.log");
        open(p.clone()).unwrap();

        line("12:00:00", "первая строка");
        assert!(std::fs::read_to_string(&p).unwrap().contains("первая строка"));

        // добиваем до порога, чтобы проверить пересоздание
        let big = "x".repeat(64 * 1024);
        for _ in 0..70 {
            line("12:00:01", &big);
        }
        assert!(p.with_extension("log.1").exists(), "старый файл должен уехать в .1");
        assert!(
            std::fs::metadata(&p).unwrap().len() < MAX_BYTES,
            "запись должна продолжиться в чистый файл"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
