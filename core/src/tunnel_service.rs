//! Служба, поднимающая перехват, — своя на каждой системе.
//!
//! ⛔ Зачем она. Сетевой интерфейс создаётся только с правами
//! администратора. Просить их при каждом включении — ровно то, чем
//! людей раздражает Proxifier. Поэтому права спрашиваются ОДИН раз, при
//! установке службы; дальше перехват включается без единого вопроса.
//! Само окно программы прав не имеет и иметь не должно.
//!
//! Побочная польза: служба переживает перезапуск программы, поэтому
//! перехват не отваливается, когда человек закрыл и открыл окно.

use std::path::Path;

pub const NAME: &str = "NexusProxyTunnel";

/// Что сейчас со службой.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub enum State {
    /// Не установлена — нужен один запрос прав.
    Absent,
    /// Установлена, но перехват выключен.
    Stopped,
    /// Перехват работает.
    Running,
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::process::Command;

    /// ⛔ Службой Windows может быть только программа, умеющая отчитаться
    /// диспетчеру о запуске. sing-box этого не умеет и не должен:
    /// диспетчер ждёт ответа и снимает её с ошибкой 1053.
    ///
    /// Поэтому берём задачу планировщика с повышенными правами: ставится
    /// один раз с подтверждением, запускается потом без него — ровно то,
    /// что нужно, администратор спрашивается единожды.
    fn schtasks(args: &[&str]) -> Result<String, String> {
        use std::os::windows::process::CommandExt;
        let out = Command::new("schtasks.exe")
            .args(args)
            // ⛔ Без этого флага при каждой проверке состояния мигает
            // чёрное окно консоли — а состояние мы спрашиваем постоянно.
            .creation_flags(0x0800_0000)
            .output()
            .map_err(|e| format!("не вызвать планировщик: {e}"))?;
        // ⛔ Системные программы отвечают в кодировке консоли, а не
        // UTF-8: прочитав как UTF-8, человек видит кракозябры вместо
        // причины отказа.
        let text = oem_to_utf8(&out.stdout) + &oem_to_utf8(&out.stderr);
        // ⛔ Пишем всё: без этого «не работает» невозможно разобрать —
        // видно только, что ничего не произошло.
        if !args.first().map_or(false, |a| *a == "/query") {
            crate::logfile::line(&crate::logfile::now_stamp(),
                &format!("перехват: schtasks {} → {}", args.join(" "), text.trim()));
        }
        if out.status.success() { Ok(text) } else { Err(text.trim().to_string()) }
    }

    /// Перевод из кодировки консоли Windows (866) в обычный текст.
    fn oem_to_utf8(raw: &[u8]) -> String {
        // Таблица только для кириллицы и псевдографики — остальное
        // совпадает с латиницей.
        const HIGH: [char; 128] = [
            'А','Б','В','Г','Д','Е','Ж','З','И','Й','К','Л','М','Н','О','П',
            'Р','С','Т','У','Ф','Х','Ц','Ч','Ш','Щ','Ъ','Ы','Ь','Э','Ю','Я',
            'а','б','в','г','д','е','ж','з','и','й','к','л','м','н','о','п',
            '░','▒','▓','│','┤','╡','╢','╖','╕','╣','║','╗','╝','╜','╛','┐',
            '└','┴','┬','├','─','┼','╞','╟','╚','╔','╩','╦','╠','═','╬','╧',
            '╨','╤','╥','╙','╘','╒','╓','╫','╪','┘','┌','█','▄','▌','▐','▀',
            'р','с','т','у','ф','х','ц','ч','ш','щ','ъ','ы','ь','э','ю','я',
            'Ё','ё','Є','є','Ї','ї','Ў','ў','°','∙','·','√','№','¤','■',' ',
        ];
        raw.iter()
            .map(|&b| if b < 0x80 { b as char } else { HIGH[(b - 0x80) as usize] })
            .collect()
    }

    pub fn state() -> State {
        match schtasks(&["/query", "/tn", NAME, "/fo", "list"]) {
            Err(_) => State::Absent,
            Ok(t) if t.contains("Running") || t.contains("Выполняется") => State::Running,
            Ok(_) => State::Stopped,
        }
    }

    /// ⛔ Кавычки обязательны: в путях бывают пробелы («Program Files»,
    /// имя пользователя). Без них задача получит обрезанный путь и молча
    /// не запустится — перехват «не работает», а почему, не видно.
    /// ⛔ Задача запускает НАС, а не движок напрямую: сама она окно
    /// консоли спрятать не умеет, и у человека висело бы чёрное окно с
    /// журналом. Движок поднимаем мы, уже без окна.
    pub fn install_command(exe: &Path, dir: &Path) -> String {
        format!(
            "schtasks.exe /create /tn {NAME} /f /sc once /st 00:00 /rl highest \
             /tr \"\\\"{}\\\" --run-tunnel \\\"{}\\\"\"",
            exe.display(), dir.display()
        )
    }

    pub fn uninstall_command() -> String {
        format!("schtasks.exe /end /tn {NAME} & schtasks.exe /delete /tn {NAME} /f")
    }

    pub fn start() -> Result<(), String> {
        // ⛔ Сначала снимаем, потом запускаем. Движок читает настройки
        // при запуске: если задача уже выполняется, просто «запустить»
        // ничего не меняет — он продолжает работать со старыми. Так у
        // человека и оставался прежний сервер имён после исправления.
        let _ = schtasks(&["/end", "/tn", NAME]);
        std::thread::sleep(std::time::Duration::from_millis(600));
        schtasks(&["/run", "/tn", NAME]).map(|_| ())
            .map_err(|e| format!("перехват не включился: {e}"))
    }

    pub fn stop() -> Result<(), String> {
        match schtasks(&["/end", "/tn", NAME]) {
            Ok(_) => Ok(()),
            Err(e) if e.contains("267011") || e.to_lowercase().contains("not running") => Ok(()),
            Err(e) => Err(format!("перехват не выключился: {e}")),
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    /// ⛔ Системным демоном на macOS может управлять только root. Если
    /// включать и выключать его через launchctl, пароль спрашивался бы
    /// каждый раз — ровно то, чего мы избегаем.
    ///
    /// Поэтому демон следит за файлом-признаком: файл появился — launchd
    /// поднял перехват, файл удалён — остановил. Создать и удалить файл
    /// в своей папке может обычный пользователь, без всяких прав.
    /// Администратор нужен один раз, чтобы положить описание демона.
    pub fn flag_path(dir: &Path) -> std::path::PathBuf {
        dir.join("enabled")
    }

    pub fn plist_path() -> std::path::PathBuf {
        std::path::PathBuf::from(format!("/Library/LaunchDaemons/{NAME}.plist"))
    }

    pub fn state_in(dir: &Path) -> State {
        if !plist_path().exists() {
            return State::Absent;
        }
        if flag_path(dir).exists() { State::Running } else { State::Stopped }
    }

    pub fn state() -> State {
        if plist_path().exists() { State::Stopped } else { State::Absent }
    }

    /// Описание демона.
    ///
    /// ⛔ Демон работает ПОСТОЯННО, а перехват включает и выключает
    /// признак-файл, за которым следит наша обёртка.
    ///
    /// Раньше было наоборот: демон поднимался по появлению файла. На
    /// это launchd не реагировал — демон не стартовал ни разу, и в
    /// журнале за день не было ни одной записи о запуске движка.
    ///
    /// Сам по себе демон трафик не заворачивает: без признака обёртка
    /// движок не поднимает. Так что «работает постоянно» — это про
    /// наблюдателя, а не про перехват.
    /// Путь к сценарию-наблюдателю.
    pub fn watcher_path(dir: &Path) -> std::path::PathBuf {
        dir.join("watch.sh")
    }

    /// ⛔ Демон запускает обычный сценарий оболочки, а не наш файл из
    /// бандла. macOS не даёт системному демону запускать программу,
    /// подписанную самоподписанным сертификатом, — демон молча не
    /// стартует, и в журнале нет ни строчки. Сценарий таких ограничений
    /// не имеет.
    pub fn watcher(dir: &Path) -> String {
        format!(r#"#!/bin/sh
# Наблюдатель перехвата NexusProxy.
# Есть признак — движок работает, нет — стоит.
BIN="{bin}"
CFG="{cfg}"
FLAG="{flag}"
LOG="{log}"

echo "$(date '+%F %T') наблюдатель запущен" >> "$LOG"
while true; do
  if [ -f "$FLAG" ] && [ -x "$BIN" ]; then
    # ⛔ Журнал движка чистим при каждом запуске. Дописываясь без конца,
    # он смешивает вчерашние отказы с сегодняшними: старые FATAL выглядят
    # как свежие, а список опознанных программ — как будто из этого
    # сеанса. Разбирать по такому журналу нельзя.
    : > "{enginelog}"
    : > "$LOG"
    echo "$(date '+%F %T') поднимаю движок" >> "$LOG"
    "$BIN" run -c "$CFG" >> "$LOG" 2>&1 &
    PID=$!
    # держим, пока признак на месте и настройки не изменились
    STAMP=$(stat -f %m "$CFG" 2>/dev/null)
    while [ -f "$FLAG" ] && kill -0 "$PID" 2>/dev/null; do
      NOW=$(stat -f %m "$CFG" 2>/dev/null)
      if [ "$NOW" != "$STAMP" ]; then
        echo "$(date '+%F %T') настройки изменились, перезапускаю" >> "$LOG"
        break
      fi
      sleep 1
    done
    kill "$PID" 2>/dev/null
    wait "$PID" 2>/dev/null
    echo "$(date '+%F %T') движок остановлен" >> "$LOG"
  fi
  sleep 1
done
"#,
            bin = crate::tunnel::binary_path(dir).display(),
            cfg = crate::tunnel::config_path(dir).display(),
            flag = flag_path(dir).display(),
            log = dir.join("daemon.log").display(),
            enginelog = crate::tunnel::engine_log_path(dir).display())
    }

    pub fn plist(exe: &Path, dir: &Path) -> String {
        format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{NAME}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>{}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>{}</string>
</dict>
</plist>
"#, watcher_path(dir).display(), dir.join("daemon.log").display())
    }

    /// ⛔ Ошибки здесь НЕ подавляем. Раньше стояло `2>/dev/null; true`,
    /// и когда launchd отказывался поднимать демона, мы этого не видели
    /// вовсе: установка «успешна», а обёртка не запускается никогда.
    pub fn install_command(exe: &Path, dir: &Path) -> String {
        let _ = exe;
        let p = plist_path();
        let w = watcher_path(dir);
        // Здесь-документ: в путях бывают пробелы, а кавычки внутри xml
        // пришлось бы экранировать дважды.
        format!(
            "cat > '{w}' <<'NEXUSPROXY_WATCH'\n{watch}NEXUSPROXY_WATCH\n\
             chmod 755 '{w}' && \
             cat > '{p}' <<'NEXUSPROXY_PLIST'\n{plist}NEXUSPROXY_PLIST\n\
             chown root:wheel '{p}' && chmod 644 '{p}' && \
             launchctl bootout system/{NAME} 2>&1; \
             launchctl bootstrap system '{p}' 2>&1 && \
             launchctl print system/{NAME} 2>&1 | head -12",
            w = w.display(), watch = watcher(dir),
            p = p.display(), plist = plist(exe, dir)
        )
    }

    pub fn uninstall_command() -> String {
        let p = plist_path();
        format!("launchctl bootout system/{NAME} 2>/dev/null; rm -f '{}'", p.display())
    }

    /// Включение и выключение — просто файл. Прав не требует.
    pub fn start_in(dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("не создать папку: {e}"))?;
        let flag = flag_path(dir);
        let was_on = flag.exists();
        std::fs::write(&flag, b"on")
            .map_err(|e| format!("перехват не включился: {e}"))?;

        // ⛔ Движок читает настройки при запуске. Если он уже работает,
        // признак не меняется, launchd ничего не перезапускает — и
        // движок продолжает жить со старым списком приложений. Человек
        // добавил Cursor, а трафик идёт мимо.
        //
        // ⛔ Снять движок своими силами нельзя: он работает от системы, а
        // мы — от пользователя, прав не хватает (в журнале было «снято:
        // 0»). Поэтому перезапускаем признаком: убрали файл — launchd
        // остановил движок, вернули — поднял заново, уже с новыми
        // настройками.
        if was_on {
            let _ = std::fs::remove_file(&flag);
            std::thread::sleep(std::time::Duration::from_millis(1500));
            std::fs::write(&flag, b"on")
                .map_err(|e| format!("перехват не перезапустился: {e}"))?;
            crate::logfile::line(&crate::logfile::now_stamp(),
                "перехват: движок перезапущен с новыми настройками");
        } else {
            crate::logfile::line(&crate::logfile::now_stamp(),
                &format!("перехват: признак включения создан ({})", flag.display()));
        }
        Ok(())
    }

    pub fn stop_in(dir: &Path) -> Result<(), String> {
        match std::fs::remove_file(flag_path(dir)) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("перехват не выключился: {e}")),
        }
    }

    pub fn start() -> Result<(), String> {
        Err("не указана папка перехвата".into())
    }
    pub fn stop() -> Result<(), String> { Ok(()) }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod imp {
    use super::*;
    pub fn state() -> State { State::Absent }
    pub fn install_command(_e: &Path, _d: &Path) -> String { String::new() }
    pub fn uninstall_command() -> String { String::new() }
    pub fn start() -> Result<(), String> { Err("перехват на этой системе не поддерживается".into()) }
    pub fn stop() -> Result<(), String> { Ok(()) }
}

pub use imp::{install_command, uninstall_command};

/// Что сейчас с перехватом.
pub fn state_in(dir: &Path) -> State {
    #[cfg(target_os = "macos")]
    { imp::state_in(dir) }
    #[cfg(not(target_os = "macos"))]
    { let _ = dir; imp::state() }
}

/// Включить. На macOS — создать файл-признак, на Windows — запустить задачу.
pub fn start_in(dir: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    { imp::start_in(dir) }
    #[cfg(not(target_os = "macos"))]
    { let _ = dir; imp::start() }
}

/// Выключить.
pub fn stop_in(dir: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    { imp::stop_in(dir) }
    #[cfg(not(target_os = "macos"))]
    { let _ = dir; imp::stop() }
}

// ⛔ Механизма нет на Linux, и проверять там нечего: заглушка отдаёт
// пустую строку. Тесты идут только там, где перехват работает.
#[cfg(all(test, any(windows, target_os = "macos")))]
mod tests {
    use super::*;

    /// ⛔ В путях бывают пробелы — и в «Program Files», и в имени
    /// пользователя. Потеряв часть пути, служба молча не запустится.
    /// ⛔ В путях бывают пробелы — и в «Program Files», и в имени
    /// пользователя. Потеряв часть пути, служба молча не запустится.
    #[test]
    fn путь_с_пробелами_не_теряется() {
        let c = install_command(
            Path::new("/Applications/Nexus Proxy/NexusProxy"),
            Path::new("/Users/Иван Петров/перехват"),
        );
        assert!(c.contains("Иван Петров"), "{c}");
    }

    /// ⛔ Перехват включает человек, а не система при загрузке. На
    /// Windows это ручной запуск задачи; на macOS демон-наблюдатель
    /// работает постоянно, но движок поднимает только при появлении
    /// признака — иначе трафик заворачивался бы сам, без спросу.
    #[test]
    fn перехват_не_включается_сам() {
        let c = install_command(Path::new("a"), Path::new("b"));
        #[cfg(windows)]
        assert!(c.contains("/sc once"), "задача не должна запускаться сама: {c}");
        #[cfg(target_os = "macos")]
        {
            // демон поднимает наблюдателя, а тот запускает движок только
            // при наличии признака — сам по себе перехват не включается
            assert!(c.contains("watch.sh"), "демон обязан запускать наблюдателя: {c}");
            assert!(c.contains("[ -f \"$FLAG\" ]"),
                    "наблюдатель обязан смотреть на признак: {c}");
        }
        let _ = c;
    }
}

/// Поставить службу — один запрос прав у системы.
///
/// ⛔ Это единственное место, где программа просит администратора.
/// Дальше перехват включается и выключается без вопросов: службе при
/// установке выдаётся право на запуск и остановку обычным пользователем.
/// Чем именно сейчас установлена служба. Пусто — не установлена или
/// поставлена версией, которая этого не записывала.
fn signature_path(dir: &Path) -> std::path::PathBuf {
    dir.join("service-signature")
}

/// ⛔ Задача планировщика и демон создаются один раз и сами не
/// обновляются. После обновления программы они продолжают делать
/// по-старому — человек ставит новую версию и не видит НИКАКИХ
/// изменений, потому что работает старая запись. Поэтому храним, чем
/// именно она поставлена, и переустанавливаем при расхождении.
pub fn needs_reinstall(dir: &Path) -> bool {
    let want = match std::env::current_exe() {
        Ok(me) => install_command(&me, dir),
        Err(_) => return false,
    };
    match std::fs::read_to_string(signature_path(dir)) {
        Ok(have) => have.trim() != want.trim(),
        Err(_) => true,
    }
}

pub fn install(dir: &Path) -> Result<(), String> {
    if !crate::tunnel::binary_path(dir).is_file() {
        return Err("движок перехвата ещё не скачан".into());
    }
    // Задача запускает нас же — мы поднимем движок без окна.
    let me = std::env::current_exe()
        .map_err(|e| format!("не найти себя: {e}"))?;
    let cmd = install_command(&me, dir);
    crate::logfile::line(&crate::logfile::now_stamp(),
        &format!("перехват: ставлю службу заново\n  {cmd}"));
    // Старую убираем сразу: иначе на Windows останется задача с прежним
    // способом запуска, и человек увидит поведение старой версии.
    // ⛔ cmd не считает перевод строки разделителем команд: склеенные
    // через \n они превращаются в бессмыслицу, и он отвечает «не удалось
    // найти указанный файл». Разделять только амперсандом.
    let full = format!("{} & {cmd}", uninstall_command());
    run_elevated(&full)?;
    let _ = std::fs::write(signature_path(dir), &cmd);
    crate::logfile::line(&crate::logfile::now_stamp(), "перехват: служба установлена");
    Ok(())
}

/// Убрать службу — тоже с запросом прав.
pub fn uninstall() -> Result<(), String> {
    run_elevated(&uninstall_command())
}

#[cfg(windows)]
fn run_elevated(cmd: &str) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    use windows_sys::Win32::Foundation::CloseHandle;

    let wide = |s: &str| -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    };
    let verb = wide("runas");
    let file = wide("cmd.exe");
    let args = wide(&format!("/c {cmd}"));

    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = args.as_ptr();
    info.nShow = 0;

    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok == 0 {
        // Человек мог нажать «Нет» — это его решение, а не наша поломка.
        return Err("права администратора не выданы".into());
    }
    unsafe {
        WaitForSingleObject(info.hProcess, 60_000);
        CloseHandle(info.hProcess);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_elevated(cmd: &str) -> Result<(), String> {
    // Что ответила система — в журнал целиком: без этого «не работает»
    // невозможно разобрать, а гадать мы уже пробовали.
    // ⛔ Кавычки внутри скрипта нужно удвоить: osascript отдаёт строку
    // оболочке, и одиночная кавычка оборвала бы команду на середине.
    let escaped = cmd.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!(
        "do shell script \"{escaped}\" with administrator privileges"
    );
    let out = std::process::Command::new("osascript")
        .arg("-e").arg(&script)
        .output()
        .map_err(|e| format!("не вызвать osascript: {e}"))?;
    let said = String::from_utf8_lossy(&out.stdout).to_string()
        + &String::from_utf8_lossy(&out.stderr);
    crate::logfile::line(&crate::logfile::now_stamp(),
        &format!("перехват: система ответила: {}", said.trim()));
    if out.status.success() {
        Ok(())
    } else {
        if said.contains("-128") {
            Err("права администратора не выданы".into())
        } else {
            Err(format!("не поставить службу перехвата: {}", said.trim()))
        }
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn run_elevated(_cmd: &str) -> Result<(), String> {
    Err("перехват на этой системе не поддерживается".into())
}
