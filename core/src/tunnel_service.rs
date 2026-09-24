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
    pub fn oem_to_utf8(raw: &[u8]) -> String {
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

    pub fn install_command(_exe: &Path, dir: &Path) -> String {
        format!("schtasks.exe /create /tn {NAME} /f /xml \"{}\" & schtasks.exe /run /tn {NAME}",
                xml_path(dir).display())
    }

    pub fn uninstall_command() -> String {
        format!("schtasks.exe /end /tn {NAME} & schtasks.exe /delete /tn {NAME} /f")
    }

    /// Работает ли задача сама по себе — независимо от того, просили мы
    /// перехват или нет.
    fn task_running() -> bool {
        matches!(schtasks(&["/query", "/tn", NAME, "/fo", "list"]),
                 Ok(t) if t.contains("Running") || t.contains("Выполняется"))
    }

    pub fn state_in(dir: &Path) -> State {
        if let Err(_) = schtasks(&["/query", "/tn", NAME, "/fo", "list"]) {
            return State::Absent;
        }
        if super::flag_path(dir).exists() && task_running() { State::Running } else { State::Stopped }
    }

    /// ⛔ Ставим признак, а не запускаем задачу. Задача принадлежит
    /// системе, и обычный пользователь запустить её не вправе —
    /// планировщик отвечает отказом. Задача крутится сама и смотрит на
    /// этот файл; создать его человек может своими правами.
    pub fn start_in(dir: &Path) -> Result<(), String> {
        std::fs::write(super::flag_path(dir), b"1")
            .map_err(|e| format!("не включить перехват: {e}"))?;
        // Если задача почему-то не выполняется — попробуем поднять. Без
        // прав это не выйдет, и тогда скажем человеку прямо.
        if !task_running() {
            let _ = schtasks(&["/run", "/tn", NAME]);
            std::thread::sleep(std::time::Duration::from_millis(800));
            if !task_running() {
                return Err("служба перехвата не выполняется. Переустановите её \
                            в настройках — потребуются права администратора".into());
            }
        }
        Ok(())
    }

    pub fn stop_in(dir: &Path) -> Result<(), String> {
        let _ = std::fs::remove_file(super::flag_path(dir));
        Ok(())
    }

    pub fn start() -> Result<(), String> {
        Err("перехват включается признаком в своей папке".into())
    }

    pub fn stop() -> Result<(), String> { Ok(()) }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::*;

    /// ⛔ Системным демоном на macOS может управлять только root. Если
    /// включать и выключать его через launchctl, пароль спрашивался бы
    /// каждый раз — ровно то, чего мы избегаем.
    ///
    /// Поэтому демон следит за файлом-признаком: файл появился —
    /// перехват поднят, файл удалён — остановлен. Сам признак общий для
    /// обеих систем, см. [`super::flag_path`].

    pub fn plist_path() -> std::path::PathBuf {
        std::path::PathBuf::from(format!("/Library/LaunchDaemons/{NAME}.plist"))
    }

    pub fn state_in(dir: &Path) -> State {
        if !plist_path().exists() {
            return State::Absent;
        }
        if super::flag_path(dir).exists() { State::Running } else { State::Stopped }
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
    echo "$(date '+%F %T') поднимаю движок" >> "$LOG"
    "$BIN" run -c "$CFG" >> "$LOG" 2>&1 &
    PID=$!
    # держим, пока признак на месте и настройки не изменились
    STAMP=$(stat -f %m "$CFG" 2>/dev/null)
    while [ -f "$FLAG" ] && kill -0 "$PID" 2>/dev/null; do
      # ⛔ Журнал движка растёт мегабайтами в час. Без обрезки за неделю
      # работы набежали бы сотни мегабайт в папке настроек.
      SIZE=$(stat -f %z "{enginelog}" 2>/dev/null || echo 0)
      if [ "$SIZE" -gt 8388608 ]; then
        tail -c 4194304 "{enginelog}" > "{enginelog}.tmp" && mv "{enginelog}.tmp" "{enginelog}"
      fi
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
            flag = super::flag_path(dir).display(),
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
        let flag = super::flag_path(dir);
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
        match std::fs::remove_file(super::flag_path(dir)) {
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
    pub fn state_in(_d: &Path) -> State { State::Absent }
    pub fn start_in(_d: &Path) -> Result<(), String> { start() }
    pub fn stop_in(_d: &Path) -> Result<(), String> { stop() }
    pub fn install_command(_e: &Path, _d: &Path) -> String { String::new() }
    pub fn uninstall_command() -> String { String::new() }
    pub fn start() -> Result<(), String> { Err("перехват на этой системе не поддерживается".into()) }
    pub fn stop() -> Result<(), String> { Ok(()) }
}

pub use imp::{install_command, uninstall_command};

/// Что сейчас с перехватом.
pub fn state_in(dir: &Path) -> State {
    imp::state_in(dir)
}

/// Включить. На macOS — создать файл-признак, на Windows — запустить задачу.
pub fn start_in(dir: &Path) -> Result<(), String> {
    imp::start_in(dir)
}

/// Выключить.
pub fn stop_in(dir: &Path) -> Result<(), String> {
    imp::stop_in(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⛔ В путях бывают пробелы — и в «Program Files», и в имени
    /// пользователя. Потеряв часть пути, служба молча не запустится.
    #[test]
    fn путь_с_пробелами_не_теряется() {
        let xml = task_xml(
            Path::new("C:\\Program Files\\Nexus Proxy\\app.exe"),
            Path::new("C:\\Users\\Иван Петров\\перехват"),
        );
        assert!(xml.contains("Program Files\\Nexus Proxy"), "{xml}");
        assert!(xml.contains("Иван Петров"), "{xml}");
    }

    /// ⛔ Задача обязана работать ОТ СИСТЕМЫ. От имени человека без прав
    /// администратора движок падает на создании интерфейса — «configure
    /// tun interface: Access is denied», — и перехват не включается
    /// вовсе, а выглядит это как «программа сломалась». «Наивысшие
    /// доступные» права обычной учётной записи — это обычные права.
    #[test]
    fn задача_работает_от_системы() {
        let xml = task_xml(Path::new("C:\\app.exe"), Path::new("C:\\tunnel"));
        assert!(xml.contains("<UserId>S-1-5-18</UserId>"), "задача не от системы: {xml}");
        assert!(xml.contains("<LogonType>ServiceAccount</LogonType>"), "{xml}");
        assert!(xml.contains("<RunLevel>HighestAvailable</RunLevel>"), "{xml}");
    }

    /// ⛔ Служба переживает перезагрузку: иначе человек включил перехват,
    /// выключил компьютер — и наутро ничего не работает.
    #[test]
    fn служба_поднимается_после_перезагрузки() {
        let xml = task_xml(Path::new("C:\\app.exe"), Path::new("C:\\tunnel"));
        assert!(xml.contains("<BootTrigger>"), "не поднимется после перезагрузки: {xml}");
        assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"),
                "планировщик снимет службу через трое суток: {xml}");
    }

    /// ⛔ Служба работает всегда, а перехват включается признаком.
    /// Запускать и останавливать саму службу человек не может: она
    /// принадлежит системе, и прав на неё у него нет.
    #[test]
    fn перехват_включается_признаком_а_не_запуском_службы() {
        let dir = Path::new("/папка/перехват");
        assert_eq!(flag_path(dir), dir.join("enabled"));
        let xml = task_xml(Path::new("/app"), dir);
        assert!(xml.contains("--run-tunnel"), "служба обязана следить за признаком: {xml}");
    }

    /// ⛔ Сам по себе перехват не включается — движок поднимается только
    /// при появлении признака, иначе трафик заворачивался бы без спросу.
    #[cfg(target_os = "macos")]
    #[test]
    fn наблюдатель_смотрит_на_признак() {
        let w = imp::watcher(Path::new("/папка"));
        assert!(w.contains("[ -f \"$FLAG\" ]"), "наблюдатель не смотрит на признак: {w}");
    }

    /// Угловые скобки и амперсанд в пути не должны ломать описание задачи.
    #[test]
    fn опасные_знаки_в_пути_экранируются() {
        let xml = task_xml(Path::new("C:\\a&b"), Path::new("C:\\<t>"));
        assert!(xml.contains("C:\\a&amp;b"), "{xml}");
        assert!(xml.contains("C:\\&lt;t&gt;"), "{xml}");
    }
}

/// Поставить службу — один запрос прав у системы.
///
/// ⛔ Это единственное место, где программа просит администратора.
/// Дальше перехват включается и выключается без вопросов: службе при
/// установке выдаётся право на запуск и остановку обычным пользователем.
/// Файл-признак: есть — перехват включён. ⛔ Через него, а не через
/// запуск службы: служба принадлежит системе, и человек без прав
/// администратора запустить её не может, а файл в своей папке — может.
pub fn flag_path(dir: &Path) -> std::path::PathBuf {
    dir.join("enabled")
}

pub fn xml_path(dir: &Path) -> std::path::PathBuf {
    dir.join("task.xml")
}

/// ⛔ Задача работает от СИСТЕМЫ, а не от человека за компьютером.
/// Сетевой интерфейс создаётся только с правами администратора, а в
/// организации у человека их нет: задача от его имени поднимается с
/// обычными правами и движок падает с «configure tun interface:
/// Access is denied». «Наивысшие доступные» права для обычной
/// учётной записи — это обычные права.
const SYSTEM: &str = "S-1-5-18";

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// ⛔ Задача описывается файлом, а не параметром `/tr`. В `/tr` путь
/// приходится брать в кавычки внутри кавычек, и на части систем
/// планировщик разбирает это по-своему и отказывается создавать
/// задачу вовсе. В файле путь и аргументы лежат отдельными полями,
/// и экранировать нечего.
/// ⛔ Задача запускает НАС, а не движок напрямую: сама она окно
/// консоли спрятать не умеет, и у человека висело бы чёрное окно с
/// журналом. Движок поднимаем мы, уже без окна.
pub fn task_xml(exe: &Path, dir: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
<Description>Перехват трафика NexusProxy</Description>
  </RegistrationInfo>
  <Triggers>
<!-- ⛔ Задача поднимается при включении компьютера и работает
     постоянно. Человек без прав администратора запустить её не
     может, поэтому просить его об этом нельзя: включение и
     выключение идут через файл-признак, который пишется обычными
     правами. -->
<BootTrigger>
  <Enabled>true</Enabled>
</BootTrigger>
  </Triggers>
  <Principals>
<Principal id="Author">
  <UserId>{who}</UserId>
  <LogonType>ServiceAccount</LogonType>
  <RunLevel>HighestAvailable</RunLevel>
</Principal>
  </Principals>
  <Settings>
<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
<AllowHardTerminate>true</AllowHardTerminate>
<StartWhenAvailable>false</StartWhenAvailable>
<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
<IdleSettings>
  <StopOnIdleEnd>false</StopOnIdleEnd>
  <RestartOnIdle>false</RestartOnIdle>
</IdleSettings>
<AllowStartOnDemand>true</AllowStartOnDemand>
<Enabled>true</Enabled>
<Hidden>false</Hidden>
<RunOnlyIfIdle>false</RunOnlyIfIdle>
<WakeToRun>false</WakeToRun>
<!-- ⛔ Без ограничения по времени: по умолчанию планировщик снимает
     задачу через трое суток, и перехват отваливается сам собой. -->
<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
<Priority>5</Priority>
  </Settings>
  <Actions Context="Author">
<Exec>
  <Command>{exe}</Command>
  <Arguments>--run-tunnel "{dir}"</Arguments>
</Exec>
  </Actions>
</Task>
"#,
        who = SYSTEM,
        exe = esc(&exe.display().to_string()),
        dir = esc(&dir.display().to_string()),
    )
}

/// Файл задачи должен быть в UTF-16: планировщик отказывается читать
/// его в другой кодировке, а имена папок бывают и кириллицей.
pub fn write_xml(exe: &Path, dir: &Path) -> Result<(), String> {
    let text = task_xml(exe, dir);
    let mut bytes = vec![0xFF, 0xFE];
    for u in text.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    std::fs::write(xml_path(dir), bytes)
        .map_err(|e| format!("не записать описание задачи: {e}"))
}


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
/// ⛔ Подпись — не только команда установки, но и ПОЛНОЕ описание
/// задачи и наблюдателя. Иначе правка внутри них (путь, аргументы,
/// обрезка журнала) не меняет команду, программа считает установленное
/// свежим и продолжает работать по-старому.
fn signature_text(exe: &Path, dir: &Path) -> String {
    let mut s = install_command(exe, dir);
    #[cfg(windows)]
    {
        s.push('\n');
        s.push_str(&task_xml(exe, dir));
    }
    #[cfg(target_os = "macos")]
    {
        s.push('\n');
        s.push_str(&imp::plist(exe, dir));
        s.push('\n');
        s.push_str(&imp::watcher(dir));
    }
    s
}

pub fn needs_reinstall(dir: &Path) -> bool {
    let want = match std::env::current_exe() {
        Ok(me) => signature_text(&me, dir),
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
    // Описание задачи кладём заранее: пишется оно правами обычного
    // пользователя, а повышение нужно только на саму установку.
    #[cfg(windows)]
    write_xml(&me, dir)?;

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

    // ⛔ Спрашиваем систему, появилась ли задача на самом деле. Раньше
    // здесь стояла запись «служба установлена» сразу после запроса прав
    // — и она появлялась в журнале ВСЕГДА, даже когда установка
    // проваливалась. Человек видел «установлена», а затем поток строк
    // «не удается найти указанный файл»: задачи не было, а программа
    // была уверена в обратном.
    if state_in(dir) == State::Absent {
        crate::logfile::line(&crate::logfile::now_stamp(),
            "перехват: задача не создалась — смотрите ответ системы выше");
        return Err("не удалось создать задачу перехвата. Подробности — \
                    в журнале программы, строка «система ответила»".into());
    }

    let _ = std::fs::write(signature_path(dir), signature_text(&me, dir));
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
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows_sys::Win32::Foundation::CloseHandle;

    let wide = |s: &str| -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    };
    // ⛔ Вывод обязательно в файл. Окно скрыто, и всё, что система
    // ответила об отказе, раньше уходило в никуда: в журнале оставалось
    // бодрое «служба установлена», а причина — почему задача не
    // создалась — терялась безвозвратно.
    let log = std::env::temp_dir().join("nexusproxy-elevated.log");
    let _ = std::fs::remove_file(&log);
    let verb = wide("runas");
    let file = wide("cmd.exe");
    // ⛔ Скобки обязательны. Перенаправление в cmd относится только к
    // ТОЙ команде, после которой стоит: без скобок в журнал попадал бы
    // ответ последней команды цепочки, а отказ на создании задачи — то
    // единственное, ради чего журнал и заводился, — терялся бы.
    // Внешние кавычки cmd снимает сам, поэтому внутренние, вокруг путей
    // с пробелами, доходят до команды целыми.
    let args = wide(&format!("/c \"( {cmd} ) > \"{}\" 2>&1\"", log.display()));

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
    let mut code: u32 = 0;
    unsafe {
        WaitForSingleObject(info.hProcess, 60_000);
        GetExitCodeProcess(info.hProcess, &mut code);
        CloseHandle(info.hProcess);
    }

    let said = std::fs::read(&log).map(|b| imp::oem_to_utf8(&b)).unwrap_or_default();
    let _ = std::fs::remove_file(&log);
    crate::logfile::line(&crate::logfile::now_stamp(),
        &format!("перехват: система ответила ({code}): {}",
                 if said.trim().is_empty() { "молча" } else { said.trim() }));

    if code == 0 {
        Ok(())
    } else {
        Err(if said.trim().is_empty() {
            format!("планировщик отказал, код {code}")
        } else {
            said.trim().to_string()
        })
    }
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
