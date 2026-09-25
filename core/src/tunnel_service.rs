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

    pub fn install_command(_exe: &Path, dir: &Path) -> String {
        format!("powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {}",
                super::encode_ps(&super::install_script(dir)))
    }

    pub fn uninstall_command() -> String {
        format!("schtasks.exe /end /tn {NAME} & schtasks.exe /delete /tn {NAME} /f")
    }

    /// ⛔ Отказ в доступе — это НЕ «задачи нет». Задача принадлежит
    /// системе, и у человека нет прав даже прочитать её. Раньше мы
    /// принимали отказ за отсутствие: программа писала «служба не
    /// установлена» и «задача не создалась» при работающем перехвате, а
    /// затем пыталась запустить задачу и получала тот же отказ.
    fn denied(e: &str) -> bool {
        let t = e.to_lowercase();
        t.contains("отказано") || t.contains("access is denied") || t.contains("denied")
    }

    /// Есть ли задача вообще. Отказ в доступе означает, что есть.
    fn task_exists() -> bool {
        match schtasks(&["/query", "/tn", NAME, "/fo", "list"]) {
            Ok(_) => true,
            Err(e) => denied(&e),
        }
    }

    /// Работает ли задача сама по себе. При отказе в доступе спросить
    /// планировщик нельзя — смотрим на сам движок.
    fn task_running(dir: &Path) -> bool {
        match schtasks(&["/query", "/tn", NAME, "/fo", "list"]) {
            Ok(t) => t.contains("Running") || t.contains("Выполняется"),
            Err(e) => denied(&e) && crate::tunnel::is_alive(dir),
        }
    }

    pub fn state_in(dir: &Path) -> State {
        if !task_exists() {
            return State::Absent;
        }
        // ⛔ Ни записи в журнал, ни лишних вопросов системе: состояние
        // спрашивает окно раз в две секунды. Запись отсюда давала
        // сорок тысяч строк в сутки и вытесняла из журнала ровно то,
        // ради чего он ведётся, — как ставилась служба и что ответила
        // система. Про «признак стоит, а движка нет» говорит проверка
        // при запуске, и этого достаточно.
        if super::flag_path(dir).exists() && task_running(dir) {
            State::Running
        } else {
            State::Stopped
        }
    }

    /// ⛔ Ставим признак, а не запускаем задачу. Задача принадлежит
    /// системе, и обычный пользователь запустить её не вправе —
    /// планировщик отвечает отказом. Задача крутится сама и смотрит на
    /// этот файл; создать его человек может своими правами.
    pub fn start_in(dir: &Path) -> Result<(), String> {
        crate::logfile::line(&crate::logfile::now_stamp(),
            &format!("перехват: включаю — ставлю признак {}", super::flag_path(dir).display()));
        std::fs::write(super::flag_path(dir), b"1")
            .map_err(|e| format!("не включить перехват: {e}"))?;
        // ⛔ Запускать задачу НЕ пытаемся: она принадлежит системе, и
        // попытка кончается отказом, который человек видит как поломку.
        // Задача крутится с включения компьютера и сама поднимет движок
        // по признаку — на это нужно несколько секунд.
        // ⛔ Ждём недолго. Этот вызов идёт из потока окна, и прежние
        // десять секунд означали, что программа не показывается при
        // запуске, а каждое добавление правила подвешивает окно.
        // Служба поднимет движок сама, признак она уже видит.
        for _ in 0..6 {
            if crate::tunnel::is_alive(dir) {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        if task_exists() {
            // Не ошибка: служба есть, признак стоит, движку нужно время.
            Ok(())
        } else {
            Err("служба перехвата не установлена".into())
        }
    }

    pub fn stop_in(dir: &Path) -> Result<(), String> {
        // ⛔ Отказ не проглатываем: человек нажал «выключить», получил
        // подтверждение, а трафик машины продолжал заворачиваться.
        match std::fs::remove_file(super::flag_path(dir)) {
            Ok(()) => {
                crate::logfile::line(&crate::logfile::now_stamp(),
                    "перехват: выключаю — признак снят");
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                crate::logfile::line(&crate::logfile::now_stamp(),
                    "перехват: выключать нечего — признака и так нет");
                Ok(())
            }
            Err(e) => Err(format!("не выключить перехват: не убрать признак {}: {e}",
                                  super::flag_path(dir).display())),
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
        // ⛔ Одного признака мало: он лежит на месте и когда движок не
        // скачан, упал или демон его не поднял. Окно при этом уверенно
        // показывало «перехват работает», а программа при запуске даже
        // не пыталась ничего исправить.
        if super::flag_path(dir).exists() && crate::tunnel::is_alive(dir) {
            State::Running
        } else {
            State::Stopped
        }
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
        // ⛔ В закрытой папке: этот файл выполняет root.
        super::secure_dir(dir).join("watch.sh")
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
    # ⛔ Если движок падает сразу, без этой паузы он поднимался бы
    # каждую секунду, и свой журнал наблюдателя распухал бы за сутки до
    # сотен мегабайт — а читает его программа целиком, ровно тогда,
    # когда человек полез смотреть, почему не работает.
    if [ -f "$FLAG" ]; then sleep 5; fi
  fi
  # ⛔ Свой журнал тоже обрезаем.
  MYSIZE=$(stat -f %z "$LOG" 2>/dev/null || echo 0)
  if [ "$MYSIZE" -gt 2097152 ]; then
    tail -c 1048576 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
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
        let svc = super::secure_dir(dir);
        let engine = crate::tunnel::downloaded_engine(dir);
        let bin = crate::tunnel::binary_path(dir);
        format!(
            // ⛔ Папка с тем, что выполняет root, принадлежит root. Пока
            // она была пользовательской, наблюдатель можно было просто
            // удалить и положить свой — демон выполнил бы его с правами
            // root после первой же перезагрузки.
            "mkdir -p '{svc}' && \
             cat > '{w}' <<'NEXUSPROXY_WATCH'\n{watch}NEXUSPROXY_WATCH\n\
             if [ -f '{engine}' ]; then cp -f '{engine}' '{bin}'; fi; \
             chown -R root:wheel '{svc}' && chmod 755 '{svc}' && chmod 755 '{w}' && \
             cat > '{p}' <<'NEXUSPROXY_PLIST'\n{plist}NEXUSPROXY_PLIST\n\
             chown root:wheel '{p}' && chmod 644 '{p}' && \
             launchctl bootout system/{NAME} 2>&1; \
             launchctl bootstrap system '{p}' 2>&1 && \
             launchctl print system/{NAME} 2>&1 | head -12",
            svc = svc.display(), engine = engine.display(), bin = bin.display(),
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

    /// ⛔ Установка не должна требовать того, что сама же и создаёт.
    /// Проверка «движок на месте» смотрела в закрытую папку, куда он
    /// попадает ИМЕННО при установке, — и переустановка обрывалась на
    /// первой строке, молча и навсегда.
    #[test]
    fn установка_не_требует_того_что_сама_создаёт() {
        let dir = std::env::temp_dir().join(format!("np-inst-{}", crate::tunnel::random_tag()));
        std::fs::create_dir_all(&dir).unwrap();
        // движок скачан, но в закрытую папку ещё не перенесён
        std::fs::write(crate::tunnel::downloaded_engine(&dir), b"engine").unwrap();
        assert!(!crate::tunnel::binary_path(&dir).is_file(), "в закрытой папке его быть не должно");

        // ⛔ Проверяем ПРЕДУСЛОВИЕ, а не саму установку: та просит
        // права у системы, и на сборочной машине отвечать на этот
        // вопрос некому — проверка висела до снятия по сроку.
        assert!(engine_ready(&dir).is_ok(),
                "установка отказалась бы, хотя движок скачан: {:?}", engine_ready(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ⛔ Всё, что исполняется от имени системы, обязано лежать в папке,
    /// закрытой от записи. Иначе подмена файла даёт выполнение с её
    /// правами после перезагрузки.
    #[test]
    fn исполняемое_системой_лежит_в_закрытой_папке() {
        let dir = Path::new("/папка");
        assert!(runner_path(dir).starts_with(secure_dir(dir)),
                "копия программы вне закрытой папки: {:?}", runner_path(dir));
        assert!(crate::tunnel::binary_path(dir).starts_with(secure_dir(dir)),
                "движок вне закрытой папки");
        // а скачивается движок правами обычного пользователя — рядом с настройками
        assert!(!crate::tunnel::downloaded_engine(dir).starts_with(secure_dir(dir)));
    }

    #[test]
    fn команда_установки_закрывает_права_и_ставит_задачу() {
        let back = install_script(Path::new("C:\\данные"));
        assert!(back.contains("icacls"), "права не закрываются: {back}");
        assert!(back.contains("S-1-5-18"), "задача не от системы: {back}");
        assert!(back.contains("Register-ScheduledTask"), "{back}");
        assert!(back.contains("-AtStartup"), "не поднимется после перезагрузки");
        assert!(back.contains("RestartCount"), "не поднимется после сбоя");
    }

    /// Обратное преобразование — только для проверки.
    #[allow(dead_code)]
    fn decode_ps(b64: &str) -> String {
        const ABC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bits = Vec::new();
        for ch in b64.bytes().filter(|c| *c != b'=') {
            let v = ABC.iter().position(|c| *c == ch).unwrap() as u32;
            bits.push(v);
        }
        let mut raw = Vec::new();
        for c in bits.chunks(4) {
            let mut n = 0u32;
            for (i, v) in c.iter().enumerate() { n |= v << (18 - 6 * i); }
            raw.push((n >> 16) as u8);
            if c.len() > 2 { raw.push((n >> 8) as u8); }
            if c.len() > 3 { raw.push(n as u8); }
        }
        let units: Vec<u16> = raw.chunks(2)
            .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)])).collect();
        String::from_utf16_lossy(&units)
    }


    /// ⛔ В путях бывают пробелы — и в «Program Files», и в имени
    /// пользователя. Потеряв часть пути, служба молча не запустится.
    #[test]
    fn путь_с_пробелами_не_теряется() {
        let dir = Path::new("C:\\Users\\Иван Петров\\Мой перехват");
        let xml = task_xml(Path::new("C:\\Program Files\\NexusProxy\\app.exe"), dir);
        assert!(xml.contains("Иван Петров\\Мой перехват"), "потерян путь: {xml}");
        // Служба запускает копию в папке данных, а не программу из папки
        // установки: занятый файл нельзя заменить при обновлении.
        assert!(xml.contains(&runner_path(dir).display().to_string()),
                "задача должна запускать копию: {xml}");
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
        assert!(!xml.contains("<LogonType>"), "способ входа указывать нельзя: {xml}");
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
        let xml = task_xml(Path::new("C:\\app.exe"), Path::new("C:\\<t>&b"));
        assert!(xml.contains("C:\\&lt;t&gt;&amp;b"), "{xml}");
        assert!(!xml.contains("C:\\<t>&b"), "знаки не экранированы: {xml}");
    }
}

/// Поставить службу — один запрос прав у системы.
///
/// ⛔ Это единственное место, где программа просит администратора.
/// Дальше перехват включается и выключается без вопросов: службе при
/// установке выдаётся право на запуск и остановку обычным пользователем.
/// Папка, закрытая от записи обычным пользователем. В ней лежит всё,
/// что исполняется от имени системы.
///
/// ⛔ Иначе подмена одного файла в папке данных даёт выполнение от
/// системы после перезагрузки — без запроса прав и без следов.
pub fn secure_dir(dir: &Path) -> std::path::PathBuf {
    dir.join("svc")
}

/// Что именно выполняется с правами администратора при установке.
///
/// ⛔ Раньше задача запускала файлы из папки данных пользователя, куда
/// он (и любая программа от его имени) может писать. Подменив один
/// файл, можно было получить выполнение от имени системы после
/// перезагрузки, без единого запроса прав, — то есть обойти ровно ту
/// политику, ради которой человека этих прав и лишили. Поэтому первым
/// делом закрываем папку, и только потом кладём в неё исполняемое.
///
/// ⛔ Команды связаны `;` при снятии прежнего (его может не быть — это
/// не ошибка) и остановом на первой же неудаче дальше: раньше успех
/// определялся по последней команде цепочки, и неудачное копирование
/// оставалось незамеченным — служба навсегда запускала прежнюю
/// программу, а установка считалась удавшейся.
pub fn install_script(dir: &Path) -> String {
    let q = |v: String| format!("'{}'", v.replace('\'', "''"));
    format!(
        "$ErrorActionPreference='Stop'\n\
         $svc={svc}\n\
         $runner={runner}\n\
         $bin={bin}\n\
         $src={src}\n\
         $engine={engine}\n\
         New-Item -ItemType Directory -Force -Path $svc | Out-Null\n\
         icacls $svc /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-11:(OI)(CI)RX' | Out-Null\n\
         Copy-Item -LiteralPath $src -Destination $runner -Force\n\
         if (Test-Path -LiteralPath $engine) {{ Copy-Item -LiteralPath $engine -Destination $bin -Force }}\n\
         $a=New-ScheduledTaskAction -Execute $runner -Argument ('--run-tunnel \"' + {dir} + '\"')\n\
         $p=New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -RunLevel Highest\n\
         $s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)\n\
         $t=New-ScheduledTaskTrigger -AtStartup\n\
         Register-ScheduledTask -TaskName '{NAME}' -Action $a -Principal $p -Settings $s -Trigger $t -Force | Out-Null\n\
         Start-ScheduledTask -TaskName '{NAME}'\n",
        svc = q(secure_dir(dir).display().to_string()),
        runner = q(runner_path(dir).display().to_string()),
        bin = q(crate::tunnel::binary_path(dir).display().to_string()),
        src = q(current_exe_display()),
        engine = q(crate::tunnel::downloaded_engine(dir).display().to_string()),
        dir = q(dir.display().to_string()),
    )
}

/// Команда для оболочки Windows — в её собственной кодировке.
///
/// ⛔ Так команда передаётся ОДНОЙ строкой параметра, без временного
/// файла и без кавычек, которые пришлось бы согласовывать между cmd,
/// оболочкой и планировщиком. Файл со сценарием пришлось бы класть в
/// папку пользователя, а значит — снова открывать путь к подмене.
pub fn encode_ps(script: &str) -> String {
    const ABC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut raw = Vec::with_capacity(script.len() * 2);
    for u in script.encode_utf16() {
        raw.extend_from_slice(&u.to_le_bytes());
    }
    let mut out = String::new();
    for c in raw.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ABC[(n >> 18) as usize & 63] as char);
        out.push(ABC[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { ABC[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { ABC[n as usize & 63] as char } else { '=' });
    }
    out
}

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
pub fn task_xml(_exe: &Path, dir: &Path) -> String {
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
      <!-- ⛔ Способ входа здесь НЕ указывается. «ServiceAccount» — слово
           из обёртки PowerShell, в самом XML такого значения нет, и
           планировщик отвергает файл целиком: «LogonType:ServiceAccount
           — значение в неправильном формате», а служба не ставится
           вовсе. У системной учётной записи способ входа не указывают. -->
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
            exe = esc(&runner_path(dir).display().to_string()),
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
    #[allow(unused_mut)]
    let mut s = install_command(exe, dir);
    s.push('\n');
    s.push_str(&SERVICE_REVISION.to_string());
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
        Err(e) => {
            crate::logfile::line(&crate::logfile::now_stamp(),
                &format!("перехват: не понять, чем поставлена служба: {e}"));
            return false;
        }
    };
    match std::fs::read_to_string(signature_path(dir)) {
        Ok(have) if have.trim() == want.trim() => false,
        Ok(_) => {
            crate::logfile::line(&crate::logfile::now_stamp(),
                "перехват: служба поставлена прежней версией — нужна переустановка");
            true
        }
        Err(e) => {
            crate::logfile::line(&crate::logfile::now_stamp(),
                &format!("перехват: отметки об установке нет ({}): {e}",
                         signature_path(dir).display()));
            true
        }
    }
}

/// Копия программы, которую запускает служба.
///
/// ⛔ Служба обязана запускать КОПИЮ, а не программу из папки установки.
/// Служба работает от имени системы и держит файл открытым, а установщик
/// идёт от имени человека — заменить занятый файл он не может, и
/// обновление падает с ошибкой на ровном месте.
/// Путь к самой программе — для команды копирования.
fn current_exe_display() -> String {
    std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default()
}

/// Что запускает служба на этой системе: на Windows — копию программы,
/// на macOS — сценарий наблюдателя.
fn launched_path(dir: &Path) -> std::path::PathBuf {
    #[cfg(target_os = "macos")]
    { imp::watcher_path(dir) }
    #[cfg(not(target_os = "macos"))]
    { runner_path(dir) }
}

/// ⛔ Имя копии ПОСТОЯННОЕ. Меняющееся означало бы новое описание
/// задачи при каждом обновлении программы, а значит и запрос прав —
/// ровно то, чего быть не должно. Занятый файл перезаписывается уже
/// под повышением, когда служба остановлена.
pub fn runner_path(dir: &Path) -> std::path::PathBuf {
    secure_dir(dir).join(if cfg!(windows) { "runner.exe" } else { "runner" })
}

/// ⛔ Номер повадок службы. Подпись НЕ включает версию программы: иначе
/// каждое обновление требовало бы прав администратора. Права нужны лишь
/// когда меняется сама служба — тогда номер поднимается в коде, и
/// переустановка проходит один раз.
const SERVICE_REVISION: u32 = 6;

/// Есть ли чем поднимать перехват.
///
/// ⛔ Спрашиваем про СКАЧАННЫЙ движок, а не про тот, что в закрытой
/// папке: в закрытую его переносит сама установка. Спрашивая про него
/// перед установкой, мы обрывались на первой же строке — «движок ещё не
/// скачан», — и служба не переустанавливалась НИКОГДА. Именно из-за
/// этого защита прав не доезжала до людей: программа видела, что служба
/// устарела, бралась её ставить и молча выходила.
pub fn engine_ready(dir: &Path) -> Result<(), String> {
    if crate::tunnel::downloaded_engine(dir).is_file()
        || crate::tunnel::binary_path(dir).is_file()
    {
        return Ok(());
    }
    Err(format!("движок перехвата ещё не скачан: нет {}",
                crate::tunnel::downloaded_engine(dir).display()))
}

pub fn install(dir: &Path) -> Result<(), String> {
    engine_ready(dir)?;
    let me = std::env::current_exe()
        .map_err(|e| format!("не найти себя: {e}"))?;
    // Описание задачи кладём заранее: пишется оно правами обычного
    // пользователя, а повышение нужно только на саму установку.
    #[cfg(windows)]
    write_xml(&me, dir)?;

    let cmd = install_command(&me, dir);
    crate::logfile::line(&crate::logfile::now_stamp(), &format!(
        "перехват: ставлю службу\n  \
         программа: {}\n  \
         закрытая папка: {}\n  \
         служба запустит: {}\n  \
         движок скачан: {}\n  \
         команда: {cmd}",
        me.display(),
        secure_dir(dir).display(),
        launched_path(dir).display(),
        if crate::tunnel::downloaded_engine(dir).is_file() { "да" } else { "НЕТ" },
    ));
    // Старую убираем сразу: иначе на Windows останется задача с прежним
    // способом запуска, и человек увидит поведение старой версии.
    // ⛔ Разделитель у каждой оболочки свой. В cmd перевод строки не
    // считается разделителем — нужен амперсанд. А в оболочке macOS
    // амперсанд означает «в фоне»: снятие прежнего демона уходило в фон
    // и могло снести только что записанное описание нового.
    let full = if cfg!(windows) {
        format!("{} & {cmd}", uninstall_command())
    } else {
        format!("{} ; {cmd}", uninstall_command())
    };
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

    // ⛔ Наличия задачи МАЛО: прежняя никуда не делась и маскирует
    // провал. Так и вышло у человека — установка ответила «не удается
    // найти указанный файл», но была засчитана удавшейся, подпись
    // записалась, и программа с тех пор считала службу свежей, ни разу
    // больше не попытавшись её поставить. Проверяем по делу: то, что
    // служба запускает, должно оказаться на своём месте.
    //
    // ⛔ На каждой системе это СВОЙ файл: на Windows задача запускает
    // копию программы, на macOS демон — сценарий наблюдателя. Проверять
    // копию на обеих значило бы объявлять установку на macOS всегда
    // неудавшейся.
    let expected = launched_path(dir);
    if !expected.is_file() {
        crate::logfile::line(&crate::logfile::now_stamp(),
            &format!("перехват: не появилось то, что запускает служба: {}",
                     expected.display()));
        return Err(format!("служба поставлена не полностью: не появился файл {}. \
                            Подробности — в журнале, строка «система ответила»",
                           expected.display()));
    }

    if let Err(e) = std::fs::write(signature_path(dir), signature_text(&me, dir)) {
        // ⛔ Без отметки программа будет ставить службу заново при каждом
        // запуске — и каждый раз спрашивать права.
        crate::logfile::line(&crate::logfile::now_stamp(),
            &format!("перехват: не записать отметку об установке ({}): {e}",
                     signature_path(dir).display()));
    }
    crate::logfile::line(&crate::logfile::now_stamp(), &format!(
        "перехват: служба установлена\n  \
         запускает: {}\n  \
         движок в закрытой папке: {}\n  \
         состояние задачи: {:?}",
        launched_path(dir).display(),
        if crate::tunnel::binary_path(dir).is_file() { "да" } else { "НЕТ" },
        state_in(dir),
    ));
    Ok(())
}

/// Убрать службу — тоже с запросом прав.
pub fn uninstall() -> Result<(), String> {
    match run_elevated(&uninstall_command()) {
        Ok(()) => Ok(()),
        // ⛔ Снимать нечего — это не отказ. Человеку показывали ошибку
        // там, где всё уже в нужном состоянии.
        Err(e) if e.to_lowercase().contains("не найден")
            || e.to_lowercase().contains("cannot find")
            || e.to_lowercase().contains("does not exist") => Ok(()),
        Err(e) => Err(e),
    }
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
    // ⛔ Имя непредсказуемое. С постоянным именем во временной папке
    // другой процесс успевает подставить по этому пути ссылку на чужой
    // файл, и перенаправление вывода от имени администратора затирает
    // его содержимое.
    let log = std::env::temp_dir().join(format!("nexusproxy-{}.log", crate::tunnel::random_tag()));
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
    // ⛔ Ждём столько, сколько нужно: установка идёт с проверкой файлов
    // сторожевой программой и на медленном диске занимает минуты. По
    // истечении срока код возврата брался у ЕЩЁ РАБОТАЮЩЕГО процесса и
    // равнялся «выполняется» — установка объявлялась провалившейся, а
    // человек жал ещё раз и получал вторую поверх идущей.
    const WAIT_MS: u32 = 10 * 60 * 1000;
    let mut code: u32 = 0;
    let waited = unsafe { WaitForSingleObject(info.hProcess, WAIT_MS) };
    unsafe {
        if waited == 0 {
            GetExitCodeProcess(info.hProcess, &mut code);
        } else {
            code = u32::MAX; // не дождались — считаем неудачей честно
        }
        CloseHandle(info.hProcess);
    }
    if code == u32::MAX {
        return Err("установка не завершилась за отведённое время".into());
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
