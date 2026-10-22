//! Запуск системных программ без мелькающих окон консоли.
//!
//! ⛔ На Windows `Command::new` показывает окно консоли. Для КАЖДОЙ
//! служебной команды это чёрный прямоугольник, выскакивающий поверх
//! всего на долю секунды, — а их при запуске программы несколько.
//! Человек видит мигание непонятных окон и справедливо считает, что
//! программа делает что-то подозрительное.
//!
//! Флаг прятался по месту вызова и в одном месте оказался забыт
//! (`system_resolvers`, powershell за списком серверов имён) — отсюда и
//! мигание при каждом запуске. Чтобы это не повторилось, все служебные
//! команды заводятся ЗДЕСЬ, а проверка ниже следит, что мимо не идёт
//! никто.

use std::process::Command;

/// CREATE_NO_WINDOW — окна консоли не создавать.
#[cfg(windows)]
const БЕЗ_ОКНА: u32 = 0x0800_0000;

/// Служебная команда: на Windows — без окна консоли, на остальных
/// системах обычный запуск.
///
/// ⛔ Не для запуска программ ПОЛЬЗОВАТЕЛЯ: тем окно как раз нужно.
/// Для них есть `launch::start`.
pub fn тихая<S: AsRef<std::ffi::OsStr>>(program: S) -> Command {
    // На других системах флаг не ставится и изменяемость не нужна.
    #[allow(unused_mut)]
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(БЕЗ_ОКНА);
    }
    cmd
}

/// То же, но с дополнительными флагами запуска (своя группа процессов и
/// прочее). Флаг «без окна» добавляется сам.
#[cfg(windows)]
pub fn тихая_с_флагами<S: AsRef<std::ffi::OsStr>>(program: S, флаги: u32) -> Command {
    use std::os::windows::process::CommandExt;
    let mut cmd = Command::new(program);
    cmd.creation_flags(БЕЗ_ОКНА | флаги);
    cmd
}

#[cfg(test)]
mod tests {
    /// ⛔ Ни одна команда только-для-Windows не должна заводиться в обход
    /// `cmd::тихая`: забытый флаг — это мигающее окно консоли у каждого
    /// пользователя, и заметить его на машине сборки невозможно.
    ///
    /// Проверка идёт по исходникам: узнать флаги у готового `Command`
    /// изнутри нельзя — поля закрыты, а запустить Windows-ветку на сборке
    /// под Linux нечем.
    #[test]
    fn команды_windows_не_в_обход_помощника() {
        let корень = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        // Имена программ, которые бывают только на Windows: на других
        // системах их просто нет, и окну взяться неоткуда.
        let только_windows = ["powershell", "schtasks", "cmd.exe", "netsh", "wmic"];
        let mut беда = Vec::new();
        for файл in файлы_исходников(&корень.join("src")) {
            if файл.file_name().map(|n| n == "cmd.rs").unwrap_or(false) {
                continue; // сам помощник
            }
            let Ok(текст) = std::fs::read_to_string(&файл) else { continue };
            for (n, строка) in текст.lines().enumerate() {
                if !строка.contains("Command::new(") {
                    continue;
                }
                if только_windows.iter().any(|p| строка.contains(p)) {
                    беда.push(format!("{}:{}: {}", файл.display(), n + 1, строка.trim()));
                }
            }
        }
        assert!(беда.is_empty(),
                "команда Windows заведена мимо cmd::тихая — будет мигать окно консоли:\n{}",
                беда.join("\n"));
    }

    fn файлы_исходников(корень: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut из = Vec::new();
        let Ok(rd) = std::fs::read_dir(корень) else { return из };
        for e in rd.filter_map(|e| e.ok()) {
            let p = e.path();
            if p.is_dir() {
                из.extend(файлы_исходников(&p));
            } else if p.extension().map(|x| x == "rs").unwrap_or(false) {
                из.push(p);
            }
        }
        из
    }
}
