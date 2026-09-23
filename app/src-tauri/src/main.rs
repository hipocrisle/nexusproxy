#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // ⛔ Сторож запускается тем же файлом с особым доводом. Он ничего не
    // рисует и ни во что не вмешивается: ждёт, пока программа завершится,
    // и возвращает системные настройки, если она не успела сама.
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 4 && args[1] == "--restore-guard" {
        if let Ok(pid) = args[2].parse::<u32>() {
            nexusproxy_core::sysproxy::guard(pid, &args[3]);
        }
        return;
    }
    // Запуск движка перехвата задачей планировщика: окно прячем мы.
    if args.len() >= 3 && args[1] == "--run-tunnel" {
        let dir = std::path::PathBuf::from(&args[2]);
        // На macOS демон живёт постоянно и сам следит за признаком
        // включения: полагаться на launchd в этом нельзя.
        let r = if cfg!(target_os = "macos") {
            let flag = dir.join("enabled");
            nexusproxy_core::tunnel::watch_flag(&dir, &flag)
        } else {
            nexusproxy_core::tunnel::run_foreground(&dir)
        };
        if let Err(e) = r {
            eprintln!("{e}");
        }
        return;
    }
    nexusproxy_lib::run()
}
