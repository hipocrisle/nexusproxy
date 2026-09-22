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
    nexusproxy_lib::run()
}
