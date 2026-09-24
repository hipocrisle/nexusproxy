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
        // ⛔ Служба живёт постоянно и сама следит за признаком
        // включения — на обеих системах. Запускать и останавливать её
        // из окна нельзя: она принадлежит системе, а у человека в
        // организации прав на неё нет. Признак же он пишет своими.
        let flag = dir.join("enabled");
        let r = nexusproxy_core::tunnel::watch_flag(&dir, &flag);
        if let Err(e) = r {
            eprintln!("{e}");
        }
        return;
    }
    nexusproxy_lib::run()
}
