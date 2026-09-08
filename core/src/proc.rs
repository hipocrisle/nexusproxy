//! Какое приложение открыло соединение.
//!
//! Возвращаем не только имя файла, но и полный путь с номером процесса:
//! одного имени мало, когда одноимённых программ несколько.
//! Сопоставляем локальный порт клиента с процессом — та самая колонка,
//! ради которой держат Proxifier.

/// Что удалось узнать о программе, открывшей соединение.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct AppInfo {
    pub name: String,
    pub path: String,
    pub pid: u32,
}

#[cfg(windows)]
mod imp {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// Таблица портов обновляется не чаще, чем раз в секунду:
    /// системный вызов недешёвый, а соединений бывает много.
    static CACHE: Mutex<Option<(Instant, HashMap<u16, u32>)>> = Mutex::new(None);

    /// Заполняет таблицу для одного семейства адресов.
    ///
    /// ⛔ Здесь был ручной разбор по смещениям, и он брал не то поле:
    /// у IPv4-записи идентификатор процесса лежит на 20-м байте, а не на
    /// 12-м — там адрес узла. Колонка приложения из-за этого оставалась
    /// пустой. Работаем через объявленные структуры, а не через счёт байтов.
    unsafe fn collect_v4(map: &mut HashMap<u16, u32>) {
        let mut size = 0u32;
        GetExtendedTcpTable(
            std::ptr::null_mut(), &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0,
        );
        if size == 0 {
            return;
        }
        let mut buf = vec![0u8; size as usize];
        if GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut _, &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0,
        ) != 0
        {
            return;
        }
        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(
            table.table.as_ptr(),
            table.dwNumEntries as usize,
        );
        for r in rows {
            // порт в таблице лежит в сетевом порядке байт
            map.insert(u16::from_be((r.dwLocalPort & 0xFFFF) as u16), r.dwOwningPid);
        }
    }

    unsafe fn collect_v6(map: &mut HashMap<u16, u32>) {
        let mut size = 0u32;
        GetExtendedTcpTable(
            std::ptr::null_mut(), &mut size, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0,
        );
        if size == 0 {
            return;
        }
        let mut buf = vec![0u8; size as usize];
        if GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut _, &mut size, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0,
        ) != 0
        {
            return;
        }
        let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(
            table.table.as_ptr(),
            table.dwNumEntries as usize,
        );
        for r in rows {
            map.insert(u16::from_be((r.dwLocalPort & 0xFFFF) as u16), r.dwOwningPid);
        }
    }

    fn port_to_pid(force: bool) -> HashMap<u16, u32> {
        let mut g = CACHE.lock().unwrap();
        if !force {
            if let Some((t, m)) = g.as_ref() {
                if t.elapsed() < Duration::from_secs(1) {
                    return m.clone();
                }
            }
        }
        let mut map = HashMap::new();
        unsafe {
            // клиент может прийти и по IPv4, и по IPv6 — смотрим обе таблицы
            collect_v4(&mut map);
            collect_v6(&mut map);
        }
        *g = Some((Instant::now(), map.clone()));
        map
    }

    /// Полный путь к исполняемому файлу процесса.
    /// Путь нужен, чтобы различать одноимённые программы: у пользователя
    /// четыре разных браузера с одним и тем же именем файла.
    ///
    /// ⛔ Раньше здесь был GetModuleBaseNameW — он требует прав
    /// PROCESS_VM_READ, которых мы не просим, и потому всегда возвращал
    /// пусто: колонка приложений была вечно в прочерках.
    /// QueryFullProcessImageNameW обходится теми правами, что есть.
    fn pid_path(pid: u32) -> Option<String> {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let mut buf = [0u16; 512];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
            CloseHandle(h);
            if ok == 0 || len == 0 {
                return None;
            }
            Some(String::from_utf16_lossy(&buf[..len as usize]))
        }
    }

    pub fn app_by_port(port: u16) -> super::AppInfo {
        // Соединение могло появиться уже после снимка таблицы — тогда
        // с первого раза процесс не находится. Раньше в колонке из-за
        // этого стояли прочерки: пробуем ещё раз со свежей таблицей.
        let mut pid = port_to_pid(false).get(&port).copied();
        if pid.is_none() {
            pid = port_to_pid(true).get(&port).copied();
        }
        match pid {
            Some(pid) => {
                let full = pid_path(pid).unwrap_or_default();
                let name = full.rsplit(['\\', '/']).next().unwrap_or("").to_string();
                super::AppInfo { name, path: full, pid }
            }
            None => super::AppInfo::default(),
        }
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn app_by_port(_port: u16) -> super::AppInfo {
        super::AppInfo::default()
    }
}

pub use imp::app_by_port;
