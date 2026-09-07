//! Какое приложение открыло соединение.
//! Сопоставляем локальный порт клиента с процессом — та самая колонка,
//! ради которой держат Proxifier.

#[cfg(windows)]
mod imp {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    use windows_sys::Win32::System::ProcessStatus::GetModuleBaseNameW;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// Таблица портов обновляется не чаще, чем раз в секунду:
    /// системный вызов недешёвый, а соединений бывает много.
    static CACHE: Mutex<Option<(Instant, HashMap<u16, u32>)>> = Mutex::new(None);

    fn port_to_pid() -> HashMap<u16, u32> {
        let mut g = CACHE.lock().unwrap();
        if let Some((t, m)) = g.as_ref() {
            if t.elapsed() < Duration::from_secs(1) {
                return m.clone();
            }
        }
        let mut map = HashMap::new();
        unsafe {
            let mut size = 0u32;
            GetExtendedTcpTable(
                std::ptr::null_mut(), &mut size, 0, AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL, 0,
            );
            if size > 0 {
                let mut buf = vec![0u8; size as usize];
                if GetExtendedTcpTable(
                    buf.as_mut_ptr() as *mut _, &mut size, 0, AF_INET as u32,
                    TCP_TABLE_OWNER_PID_ALL, 0,
                ) == 0
                {
                    let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                    let rows = std::slice::from_raw_parts(
                        table.table.as_ptr() as *const MIB_TCPROW_OWNER_PID,
                        table.dwNumEntries as usize,
                    );
                    for r in rows {
                        // порт в таблице лежит в сетевом порядке байт
                        let port = u16::from_be((r.dwLocalPort & 0xFFFF) as u16);
                        map.insert(port, r.dwOwningPid);
                    }
                }
            }
        }
        *g = Some((Instant::now(), map.clone()));
        map
    }

    fn pid_name(pid: u32) -> Option<String> {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return None;
            }
            let mut buf = [0u16; 260];
            let n = GetModuleBaseNameW(h, std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32);
            CloseHandle(h);
            if n == 0 {
                return None;
            }
            Some(String::from_utf16_lossy(&buf[..n as usize]))
        }
    }

    pub fn app_by_port(port: u16) -> String {
        port_to_pid()
            .get(&port)
            .and_then(|pid| pid_name(*pid))
            .unwrap_or_default()
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn app_by_port(_port: u16) -> String {
        String::new()
    }
}

pub use imp::app_by_port;
