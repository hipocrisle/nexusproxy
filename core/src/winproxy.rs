//! Переключение системного прокси и переменных окружения.
//! Пишем только в ветку текущего пользователя — права администратора
//! не нужны. Прежние значения запоминаем и возвращаем при выходе.

/// Что было до нас — чтобы вернуть как было.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Default, Clone)]
pub struct Saved {
    pub enable: Option<u32>,
    pub server: Option<String>,
    pub over: Option<String>,
    pub env: Vec<(String, Option<String>)>,
}

#[cfg_attr(not(windows), allow(dead_code))]
pub const ENV_VARS: [&str; 4] = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"];

#[cfg(windows)]
mod imp {
    use super::{Saved, ENV_VARS};
    use std::io;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HWND};
    use windows_sys::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_DWORD, REG_SZ,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
    };

    const INET: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const ENVK: &str = "Environment";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn open(path: &str, access: u32) -> io::Result<HKEY> {
        let mut k: HKEY = std::ptr::null_mut();
        let r = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, wide(path).as_ptr(), 0, access, &mut k) };
        if r != ERROR_SUCCESS {
            return Err(io::Error::other(format!("реестр: не открыть {path} (код {r})")));
        }
        Ok(k)
    }

    fn get_str(path: &str, name: &str) -> Option<String> {
        let k = open(path, KEY_READ).ok()?;
        let mut ty = 0u32;
        let mut len = 0u32;
        let n = wide(name);
        unsafe {
            if RegQueryValueExW(k, n.as_ptr(), std::ptr::null(), &mut ty, std::ptr::null_mut(), &mut len)
                != ERROR_SUCCESS
            {
                RegCloseKey(k);
                return None;
            }
            let mut buf = vec![0u8; len as usize];
            let ok = RegQueryValueExW(k, n.as_ptr(), std::ptr::null(), &mut ty, buf.as_mut_ptr(), &mut len)
                == ERROR_SUCCESS;
            RegCloseKey(k);
            if !ok {
                return None;
            }
            let u: Vec<u16> = buf
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0)
                .collect();
            Some(String::from_utf16_lossy(&u))
        }
    }

    fn get_dword(path: &str, name: &str) -> Option<u32> {
        let k = open(path, KEY_READ).ok()?;
        let mut ty = 0u32;
        let mut val = 0u32;
        let mut len = 4u32;
        let n = wide(name);
        unsafe {
            let ok = RegQueryValueExW(
                k, n.as_ptr(), std::ptr::null(), &mut ty,
                &mut val as *mut u32 as *mut u8, &mut len,
            ) == ERROR_SUCCESS;
            RegCloseKey(k);
            if ok { Some(val) } else { None }
        }
    }

    fn set_str(path: &str, name: &str, value: &str) -> io::Result<()> {
        let k = open(path, KEY_WRITE)?;
        let v = wide(value);
        let bytes: Vec<u8> = v.iter().flat_map(|c| c.to_le_bytes()).collect();
        let r = unsafe {
            let r = RegSetValueExW(k, wide(name).as_ptr(), 0, REG_SZ, bytes.as_ptr(), bytes.len() as u32);
            RegCloseKey(k);
            r
        };
        if r != ERROR_SUCCESS {
            return Err(io::Error::other(format!("реестр: не записать {name} (код {r})")));
        }
        Ok(())
    }

    fn set_dword(path: &str, name: &str, value: u32) -> io::Result<()> {
        let k = open(path, KEY_WRITE)?;
        let r = unsafe {
            let r = RegSetValueExW(
                k, wide(name).as_ptr(), 0, REG_DWORD,
                &value as *const u32 as *const u8, 4,
            );
            RegCloseKey(k);
            r
        };
        if r != ERROR_SUCCESS {
            return Err(io::Error::other(format!("реестр: не записать {name} (код {r})")));
        }
        Ok(())
    }

    fn del(path: &str, name: &str) {
        if let Ok(k) = open(path, KEY_WRITE) {
            unsafe {
                RegDeleteValueW(k, wide(name).as_ptr());
                RegCloseKey(k);
            }
        }
    }

    /// Сообщаем системе, что настройки изменились. Без этого часть
    /// приложений продолжит работать по старым до перезапуска.
    fn notify() {
        unsafe {
            InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null(), 0);
            InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
            let env = wide("Environment");
            let mut res: usize = 0;
            SendMessageTimeoutW(
                HWND_BROADCAST as HWND, WM_SETTINGCHANGE, 0,
                env.as_ptr() as isize, SMTO_ABORTIFHUNG, 3000, &mut res,
            );
        }
    }

    pub fn apply(proxy: &str, no_proxy: &str) -> io::Result<Saved> {
        let saved = Saved {
            enable: get_dword(INET, "ProxyEnable"),
            server: get_str(INET, "ProxyServer"),
            over: get_str(INET, "ProxyOverride"),
            env: ENV_VARS.iter().map(|v| (v.to_string(), get_str(ENVK, v))).collect(),
        };
        set_str(INET, "ProxyServer", proxy)?;
        set_str(INET, "ProxyOverride", "<local>")?;
        set_dword(INET, "ProxyEnable", 1)?;
        let url = format!("http://{proxy}");
        for v in ENV_VARS {
            if v == "NO_PROXY" {
                set_str(ENVK, v, no_proxy)?;
            } else {
                set_str(ENVK, v, &url)?;
            }
        }
        notify();
        Ok(saved)
    }

    pub fn restore(s: &Saved) {
        match s.enable {
            Some(v) => { let _ = set_dword(INET, "ProxyEnable", v); }
            None => del(INET, "ProxyEnable"),
        }
        match &s.server {
            Some(v) => { let _ = set_str(INET, "ProxyServer", v); }
            None => del(INET, "ProxyServer"),
        }
        match &s.over {
            Some(v) => { let _ = set_str(INET, "ProxyOverride", v); }
            None => del(INET, "ProxyOverride"),
        }
        for (name, val) in &s.env {
            match val {
                Some(v) => { let _ = set_str(ENVK, name, v); }
                None => del(ENVK, name),
            }
        }
        notify();
    }

    pub fn current() -> String {
        let on = get_dword(INET, "ProxyEnable").unwrap_or(0) == 1;
        let srv = get_str(INET, "ProxyServer").unwrap_or_default();
        if on { format!("включён, {srv}") } else { "выключен".into() }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::Saved;
    use std::io;
    pub fn apply(_proxy: &str, _no_proxy: &str) -> io::Result<Saved> {
        Err(io::Error::other("переключение системного прокси есть только в версии для Windows"))
    }
    pub fn restore(_s: &Saved) {}
    pub fn current() -> String {
        "не поддерживается на этой системе".into()
    }
}

pub use imp::{apply, current, restore};
