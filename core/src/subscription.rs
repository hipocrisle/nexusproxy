//! Разбор подписки в список стран.
//!
//! Поддерживаются два вида, которые встречаются на практике:
//! готовый JSON-массив настроек (его отдают наши подписки) и список
//! ссылок vless://, обычный или в base64.
//!
//! Из каждой записи достаём имя для показа и готовый outbound для xray.

use serde_json::{json, Value};

#[derive(Debug, Clone, serde::Serialize)]
pub struct Profile {
    /// как показывать в списке прокси
    pub name: String,
    /// готовый outbound для xray
    #[serde(skip)]
    pub outbound: Value,
}

/// Разобрать содержимое подписки. Возвращает список стран.
pub fn parse(text: &str) -> Result<Vec<Profile>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("подписка пуста".into());
    }

    // 1. Готовый JSON-массив настроек
    if text.starts_with('[') {
        return from_json_array(text);
    }

    // 2. Настройки sing-box: один объект со списком выходов
    if text.starts_with('{') {
        return from_singbox(text);
    }

    // 3. Ссылки — как есть или закодированные
    let decoded = if text.contains("://") { text.to_string() } else { from_base64(text)? };
    let mut out = Vec::new();
    for line in decoded.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with("vless://") {
            continue;
        }
        match from_vless(line) {
            Ok(p) => out.push(p),
            Err(e) => return Err(format!("строка «{}…»: {e}", &line[..line.len().min(30)])),
        }
    }
    if out.is_empty() {
        return Err("в подписке не нашлось ни одной ссылки vless://".into());
    }
    Ok(out)
}

fn from_json_array(text: &str) -> Result<Vec<Profile>, String> {
    let arr: Vec<Value> = serde_json::from_str(text).map_err(|e| format!("испорченный JSON: {e}"))?;
    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let name = item.get("remarks").and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("профиль {}", i + 1));
        // берём первый исходящий, который куда-то ходит
        let ob = item.get("outbounds").and_then(|v| v.as_array()).and_then(|a| {
            a.iter().find(|o| {
                matches!(o.get("protocol").and_then(|p| p.as_str()),
                         Some("vless") | Some("vmess") | Some("trojan") | Some("shadowsocks"))
            })
        });
        match ob {
            Some(o) => out.push(Profile { name, outbound: o.clone() }),
            None => continue,
        }
    }
    if out.is_empty() {
        return Err("в подписке нет ни одного подходящего профиля".into());
    }
    Ok(out)
}

/// Настройки sing-box: выходы описаны по-своему, приводим к виду xray.
fn from_singbox(text: &str) -> Result<Vec<Profile>, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("испорченный JSON: {e}"))?;
    let outs = v.get("outbounds").and_then(|o| o.as_array())
        .ok_or("это не похоже на настройки sing-box: нет списка outbounds")?;
    let mut res = Vec::new();
    for o in outs {
        if o.get("type").and_then(|t| t.as_str()) != Some("vless") {
            continue;
        }
        let name = o.get("tag").and_then(|t| t.as_str()).unwrap_or("профиль").to_string();
        let host = o.get("server").and_then(|x| x.as_str()).unwrap_or_default();
        let port = o.get("server_port").and_then(|x| x.as_u64()).unwrap_or(443);
        let uuid = o.get("uuid").and_then(|x| x.as_str()).unwrap_or_default();

        let tls = o.get("tls");
        let tls_on = tls.and_then(|t| t.get("enabled")).and_then(|x| x.as_bool()).unwrap_or(false);
        let sni = tls.and_then(|t| t.get("server_name")).and_then(|x| x.as_str())
            .unwrap_or(host).to_string();

        let mut stream = json!({
            "network": "tcp",
            "security": if tls_on { "tls" } else { "none" },
        });
        if tls_on {
            stream["tlsSettings"] = json!({ "serverName": sni, "fingerprint": "chrome" });
        }
        if let Some(tr) = o.get("transport") {
            match tr.get("type").and_then(|x| x.as_str()) {
                Some("ws") => {
                    stream["network"] = json!("ws");
                    stream["wsSettings"] = json!({
                        "path": tr.get("path").and_then(|x| x.as_str()).unwrap_or("/"),
                        "headers": { "Host": sni },
                    });
                }
                Some("grpc") => {
                    stream["network"] = json!("grpc");
                    stream["grpcSettings"] = json!({
                        "serviceName": tr.get("service_name").and_then(|x| x.as_str()).unwrap_or(""),
                    });
                }
                _ => {}
            }
        }
        let mut user = json!({ "id": uuid, "encryption": "none" });
        if let Some(f) = o.get("flow").and_then(|x| x.as_str()) {
            if !f.is_empty() {
                user["flow"] = json!(f);
            }
        }
        res.push(Profile {
            name,
            outbound: json!({
                "protocol": "vless",
                "settings": { "vnext": [{ "address": host, "port": port, "users": [user] }] },
                "streamSettings": stream,
            }),
        });
    }
    if res.is_empty() {
        return Err("в настройках sing-box нет ни одного профиля vless".into());
    }
    Ok(res)
}

fn from_base64(s: &str) -> Result<String, String> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let clean: Vec<u8> = s.bytes().filter(|b| !b" \n\r\t".contains(b)).collect();
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::new();
    for b in clean {
        let b = if b == b'-' { b'+' } else if b == b'_' { b'/' } else { b };
        if b == b'=' {
            break;
        }
        let v = match A.iter().position(|c| *c == b) {
            Some(v) => v as u32,
            None => return Err("подписка не похожа ни на ссылки, ни на base64".into()),
        };
        bits = (bits << 6) | v;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    String::from_utf8(out).map_err(|_| "после раскодирования получился не текст".into())
}

/// vless://uuid@host:port?параметры#имя
fn from_vless(link: &str) -> Result<Profile, String> {
    let rest = &link["vless://".len()..];
    let (main, name) = match rest.split_once('#') {
        Some((m, n)) => (m, percent_decode(n)),
        None => (rest, String::new()),
    };
    let (main, query) = match main.split_once('?') {
        Some((m, q)) => (m, q),
        None => (main, ""),
    };
    let (uuid, hostport) = main.split_once('@').ok_or("нет разделителя @")?;
    let (host, port) = hostport.rsplit_once(':').ok_or("нет порта")?;
    let port: u16 = port.parse().map_err(|_| "порт не число")?;

    let mut p = std::collections::HashMap::new();
    for kv in query.split('&').filter(|s| !s.is_empty()) {
        if let Some((k, v)) = kv.split_once('=') {
            p.insert(k, percent_decode(v));
        }
    }
    let get = |k: &str| p.get(k).cloned().unwrap_or_default();

    let network = if get("type").is_empty() { "tcp".to_string() } else { get("type") };
    let security = if get("security").is_empty() { "none".to_string() } else { get("security") };

    let mut stream = json!({ "network": network, "security": security });
    match security.as_str() {
        "tls" => stream["tlsSettings"] = json!({
            "serverName": if get("sni").is_empty() { host.to_string() } else { get("sni") },
            "fingerprint": if get("fp").is_empty() { "chrome".into() } else { get("fp") },
        }),
        "reality" => stream["realitySettings"] = json!({
            "serverName": get("sni"),
            "fingerprint": if get("fp").is_empty() { "chrome".into() } else { get("fp") },
            "publicKey": get("pbk"),
            "shortId": get("sid"),
        }),
        _ => {}
    }
    match network.as_str() {
        "ws" => stream["wsSettings"] = json!({
            "path": if get("path").is_empty() { "/".into() } else { get("path") },
            "headers": { "Host": if get("host").is_empty() { host.to_string() } else { get("host") } },
        }),
        "grpc" => stream["grpcSettings"] = json!({ "serviceName": get("serviceName") }),
        "xhttp" | "splithttp" => stream["xhttpSettings"] = json!({
            "path": if get("path").is_empty() { "/".into() } else { get("path") },
            "host": if get("host").is_empty() { host.to_string() } else { get("host") },
            "mode": if get("mode").is_empty() { "auto".into() } else { get("mode") },
        }),
        _ => {}
    }

    let mut user = json!({ "id": uuid, "encryption": "none" });
    if !get("flow").is_empty() {
        user["flow"] = json!(get("flow"));
    }

    Ok(Profile {
        name: if name.is_empty() { format!("{host}:{port}") } else { name },
        outbound: json!({
            "protocol": "vless",
            "settings": { "vnext": [{ "address": host, "port": port, "users": [user] }] },
            "streamSettings": stream,
        }),
    })
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_json_array_subscription() {
        // так выглядят наши подписки
        let text = r#"[
          {"remarks":"🇩🇪 Германия-2","outbounds":[
            {"tag":"proxy","protocol":"vless","settings":{"vnext":[
              {"address":"1.2.3.4","port":443,"users":[{"id":"abc"}]}]}},
            {"tag":"direct","protocol":"freedom"}]},
          {"remarks":"🇫🇷 Франция","outbounds":[
            {"protocol":"vless","settings":{"vnext":[
              {"address":"5.6.7.8","port":443,"users":[{"id":"def"}]}]}}]}
        ]"#;
        let v = parse(text).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].name, "🇩🇪 Германия-2");
        // freedom не должен попасть в список стран
        assert_eq!(v[0].outbound["protocol"], "vless");
        assert_eq!(v[1].outbound["settings"]["vnext"][0]["address"], "5.6.7.8");
    }

    #[test]
    fn reads_vless_link_with_reality() {
        let link = "vless://uuid-1@example.com:443?type=tcp&security=reality&sni=www.google.com\
                    &pbk=KEY&sid=ab12&fp=firefox&flow=xtls-rprx-vision#%F0%9F%87%A9%F0%9F%87%AA%20Berlin";
        let v = parse(link).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "🇩🇪 Berlin", "имя берётся из части после #");
        let o = &v[0].outbound;
        assert_eq!(o["settings"]["vnext"][0]["port"], 443);
        assert_eq!(o["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(o["streamSettings"]["realitySettings"]["publicKey"], "KEY");
        assert_eq!(o["streamSettings"]["realitySettings"]["fingerprint"], "firefox");
    }

    #[test]
    fn reads_ws_tls_link() {
        let link = "vless://u2@host.example:8443?type=ws&security=tls&path=%2Fabc&host=cdn.example#Тест";
        let o = &parse(link).unwrap()[0].outbound;
        assert_eq!(o["streamSettings"]["wsSettings"]["path"], "/abc");
        assert_eq!(o["streamSettings"]["wsSettings"]["headers"]["Host"], "cdn.example");
        assert_eq!(o["streamSettings"]["tlsSettings"]["serverName"], "host.example");
    }

    #[test]
    fn reads_base64_list() {
        let plain = "vless://a@h1.example:443?type=tcp#Один\nvless://b@h2.example:443?type=tcp#Два";
        // кодируем так же, как это делают подписки
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut enc = String::new();
        for c in plain.as_bytes().chunks(3) {
            let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            enc.push(A[(n >> 18) as usize & 63] as char);
            enc.push(A[(n >> 12) as usize & 63] as char);
            enc.push(if c.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
            enc.push(if c.len() > 2 { A[n as usize & 63] as char } else { '=' });
        }
        let v = parse(&enc).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].name, "Один");
        assert_eq!(v[1].name, "Два");
    }

    #[test]
    fn reads_singbox_subscription() {
        // так устроена вторая ссылка, которую выдаёт наш бот
        let text = r#"{"log":{},"dns":{},"inbounds":[],"route":{},
          "outbounds":[
            {"type":"vless","tag":"🇩🇪 Германия-2 · Vless","server":"81.177.166.155",
             "server_port":443,"uuid":"u-1",
             "tls":{"enabled":true,"server_name":"chat.example.org"},
             "transport":{"type":"ws","path":"/secret"}},
            {"type":"direct","tag":"direct"},
            {"type":"vless","tag":"🇫🇷 Франция","server":"1.2.3.4","server_port":443,"uuid":"u-2",
             "tls":{"enabled":true,"server_name":"x.example"}}
          ]}"#;
        let v = parse(text).unwrap();
        assert_eq!(v.len(), 2, "direct в список стран попадать не должен");
        assert_eq!(v[0].name, "🇩🇪 Германия-2 · Vless");
        let o = &v[0].outbound;
        assert_eq!(o["streamSettings"]["network"], "ws");
        assert_eq!(o["streamSettings"]["wsSettings"]["path"], "/secret");
        assert_eq!(o["streamSettings"]["wsSettings"]["headers"]["Host"], "chat.example.org");
        assert_eq!(o["settings"]["vnext"][0]["users"][0]["id"], "u-1");
    }

    #[test]
    fn empty_and_garbage_are_reported() {
        assert!(parse("").is_err());
        assert!(parse("не подписка, а просто текст").is_err());
        assert!(parse("[]").is_err(), "пустой массив — тоже ошибка, а не тишина");
        assert!(parse("{\"outbounds\":[]}").is_err(), "пустой sing-box — тоже");
    }

    #[test]
    fn link_without_name_falls_back_to_address() {
        let v = parse("vless://u@srv.example:2053?type=tcp").unwrap();
        assert_eq!(v[0].name, "srv.example:2053");
    }
}
