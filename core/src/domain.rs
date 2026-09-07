//! Определение «основного» домена.
//!
//! Зачем: у видео на ютубе имена узлов вида `rr3---sn-4g5edndz.googlevideo.com`
//! генерируются на каждый сеанс. Добавлять их поштучно бессмысленно — в
//! следующий раз будут другие. Правило нужно на `googlevideo.com` целиком.

/// Суффиксы, у которых значимая часть — на уровень глубже.
/// Список короткий намеренно: он покрывает то, что реально встречается,
/// а полный реестр публичных суффиксов сюда тащить незачем.
const MULTI: &[&str] = &[
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "com.br", "com.cn", "com.mx", "com.tr", "com.ua", "com.tw", "co.jp", "ne.jp",
    "or.jp", "co.kr", "co.nz", "co.za", "co.in", "com.sg", "com.hk", "com.ar",
    "com.pl", "com.ru", "net.ru", "org.ru", "msk.ru", "spb.ru", "com.by", "com.kz",
];

/// Домен, на который имеет смысл ставить правило.
/// `rr3---sn-x.googlevideo.com` → `googlevideo.com`
/// `api.example.co.uk`          → `example.co.uk`
/// Адрес возвращается как есть — для него правило по домену не применимо.
pub fn registrable(host: &str) -> String {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if h.parse::<std::net::IpAddr>().is_ok() {
        return h;
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels.len() <= 2 {
        return h;
    }
    let last_two = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    let take = if MULTI.contains(&last_two.as_str()) { 3 } else { 2 };
    if labels.len() <= take {
        return h;
    }
    labels[labels.len() - take..].join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_generated_hostnames() {
        // ровно тот случай, из-за которого ютуб открывался наполовину
        assert_eq!(registrable("rr3---sn-4g5edndz.googlevideo.com"), "googlevideo.com");
        assert_eq!(registrable("rr1---sn-4g5ednsy.googlevideo.com"), "googlevideo.com");
        assert_eq!(registrable("i.ytimg.com"), "ytimg.com");
        assert_eq!(registrable("youtubei.googleapis.com"), "googleapis.com");
    }

    #[test]
    fn keeps_two_label_domains() {
        assert_eq!(registrable("openai.com"), "openai.com");
        assert_eq!(registrable("2ip.io"), "2ip.io");
    }

    #[test]
    fn handles_multipart_suffixes() {
        assert_eq!(registrable("api.example.co.uk"), "example.co.uk");
        assert_eq!(registrable("example.co.uk"), "example.co.uk");
        assert_eq!(registrable("shop.example.com.ru"), "example.com.ru");
    }

    #[test]
    fn addresses_stay_as_is() {
        assert_eq!(registrable("10.1.2.3"), "10.1.2.3");
        assert_eq!(registrable("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn case_and_trailing_dot() {
        assert_eq!(registrable("API.OpenAI.COM."), "openai.com");
    }
}
