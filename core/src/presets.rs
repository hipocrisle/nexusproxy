//! Готовые наборы доменов. Подбирать вручную по одному — долгая история,
//! а для ходовых сервисов список известен заранее.

#[derive(serde::Serialize)]
pub struct Preset {
    pub name: String,
    pub note: String,
    pub domains: Vec<String>,
}

fn p(name: &str, note: &str, domains: &[&str]) -> Preset {
    Preset {
        name: name.into(),
        note: note.into(),
        domains: domains.iter().map(|s| s.to_string()).collect(),
    }
}

pub fn all() -> Vec<Preset> {
    vec![
        p("ChatGPT и Codex",
          "Сайт, вход и загрузка страницы",
          &["openai.com", "chatgpt.com", "oaistatic.com", "oaistatsig.com",
            "oaiusercontent.com", "sora.com"]),
        p("Claude и Claude Code",
          "Сайт, приложение и консольный клиент",
          &["anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com"]),
        p("YouTube",
          "Сайт, видео и картинки",
          &["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com",
            "googleapis.com", "gstatic.com"]),
        p("Google — вход и поиск",
          "Вход через Google и поиск",
          &["google.com", "googleusercontent.com", "gstatic.com", "googleapis.com"]),
        p("Инструменты разработчика",
          "GitHub и хранилища пакетов",
          &["github.com", "githubusercontent.com", "registry.npmjs.org",
            "pypi.org", "pythonhosted.org", "crates.io"]),
        p("Gemini",
          "Веб-версия, отдельного приложения нет",
          &["gemini.google.com", "google.com", "googleapis.com", "gstatic.com"]),
        p("Другие ИИ-сервисы",
          "Perplexity, Copilot, Mistral, DeepSeek, Grok",
          &["perplexity.ai", "copilot.microsoft.com", "githubcopilot.com",
            "mistral.ai", "deepseek.com", "x.ai", "grok.com"]),
        p("Курсор и редакторы с ИИ",
          "Cursor, Windsurf, Codeium, JetBrains",
          &["cursor.com", "cursor.sh", "codeium.com", "windsurf.com",
            "jetbrains.com", "jetbrains.ai"]),
        p("Docker и реестры образов",
          "Docker Hub и реестры. Docker Desktop может требовать свои настройки",
          &["docker.com", "docker.io", "ghcr.io", "quay.io", "gcr.io", "k8s.io"]),
        p("Телеграм",
          "Веб-версия. Приложению укажите наш SOCKS5 в его настройках связи",
          &["telegram.org", "t.me", "telegram.me", "telegra.ph", "tdesktop.com"]),
        p("Документация и справка",
          "Stack Overflow, MDN, readthedocs",
          &["stackoverflow.com", "stackexchange.com", "readthedocs.io",
            "mozilla.org", "w3.org", "rust-lang.org", "docs.rs"]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_are_sane() {
        let all = all();
        assert!(all.len() >= 5);
        for pr in &all {
            assert!(!pr.domains.is_empty(), "{} без доменов", pr.name);
            for d in &pr.domains {
                assert!(!d.contains(' ') && d.contains('.'), "{d} не похож на домен");
            }
        }
    }

    #[test]
    fn notes_do_not_promise_desktop_apps_that_ignore_system_proxy() {
        // Приложение Telegram системный прокси не слушает — набор не должен
        // обещать, что оно заработает само.
        let tg = all().into_iter().find(|p| p.name.contains("Телеграм")).unwrap();
        assert!(!tg.note.contains("приложение") || tg.note.contains("укажите"),
                "нельзя обещать работу приложения без его собственной настройки: {}", tg.note);
    }

    #[test]
    fn names_are_unique() {
        let all = all();
        let mut names: Vec<_> = all.iter().map(|p| p.name.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "названия наборов должны быть разными");
    }

    #[test]
    fn youtube_covers_the_video_cdn() {
        // без этого домена ютуб открывается наполовину
        let yt = all().into_iter().find(|p| p.name.contains("YouTube")).unwrap();
        assert!(yt.domains.contains(&"googlevideo.com".to_string()));
    }
}
