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
          "Сам сервис плюс домены, с которых он тянет оформление и данные",
          &["openai.com", "chatgpt.com", "oaistatic.com", "oaistatsig.com",
            "oaiusercontent.com", "sora.com"]),
        p("Claude и Claude Code",
          "Claude Code не поддерживает SOCKS — ходит только через наш HTTP-вход",
          &["anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com"]),
        p("YouTube",
          "Видео раздаётся с googlevideo.com, имена узлов там меняются каждый сеанс",
          &["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com",
            "googleapis.com", "gstatic.com"]),
        p("Google — вход и поиск",
          "Нужен, если через Google выполняется вход в другие сервисы",
          &["google.com", "googleusercontent.com", "gstatic.com", "googleapis.com"]),
        p("Инструменты разработчика",
          "Установка пакетов и работа с репозиториями",
          &["github.com", "githubusercontent.com", "registry.npmjs.org",
            "pypi.org", "pythonhosted.org", "crates.io"]),
        p("Gemini",
          "Работает в браузере, отдельного приложения нет",
          &["gemini.google.com", "google.com", "googleapis.com", "gstatic.com"]),
        p("Другие ИИ-сервисы",
          "Perplexity, Copilot, Mistral, DeepSeek, Grok",
          &["perplexity.ai", "copilot.microsoft.com", "githubcopilot.com",
            "mistral.ai", "deepseek.com", "x.ai", "grok.com"]),
        p("Курсор и редакторы с ИИ",
          "Cursor, Windsurf, JetBrains AI — им нужен свой обмен с сервером",
          &["cursor.com", "cursor.sh", "codeium.com", "windsurf.com",
            "jetbrains.com", "jetbrains.ai"]),
        p("Docker и реестры образов",
          "Скачивание образов идёт с отдельных доменов",
          &["docker.com", "docker.io", "ghcr.io", "quay.io", "gcr.io", "k8s.io"]),
        p("Телеграм",
          "И веб-версия, и рабочий стол",
          &["telegram.org", "t.me", "telegram.me", "telegra.ph", "tdesktop.com"]),
        p("Документация и справка",
          "Куда чаще всего ходят за ответами",
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
