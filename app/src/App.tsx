import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open as openFile, save as saveFile } from "@tauri-apps/plugin-dialog";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { enable as autoOn, disable as autoOff, isEnabled as autoIs } from "@tauri-apps/plugin-autostart";

type Status = {
  running: boolean; upstream: string; http_port: number; socks_port: number;
  system_on: boolean; discovering: boolean; rules_count: number;
  auto_reconnect: boolean; minimize_to_tray: boolean;
  upstream_up: boolean; upstream_error: string | null;
  config_path: string; log_path: string; error: string | null;
};
type Entry = { id: number; host: string; port: number; route: string };
type Candidate = {
  domain: string; count: number; hosts_count: number;
  examples: string[]; triggered_by: string | null;
};
type Preset = { name: string; note: string; domains: string[] };
type Bulk = { added: string[]; skipped: string[]; invalid: string[] };

const routeLabel: Record<string, string> = { proxy: "через прокси", direct: "напрямую", block: "запрещено" };

type Theme = "system" | "light" | "dark";

export default function App() {
  const [tab, setTab] = useState<"rules" | "discover" | "log" | "settings">("rules");
  const [st, setSt] = useState<Status | null>(null);
  const [theme, setTheme] = useState<Theme>(
    () => (localStorage.getItem("theme") as Theme) || "system"
  );

  useEffect(() => {
    localStorage.setItem("theme", theme);
    const root = document.documentElement;
    if (theme === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", theme);
    // Титульная полоса с кнопками — это системная рамка окна, темой
    // страницы она не управляется. Переключаем её отдельно, иначе в
    // тёмной теме сверху остаётся светлая полоса.
    getCurrentWindow().setTheme(theme === "system" ? null : theme).catch(() => {});
  }, [theme]);

  const refresh = useCallback(async () => {
    try { setSt(await invoke<Status>("status")); } catch { /* окно ещё поднимается */ }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 2000);
    return () => clearInterval(t);
  }, [refresh]);

  const toggle = async () => {
    if (!st) return;
    try { await invoke("system_proxy", { on: !st.system_on }); }
    catch (e) { alert(String(e)); }
    refresh();
  };

  return (
    <div className="app">
      <div className="top">
        <span className="brand">NexusProxy</span>
        <span className={"pill" + (st?.system_on ? " on" : "")}>
          <span className="dot" />
          {st?.system_on ? "трафик идёт через нас" : "выключен"}
        </span>
        {st?.running && !st.upstream_up && (
          <span className="pill down" title={st.upstream_error ?? ""}>
            <span className="dot" />вышестоящий прокси не отвечает
          </span>
        )}
        <span className="grow" />
        <span className="meta">
          {st?.running ? `${st.upstream} · правил ${st.rules_count}` : "движок не запущен"}
        </span>
        <div className="theme">
          {(["system", "light", "dark"] as const).map((t) => (
            <button key={t} className={theme === t ? "sel" : ""} onClick={() => setTheme(t)}
              title={t === "system" ? "как в системе" : t === "light" ? "светлая" : "тёмная"}>
              {t === "system" ? "Авто" : t === "light" ? "Светлая" : "Тёмная"}
            </button>
          ))}
        </div>
        <button className={"switch" + (st?.system_on ? " on" : "")} onClick={toggle} disabled={!st?.running}>
          {st?.system_on ? "Выключить" : "Включить"}
        </button>
      </div>

      <div className="tabs">
        {([["rules", "Правила"], ["discover", "Подбор доменов"], ["log", "Журнал"], ["settings", "Настройки"]] as const)
          .map(([k, label]) => (
            <button key={k} className={"tab" + (tab === k ? " sel" : "")} onClick={() => setTab(k)}>
              {label}{k === "discover" && st?.discovering ? " ●" : ""}
            </button>
          ))}
      </div>

      <div className="body">
        {tab === "rules" && <Rules onChange={refresh} />}
        {tab === "discover" && <Discover active={!!st?.discovering} onChange={refresh} />}
        {tab === "log" && <Log />}
        {tab === "settings" && <Settings st={st} onSaved={refresh} />}
      </div>
    </div>
  );
}

/* ─────────────── Правила ─────────────── */

function Rules({ onChange }: { onChange: () => void }) {
  const [items, setItems] = useState<string[]>([]);
  const [text, setText] = useState("");
  const [result, setResult] = useState<Bulk | null>(null);
  const [probe, setProbe] = useState("");
  const [verdicts, setVerdicts] = useState<{ host: string; route: string }[]>([]);
  const [presets, setPresets] = useState<Preset[]>([]);
  const [filter, setFilter] = useState("");
  const [editing, setEditing] = useState<string | null>(null);
  const [draft, setDraft] = useState("");

  const load = useCallback(async () => {
    try {
      const r = await invoke<{ through_proxy: string[] }>("rules_list");
      setItems(r.through_proxy);
    } catch { /* движок ещё не поднялся */ }
  }, []);
  useEffect(() => { load(); invoke<Preset[]>("presets").then(setPresets).catch(() => {}); }, [load]);

  const addText = async (t: string) => {
    if (!t.trim()) return;
    try { setResult(await invoke<Bulk>("rule_add", { text: t })); load(); onChange(); }
    catch (e) { alert(String(e)); }
  };

  const fromFile = async () => {
    const picked = await openFile({
      multiple: false,
      filters: [{ name: "Список", extensions: ["txt", "list", "csv", "json"] }],
    });
    if (typeof picked !== "string") return;
    try { setResult(await invoke<Bulk>("rule_add_from_file", { path: picked })); load(); onChange(); }
    catch (e) { alert(String(e)); }
  };

  const remove = async (p: string) => { await invoke("rule_remove", { pattern: p }); load(); onChange(); };

  const saveEdit = async (old: string) => {
    if (draft.trim() && draft !== old) {
      try { await invoke<Bulk>("rule_edit", { old, new: draft }); } catch (e) { alert(String(e)); }
    }
    setEditing(null); load(); onChange();
  };

  const doCheck = async () => {
    const hosts = probe.split(/[\s,]+/).filter(Boolean);
    if (!hosts.length) return;
    setVerdicts(await invoke("check", { hosts }));
  };

  const plain = items.filter((i) => !i.startsWith("_"));
  const shown = plain.filter((i) => !filter || i.toLowerCase().includes(filter.toLowerCase()));
  const copyAll = () => navigator.clipboard.writeText(shown.join("\n"));
  const hasAll = (p: Preset) => p.domains.every((d) => plain.some((i) => i === "domain:" + d));

  return (
    <div className="panel split">
      <div className="card wide">
        <h3>Готовые наборы</h3>
        <p className="hint">
          Добавляют сразу все домены сервиса. Подбирать их по одному долго, а для
          ходовых список известен заранее — например, ютубу нужен ещё
          <code>googlevideo.com</code>, откуда раздаётся само видео.
        </p>
        <div className="presets">
          {presets.map((p) => (
            <button key={p.name} className={"preset" + (hasAll(p) ? " done" : "")}
              onClick={() => addText(p.domains.join("\n"))}
              title={p.domains.join(", ")}>
              <b>{hasAll(p) ? "✓ " : "+ "}{p.name}</b>
              <span>{p.note}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="card">
        <h3>Добавить своё</h3>
        <p className="hint">
          Списком: домены, адреса и диапазоны вперемешку, по строке или через запятую.
          Ссылки можно вставлять целиком — останется имя узла.
        </p>
        <textarea className="field" value={text} placeholder={"openai.com\n10.0.0.0/8\n192.168.1.10"}
          onChange={(e) => setText(e.target.value)} />
        <div className="row" style={{ marginTop: 8 }}>
          <button className="btn primary" onClick={() => { addText(text); setText(""); }} disabled={!text.trim()}>
            Добавить
          </button>
          <button className="btn" onClick={fromFile}>Загрузить из файла</button>
        </div>
        {result && (
          <p className="hint" style={{ marginTop: 8, marginBottom: 0 }}>
            принято {result.added.length}
            {result.skipped.length ? `, уже было ${result.skipped.length}` : ""}
            {result.invalid.length ? `, не разобрано ${result.invalid.length}` : ""}
          </p>
        )}
        {result?.invalid.length ? (
          <div className="note" style={{ marginTop: 8 }}>Не разобрано: {result.invalid.join("; ")}</div>
        ) : null}
      </div>

      <div className="card">
        <h3>Проверить, каким путём пойдёт</h3>
        <p className="hint">Отвечает по текущим правилам, ничего не открывая.</p>
        <div className="row">
          <input className="field" value={probe} placeholder="api.openai.com"
            onChange={(e) => setProbe(e.target.value)} onKeyDown={(e) => e.key === "Enter" && doCheck()} />
          <button className="btn" onClick={doCheck}>Проверить</button>
        </div>
        {verdicts.length > 0 && (
          <div className="list" style={{ marginTop: 10 }}>
            {verdicts.map((v) => (
              <div className="item" key={v.host}>
                <span className="grow">{v.host}</span>
                <span className={"tag " + v.route}>{routeLabel[v.route]}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card wide">
        <div className="row" style={{ marginBottom: 8 }}>
          <h3 style={{ margin: 0 }}>В списке — {plain.length}</h3>
          <span className="grow" />
          <input className="field" style={{ maxWidth: 220 }} placeholder="поиск"
            value={filter} onChange={(e) => setFilter(e.target.value)} />
          <button className="btn small" onClick={copyAll} disabled={!shown.length}>Копировать</button>
          <button className="btn small" disabled={!plain.length} onClick={async () => {
            const p = await saveFile({ defaultPath: "nexusproxy-rules.txt",
              filters: [{ name: "Список", extensions: ["txt"] }] });
            if (typeof p !== "string") return;
            try {
              const n = await invoke<number>("rules_export", { path: p });
              alert(`Выгружено правил: ${n}`);
            } catch (e) { alert(String(e)); }
          }}>Выгрузить в файл</button>
        </div>
        <div className="list">
          {plain.length === 0 && <div className="empty">Пока пусто. Весь трафик идёт напрямую.</div>}
          {shown.map((p) => (
            <div className="item" key={p}>
              {editing === p ? (
                <>
                  <input className="edit" value={draft} autoFocus
                    onChange={(e) => setDraft(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") saveEdit(p);
                      if (e.key === "Escape") setEditing(null);
                    }} />
                  <button className="btn small" onClick={() => saveEdit(p)}>Сохранить</button>
                  <button className="btn small" onClick={() => setEditing(null)}>Отмена</button>
                </>
              ) : (
                <>
                  <span className="grow">{p}</span>
                  <button className="btn small" onClick={() => { setEditing(p); setDraft(p); }}>Править</button>
                  <button className="btn small" onClick={() => remove(p)}>Убрать</button>
                </>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ─────────────── Подбор доменов ─────────────── */

function Discover({ active, onChange }: { active: boolean; onChange: () => void }) {
  const [live, setLive] = useState<Candidate[]>([]);
  const [added, setAdded] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (!active) return;
    const t = setInterval(async () => setLive(await invoke<Candidate[]>("discovery_live")), 1200);
    return () => clearInterval(t);
  }, [active]);

  const start = async () => { setAdded(new Set()); setLive([]); await invoke("discovery_start"); onChange(); };
  const stop = async () => { await invoke("discovery_stop"); onChange(); };

  const addOne = async (domain: string) => {
    await invoke<Bulk>("rule_add", { text: domain });
    setAdded((s) => new Set(s).add(domain));
    onChange();
  };
  const rest = live.filter((c) => !added.has(c.domain));
  const addAll = async () => {
    if (!rest.length) return;
    await invoke<Bulk>("rule_add", { text: rest.map((c) => c.domain).join("\n") });
    setAdded((s) => { const n = new Set(s); rest.forEach((c) => n.add(c.domain)); return n; });
    onChange();
  };
  const copyList = () => navigator.clipboard.writeText(live.map((c) => c.domain).join("\n"));

  return (
    <div className="panel">
      <div className="card">
        <h3>Подбор сопутствующих доменов</h3>
        <p className="hint">
          Нажми «Начать», открой нужный сервис и попользуйся им. Ниже появятся домены,
          которые пошли мимо прокси сразу после обращений через него.
        </p>
        <p className="hint">
          Предлагается <b>домен целиком</b>, а не отдельные имена узлов: у видео на
          ютубе имена вида <code>rr3---sn-4g5edndz.googlevideo.com</code> меняются
          каждый сеанс, и добавлять их поштучно бесполезно. Рядом с каждым доменом
          показано, сколько разных имён за ним стояло.
        </p>
        <p className="hint">
          Всё, что программа видела до начала подбора, в список не попадает — так
          отсеиваются мониторинг, реклама и прочий постоянный фон.
        </p>
        <div className="row">
          {!active
            ? <button className="btn primary" onClick={start}>Начать подбор</button>
            : <button className="btn" onClick={stop}>Закончить</button>}
          {active && <span className="meta">идёт запись — открой нужный сервис</span>}
          <span className="grow" />
          {active && live.length > 0 && (
            <>
              <button className="btn small" onClick={copyList}>Копировать</button>
              <button className="btn" onClick={addAll} disabled={!rest.length}>
                Добавить все ({rest.length})
              </button>
            </>
          )}
        </div>
      </div>

      {active && (
        <div className="card">
          <h3>Найдено доменов — {live.length}</h3>
          <div className="list">
            {live.length === 0 && <div className="empty">Пока ничего нового. Открой сервис и попользуйся им.</div>}
            {live.map((c) => (
              <div className="item" key={c.domain}>
                <span className="grow">
                  {c.domain}
                  {c.hosts_count > 1 && (
                    <span className="sub"> · {c.hosts_count} имён, напр. {c.examples[0]}</span>
                  )}
                </span>
                {c.triggered_by && <span className="tag">следом за {c.triggered_by}</span>}
                <span className="tag">×{c.count}</span>
                {added.has(c.domain)
                  ? <span className="tag proxy">добавлен</span>
                  : <button className="btn small" onClick={() => addOne(c.domain)}>Добавить</button>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ─────────────── Журнал ─────────────── */

function Log() {
  const [lines, setLines] = useState<Entry[]>([]);
  const [filter, setFilter] = useState("");
  const [onlyProxy, setOnlyProxy] = useState(false);
  const last = useRef(0);

  useEffect(() => {
    const tick = async () => {
      const fresh = await invoke<Entry[]>("journal_since", { after: last.current });
      if (fresh.length) {
        last.current = fresh[fresh.length - 1].id;
        setLines((p) => [...fresh.reverse(), ...p].slice(0, 800));
      }
    };
    tick();
    const t = setInterval(tick, 900);
    return () => clearInterval(t);
  }, []);

  const shown = lines.filter(
    (l) => (!onlyProxy || l.route === "proxy") && (!filter || l.host.includes(filter.toLowerCase()))
  );

  return (
    <div className="panel">
      <div className="card">
        <div className="row">
          <input className="field" placeholder="фильтр по имени" value={filter} onChange={(e) => setFilter(e.target.value)} />
          <label className="check">
            <input type="checkbox" checked={onlyProxy} onChange={(e) => setOnlyProxy(e.target.checked)} />
            только через прокси
          </label>
          <button className="btn" onClick={() => navigator.clipboard.writeText(
            shown.map((l) => `${l.host}:${l.port}`).join("\n"))} disabled={!shown.length}>
            Копировать
          </button>
          <button className="btn" onClick={() => { setLines([]); invoke("journal_clear"); }}>Очистить</button>
        </div>
      </div>
      <div className="card">
        <div className="log">
          {shown.length === 0 && <div className="empty">Пока пусто. Открой что-нибудь в браузере.</div>}
          {shown.map((l) => (
            <div className="line" key={l.id}>
              <span className={"tag " + l.route}>{routeLabel[l.route]}</span>
              <span className="who">{l.host}:{l.port}</span>
              {l.route === "direct" && (
                <button className="btn small" title="добавить домен в список «через прокси»"
                  onClick={() => invoke("rule_add", { text: l.host })}>+</button>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ─────────────── Настройки ─────────────── */

function Settings({ st, onSaved }: { st: Status | null; onSaved: () => void }) {
  const [address, setAddress] = useState("");
  const [port, setPort] = useState("1080");
  const [user, setUser] = useState("");
  const [password, setPassword] = useState("");
  const [httpPort, setHttpPort] = useState("18080");
  const [socksPort, setSocksPort] = useState("18081");
  const [auto, setAuto] = useState(false);
  const [saved, setSaved] = useState("");

  useEffect(() => {
    if (!st?.running) return;
    const [a, p] = st.upstream.split(":");
    setAddress(a || ""); setPort(p || "1080");
    setHttpPort(String(st.http_port)); setSocksPort(String(st.socks_port));
  }, [st?.upstream, st?.http_port, st?.socks_port, st?.running]);

  const [autoErr, setAutoErr] = useState("");
  useEffect(() => {
    autoIs().then(setAuto).catch((e) => setAutoErr(String(e)));
  }, []);

  const save = async () => {
    try {
      await invoke("settings_save", {
        s: {
          address, port: Number(port), user, password,
          http_port: Number(httpPort), socks_port: Number(socksPort),
        },
      });
      setSaved("Сохранено, движок перезапущен");
      onSaved();
    } catch (e) { setSaved("Не сохранено: " + String(e)); }
  };

  const toggleAuto = async (on: boolean) => {
    try {
      if (on) await autoOn(); else await autoOff();
      // не верим на слово — перечитываем, как оно на самом деле
      setAuto(await autoIs());
      setAutoErr("");
    } catch (e) {
      setAutoErr(String(e));
      setAuto(await autoIs().catch(() => false));
    }
  };

  return (
    <div className="panel">
      <div className="card">
        <h3>Вышестоящий прокси</h3>
        <p className="hint">Тот SOCKS5, через который должны идти выбранные ресурсы.</p>
        <div className="grid2">
          <label className="lbl">Адрес<input className="field" value={address} onChange={(e) => setAddress(e.target.value)} /></label>
          <label className="lbl">Порт<input className="field" value={port} onChange={(e) => setPort(e.target.value)} /></label>
          <label className="lbl">Логин, если нужен<input className="field" value={user} onChange={(e) => setUser(e.target.value)} /></label>
          <label className="lbl">Пароль<input className="field" type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        </div>
      </div>

      <div className="card">
        <h3>Наши порты</h3>
        <p className="hint">На них слушает сама программа. Менять стоит, только если порт уже занят.</p>
        <div className="grid2">
          <label className="lbl">HTTP-прокси<input className="field" value={httpPort} onChange={(e) => setHttpPort(e.target.value)} /></label>
          <label className="lbl">SOCKS5-прокси<input className="field" value={socksPort} onChange={(e) => setSocksPort(e.target.value)} /></label>
        </div>
      </div>

      <div className="card">
        <h3>Поведение</h3>
        <label className="check">
          <input type="checkbox" checked={auto} onChange={(e) => toggleAuto(e.target.checked)} />
          Запускать вместе с Windows
        </label>
        {autoErr && <div className="note" style={{ marginTop: 6 }}>Автозапуск не включился: {autoErr}</div>}
        <label className="check" style={{ marginTop: 8 }}>
          <input type="checkbox" checked={st?.minimize_to_tray ?? true}
            onChange={(e) => invoke("set_flag", { name: "minimize_to_tray", value: e.target.checked }).then(onSaved)} />
          Сворачивать в трей вместо закрытия
        </label>
        <p className="hint" style={{ marginTop: 4, marginBottom: 0 }}>
          Полностью закрыть — «Выход» в меню значка. Только так возвращаются
          системные настройки: иначе останется прокси, указывающий в никуда.
        </p>
        <label className="check" style={{ marginTop: 12 }}>
          <input type="checkbox" checked={st?.auto_reconnect ?? true}
            onChange={(e) => invoke("set_flag", { name: "auto_reconnect", value: e.target.checked }).then(onSaved)} />
          Переподключаться, если прокси оборвался
        </label>
        <p className="hint" style={{ marginTop: 4, marginBottom: 0 }}>
          Повторяет попытку и следит за доступностью раз в 15 секунд.
        </p>
        <p className="hint" style={{ marginTop: 8 }}>
          Настройки и журнал лежат в одной папке. Журнал пишется сам,
          старый файл сохраняется как <code>nexusproxy.log.1</code>.
        </p>
        <button className="btn" onClick={() => invoke("open_folder")}>Открыть папку с журналом</button>
      </div>

      <div className="row">
        <button className="btn primary" onClick={save}>Сохранить</button>
        {saved && <span className="meta">{saved}</span>}
      </div>
      <div className="note">
        Приложения читают настройки прокси при запуске — после включения их нужно перезапустить.
      </div>
    </div>
  );
}
