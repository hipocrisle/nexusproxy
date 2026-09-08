import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open as openFile, save as saveFile } from "@tauri-apps/plugin-dialog";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { check as checkUpdate } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { enable as autoOn, disable as autoOff, isEnabled as autoIs } from "@tauri-apps/plugin-autostart";

type Status = {
  running: boolean; upstream: string; http_port: number; socks_port: number;
  system_on: boolean; discovering: boolean; rules_count: number;
  auto_reconnect: boolean; minimize_to_tray: boolean;
  upstream_up: boolean; upstream_error: string | null;
  config_path: string; log_path: string; error: string | null;
};
type Entry = { id: number; at: string; host: string; port: number; route: string; via: string };
type Candidate = {
  domain: string; count: number; hosts_count: number;
  examples: string[]; triggered_by: string | null;
};
type Preset = { name: string; note: string; domains: string[] };
type Conn = {
  id: number; host: string; port: number; route: string; via: string;
  app: string; app_path: string; pid: number;
  seconds: number; sent: number; received: number;
};
type DomainStat = { domain: string; route: string; conns: number; sent: number; received: number };
type Upstream = {
  name: string; kind: "socks5" | "http"; address: string; port: number;
  user: string | null; password: string | null;
};

export function human(b: number): string {
  const u = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let v = b, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return i === 0 ? `${b} Б` : `${v.toFixed(1)} ${u[i]}`;
}

/// Состояние, переживающее переключение вкладок.
/// Вкладки размонтируются, и обычный useState сбрасывал бы отборы —
/// галка «только через прокси» слетала при каждом переходе.
function useSticky<T>(key: string, initial: T): [T, (v: T) => void] {
  const [v, setV] = useState<T>(() => {
    try {
      const raw = localStorage.getItem("ui." + key);
      return raw === null ? initial : (JSON.parse(raw) as T);
    } catch { return initial; }
  });
  const set = (next: T) => {
    setV(next);
    try { localStorage.setItem("ui." + key, JSON.stringify(next)); } catch { /* режим без хранилища */ }
  };
  return [v, set];
}

function duration(sec: number): string {
  const m = Math.floor(sec / 60), s = sec % 60;
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}
type Bulk = { added: string[]; skipped: string[]; invalid: string[] };

const routeLabel: Record<string, string> = { proxy: "через прокси", direct: "напрямую", block: "запрещено" };

type Theme = "system" | "light" | "dark";

export default function App() {
  const [tab, setTab] = useSticky<"rules" | "discover" | "conns" | "log" | "settings">("tab", "rules");
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
          {st?.system_on ? "перехват включён" : "выключен"}
        </span>
        {st?.running && !st.upstream_up && (
          <span className="pill down" title={st.upstream_error ?? ""}>
            <span className="dot" />прокси не отвечает
          </span>
        )}
        <span className="grow" />
        {st && !st.running && st.error && (
          <span className="pill down" title={st.error}>
            <span className="dot" />{st.error}
          </span>
        )}
        <span className="meta">
          {st?.running ? `${st.upstream} · правил ${st.rules_count}` : ""}
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
        {([["rules", "Правила"], ["discover", "Подбор доменов"], ["conns", "Соединения"],
           ["log", "Журнал"], ["settings", "Настройки"]] as const)
          .map(([k, label]) => (
            <button key={k} className={"tab" + (tab === k ? " sel" : "")} onClick={() => setTab(k)}>
              {label}{k === "discover" && st?.discovering ? " ●" : ""}
            </button>
          ))}
      </div>

      <div className="body">
        {tab === "rules" && <Rules onChange={refresh} />}
        {tab === "discover" && <Discover active={!!st?.discovering} onChange={refresh} />}
        {tab === "conns" && <Connections />}
        {tab === "log" && <Log />}
        {tab === "settings" && <Settings st={st} onSaved={refresh} />}
      </div>
    </div>
  );
}

/* ─────────────── Правила ─────────────── */

type RuleItem = { pattern: string; via: string };

function Rules({ onChange }: { onChange: () => void }) {
  const [items, setItems] = useState<RuleItem[]>([]);
  const [ups, setUps] = useState<Upstream[]>([]);
  const [text, setText] = useState("");
  const [result, setResult] = useState<Bulk | null>(null);
  const [probe, setProbe] = useState("");
  const [verdicts, setVerdicts] = useState<{ host: string; route: string }[]>([]);
  const [presets, setPresets] = useState<Preset[]>([]);
  const [filter, setFilter] = useSticky("rules.filter", "");
  const [editing, setEditing] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [addVia, setAddVia] = useSticky("rules.addVia", "");

  const load = useCallback(async () => {
    try {
      const r = await invoke<{ items: RuleItem[] }>("rules_list");
      setItems(r.items);
      const u = await invoke<{ upstreams: Upstream[] }>("upstreams_list");
      setUps(u.upstreams);
    } catch { /* движок ещё не поднялся */ }
  }, []);
  useEffect(() => { load(); invoke<Preset[]>("presets").then(setPresets).catch(() => {}); }, [load]);

  const addText = async (t: string) => {
    if (!t.trim()) return;
    try { setResult(await invoke<Bulk>("rule_add", { text: t, via: addVia })); load(); onChange(); }
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

  const plain = items.filter((i) => !i.pattern.startsWith("_"));
  const shown = plain.filter((i) => !filter || i.pattern.toLowerCase().includes(filter.toLowerCase()));
  const copyAll = () => navigator.clipboard.writeText(shown.map((i) => i.pattern).join("\n"));
  const hasAll = (p: Preset) => p.domains.every((d) => plain.some((i) => i.pattern === "domain:" + d));
  const upName = (u: Upstream) => u.name || "основной";
  const togglePreset = async (p: Preset) => {
    if (hasAll(p)) {
      for (const d of p.domains) await invoke("rule_remove", { pattern: "domain:" + d });
    } else {
      await invoke<Bulk>("rule_add", { text: p.domains.join("\n"), via: addVia });
    }
    load(); onChange();
  };

  return (
    <div className="panel split">
      <div className="card wide">
        <h3>Готовые наборы</h3>
        <p className="hint">
Щелчок добавляет домены набора, повторный убирает. Галочка — набор добавлен.
        </p>
        <div className="presets">
          {presets.map((p) => (
            <button key={p.name} className={"preset" + (hasAll(p) ? " done" : "")}
              onClick={() => togglePreset(p)}
              title={hasAll(p) ? "щёлкни, чтобы убрать эти домены" : "щёлкни, чтобы добавить"}>
              <b>{hasAll(p) ? "✓ " : "+ "}{p.name}</b>
              <span>{p.note}</span>
              <span className="doms">{p.domains.join(", ")}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="card">
        <h3>Добавить своё</h3>
        <p className="hint">
Домены, адреса и подсети. Разделители: перевод строки, запятая, пробел.
          Из ссылки берётся только имя узла.
        </p>
        <textarea className="field" value={text} placeholder={"openai.com\n10.0.0.0/8\n192.168.1.10"}
          onChange={(e) => setText(e.target.value)} />
        <div className="row" style={{ marginTop: 8 }}>
          <button className="btn primary" onClick={() => { addText(text); setText(""); }} disabled={!text.trim()}>
            Добавить
          </button>
          <button className="btn" onClick={fromFile}>Загрузить из файла</button>
          {ups.length > 1 && (
            <>
              <span className="grow" />
              <label className="check">через прокси</label>
              <select className="field small-sel" value={addVia}
                onChange={(e) => setAddVia(e.target.value)}>
                {ups.map((u, i) => (
                  <option key={u.name || i} value={i === 0 ? "" : u.name}>{upName(u)}</option>
                ))}
              </select>
            </>
          )}
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
        <p className="hint">Результат по текущим правилам, без обращения к ресурсу.</p>
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
          {ups.length > 1 && <span className="meta">колонка справа — назначенный прокси</span>}
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
          {plain.length === 0 && <div className="empty">Правил нет — весь трафик идёт напрямую.</div>}
          {shown.map((it) => (
            <div className="item" key={it.pattern}>
              {editing === it.pattern ? (
                <>
                  <input className="edit" value={draft} autoFocus
                    onChange={(e) => setDraft(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") saveEdit(it.pattern);
                      if (e.key === "Escape") setEditing(null);
                    }} />
                  <button className="btn small" onClick={() => saveEdit(it.pattern)}>Сохранить</button>
                  <button className="btn small" onClick={() => setEditing(null)}>Отмена</button>
                </>
              ) : (
                <>
                  <span className="grow">{it.pattern}</span>
                  {ups.length > 1 && (
                    <select className="field small-sel" value={it.via}
                      title="через какой прокси пускать"
                      onChange={async (e) => {
                        await invoke("rule_set_via", { pattern: it.pattern, via: e.target.value });
                        load(); onChange();
                      }}>
                      {ups.map((u, i) => (
                        <option key={u.name || i} value={i === 0 ? "" : u.name}>{upName(u)}</option>
                      ))}
                    </select>
                  )}
                  <button className="btn small" onClick={() => { setEditing(it.pattern); setDraft(it.pattern); }}>Править</button>
                  <button className="btn small" onClick={() => remove(it.pattern)}>Убрать</button>
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
          Записывает адреса, ушедшие напрямую в течение 15 секунд после обращения
          через прокси. Адреса, встречавшиеся до начала записи, исключаются.
        </p>
        <p className="hint">
          Результат сводится к домену второго уровня: имена узлов у части сервисов
          генерируются на каждый сеанс. В скобках — сколько имён относится к домену.
        </p>
        <div className="row">
          {!active
            ? <button className="btn primary" onClick={start}>Начать подбор</button>
            : <button className="btn" onClick={stop}>Закончить</button>}
          {active && <span className="meta">идёт запись</span>}
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
            {live.length === 0 && <div className="empty">Новых адресов не зафиксировано.</div>}
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

/* ─────────────── Соединения и трафик ─────────────── */

type SortKey = "host" | "app" | "seconds" | "sent" | "received";
type TotalKey = "domain" | "conns" | "sent" | "received";

function Connections() {
  const [live, setLive] = useState<Conn[]>([]);
  const [totals, setTotals] = useState<DomainStat[]>([]);
  const [filter, setFilter] = useSticky("conn.filter", "");
  const [onlyProxy, setOnlyProxy] = useSticky("conn.onlyProxy", false);
  const [sort, setSort] = useSticky<SortKey>("conn.sort", "received");
  const [asc, setAsc] = useSticky("conn.asc", false);

  const flip = (k: SortKey) => { if (sort === k) setAsc(!asc); else { setSort(k); setAsc(false); } };
  const arrow = (k: SortKey) => (sort === k ? (asc ? " ↑" : " ↓") : "");

  const [tSort, setTSort] = useSticky<TotalKey>("tot.sort", "received");
  const [tAsc, setTAsc] = useSticky("tot.asc", false);
  const tFlip = (k: TotalKey) => { if (tSort === k) setTAsc(!tAsc); else { setTSort(k); setTAsc(false); } };
  const tArrow = (k: TotalKey) => (tSort === k ? (tAsc ? " ↑" : " ↓") : "");

  useEffect(() => {
    const tick = async () => {
      setLive(await invoke<Conn[]>("conns_active").catch(() => []));
      setTotals(await invoke<DomainStat[]>("conns_totals").catch(() => []));
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, []);

  const sum = totals.reduce((a, t) => ({ s: a.s + t.sent, r: a.r + t.received }), { s: 0, r: 0 });
  const viaProxy = totals.filter((t) => t.route === "proxy")
    .reduce((a, t) => a + t.sent + t.received, 0);

  const match = (host: string, app: string) =>
    !filter || (host + " " + app).toLowerCase().includes(filter.toLowerCase());

  const shownLive = live
    .filter((c) => (!onlyProxy || c.route === "proxy") && match(c.host, c.app + " " + c.app_path))
    .sort((a, b) => {
      const d = sort === "host" ? a.host.localeCompare(b.host)
        : sort === "app" ? (a.app || "").localeCompare(b.app || "")
        : (a[sort] as number) - (b[sort] as number);
      return asc ? d : -d;
    });

  const shownTotals = totals
    .filter((t) => (!onlyProxy || t.route === "proxy") && match(t.domain, ""))
    .sort((a, b) => {
      const d = tSort === "domain" ? a.domain.localeCompare(b.domain)
        : (a[tSort] as number) - (b[tSort] as number);
      return tAsc ? d : -d;
    });

  return (
    <div className="panel">
      <div className="card">
        <div className="row">
          <h3 style={{ margin: 0 }}>Открыто сейчас — {live.length}</h3>
          <span className="grow" />
          <span className="meta">
            всего отдано {human(sum.s)} · получено {human(sum.r)} · через прокси {human(viaProxy)}
          </span>
          <button className="btn small" onClick={() => invoke("conns_reset")}>Сбросить счётчики</button>
        </div>
        <div className="row" style={{ marginTop: 8 }}>
          <input className="field" placeholder="поиск по адресу, программе или её пути"
            value={filter} onChange={(e) => setFilter(e.target.value)} />
          <label className="check">
            <input type="checkbox" checked={onlyProxy} onChange={(e) => setOnlyProxy(e.target.checked)} />
            только через прокси
          </label>
        </div>
        <div className="list" style={{ marginTop: 8 }}>
          <div className="item head">
            <span className="grow sortable" onClick={() => flip("host")}>Куда{arrow("host")}</span>
            <span className="col-app sortable" onClick={() => flip("app")}>Приложение{arrow("app")}</span>
            <span className="col-t sortable" onClick={() => flip("seconds")}>Время{arrow("seconds")}</span>
            <span className="col-v">Через что</span>
            <span className="col-b sortable" onClick={() => flip("sent")}>Отдано{arrow("sent")}</span>
            <span className="col-b sortable" onClick={() => flip("received")}>Получено{arrow("received")}</span>
          </div>
          {shownLive.length === 0 && <div className="empty">Ничего не открыто.</div>}
          {shownLive.map((c) => (
            <div className="item" key={c.id}>
              <span className="grow">{c.host}:{c.port}</span>
              <span className="col-app sub"
                title={c.app_path ? `${c.app_path}\nпроцесс ${c.pid}` : "программу определить не удалось"}>
                {c.app || "—"}{c.pid ? <span className="pid"> {c.pid}</span> : null}
              </span>
              <span className="col-t sub">{duration(c.seconds)}</span>
              <span className={"col-v tag " + c.route}>{c.via || routeLabel[c.route]}</span>
              <span className="col-b sub">{human(c.sent)}</span>
              <span className="col-b sub">{human(c.received)}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <h3>Трафик по доменам</h3>
        <p className="hint">Учёт по домену второго уровня, за всё время работы программы.</p>
        <div className="list">
          <div className="item head">
            <span className="grow sortable" onClick={() => tFlip("domain")}>Домен{tArrow("domain")}</span>
            <span className="col-v">Каким путём</span>
            <span className="col-n sortable" onClick={() => tFlip("conns")}>Соединений{tArrow("conns")}</span>
            <span className="col-b sortable" onClick={() => tFlip("sent")}>Отдано{tArrow("sent")}</span>
            <span className="col-b sortable" onClick={() => tFlip("received")}>Получено{tArrow("received")}</span>
          </div>
          {shownTotals.length === 0 && <div className="empty">Пока пусто.</div>}
          {shownTotals.map((t) => (
            <div className="item" key={t.domain}>
              <span className="grow">{t.domain}</span>
              <span className={"col-v tag " + t.route}>{routeLabel[t.route]}</span>
              <span className="col-n sub">{t.conns}</span>
              <span className="col-b sub">{human(t.sent)}</span>
              <span className="col-b sub">{human(t.received)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ─────────────── Журнал ─────────────── */

function Log() {
  const [lines, setLines] = useState<Entry[]>([]);
  const [filter, setFilter] = useSticky("log.filter", "");
  const [onlyProxy, setOnlyProxy] = useSticky("log.onlyProxy", false);
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
          {shown.length === 0 && <div className="empty">Записей нет.</div>}
          {shown.map((l) => (
            <div className="line" key={l.id}>
              <span className="at">{l.at}</span>
              <span className={"tag " + l.route}>{l.via || routeLabel[l.route]}</span>
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
        <p className="hint">Прокси по умолчанию для правил без явного назначения.</p>
        <div className="grid2">
          <label className="lbl">Адрес<input className="field" value={address} onChange={(e) => setAddress(e.target.value)} /></label>
          <label className="lbl">Порт<input className="field" value={port} onChange={(e) => setPort(e.target.value)} /></label>
          <label className="lbl">Логин, если нужен<input className="field" value={user} onChange={(e) => setUser(e.target.value)} /></label>
          <label className="lbl">Пароль<input className="field" type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        </div>
      </div>

      <Upstreams />

      <div className="card">
        <h3>Наши порты</h3>
        <p className="hint">Локальные порты программы. Менять при конфликте портов.</p>
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
Выход — через меню значка. При выходе системные настройки прокси
          возвращаются к прежним.
        </p>
        <label className="check" style={{ marginTop: 12 }}>
          <input type="checkbox" checked={st?.auto_reconnect ?? true}
            onChange={(e) => invoke("set_flag", { name: "auto_reconnect", value: e.target.checked }).then(onSaved)} />
          Переподключаться, если прокси оборвался
        </label>
        <p className="hint" style={{ marginTop: 4, marginBottom: 0 }}>
Повтор при обрыве, проверка доступности каждые 15 секунд.
        </p>
        <p className="hint" style={{ marginTop: 8 }}>
Настройки и журнал в одной папке. Журнал ротируется при 4 МБ,
          предыдущий файл — <code>nexusproxy.log.1</code>.
        </p>
        <button className="btn" onClick={() => invoke("open_folder")}>Открыть папку с журналом</button>
      </div>

      <div className="row">
        <button className="btn primary" onClick={save}>Сохранить</button>
        {saved && <span className="meta">{saved}</span>}
      </div>
      <Updates />

      <div className="note">
Настройки прокси читаются приложениями при запуске. После включения перезапустите их.
      </div>
    </div>
  );
}


/* ─────────────── Несколько прокси ─────────────── */

type ProxyHealth = { name: string; up: boolean; ms: number; checked_secs_ago: number };

function Upstreams() {
  const [ups, setUps] = useState<Upstream[]>([]);
  const [health, setHealth] = useState<ProxyHealth[]>([]);
  const [adding, setAdding] = useState(false);
  /// имя, под которым прокси был до правки; null — добавляем новый
  const [editingName, setEditingName] = useState<string | null>(null);
  const empty: Upstream = { name: "", kind: "socks5", address: "", port: 1080, user: "", password: "" };
  const [draft, setDraft] = useState<Upstream>(empty);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    try {
      const r = await invoke<{ upstreams: Upstream[] }>("upstreams_list");
      setUps(r.upstreams);
    } catch { /* движок ещё не поднялся */ }
  }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const tick = () => invoke<ProxyHealth[]>("proxies_health").then(setHealth).catch(() => {});
    tick();
    const t = setInterval(tick, 5000);
    return () => clearInterval(t);
  }, []);

  const save = async () => {
    if (!draft.address.trim()) { setErr("не указан адрес"); return; }
    if (editingName === null && !draft.name.trim()) { setErr("не указано имя"); return; }
    try {
      await invoke("upstream_save", {
        up: { ...draft, port: Number(draft.port) },
        oldName: editingName,
      });
      setAdding(false); setEditingName(null); setErr(""); setDraft(empty);
      load();
    } catch (e) { setErr(String(e)); }
  };

  const startEdit = (u: Upstream) => {
    setDraft({ ...u, user: u.user ?? "", password: u.password ?? "" });
    setEditingName(u.name);
    setAdding(true);
    setErr("");
  };

  const remove = async (name: string) => {
    try { await invoke("upstream_remove", { name }); setErr(""); load(); }
    catch (e) { setErr(String(e)); }
  };

  return (
    <div className="card">
      <h3>Дополнительные прокси</h3>
      <p className="hint">
Правилу назначается прокси в списке правил. Поддерживаются SOCKS5 и HTTP,
        с логином и паролем.
      </p>
      <div className="list">
        {ups.map((u, i) => {
          const h = health.find((x) => x.name === (u.name || `${u.address}:${u.port}`));
          return (
            <div className="item" key={u.name || "основной-" + i}>
              <span className={"state " + (h ? (h.up ? "up" : "down") : "unknown")}
                title={h ? (h.up ? `отвечает, ${h.ms} мс` : "не отвечает") : "ещё не проверялся"} />
              <span className="grow">
                {u.name || "основной"}
                <span className="sub"> · {u.kind === "http" ? "HTTP" : "SOCKS5"} · {u.address}:{u.port}</span>
              </span>
              <span className="sub">{h ? (h.up ? `${h.ms} мс` : "не отвечает") : "—"}</span>
              <button className="btn small" onClick={() => startEdit(u)}>Править</button>
              {i > 0 && <button className="btn small" onClick={() => remove(u.name)}>Убрать</button>}
            </div>
          );
        })}
      </div>

      {adding ? (
        <div style={{ marginTop: 10 }}>
          <div className="grid2">
            <label className="lbl">Имя<input className="field" value={draft.name}
              placeholder={editingName === "" ? "основной" : "vpn"}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })} /></label>
            <label className="lbl">Протокол
              <select className="field" value={draft.kind}
                onChange={(e) => setDraft({ ...draft, kind: e.target.value as "socks5" | "http" })}>
                <option value="socks5">SOCKS5</option>
                <option value="http">HTTP</option>
              </select>
            </label>
            <label className="lbl">Адрес<input className="field" value={draft.address}
              placeholder="127.0.0.1" onChange={(e) => setDraft({ ...draft, address: e.target.value })} /></label>
            <label className="lbl">Порт<input className="field" value={draft.port}
              onChange={(e) => setDraft({ ...draft, port: Number(e.target.value) || 0 })} /></label>
            <label className="lbl">Логин<input className="field" value={draft.user ?? ""}
              onChange={(e) => setDraft({ ...draft, user: e.target.value })} /></label>
            <label className="lbl">Пароль<input className="field" type="password" value={draft.password ?? ""}
              onChange={(e) => setDraft({ ...draft, password: e.target.value })} /></label>
          </div>
          <div className="row" style={{ marginTop: 8 }}>
            <button className="btn primary" onClick={save}>Сохранить</button>
            <button className="btn" onClick={() => {
              setAdding(false); setEditingName(null); setDraft(empty); setErr("");
            }}>Отмена</button>
            {editingName !== null && editingName !== draft.name && (
              <span className="meta">группы правил переедут на новое имя</span>
            )}
          </div>
        </div>
      ) : (
        <button className="btn" style={{ marginTop: 10 }}
          onClick={() => { setDraft(empty); setEditingName(null); setAdding(true); }}>
          Добавить прокси
        </button>
      )}
      {err && <div className="note" style={{ marginTop: 8 }}>{err}</div>}
    </div>
  );
}

/* ─────────────── Обновления ─────────────── */

/// Куда ходит проверка обновлений: сам список и скачивание файла
/// идут с разных доменов GitHub, поэтому их три.
const UPDATE_HOSTS = [
  "github.com",
  "objects.githubusercontent.com",
  "github-releases.githubusercontent.com",
];

type Install = { version: string; portable: boolean; exe_dir: string; installed_dir: string };

function Updates() {
  const [inst, setInst] = useState<Install | null>(null);
  useEffect(() => { invoke<Install>("install_info").then(setInst).catch(() => {}); }, []);
  const [state, setState] = useState<"idle" | "checking" | "none" | "found" | "installing" | "error">("idle");
  const [version, setVersion] = useState("");
  const [err, setErr] = useState("");
  const [added, setAdded] = useState(false);

  // Тихая проверка при запуске: за корпоративным периметром канал обновлений
  // может быть недоступен, и это НЕ повод показывать ошибку.
  useEffect(() => {
    checkUpdate()
      .then((u) => { if (u) { setVersion(u.version); setState("found"); } })
      .catch(() => {});
  }, []);

  const look = async () => {
    setState("checking"); setErr("");
    try {
      const u = await checkUpdate();
      if (u) { setVersion(u.version); setState("found"); } else setState("none");
    } catch (e) { setErr(String(e)); setState("error"); }
  };

  const install = async () => {
    setState("installing");
    try {
      const u = await checkUpdate();
      if (!u) { setState("none"); return; }
      await u.downloadAndInstall();
      await relaunch();
    } catch (e) { setErr(String(e)); setState("error"); }
  };

  return (
    <div className="card">
      <div className="row" style={{ marginBottom: 8 }}>
        <h3 style={{ margin: 0 }}>Обновления</h3>
        <span className="grow" />
        {inst && <span className="meta">версия {inst.version}</span>}
      </div>
      {inst?.portable && (
        <div className="note" style={{ marginBottom: 10 }}>
          <b>Запущена портативная копия.</b>
          <span>
            Обновление выполняется установщиком: он размещает программу
            в <code>{inst.installed_dir}</code> и добавляет ярлык в меню «Пуск».
            Текущий файл в <code>{inst.exe_dir}</code> остаётся прежней версии —
            после обновления запускайте установленную копию.
          </span>
          <div className="row">
            <button className="btn small" onClick={() => invoke("open_installed")}>
              Открыть папку установки
            </button>
          </div>
        </div>
      )}
      <div className="row">
        <button className="btn" onClick={look} disabled={state === "checking" || state === "installing"}>
          {state === "checking" ? "Проверка…" : "Проверить обновления"}
        </button>
        {state === "found" && (
          <button className="btn primary" onClick={install} disabled={state !== "found"}>
            {inst?.portable ? `Установить ${version}` : `Обновить до ${version}`}
          </button>
        )}
        {state === "none" && <span className="meta">установлена актуальная версия</span>}
        {state === "installing" && <span className="meta">загрузка и установка…</span>}
      </div>
      {state === "error" && (
        <div className="note" style={{ marginTop: 10 }}>
          <b>Не удалось проверить обновления.</b>
          <span>{err}</span>
          <span>
Требуемые адреса:
          </span>
          <div style={{ fontFamily: "ui-monospace, Consolas, monospace", fontSize: "12px", margin: "4px 0" }}>
            {UPDATE_HOSTS.map((h) => <div key={h}>{h}</div>)}
          </div>
          <div className="row">
            {added ? (
              <span className="meta">добавлено, повторите проверку</span>
            ) : (
              <button className="btn small" onClick={async () => {
                await invoke("rule_add", { text: UPDATE_HOSTS.join("\n") });
                setAdded(true);
              }}>Добавить их в правила</button>
            )}
            <button className="btn small" onClick={() => navigator.clipboard.writeText(UPDATE_HOSTS.join("\n"))}>
              Копировать
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
