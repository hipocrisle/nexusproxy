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
  enable_on_start: boolean; default_upstream: string;
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
type DomainStat = {
  domain: string; route: string; via: string;
  conns: number; sent: number; received: number;
};
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

/// Флаг для названия прокси.
///
/// Если в имени уже есть флаг — берём его. Если нет, пробуем узнать страну
/// по слову: подписки называют профили по-разному, а видеть флаг привычно.
const FLAGS: [RegExp, string][] = [
  [/герман|germany|deutsch|\bde\b/i, "🇩🇪"], [/франц|france|\bfr\b/i, "🇫🇷"],
  [/финлянд|finland|suomi|\bfi\b/i, "🇫🇮"], [/сша|usa|united states|\bus\b/i, "🇺🇸"],
  [/литв|lithuania|\blt\b/i, "🇱🇹"], [/нидерл|netherl|holland|\bnl\b/i, "🇳🇱"],
  [/швец|sweden|\bse\b/i, "🇸🇪"], [/швейцар|switzerl|\bch\b/i, "🇨🇭"],
  [/великобрит|united kingdom|england|\buk\b|\bgb\b/i, "🇬🇧"],
  [/польш|poland|\bpl\b/i, "🇵🇱"], [/турц|turkey|türkiye|\btr\b/i, "🇹🇷"],
  [/япон|japan|\bjp\b/i, "🇯🇵"], [/сингапур|singapore|\bsg\b/i, "🇸🇬"],
  [/росси|russia|\bru\b/i, "🇷🇺"], [/казахст|kazakh|\bkz\b/i, "🇰🇿"],
  [/армен|armenia|\bam\b/i, "🇦🇲"], [/груз|georgia|\bge\b/i, "🇬🇪"],
  [/кипр|cyprus|\bcy\b/i, "🇨🇾"], [/австр(ия|ии)|austria|\bat\b/i, "🇦🇹"],
  [/испан|spain|\bes\b/i, "🇪🇸"], [/итал|italy|\bit\b/i, "🇮🇹"],
  [/канад|canada|\bca\b/i, "🇨🇦"], [/латв|latvia|\blv\b/i, "🇱🇻"],
  [/эстон|estonia|\bee\b/i, "🇪🇪"], [/чех|czech|\bcz\b/i, "🇨🇿"],
  [/украин|ukraine|\bua\b/i, "🇺🇦"], [/бела?рус|belarus|\bby\b/i, "🇧🇾"],
];

export function flagOf(name: string): string {
  // готовый флаг в имени — пара символов из диапазона региональных букв
  const has = name.match(/[\u{1F1E6}-\u{1F1FF}]{2}/u);
  if (has) return has[0];
  for (const [re, flag] of FLAGS) if (re.test(name)) return flag;
  return "";
}

/// Имя без флага — чтобы не показывать его дважды.
function nameOnly(name: string): string {
  return name.replace(/[\u{1F1E6}-\u{1F1FF}]{2}\s*/u, "").trim() || name;
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
  const [version, setVersion] = useState("");
  useEffect(() => {
    invoke<{ version: string }>("install_info").then((i) => setVersion(i.version)).catch(() => {});
  }, []);
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
    // ⛔ В try: сбой здесь не должен ронять всё окно ради одной рамки.
    try {
      getCurrentWindow().setTheme(theme === "system" ? null : theme).catch(() => {});
    } catch { /* окно недоступно — тема страницы всё равно применилась */ }
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
        <span className="ver">{version || ""}</span>
        <span className={"pill" + (st?.system_on ? " on" : "")}>
          <span className="dot" />
          {st?.system_on ? "включён" : "выключен"}
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

      <Alerts st={st} onChange={refresh} />

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

/* ─────────────── Полоса важных сообщений ─────────────── */

type ProxyHealth = { name: string; up: boolean; ms: number; checked_secs_ago: number };
type Override = { from: string; to: string };

/// Всё, о чём человек должен узнать сразу, а не найдя в настройках:
/// новая версия и упавший прокси, через который идут его правила.
function Alerts({ st, onChange }: { st: Status | null; onChange: () => void }) {
  const [newVersion, setNewVersion] = useState("");
  const [updateHidden, setUpdateHidden] = useState(false);
  const [installing, setInstalling] = useState(false);

  const [health, setHealth] = useState<ProxyHealth[]>([]);
  const [inUse, setInUse] = useState<string[]>([]);
  const [overrides, setOverrides] = useState<Override[]>([]);
  const [declined, setDeclined] = useState<Set<string>>(new Set());
  const [pick, setPick] = useState<Record<string, string>>({});

  // Проверка при запуске. Недоступность канала — не ошибка: за периметром
  // это норма, пугать человека при каждом старте нельзя.
  useEffect(() => {
    checkUpdate().then((u) => { if (u) setNewVersion(u.version); }).catch(() => {});
  }, []);

  useEffect(() => {
    const tick = async () => {
      setHealth(await invoke<ProxyHealth[]>("proxies_health").catch(() => []));
      setInUse(await invoke<string[]>("proxies_in_use").catch(() => []));
      setOverrides(await invoke<Override[]>("overrides_list").catch(() => []));
    };
    tick();
    const t = setInterval(tick, 4000);
    return () => clearInterval(t);
  }, []);

  const install = async () => {
    setInstalling(true);
    try {
      const u = await checkUpdate();
      if (u) { await u.downloadAndInstall(); await relaunch(); }
    } catch { setInstalling(false); }
  };

  // упавшие прокси, через которые реально идут правила и подмены ещё нет
  const broken = health.filter(
    (h) => !h.up && inUse.includes(h.name)
      && !overrides.some((o) => o.from === h.name) && !declined.has(h.name)
  );
  const alive = health.filter((h) => h.up).map((h) => h.name);

  const showUpdate = newVersion && !updateHidden;
  if (!showUpdate && broken.length === 0 && overrides.length === 0) return null;

  return (
    <div className="alerts">
      {showUpdate && (
        <div className="alert">
          <span className="grow">Доступна версия <b>{newVersion}</b></span>
          <button className="btn small primary" onClick={install} disabled={installing}>
            {installing ? "Устанавливаю…" : "Обновить"}
          </button>
          <button className="btn small" onClick={() => setUpdateHidden(true)}>Позже</button>
        </div>
      )}

      {broken.map((h) => {
        const options = alive.filter((n) => n !== h.name);
        const chosen = pick[h.name] ?? options[0] ?? "";
        return (
          <div className="alert warn" key={h.name}>
            <span className="grow">
              Прокси <b>{h.name}</b> не отвечает
              {options.length === 0 && " — заменить нечем, других доступных нет"}
            </span>
            {options.length > 1 && (
              <select className="field small-sel" value={chosen}
                onChange={(e) => setPick({ ...pick, [h.name]: e.target.value })}>
                {options.map((n) => <option key={n} value={n}>{n}</option>)}
              </select>
            )}
            {options.length > 0 && (
              <button className="btn small primary" onClick={async () => {
                await invoke("override_set", { from: h.name, to: chosen });
                onChange();
              }}>
                Перевести на {options.length > 1 ? "выбранный" : chosen}
              </button>
            )}
            <button className="btn small"
              onClick={() => setDeclined((s) => new Set(s).add(h.name))}>
              Оставить
            </button>
          </div>
        );
      })}

      {overrides.map((o) => (
        <div className="alert sub-on" key={o.from}>
          <span className="grow">
            Правила <b>{o.from}</b> временно идут через <b>{o.to}</b>.
            Вернётся само, когда {o.from} снова ответит
          </span>
          <button className="btn small" onClick={async () => {
            await invoke("override_clear", { from: o.from });
            onChange();
          }}>
            Вернуть сейчас
          </button>
        </div>
      ))}
      {st && null}
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

  /// Через что идут домены набора. Если по-разному — «смешано»:
  /// один домен может входить в несколько наборов, а идти обязан
  /// одним путём. Показываем как есть, а не делаем вид, что всё ровно.
  const presetVia = (p: Preset): string | null => {
    const mine = p.domains
      .map((d) => plain.find((i) => i.pattern === "domain:" + d))
      .filter(Boolean) as RuleItem[];
    if (mine.length === 0) return null;
    const first = mine[0].via;
    return mine.every((i) => i.via === first) ? first : "\u0000mixed";
  };

  const movePreset = async (p: Preset, via: string) => {
    await invoke("rules_set_via", {
      patterns: p.domains.map((d) => "domain:" + d),
      via,
    });
    load(); onChange();
  };
  const upName = (u: Upstream) => {
    const f = flagOf(u.name);
    return (f ? f + " " : "") + (nameOnly(u.name) || "по умолчанию");
  };
  const togglePreset = async (p: Preset) => {
    if (hasAll(p)) {
      // Наборы делят домены: у Gemini и YouTube общие google-адреса.
      // Убирать общее нельзя — иначе снятие одного набора рушит другой.
      const нужны_другим = new Set(
        presets.filter((o) => o.name !== p.name && hasAll(o)).flatMap((o) => o.domains)
      );
      for (const d of p.domains) {
        if (!нужны_другим.has(d)) {
          await invoke("rule_remove", { pattern: "domain:" + d });
        }
      }
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
            <div key={p.name} className={"preset" + (hasAll(p) ? " done" : "")}>
              <button className="preset-head" onClick={() => togglePreset(p)}
                title={hasAll(p) ? "убрать домены набора" : "добавить домены набора"}>
                <b>{hasAll(p) ? "✓ " : "+ "}{p.name}</b>
                <span>{p.note}</span>
                <span className="doms">{p.domains.join(", ")}</span>
              </button>
              {hasAll(p) && ups.length > 1 && (
                <div className="preset-via">
                  <span>через</span>
                  <select className="field small-sel"
                    value={presetVia(p) === "\u0000mixed" ? "" : (presetVia(p) ?? "")}
                    onChange={(e) => movePreset(p, e.target.value)}>
                    {presetVia(p) === "\u0000mixed" && <option value="">смешано</option>}
                    {ups.map((u, i) => (
                      <option key={u.name || i} value={i === 0 ? "" : u.name}>{upName(u)}</option>
                    ))}
                  </select>
                </div>
              )}
            </div>
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

type Failure = {
  domain: string; count: number; route: string; via: string;
  error: string; secs_ago: number;
};

type SortKey = "host" | "app" | "seconds" | "sent" | "received";
type TotalKey = "domain" | "conns" | "sent" | "received";

function Connections() {
  const [live, setLive] = useState<Conn[]>([]);
  const [totals, setTotals] = useState<DomainStat[]>([]);
  const [fails, setFails] = useState<Failure[]>([]);
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
      setFails(await invoke<Failure[]>("failures_recent").catch(() => []));
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
      {fails.length > 0 && (
        <div className="card">
          <div className="row" style={{ marginBottom: 6 }}>
            <h3 style={{ margin: 0 }}>Не удалось подключиться — {fails.length}</h3>
            <span className="grow" />
            <button className="btn small" onClick={() => { invoke("failures_clear"); setFails([]); }}>
              Очистить
            </button>
          </div>
          <div className="list">
            {fails.map((f) => (
              <div className="item" key={f.domain}>
                <span className="grow">
                  {f.domain}
                  <span className="sub"> · {f.error} · попыток {f.count}</span>
                </span>
                {f.route === "direct" ? (
                  <button className="btn small" title="пустить этот домен через прокси"
                    onClick={async () => {
                      await invoke("rule_add", { text: f.domain });
                      invoke("failures_clear"); setFails([]);
                    }}>
                    Пустить через прокси
                  </button>
                ) : (
                  <span className="tag">шёл через {f.via || "прокси"}</span>
                )}
              </div>
            ))}
          </div>
          <p className="hint" style={{ marginTop: 8, marginBottom: 0 }}>
            Шло напрямую и не открылось — вероятно, ресурс доступен только через прокси.
            Шло через прокси и не открылось — проверьте его доступность в настройках.
          </p>
        </div>
      )}

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
              <span className={"col-v tag " + t.route}>{t.via || routeLabel[t.route]}</span>
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
  const [httpPort, setHttpPort] = useState("18080");
  const [socksPort, setSocksPort] = useState("18081");
  const [auto, setAuto] = useState(false);
  const [saved, setSaved] = useState("");

  useEffect(() => {
    if (!st?.running) return;
    setHttpPort(String(st.http_port)); setSocksPort(String(st.socks_port));
  }, [st?.http_port, st?.socks_port, st?.running]);

  const [autoErr, setAutoErr] = useState("");
  useEffect(() => {
    autoIs().then(setAuto).catch((e) => setAutoErr(String(e)));
  }, []);

  const save = async () => {
    try {
      await invoke("settings_save", {
        s: { http_port: Number(httpPort), socks_port: Number(socksPort) },
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
      <Subscription onChange={onSaved} />

      <Upstreams defaultName={st?.default_upstream ?? ""} onSaved={onSaved} />

      <div className="card">
        <h3>Локальные порты</h3>
        <p className="hint">
          На них программа принимает трафик от приложений: HTTP-порт прописывается
          в системные настройки, SOCKS5 — для приложений, работающих напрямую.
          Менять только при конфликте с другой программой; после изменения
          движок перезапускается.
        </p>
        <div className="grid2">
          <label className="lbl">HTTP-прокси<input className="field" value={httpPort} onChange={(e) => setHttpPort(e.target.value)} /></label>
          <label className="lbl">SOCKS5-прокси<input className="field" value={socksPort} onChange={(e) => setSocksPort(e.target.value)} /></label>
        </div>
        <div className="row" style={{ marginTop: 10 }}>
          <button className="btn" onClick={save}>Применить и перезапустить</button>
          {saved && <span className="meta">{saved}</span>}
        </div>

        <details className="fold" style={{ marginTop: 12 }}>
          <summary>Если приложение умеет работать через прокси само</summary>
          <span className="hint">
            Программы со своими настройками связи — Telegram, Docker, часть
            почтовых клиентов и редакторов — системный прокси не слушают.
            Впишите в их настройках один из этих адресов, и они пойдут через
            нас со всеми правилами.
          </span>
          <div className="list" style={{ marginTop: 6 }}>
            <div className="item">
              <span className="grow">SOCKS5 — <code>127.0.0.1:{st?.socks_port ?? 18081}</code></span>
              <button className="btn small"
                onClick={() => navigator.clipboard.writeText(`127.0.0.1:${st?.socks_port ?? 18081}`)}>
                Копировать
              </button>
            </div>
            <div className="item">
              <span className="grow">HTTP — <code>127.0.0.1:{st?.http_port ?? 18080}</code></span>
              <button className="btn small"
                onClick={() => navigator.clipboard.writeText(`127.0.0.1:${st?.http_port ?? 18080}`)}>
                Копировать
              </button>
            </div>
          </div>
          <span className="hint">
            Логин и пароль не нужны. Если в приложении есть выбор — берите SOCKS5,
            он подходит для любого трафика, а не только для веб-запросов.
          </span>
        </details>
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
          <input type="checkbox" checked={st?.enable_on_start ?? false}
            onChange={(e) => invoke("set_flag", { name: "enable_on_start", value: e.target.checked }).then(onSaved)} />
          Сразу включать при запуске
        </label>
        <p className="hint" style={{ marginTop: 4, marginBottom: 0 }}>
          То же, что нажать «Включить» в шапке: программа прописывается
          в системные настройки прокси, и приложения начинают ходить через неё.
          Без галки после запуска нужно включать вручную.
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


      <Updates />

      <div className="note">
Настройки прокси читаются приложениями при запуске. После включения перезапустите их.
      </div>
    </div>
  );
}


/* ─────────────── Несколько прокси ─────────────── */

function Upstreams({ defaultName, onSaved }: { defaultName: string; onSaved: () => void }) {
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
      <h3>Прокси</h3>
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
                {flagOf(u.name) && <span className="flag">{flagOf(u.name)}</span>}
                {nameOnly(u.name)}
                {u.name === defaultName && <span className="tag" style={{ marginLeft: 6 }}>по умолчанию</span>}
                <span className="sub"> · {u.kind === "http" ? "HTTP" : "SOCKS5"} · {u.address}:{u.port}</span>
              </span>
              <span className="sub">{h ? (h.up ? `${h.ms} мс` : "не отвечает") : "—"}</span>
              {u.name !== defaultName && (
                <button className="btn small" title="правила без явного назначения пойдут через него"
                  onClick={async () => { await invoke("upstream_set_default", { name: u.name }); onSaved(); load(); }}>
                  Сделать основным
                </button>
              )}
              <button className="btn small" onClick={() => startEdit(u)}>Править</button>
              {ups.length > 1 && u.name !== defaultName &&
                <button className="btn small" onClick={() => remove(u.name)}>Убрать</button>}
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


/* ─────────────── Подписка со странами ─────────────── */

type SubState = {
  installed: boolean; running: boolean; url: string;
  has_text: boolean; enabled: boolean; countries: string[]; dir: string;
};

function Subscription({ onChange }: { onChange: () => void }) {
  const [st, setSt] = useState<SubState | null>(null);
  const [source, setSource] = useState("");
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");
  const [open, setOpen] = useState(false);

  const load = useCallback(async () => {
    try { setSt(await invoke<SubState>("sub_state")); } catch { /* движок ещё не поднялся */ }
  }, []);
  useEffect(() => { load(); const t = setInterval(load, 4000); return () => clearInterval(t); }, [load]);

  const run = async (what: string, fn: () => Promise<unknown>) => {
    setBusy(what); setErr("");
    try { await fn(); } catch (e) { setErr(String(e)); }
    setBusy(""); load(); onChange();
  };

  const countries = st?.countries ?? [];

  return (
    <details className="fold" open={open} onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}>
      <summary>
        Подписка со странами
        {countries.length > 0 && ` — ${countries.length} шт.`}
        {st?.running && " · работает"}
      </summary>

      <span className="hint">
        Вставьте ссылку на подписку или её содержимое. Каждая страна станет
        отдельным прокси в списке, и любому правилу можно будет назначить любую.
      </span>

      {!st?.installed && (
        <div className="note" style={{ marginTop: 8 }}>
          <b>Нужен xray</b>
          <span>
            Для подписок требуется отдельная программа — xray. В состав она не
            входит: на рабочих машинах её присутствие ни к чему. Скачивается
            один раз, из официальных выпусков, в папку с настройками.
          </span>
          <div className="row">
            <button className="btn small primary" disabled={busy !== ""}
              onClick={() => run("install", () => invoke("sub_install"))}>
              {busy === "install" ? "Скачиваю…" : "Скачать xray"}
            </button>
          </div>
        </div>
      )}

      <div className="row" style={{ marginTop: 8 }}>
        <input className="field" placeholder="https://… или содержимое подписки"
          value={source} onChange={(e) => setSource(e.target.value)} />
        <button className="btn" disabled={!source.trim() || busy !== ""}
          onClick={() => run("load", async () => {
            await invoke("sub_load", { source });
            setSource("");
            if (st?.installed) await invoke("sub_apply");
          })}>
          {busy === "load" ? "Читаю…" : "Загрузить"}
        </button>
      </div>

      {st?.url && (
        <p className="hint" style={{ marginTop: 6 }}>
          Источник: <code>{st.url}</code>
        </p>
      )}

      {st?.has_text && (
        <div className="row" style={{ marginTop: 8 }}>
          <button className="btn small" disabled={!st.installed || busy !== ""}
            onClick={() => run("apply", () => invoke("sub_apply"))}>
            {busy === "apply" ? "Поднимаю…" : st.running ? "Перезапустить" : "Включить"}
          </button>
          {st.running && (
            <button className="btn small" disabled={busy !== ""}
              onClick={() => run("off", () => invoke("sub_disable"))}>
              Выключить
            </button>
          )}
          <span className="grow" />
          <span className="meta">{st.running ? "страны подняты" : "выключено"}</span>
        </div>
      )}

      {countries.length > 0 && (
        <div className="list" style={{ marginTop: 8 }}>
          {countries.map((c) => (
            <div className="item" key={c}>
              <span className="grow">
                {flagOf(c) && <span className="flag">{flagOf(c)}</span>}
                {nameOnly(c)}
              </span>
            </div>
          ))}
        </div>
      )}

      {err && <div className="note" style={{ marginTop: 8 }}>{err}</div>}
    </details>
  );
}
