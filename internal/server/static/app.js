"use strict";
const SEV = ["", "low", "medium", "high", "critical"];
const COLORS = ["", "#3b82f6", "#eab308", "#f97316", "#ef4444"];
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
const clock = (iso) => new Date(iso).toISOString().slice(11, 19);
let current = null;

function row(a, fresh) {
  const r = el("div", "row");
  if (!fresh) r.style.animation = "none";
  r.append(el("span", "pill p" + a.severity, SEV[a.severity]));
  const mid = el("div");
  mid.append(el("div", "title", a.title));
  mid.append(el("div", "meta", `${a.technique} ${a.technique_name} · ${a.host} · ${a.user}`));
  r.append(mid, el("span", "meta", clock(a.time)));
  r.addEventListener("click", () => open(a));
  return r;
}

function open(a) {
  current = a;
  $("d-title").textContent = a.title;
  const meta = $("d-meta");
  meta.replaceChildren();
  for (const [k, v] of [["Severity", SEV[a.severity]], ["Technique", `${a.technique} ${a.technique_name}`], ["Tactic", a.tactic], ["Host", a.host], ["User", a.user], ["Source IP", a.src_ip], ["Time (UTC)", a.time.replace("T", " ").slice(0, 19)], ["Scenario", a.scenario || "background"]]) {
    meta.append(el("dt", "", k), el("dd", "", v));
  }
  $("d-ai").replaceChildren();
  $("ask").disabled = false;
  $("drawer").classList.remove("hidden");
}

async function ask() {
  if (!current) return;
  const btn = $("ask"); btn.disabled = true;
  const box = $("d-ai"); box.replaceChildren(el("p", "meta", "Analyst is thinking..."));
  try {
    const res = await fetch("/api/explain?id=" + current.id, { method: "POST" });
    if (!res.ok) throw new Error(await res.text());
    const a = await res.json();
    box.replaceChildren(el("h4", "", "Summary"), el("p", "", a.summary), el("h4", "", "Why it matters"), el("p", "", a.why), el("h4", "", "Recommended actions"));
    const ul = el("ul"); for (const x of a.actions) ul.append(el("li", "", x));
    box.append(ul, el("div", "src", `Confidence: ${a.confidence} · Source: ${a.source}`));
  } catch (e) {
    box.replaceChildren(el("p", "meta", "Could not get an explanation: " + e.message));
  }
  btn.disabled = false;
}

function bars(target, items, color) {
  const max = Math.max(1, ...items.map((i) => i.count));
  target.replaceChildren(...items.map((i) => {
    const b = el("div", "bar"), t = el("div", "track"), f = el("div", "fill");
    f.style.width = (i.count / max) * 100 + "%"; f.style.background = color(i.count / max);
    t.append(f); b.append(el("span", "", i.name), t, el("span", "n", String(i.count)));
    return b;
  }));
}

const lerp = (a, b, t) => a.map((v, i) => Math.round(v + (b[i] - v) * t));
const heat = (x) => { const c = x < 0.5 ? lerp([59, 130, 246], [234, 179, 8], x * 2) : lerp([234, 179, 8], [239, 68, 68], (x - 0.5) * 2); return `rgb(${c.join(",")})`; };

async function refresh() {
  try {
    const s = await (await fetch("/api/stats")).json();
    $("k-total").textContent = s.total;
    $("k-crit").textContent = s.critical_incidents;
    $("k-high").textContent = s.severity[3] + s.severity[4];
    $("k-top").textContent = s.techniques.length ? s.techniques[0].name : "-";
    bars($("tactics"), s.tactics, heat);
    bars($("techniques"), s.techniques.map((t) => ({ name: t.name.length > 30 ? t.name.slice(0, 29) + "…" : t.name, count: t.count })), () => "#5b9dff");
    $("incidents").replaceChildren(...s.incidents.map((i) => {
      const box = el("div", "inc" + (i.critical ? " critical" : ""));
      const top = el("div", "top"); top.append(el("span", "", i.host), el("span", "score", "risk " + i.score));
      const chain = el("div", "chain"); for (const t of i.tactics) chain.append(el("span", "chip", t));
      box.append(top, el("div", "meta", `${i.alerts} alerts · last ${clock(i.last)}`), chain);
      return box;
    }));
  } catch (_) { /* next poll will retry */ }
}

async function start() {
  const first = await (await fetch("/api/alerts?limit=40")).json();
  $("feed").replaceChildren(...first.map((a) => row(a, false)));
  const es = new EventSource("/events");
  es.onopen = () => { $("dot").classList.add("on"); $("livetxt").textContent = "live"; };
  es.onerror = () => { $("dot").classList.remove("on"); $("livetxt").textContent = "reconnecting"; };
  es.onmessage = (m) => {
    const feed = $("feed");
    feed.prepend(row(JSON.parse(m.data), true));
    while (feed.children.length > 60) feed.lastChild.remove();
  };
  refresh(); setInterval(refresh, 1500);
}
$("close").addEventListener("click", () => $("drawer").classList.add("hidden"));
$("ask").addEventListener("click", ask);
start();
