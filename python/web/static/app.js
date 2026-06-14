"use strict";

/* ---------- helpers ---------- */
const $ = (id) => document.getElementById(id);

function sigClass(dbm) {
  if (dbm >= -65) return "sig-good";
  if (dbm >= -80) return "sig-mid";
  return "sig-bad";
}

const FLAG_CLASS = {
  "MAC-LEAK": "danger", "EVIL-TWIN!": "danger", "KARMA!": "danger",
  "DEAUTH-SRC!": "danger", "OPEN": "danger",
  "dup-SSID": "warn", "hidden": "warn",
  "rand-MAC": "priv",
};
function flagBadges(flags) {
  if (!flags || !flags.length) return '<span style="color:var(--txt-dim)">—</span>';
  return flags.map((f) => `<span class="badge ${FLAG_CLASS[f] || ""}">${esc(f)}</span>`).join("");
}

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/* ---------- sortable / filterable tables ---------- */
const sortState = {
  "ap-table": { key: "rssi", dir: -1 },
  "cli-table": { key: "rssi", dir: -1 },
};
const filters = { "ap-table": "", "cli-table": "" };

function setupSorting(tableId) {
  $(tableId).querySelectorAll("thead th[data-key]").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.key;
      const st = sortState[tableId];
      st.dir = st.key === key ? -st.dir : -1;
      st.key = key;
      lastSnap && render(lastSnap);
    });
  });
}

function sortRows(rows, st) {
  const { key, dir } = st;
  return rows.slice().sort((a, b) => {
    let x = a[key], y = b[key];
    if (Array.isArray(x)) x = x.length;
    if (Array.isArray(y)) y = y.length;
    if (typeof x === "number" && typeof y === "number") return (x - y) * dir;
    return String(x).localeCompare(String(y)) * dir;
  });
}

function applyFilter(rows, text) {
  if (!text) return rows;
  const t = text.toLowerCase();
  return rows.filter((r) => JSON.stringify(r).toLowerCase().includes(t));
}

/* ---------- renderers ---------- */
function renderApTable(aps) {
  const rows = sortRows(applyFilter(aps, filters["ap-table"]), sortState["ap-table"]);
  $("ap-table").querySelector("tbody").innerHTML = rows.map((a) => {
    const ssid = a.ssid
      ? esc(a.ssid)
      : '<span class="ssid-hidden">&lt;hidden&gt;</span>';
    return `<tr>
      <td>${esc(a.bssid)}</td>
      <td>${ssid}</td>
      <td>${esc(a.vendor)}</td>
      <td class="num">${a.channel || "–"}</td>
      <td class="num ${sigClass(a.rssi)}">${a.rssi}</td>
      <td class="num">${a.beacons || 0}</td>
      <td>${flagBadges(a.flags)}</td>
    </tr>`;
  }).join("");
}

function renderClientTable(clients) {
  const rows = sortRows(applyFilter(clients, filters["cli-table"]), sortState["cli-table"]);
  $("cli-table").querySelector("tbody").innerHTML = rows.map((c) => {
    const probed = c.probed && c.probed.length
      ? esc(c.probed.join(", "))
      : '<span style="color:var(--txt-dim)">(broadcast only)</span>';
    return `<tr>
      <td>${esc(c.mac)}</td>
      <td>${esc(c.type)}</td>
      <td class="num ${sigClass(c.rssi)}">${c.rssi}</td>
      <td>${probed}</td>
      <td>${flagBadges(c.flags)}</td>
    </tr>`;
  }).join("");
}

function renderThreats(threats) {
  const ul = $("threats");
  if (!threats || !threats.length) {
    ul.innerHTML = '<li class="empty">No notable findings.</li>';
    return;
  }
  ul.innerHTML = threats.map((t) =>
    `<li class="${t.sev}"><span class="sev">[${t.sev}]</span>${esc(t.text)}</li>`
  ).join("");
}

function renderStream(stream) {
  $("stream-table").querySelector("tbody").innerHTML = stream.map((p) => {
    const proto = p.type === "802.11" ? (p.subtype || "802.11") : (p.type || "?");
    let info;
    if (p.type === "802.11") {
      const ssid = p.ssid && !p.ssid.startsWith("[") && p.ssid !== "<HIDDEN>"
        ? `📶 ${esc(p.ssid)}` : esc(p.ssid || "");
      info = `${ssid} ${p.ch ? "(Ch:" + p.ch + ")" : ""}`;
    } else {
      const port = p.dport ? ":" + p.dport : "";
      info = `len ${p.size}${port ? " · dport" + port : ""}`;
    }
    const sig = p.type === "802.11" && p.rssi
      ? `<span class="${sigClass(p.rssi)}">${p.rssi}</span>` : "–";
    return `<tr>
      <td>${esc(p.ts)}</td>
      <td class="p-${esc(proto)}">${esc(proto)}</td>
      <td>${esc(p.src || "")}</td>
      <td>${esc(p.dst || "")}</td>
      <td>${info}</td>
      <td class="num">${sig}</td>
    </tr>`;
  }).join("");
}

function renderKpis(k) {
  $("kpi-aps").textContent = k.aps;
  $("kpi-clients").textContent = k.clients;
  $("kpi-threats").textContent = k.threats;
  $("kpi-deauth").textContent = k.deauth_frames;
  $("kpi-pps").textContent = k.pkts_per_sec;
  $("flood-banner").classList.toggle("hidden", !k.deauth_flood);
}

/* ---------- charts ---------- */
const PALETTE = ["#2dd4bf", "#58a6ff", "#e3b341", "#f85149", "#d2a8ff",
  "#3fb950", "#ff9e64", "#79c0ff", "#ffa657", "#a5d6ff", "#56d364", "#bc8cff"];

let rssiChart, chanChart;

function initCharts() {
  const gridColor = "#2a313c", tickColor = "#8b949e";
  rssiChart = new Chart($("rssiChart"), {
    type: "line",
    data: { datasets: [] },
    options: {
      animation: false, responsive: true, maintainAspectRatio: false,
      parsing: false, interaction: { mode: "nearest", intersect: false },
      scales: {
        x: { type: "linear", grid: { color: gridColor }, ticks: { color: tickColor,
          callback: (v) => { const d = new Date(v * 1000);
            return d.getMinutes() + ":" + String(d.getSeconds()).padStart(2, "0"); } } },
        y: { suggestedMin: -95, suggestedMax: -30, grid: { color: gridColor },
          ticks: { color: tickColor, callback: (v) => v + " dBm" } },
      },
      plugins: { legend: { labels: { color: tickColor, boxWidth: 10, font: { size: 10 } } } },
    },
  });

  chanChart = new Chart($("chanChart"), {
    type: "scatter",
    data: { datasets: [{ label: "APs", data: [], pointRadius: 6, pointHoverRadius: 8 }] },
    options: {
      animation: false, responsive: true, maintainAspectRatio: false,
      scales: {
        x: { type: "linear", min: 0, max: 14, title: { display: true, text: "Channel", color: tickColor },
          grid: { color: gridColor }, ticks: { color: tickColor, stepSize: 1 } },
        y: { suggestedMin: -95, suggestedMax: -30, title: { display: true, text: "RSSI", color: tickColor },
          grid: { color: gridColor }, ticks: { color: tickColor, callback: (v) => v + " dBm" } },
      },
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: (c) => {
          const p = c.raw; return `${p.ssid}  ch${p.x}  ${p.y}dBm`; } } },
      },
    },
  });
}

function updateRssiChart(series) {
  const datasets = [];
  let i = 0;
  for (const bssid in series) {
    const s = series[bssid];
    datasets.push({
      label: s.ssid.length > 16 ? s.ssid.slice(0, 15) + "…" : s.ssid,
      data: s.points.map(([t, d]) => ({ x: t, y: d })),
      borderColor: PALETTE[i % PALETTE.length],
      backgroundColor: PALETTE[i % PALETTE.length],
      borderWidth: 1.5, pointRadius: 0, tension: 0.25,
    });
    i++;
  }
  rssiChart.data.datasets = datasets;
  rssiChart.update("none");
}

function secColor(sec) {
  if (sec === "OPEN" || sec === "open") return "#f85149";
  if (sec === "?" ) return "#8b949e";
  return "#3fb950";
}
function updateChanChart(scatter) {
  chanChart.data.datasets[0].data = scatter.map((a) => ({
    x: a.channel, y: a.rssi, ssid: a.ssid,
  }));
  chanChart.data.datasets[0].pointBackgroundColor = scatter.map((a) => secColor(a.security));
  // widen x-axis if 5GHz channels appear
  const maxCh = scatter.reduce((m, a) => Math.max(m, a.channel), 14);
  chanChart.options.scales.x.max = maxCh > 14 ? maxCh + 2 : 14;
  chanChart.update("none");
}

/* ---------- main render ---------- */
let lastSnap = null;
function render(snap) {
  lastSnap = snap;
  renderKpis(snap.kpis);
  renderApTable(snap.aps);
  renderClientTable(snap.clients);
  renderThreats(snap.threats);
  renderStream(snap.stream);
  updateRssiChart(snap.rssi_series);
  updateChanChart(snap.channel_scatter);
}

/* ---------- websocket ---------- */
function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen = () => { $("conn").textContent = "live"; $("conn").className = "conn on"; };
  ws.onclose = () => {
    $("conn").textContent = "offline"; $("conn").className = "conn off";
    setTimeout(connect, 1500);
  };
  ws.onmessage = (ev) => {
    try { render(JSON.parse(ev.data)); } catch (e) { /* ignore */ }
  };
}

/* ---------- boot ---------- */
window.addEventListener("DOMContentLoaded", () => {
  initCharts();
  setupSorting("ap-table");
  setupSorting("cli-table");
  $("ap-filter").addEventListener("input", (e) => { filters["ap-table"] = e.target.value; lastSnap && renderApTable(lastSnap.aps); });
  $("cli-filter").addEventListener("input", (e) => { filters["cli-table"] = e.target.value; lastSnap && renderClientTable(lastSnap.clients); });
  connect();
});
