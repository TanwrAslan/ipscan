/* ipscan web arayüzü. Harici bağımlılık yok, tüm DOM güncellemeleri
   textContent üzerinden yapılır (XSS yüzeyi yok). */
"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  jobId: null,
  rows: [],          // tüm gelen sonuçlar
  running: false,
  es: null,
  sort: { key: "host", dir: 1 },
  renderTimer: null,
};

const SERVICES = {
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
  110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
  161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
  587: "submission", 631: "ipp", 993: "imaps", 995: "pop3s", 1433: "mssql",
  1521: "oracle", 2049: "nfs", 2181: "zookeeper", 2375: "docker", 3000: "http-alt",
  3306: "mysql", 3389: "rdp", 5432: "postgres", 5672: "amqp", 5900: "vnc",
  5985: "winrm", 6379: "redis", 8000: "http-alt", 8080: "http-proxy",
  8443: "https-alt", 9200: "elastic", 11211: "memcached", 27017: "mongodb",
};

const STATE_TR = {
  open: "AÇIK", closed: "kapalı", filtered: "filtreli",
  unreachable: "erişilemez", error: "hata",
};

/* ------------------------------------------------------------------ api -- */

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json",
               "X-Requested-With": "ipscan", ...(options.headers || {}) },
  });
  let data = {};
  try { data = await res.json(); } catch (_) { /* gövdesiz yanıt */ }
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

/* -------------------------------------------------------------- uyarılar -- */

function notice(text, kind = "warn") {
  const box = $("notices");
  box.hidden = false;
  const el = document.createElement("div");
  el.className = "notice" + (kind === "err" ? " err" : kind === "ok" ? " ok" : "");
  el.textContent = text;
  box.appendChild(el);
}

function clearNotices() {
  $("notices").textContent = "";
  $("notices").hidden = true;
}

/* ---------------------------------------------------------------- tablo -- */

function serviceName(port) { return SERVICES[port] || ""; }

function visibleRows() {
  const term = $("filter").value.trim().toLowerCase();
  const onlyOpen = $("onlyOpen").checked;
  let rows = state.rows;
  if (onlyOpen) rows = rows.filter((r) => r.state === "open");
  if (term) {
    rows = rows.filter((r) =>
      r.host.includes(term) ||
      String(r.port).includes(term) ||
      r.state.includes(term) ||
      serviceName(r.port).includes(term) ||
      (r.banner || "").toLowerCase().includes(term));
  }
  const { key, dir } = state.sort;
  return rows.slice().sort((a, b) => {
    if (key === "host") return dir * compareHost(a.host, b.host);
    if (typeof a[key] === "number") return dir * (a[key] - b[key]);
    return dir * String(a[key]).localeCompare(String(b[key]));
  });
}

function compareHost(a, b) {
  const pa = a.split("."), pb = b.split(".");
  if (pa.length === 4 && pb.length === 4) {
    for (let i = 0; i < 4; i++) {
      const d = (+pa[i] || 0) - (+pb[i] || 0);
      if (d) return d;
    }
    return 0;
  }
  return a.localeCompare(b);
}

const MAX_RENDER = 3000;

function render() {
  const rows = visibleRows();
  const tbody = $("tbody");
  const frag = document.createDocumentFragment();

  for (const r of rows.slice(0, MAX_RENDER)) {
    const tr = document.createElement("tr");
    const svc = serviceName(r.port);

    const cells = [
      { text: r.host },
      { text: svc ? `${r.port} (${svc})` : String(r.port), cls: "num" },
      { text: STATE_TR[r.state] || r.state, cls: "state-" + r.state },
      { text: `${r.latency_ms.toFixed(1)} ms`, cls: "num" },
      { text: r.banner || r.detail || "", cls: "detail" },
    ];
    for (const c of cells) {
      const td = document.createElement("td");
      td.textContent = c.text;
      if (c.cls) td.className = c.cls;
      tr.appendChild(td);
    }
    frag.appendChild(tr);
  }

  tbody.textContent = "";
  tbody.appendChild(frag);
  $("rowCount").textContent = rows.length > MAX_RENDER
    ? `${MAX_RENDER} / ${rows.length}` : String(rows.length);
  $("empty").hidden = rows.length > 0;
}

function scheduleRender() {
  if (state.renderTimer) return;
  state.renderTimer = setTimeout(() => {
    state.renderTimer = null;
    render();
  }, 200);
}

/* ------------------------------------------------------------ ilerleme -- */

function updateProgress(s) {
  const total = s.total || 0;
  const pct = total ? Math.min(100, (s.done / total) * 100) : 0;
  $("bar").style.width = pct.toFixed(1) + "%";
  $("progressText").textContent =
    `${(s.done || 0).toLocaleString("tr")} / ${total.toLocaleString("tr")} prob — %${pct.toFixed(1)}`;
  const rate = s.rate || 0;
  let eta = "";
  if (rate > 0 && total > s.done) eta = ` · kalan ~${((total - s.done) / rate).toFixed(1)} sn`;
  $("rateText").textContent = `${Math.round(rate).toLocaleString("tr")} prob/sn · ${(s.elapsed || 0).toFixed(1)} sn${eta}`;

  $("sOpen").textContent = s.open || 0;
  $("sClosed").textContent = s.closed || 0;
  $("sFiltered").textContent = s.filtered || 0;
  $("sOther").textContent = (s.unreachable || 0) + (s.error || 0);
  $("sDone").textContent = (s.done || 0).toLocaleString("tr");
}

function setRunning(on) {
  state.running = on;
  $("startBtn").disabled = on;
  $("startBtn").textContent = on ? "Taranıyor…" : "Taramayı başlat";
  $("cancelBtn").disabled = !on;
  const hasJob = !!state.jobId;
  $("exportJson").disabled = !hasJob;
  $("exportCsv").disabled = !hasJob;
}

/* ---------------------------------------------------------------- akış -- */

function openStream(jobId) {
  if (state.es) state.es.close();
  const es = new EventSource(`/api/stream?job=${encodeURIComponent(jobId)}`,
                             { withCredentials: true });
  state.es = es;

  es.addEventListener("result", (ev) => {
    state.rows.push(JSON.parse(ev.data));
    scheduleRender();
  });
  es.addEventListener("progress", (ev) => updateProgress(JSON.parse(ev.data)));
  es.addEventListener("done", (ev) => {
    const snap = JSON.parse(ev.data);
    if (snap.stats) updateProgress(snap.stats);
    es.close();
    state.es = null;
    setRunning(false);
    render();
    const s = snap.stats || {};
    if (snap.state === "error") notice("Tarama hatası: " + (snap.error || "?"), "err");
    else if (snap.state === "cancelled") notice("Tarama durduruldu.", "warn");
    else notice(`Tamamlandı: ${s.open || 0} açık port, ${(s.done || 0).toLocaleString("tr")} prob, ${(s.elapsed || 0).toFixed(2)} sn.`, "ok");
  });
  es.onerror = () => {
    if (state.running) {
      es.close();
      state.es = null;
      setRunning(false);
      notice("Sunucu bağlantısı kesildi.", "err");
    }
  };
}

/* ------------------------------------------------------------ olaylar -- */

$("scanForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (state.running) return;
  clearNotices();
  state.rows = [];
  render();
  updateProgress({ total: 0, done: 0 });

  const body = {
    targets: $("targets").value,
    ports: $("ports").value,
    timeout: parseFloat($("timeout").value) || 1,
    retries: parseInt($("retries").value, 10) || 0,
    concurrency: $("concurrency").value ? parseInt($("concurrency").value, 10) : null,
    rate: $("rate").value ? parseFloat($("rate").value) : null,
    banner: $("banner").checked,
    resolve: $("resolve").checked,
    streamAll: $("streamAll").checked,
  };

  setRunning(true);
  try {
    const res = await api("/api/scan", { method: "POST", body: JSON.stringify(body) });
    state.jobId = res.jobId;
    (res.warnings || []).forEach((w) => notice(w));
    updateProgress({ total: res.total, done: 0 });
    notice(`${res.hosts} hedef × ${res.ports} port = ${res.total.toLocaleString("tr")} prob başlatıldı (eş zamanlılık ${res.options.concurrency}).`, "ok");
    openStream(res.jobId);
  } catch (err) {
    setRunning(false);
    notice(err.message, "err");
  }
});

$("cancelBtn").addEventListener("click", async () => {
  if (!state.jobId) return;
  try {
    await api("/api/cancel", { method: "POST", body: JSON.stringify({ jobId: state.jobId }) });
  } catch (err) { notice(err.message, "err"); }
});

$("exportJson").addEventListener("click", () => download("json"));
$("exportCsv").addEventListener("click", () => download("csv"));

function download(fmt) {
  if (!state.jobId) return;
  const open = $("onlyOpen").checked ? "1" : "0";
  window.location.href =
    `/api/export?job=${encodeURIComponent(state.jobId)}&fmt=${fmt}&open=${open}`;
}

$("filter").addEventListener("input", scheduleRender);
$("onlyOpen").addEventListener("change", render);

document.querySelectorAll(".chip").forEach((chip) => {
  chip.addEventListener("click", () => { $("ports").value = chip.dataset.ports; });
});

document.querySelectorAll("thead th[data-sort]").forEach((th) => {
  th.addEventListener("click", () => {
    const key = th.dataset.sort;
    state.sort.dir = state.sort.key === key ? -state.sort.dir : 1;
    state.sort.key = key;
    render();
  });
});

window.addEventListener("beforeunload", () => { if (state.es) state.es.close(); });

/* --------------------------------------------------------------- açılış -- */

(async function init() {
  try {
    const cfg = await api("/api/config");
    $("verBadge").textContent = "v" + cfg.version;
    $("scopeBadge").textContent = "kapsam: " + cfg.scope.describe;
    $("limitBadge").textContent =
      "eş zamanlılık ≤ " + (cfg.limits.max_concurrency || cfg.limits.fd_budget);
    if (!cfg.scope.active) {
      notice("Kapsam dosyası tanımlı değil — tarama kısıtlanmıyor. " +
             "scope.txt oluşturarak yalnızca yetkili ağlara izin verebilirsiniz.");
    }
  } catch (err) {
    notice("Sunucu yapılandırması okunamadı: " + err.message, "err");
  }
  setRunning(false);
  $("targets").focus();
})();
