/* Front-end for the phishing detector.
 * All detection happens on the server; this file only renders reports.
 * Every piece of report data is inserted with textContent, never as HTML,
 * and submitted addresses are shown "defanged" and are never made clickable.
 */
(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const HISTORY_KEY = "phishdetect.history.v2";
  const HISTORY_MAX = 50;

  const SOURCE_LABELS = {
    threat_intel: "Threat intelligence", heuristic: "Rule", page: "Page content",
    ml: "ML model", reputation: "Reputation", unavailable: "Unavailable",
  };
  const SEVERITY_LABELS = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Note", positive: "Supporting" };
  const STATUS_LABELS = { ok: "Completed", clean: "No listing", match: "Listed", error: "Unavailable", not_configured: "Not enabled", skipped: "Skipped" };
  const EXAMPLES = {
    "url-phish": ["url", "https://paypa1-account.com.secure-verify.info/signin"],
    "url-safe": ["url", "https://accounts.google.com/v3/signin/identifier?continue=https%3A%2F%2Fmail.google.com%2Fmail%2F&service=mail"],
    "msg-phish": ["message", "From: PayPal Support <service.team7781@gmail.com>\nSubject: Your account has been limited\n\nDear Customer,\n\nWe noticed unusual activity and your PayPal account has been limited. You must verify your account within 24 hours or it will be permanently closed.\n\nVerify now: http://paypal-secure.account-verify.xyz/login\n\nPayPal Security Team"],
    "msg-safe": ["message", "Hi team,\n\nThe quarterly planning meeting is moved to 3pm tomorrow in room 4B. The agenda is in the shared drive.\n\nThanks,\nSam"],
  };
  const LOADING_STEPS = [
    "Checking address structure and impersonation rules",
    "Scoring with the machine-learning model",
    "Querying threat-intelligence sources",
    "Retrieving the page safely (no scripts are run)",
    "Weighing the evidence",
  ];

  let status = { limits: { max_chars: 50000 }, thresholds: { suspicious: 30, likely_phishing: 65 }, feedback_retention_days: 180 };
  let busy = false;
  let lastSubmitted = "";

  /* ------------------------------------------------------------ helpers */
  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else node.setAttribute(k, v);
    }
    for (const c of children) if (c != null) node.append(c);
    return node;
  }

  function loadHistory() {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); } catch { return []; }
  }
  function saveHistory(items) {
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, HISTORY_MAX))); } catch { /* storage full or blocked */ }
  }
  function timeAgo(iso) {
    const s = Math.max((Date.now() - new Date(iso).getTime()) / 1000, 0);
    if (s < 60) return "just now";
    if (s < 3600) return `${Math.floor(s / 60)} min ago`;
    if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
    return new Date(iso).toLocaleDateString();
  }

  /* -------------------------------------------------------------- routes */
  const ROUTES = ["analyze", "history", "how-it-works", "learn", "privacy"];
  function route() {
    const name = (location.hash.replace(/^#\/?/, "") || "analyze").split("?")[0];
    const current = ROUTES.includes(name) ? name : "analyze";
    for (const r of ROUTES) $(`#view-${r}`).hidden = r !== current;
    for (const a of $$("nav a")) {
      if (a.dataset.route === current) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
    }
    if (current === "history") renderHistory($("#history-list"), loadHistory(), $("#history-empty"));
    if (current === "analyze") renderRecent();
    document.title = { analyze: "Phishing Detector", history: "History - Phishing Detector", "how-it-works": "How it works - Phishing Detector",
      learn: "Spotting phishing - Phishing Detector", privacy: "Privacy - Phishing Detector" }[current];
  }

  /* --------------------------------------------------------- result view */
  function indicatorNode(ind) {
    const details = el("details", { class: "indicator" });
    const summary = el("summary", {},
      el("span", { class: `sev sev-${ind.severity}`, text: SEVERITY_LABELS[ind.severity] || ind.severity }),
      el("span", { class: "title", text: ind.title }),
      el("span", { class: `tag src-${ind.source}`, text: SOURCE_LABELS[ind.source] || ind.source }));
    const dl = el("dl", {},
      el("dt", { text: "Evidence" }), el("dd", { class: "mono", text: ind.evidence || "-" }),
      el("dt", { text: "Why it matters" }), el("dd", { text: ind.explanation || "-" }));
    if (ind.weight > 0) {
      dl.append(el("dt", { text: "Contribution" }),
        el("dd", { text: ind.counted ? `Weight ${ind.weight.toFixed(2)} in the risk score.` : `Weight ${ind.weight.toFixed(2)}, not counted: a stronger indicator already covers the same fact.` }));
    }
    details.append(summary, el("div", { class: "body" }, dl));
    return details;
  }

  function renderResult(report, { fromHistory = false } = {}) {
    const frag = $("#tpl-result").content.cloneNode(true);
    const root = $(".result", frag);
    root.classList.add(`v-${report.classification}`);
    $(".verdict-label", root).textContent = report.label;
    $(".subject", root).textContent = (report.input_type === "url" ? "" : "Message: ") + report.subject;
    $(".score-value", root).textContent = report.risk_score;
    const meter = $(".meter", root);
    meter.setAttribute("aria-label", `Risk score ${report.risk_score} of 100. Suspicious from ${status.thresholds.suspicious}, likely phishing from ${status.thresholds.likely_phishing}.`);
    $(".meter-fill", root).style.width = `${report.risk_score}%`;
    $(".tick-s", root).style.left = `${status.thresholds.suspicious}%`;
    $(".tick-lp", root).style.left = `${status.thresholds.likely_phishing}%`;
    const conf = $(".confidence", root);
    conf.append("Confidence in this verdict: ", el("strong", { text: report.confidence.level }));
    $(".summary", root).textContent = report.summary;
    const reasons = $(".conf-reasons", root);
    for (const r of report.confidence.reasons || []) reasons.append(el("li", { text: r }));
    if (!reasons.children.length) reasons.remove();

    for (const r of report.recommendations) $(".recommendations", root).append(el("li", { text: r }));

    const risk = report.indicators.filter((i) => i.weight > 0);
    const other = report.indicators.filter((i) => i.weight <= 0);
    const riskBlock = $(".block-risk", root);
    if (risk.length) {
      $(".count", riskBlock).textContent = `(${risk.length})`;
      risk.forEach((i, idx) => { const n = indicatorNode(i); if (idx === 0) n.open = true; $(".risk-list", root).append(n); });
    } else {
      $(".hint", riskBlock).textContent = report.classification === "likely_safe"
        ? "None found."
        : "None found. That alone does not make it safe - see the verdict above.";
    }
    const otherBlock = $(".block-other", root);
    if (other.length) {
      $(".count", otherBlock).textContent = `(${other.length})`;
      other.forEach((i) => $(".other-list", root).append(indicatorNode(i)));
    } else otherBlock.remove();

    const linksBlock = $(".block-links", root);
    if (report.links && report.links.length) {
      const tbody = $("tbody", linksBlock);
      for (const l of report.links) {
        tbody.append(el("tr", {},
          el("td", { class: "mono", text: l.url }),
          el("td", {}, el("span", { class: `pill v-${l.classification}`, text: l.label })),
          el("td", { text: String(l.risk_score) })));
      }
    } else linksBlock.remove();

    const checksBody = $(".checks-table tbody", root);
    let missing = 0;
    for (const c of report.checks) {
      if (["error", "not_configured", "skipped"].includes(c.status)) missing += 1;
      checksBody.append(el("tr", {},
        el("td", { text: c.name }),
        el("td", { class: `status status-${c.status}`, text: STATUS_LABELS[c.status] || c.status }),
        el("td", { text: c.detail })));
    }
    $(".checks-count", root).textContent = `(${report.checks.length - missing} completed, ${missing} unavailable)`;
    if (missing && report.classification !== "likely_phishing") $(".checks", root).open = report.classification === "unable_to_determine";

    $(".act-copy", root).addEventListener("click", async (ev) => {
      const text = summaryText(report);
      try { await navigator.clipboard.writeText(text); ev.target.textContent = "Copied"; }
      catch { ev.target.textContent = "Copy failed"; }
      setTimeout(() => { ev.target.textContent = "Copy summary"; }, 1800);
    });
    $(".act-download", root).addEventListener("click", () => {
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
      const a = el("a", { href: URL.createObjectURL(blob), download: `phishing-report-${report.id.slice(0, 8)}.json` });
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    });

    const fb = $(".feedback", root);
    $(".fb-days", fb).textContent = status.feedback_retention_days;
    const include = $(".fb-include", fb);
    if (fromHistory || !lastSubmitted) include.closest("label").remove();
    fb.addEventListener("change", (ev) => { if (ev.target.name === "verdict") $(".feedback-more", fb).hidden = false; });
    fb.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const verdict = (fb.querySelector("input[name=verdict]:checked") || {}).value;
      const statusEl = $(".fb-status", fb);
      if (!verdict) { statusEl.textContent = "Choose an option first."; return; }
      const body = { analysis_id: report.id, input_type: report.input_type, classification: report.classification,
        risk_score: report.risk_score, verdict, comment: $(".fb-comment", fb).value };
      if (include.isConnected && include.checked) body.content = lastSubmitted.slice(0, 50000);
      try {
        const res = await fetch("/api/feedback", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || "Could not send feedback.");
        statusEl.textContent = "Thank you. Your feedback was recorded.";
        $$("input, button", fb).forEach((n) => { n.disabled = true; });
      } catch (err) { statusEl.textContent = err.message; }
    });

    const host = $("#result");
    host.replaceChildren(frag);
    return host.firstElementChild;
  }

  function summaryText(r) {
    const lines = [
      `Phishing check: ${r.label} (risk score ${r.risk_score}/100, confidence ${r.confidence.level})`,
      `${r.input_type === "url" ? "Address" : "Message"}: ${r.subject}`,
      r.summary, "",
      "Indicators:",
      ...r.indicators.filter((i) => i.weight > 0).map((i) => ` - [${SEVERITY_LABELS[i.severity]} / ${SOURCE_LABELS[i.source]}] ${i.title}: ${i.evidence}`),
    ];
    if (r.missing_information.length) lines.push("", "Not checked:", ...r.missing_information.map((m) => ` - ${m}`));
    lines.push("", "Recommended:", ...r.recommendations.map((x) => ` - ${x}`), "", `Analysed ${r.analysed_at} (engine ${r.engine_version})`);
    return lines.join("\n");
  }

  /* -------------------------------------------------------------- history */
  function renderHistory(list, items, emptyEl) {
    list.replaceChildren();
    for (const r of items) {
      const btn = el("button", { type: "button", class: "history-item" },
        el("span", { class: `pill v-${r.classification}`, text: r.label }),
        el("span", { class: "what", text: r.subject }),
        el("span", { class: "when", text: `${r.risk_score}/100 · ${timeAgo(r.analysed_at)}` }));
      btn.addEventListener("click", () => {
        lastSubmitted = "";
        if (location.hash !== "#/" && location.hash !== "") location.hash = "#/";
        setTimeout(() => { const node = renderResult(r, { fromHistory: true }); node.scrollIntoView({ block: "start", behavior: "smooth" }); }, 0);
      });
      list.append(el("li", {}, btn));
    }
    if (emptyEl) emptyEl.hidden = items.length > 0;
  }
  function renderRecent() {
    const items = loadHistory().slice(0, 5);
    $("#recent").hidden = items.length === 0;
    renderHistory($("#recent-list"), items, null);
  }

  /* --------------------------------------------------------------- submit */
  function showError(msg) {
    const box = $("#input-error");
    box.textContent = msg; box.hidden = !msg;
    $("#content").setAttribute("aria-invalid", msg ? "true" : "false");
  }

  async function submit(ev) {
    ev.preventDefault();
    if (busy) return;
    const content = $("#content").value;
    const mode = $("input[name=mode]:checked").value;
    showError("");
    if (!content.trim()) { showError("Enter a web address or paste a message first."); $("#content").focus(); return; }
    if (content.length > status.limits.max_chars) { showError(`That is too long. The limit is ${status.limits.max_chars.toLocaleString()} characters.`); return; }

    busy = true;
    const btn = $("#submit-btn");
    btn.disabled = true; btn.textContent = "Analysing…";
    $("#result").replaceChildren();
    $("#loading").hidden = false;
    let step = 0;
    $("#loading-step").textContent = LOADING_STEPS[0];
    const ticker = setInterval(() => { step = Math.min(step + 1, LOADING_STEPS.length - 1); $("#loading-step").textContent = LOADING_STEPS[step]; }, 1400);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 60000);
    try {
      const res = await fetch("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content, mode }), signal: controller.signal });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        if (res.status === 429) throw new Error(data.error || "Too many requests. Please wait a moment and try again.");
        throw new Error(data.error || `The analysis could not be completed (error ${res.status}).`);
      }
      lastSubmitted = content;
      const node = renderResult(data);
      saveHistory([data, ...loadHistory().filter((h) => h.id !== data.id)]);
      renderRecent();
      node.scrollIntoView({ block: "start", behavior: "smooth" });
    } catch (err) {
      showError(err.name === "AbortError" ? "The analysis took too long and was cancelled. Please try again."
        : err instanceof TypeError ? "Could not reach the server. Check your connection and try again." : err.message);
    } finally {
      clearInterval(ticker); clearTimeout(timeout);
      $("#loading").hidden = true;
      btn.disabled = false; btn.textContent = "Analyse";
      busy = false;
    }
  }

  /* ----------------------------------------------------------------- init */
  async function loadStatus() {
    try {
      const res = await fetch("/api/status");
      if (!res.ok) return;
      status = await res.json();
      $("#char-max").textContent = status.limits.max_chars.toLocaleString();
      $("#retention-days").textContent = status.feedback_retention_days;
      $("#footer-version").textContent = `Engine ${status.version}.`;
      const t = status.thresholds;
      const set = (k, v) => $$(`[data-th="${k}"]`).forEach((n) => { n.textContent = v; });
      set("lp", t.likely_phishing); set("lp1", t.likely_phishing - 1); set("s", t.suspicious); set("s2", t.suspicious);
      const tbody = el("tbody");
      for (const s of status.sources) {
        tbody.append(el("tr", {}, el("td", { text: s.name }),
          el("td", { class: `status ${s.enabled ? "status-ok" : "status-not_configured"}`, text: s.enabled ? "Enabled" : "Not enabled" })));
      }
      tbody.append(el("tr", {}, el("td", { text: "URL machine-learning model" }),
        el("td", { class: `status ${status.url_model.available ? "status-ok" : "status-error"}`, text: status.url_model.available ? "Loaded" : "Unavailable" })));
      $("#status-box").replaceChildren(el("table", { class: "table" },
        el("thead", {}, el("tr", {}, el("th", { text: "Evidence source" }), el("th", { text: "Status on this server" }))), tbody));
    } catch { /* status is informational only */ }
  }

  function init() {
    $("#analyze-form").addEventListener("submit", submit);
    const ta = $("#content");
    ta.addEventListener("input", () => { $("#char-count").textContent = ta.value.length.toLocaleString(); if (ta.value.trim()) showError(""); });
    ta.addEventListener("keydown", (ev) => { if ((ev.ctrlKey || ev.metaKey) && ev.key === "Enter") $("#analyze-form").requestSubmit(); });
    $("#clear-btn").addEventListener("click", () => { ta.value = ""; ta.dispatchEvent(new Event("input")); $("#result").replaceChildren(); showError(""); ta.focus(); });
    for (const b of $$("[data-example]")) {
      b.addEventListener("click", () => {
        const [mode, text] = EXAMPLES[b.dataset.example];
        ta.value = text; ta.dispatchEvent(new Event("input"));
        $(`input[name=mode][value=${mode}]`).checked = true;
        ta.focus();
      });
    }
    $("#clear-history").addEventListener("click", () => { saveHistory([]); route(); });
    window.addEventListener("hashchange", () => { route(); $("#main").focus({ preventScroll: true }); window.scrollTo(0, 0); });
    route();
    loadStatus();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
