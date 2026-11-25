// TacoGuard local page. No inline script (the page's Content-Security-Policy forbids it);
// every value from the server is put on the page with textContent, never as HTML.
"use strict";
(function () {
  const TOKEN = document.querySelector('meta[name="tacoguard-token"]').content;
  const $ = (id) => document.getElementById(id);
  const VIEWS = ["home", "scan", "detections", "quarantine", "trusted", "settings"];

  const state = {
    view: "home", status: null, jobId: null, jobSig: "", targets: [], browsePath: "",
    quickLoaded: false, setupWatch: false, timer: null, settingsLoaded: false,
    notCheckedShown: 0,
  };

  // ---- small helpers -------------------------------------------------------------------
  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = v;
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids.flat()) {
      if (kid === null || kid === undefined || kid === false) continue;
      n.appendChild(typeof kid === "string" || typeof kid === "number" ? document.createTextNode(String(kid)) : kid);
    }
    return n;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); return n; }
  function plural(n, one, many) { return n + " " + (n === 1 ? one : (many || one + "s")); }
  function fmtBytes(b) {
    b = Number(b) || 0;
    if (b < 1024) return b + " bytes";
    const u = ["KB", "MB", "GB", "TB"]; let i = -1;
    do { b /= 1024; i++; } while (b >= 1024 && i < u.length - 1);
    return (b >= 100 ? b.toFixed(0) : b.toFixed(1)) + " " + u[i];
  }
  function fmtTime(t) {
    if (!t) return "";
    const d = new Date(t * 1000);
    return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }
  function fmtDuration(s) {
    s = Math.max(0, Math.round(s));
    if (s < 60) return plural(s, "second");
    const m = Math.floor(s / 60);
    if (m < 10 && s % 60) return plural(m, "minute") + " " + plural(s % 60, "second");
    if (m < 60) return plural(m, "minute");
    return plural(Math.floor(m / 60), "hour") + " " + plural(m % 60, "minute");
  }

  async function api(path, body) {
    const opts = { method: body === undefined ? "GET" : "POST", cache: "no-store", credentials: "same-origin",
                   headers: { "X-TacoGuard-Token": TOKEN } };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    let resp;
    try { resp = await fetch(path, opts); }
    catch (e) { $("offline").hidden = false; throw new Error("TacoGuard's page lost contact with the program."); }
    $("offline").hidden = true;
    let data = {};
    try { data = await resp.json(); } catch (e) { data = {}; }
    if (!resp.ok) throw new Error(data.error || ("Something went wrong (" + resp.status + ")."));
    return data;
  }

  let toastTimer = null;
  function toast(msg, kind) {
    const t = $("toast");
    t.textContent = msg;
    t.className = "toast" + (kind ? " " + kind : "");
    t.hidden = false;
    clearTimeout(toastTimer);
    const ms = Math.max(kind === "warn" ? 9000 : 6000, String(msg).length * 70);   // long messages stay longer
    toastTimer = setTimeout(() => { t.hidden = true; }, ms);
  }
  async function act(fn) {
    try { return await fn(); }
    catch (e) { toast(e.message, "warn"); return null; }
  }

  // A plain-words confirm box. Resolves {ok, checked}.
  function confirmBox(opt) {
    const d = $("dialog");
    $("dialog-title").textContent = opt.title;
    const text = clear($("dialog-text"));
    for (const p of opt.text) text.appendChild(el("p", { text: p }));
    const row = $("dialog-check-row");
    row.hidden = !opt.check;
    $("dialog-check").checked = false;
    if (opt.check) $("dialog-check-label").textContent = opt.check;
    const ok = $("dialog-ok");
    ok.textContent = opt.ok || "OK";
    ok.className = "btn " + (opt.danger ? "danger" : "primary");
    $("dialog-cancel").textContent = opt.cancel || "Cancel";
    return new Promise((resolve) => {
      d.returnValue = "cancel";
      d.addEventListener("close", function onClose() {
        d.removeEventListener("close", onClose);
        resolve({ ok: d.returnValue === "ok", checked: $("dialog-check").checked });
      });
      d.showModal();
      $("dialog-cancel").focus();
    });
  }

  // ---- views -----------------------------------------------------------------------------
  function showView(hash) {
    let [name, arg] = String(hash || "").split("/");
    if (!VIEWS.includes(name)) name = "home";
    if (name === "scan" && /^\d+$/.test(arg || "") && Number(arg) !== state.jobId) {
      state.jobId = Number(arg); state.jobSig = "";
    }
    state.view = name;
    for (const v of VIEWS) $("view-" + v).hidden = v !== name;
    for (const a of document.querySelectorAll(".tabs a")) {
      if (a.dataset.view === name) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
    if (name === "scan") { loadQuick(); renderScan(true); }
    if (name === "detections") loadDetections();
    if (name === "quarantine") loadQuarantine();
    if (name === "trusted") loadTrusted();
    if (name === "settings") loadSettings();
  }
  window.addEventListener("hashchange", () => showView(location.hash.slice(1)));

  // ---- polling -----------------------------------------------------------------------------
  function schedule(ms) { clearTimeout(state.timer); state.timer = setTimeout(tick, ms); }
  async function tick() {
    let busy = false;
    try {
      const st = await api("/api/status");
      state.status = st;
      const up = st.updates || {};
      busy = st.busy || up.checking || !!(up.app && up.app.state && up.app.state.running);
      renderHome();
      if (state.view === "scan") await renderScan(false);
      if (st.setup.running || state.setupWatch) await refreshSetup();
    } catch (e) { /* offline banner is shown by api() */ }
    if (state.restartWatch) return;          // watchRestart() polls while the page restarts
    schedule(busy || state.setupWatch ? 1500 : 10000);
  }

  // ---- Home ----------------------------------------------------------------------------------
  const SIG_NAMES = { hash: "Known-bad file lists", yara: "YARA rules", ml: "Machine-learning model", clamav: "ClamAV signatures" };
  const STATUS_WORDS = { queued: "Waiting to start", running: "Scanning", paused: "Paused", done: "Finished",
                         cancelled: "Stopped", failed: "Failed", interrupted: "Cut off when TacoGuard closed" };

  function renderHome() {
    const st = state.status; if (!st) return;
    // notes from start-up
    const notes = clear($("notes"));
    for (const n of st.notes || []) notes.appendChild(el("p", { class: "banner info", text: n }));

    const c = st.counts || {};
    const line = $("protection-line"), detail = $("protection-detail");
    const card = $("card-protection");
    card.className = "card";
    $("protection-link").hidden = !c.open_detections;
    if (c.open_malware) {
      card.classList.add("is-bad");
      line.textContent = "Malware found in " + plural(c.open_malware, "file") + ". You decide what to do with it.";
      detail.textContent = c.open_suspicious ? plural(c.open_suspicious, "more file is", "more files are") + " suspicious." : "";
    } else if (c.open_suspicious) {
      card.classList.add("is-warn");
      line.textContent = plural(c.open_suspicious, "suspicious file is", "suspicious files are") + " waiting for your decision.";
      detail.textContent = "Suspicious means a weaker match. Many of these turn out to be safe.";
    } else if ((st.active_jobs || []).length) {
      line.textContent = "Scanning now.";
      detail.textContent = "";
    } else {
      line.textContent = "Nothing is waiting for you.";
      detail.textContent = "TacoGuard checks files when you ask. Microsoft Defender stays your always-on protection.";
    }

    const df = st.defender || {};
    $("defender-line").textContent = df.message || "";
    $("defender-advice").textContent = df.advice || "";
    $("defender-dot").className = "dot " + ({ ok: "ok", warn: "warn", off: "warn" }[df.level] || "none");
    const bits = [];
    if (df.signature_updated) bits.push("Definitions updated " + fmtTime(df.signature_updated));
    if (df.signature_version) bits.push("version " + df.signature_version);
    $("defender-detail").textContent = bits.join(", ");

    renderSignatures(st.signatures || {});
    $("btn-setup").disabled = !!st.setup.running;
    renderUpdates(st.updates || {}, st);

    const lb = clear($("lastscan-body"));
    const j = (st.active_jobs || [])[0] || st.last_job;
    if (!j) lb.appendChild(el("p", { class: "muted", text: "No scans yet." }));
    else {
      lb.appendChild(el("p", { class: "lead", text: (STATUS_WORDS[j.status] || j.status) + ": " + (j.short_targets || []).join(", ") }));
      lb.appendChild(el("p", { class: "muted small", text: [fmtTime(j.finished || j.started || j.created), countsSummary(j.counts)].filter(Boolean).join(". ") }));
      lb.appendChild(el("div", { class: "actions" }, el("button", { type: "button", class: "btn quiet", text: "View", onclick: () => openJob(j.id) })));
    }

    const q = st.quarantine || {};
    $("quarantine-line").textContent = q.count ? plural(q.count, "file") + ", " + fmtBytes(q.bytes) : "Empty";
    $("quarantine-note").textContent = q.message || "";
    $("data-dir").textContent = st.data_dir || "";

    const badge = $("badge-detections");
    badge.hidden = !c.open_detections;
    badge.textContent = c.open_detections || "";
    badge.className = "badge" + (c.open_malware ? " bad" : " warn");
  }

  function renderSignatures(sig) {
    const ul = clear($("sig-list"));
    if (sig.error) { ul.appendChild(el("li", { class: "muted", text: sig.error })); return; }
    for (const key of ["hash", "yara", "ml", "clamav"]) {
      const s = sig[key];
      if (!s) continue;
      const bits = [];
      if (s.count) bits.push(Number(s.count).toLocaleString() + (Number(s.count) === 1 ? " entry" : " entries"));
      if (s.updated) bits.push("updated " + fmtTime(s.updated));
      if (s.ready && s.version && !/none/.test(s.version)) bits.push("version " + s.version);
      ul.appendChild(el("li", {},
        el("span", { class: "dot " + (s.ready ? "ok" : "none") }),
        el("strong", { text: SIG_NAMES[key] }), " ",
        el("span", { text: s.message || (s.ready ? "Ready" : "Not set up yet") }),
        bits.length ? el("span", { class: "muted small block", text: bits.join(", ") }) : null));
    }
    if (!ul.firstChild) ul.appendChild(el("li", { class: "muted", text: "No signature information yet." }));
  }

  // ---- Updates card (Phase 2) ----------------------------------------------------------------
  const UPDATE_STATE_WORDS = {
    ok: "Up to date", current: "Up to date", up_to_date: "Up to date", updated: "Updated",
    checking: "Checking...", downloading: "Downloading...", staged: "New set ready: switched in after the current scan",
    waiting: "New set ready: switched in after the current scan", failed: "The last check didn't work",
    error: "The last check didn't work", offline: "No internet connection: kept the last set",
    rejected: "Update refused: kept the last good set", missing: "Not installed yet",
    not_installed: "Not installed yet", available: "Update available", disabled: "Turned off in Settings",
    unknown: "Not checked yet", rate_limited: "Waiting a while before asking again",
    not_published: "Nothing published yet",
    expired: "Paused until a new TacoGuard release is published",
  };
  const OK_STATES = ["ok", "current", "up_to_date", "updated", "available"];
  const WARN_STATES = ["failed", "error", "offline", "rejected"];

  function renderUpdates(u, st) {
    const ul = clear($("updates-list"));
    const btn = $("btn-check-updates");
    const stale = $("updates-stale");
    stale.hidden = !(u.stale && u.stale.message);
    stale.textContent = (u.stale && u.stale.message) || "";
    const rej = clear($("updates-rejected"));
    rej.hidden = !(u.rejected || []).length;
    for (const label of u.rejected || []) rej.appendChild(el("p", { text: label + ": " + u.rejected_message }));
    renderAppOffer(u.app || {}, st);

    if (!u.available) {
      ul.appendChild(el("li", { class: "muted", text: u.message || "Automatic updates are not available yet." }));
      btn.disabled = true;
      $("updates-times").textContent = "";
      $("updates-check-state").textContent = "";
      return;
    }
    for (const c of u.components || []) {
      const words = UPDATE_STATE_WORDS[c.state] || "";
      const dot = c.rejected || WARN_STATES.includes(c.state) ? "warn" : (OK_STATES.includes(c.state) ? "ok" : "none");
      const bits = [];
      if (c.version) bits.push("version " + c.version);
      if (c.updated) bits.push("updated " + fmtTime(c.updated));
      ul.appendChild(el("li", {},
        el("span", { class: "dot " + dot }),
        el("strong", { text: c.label }), " ",
        el("span", { text: c.message || words || c.state || "" }),
        bits.length ? el("span", { class: "muted small block", text: bits.join(", ") }) : null,
        c.last_error && c.last_error !== c.message ? el("span", { class: "muted small block", text: c.last_error }) : null));
    }
    if (!ul.firstChild) ul.appendChild(el("li", { class: "muted", text: u.message || "No update information yet." }));
    else if (u.message) ul.appendChild(el("li", { class: "muted", text: u.message }));
    const times = [];
    if (u.last_check) times.push("Last checked " + fmtTime(u.last_check) + ".");
    if (!u.auto_update) times.push("Automatic checks are off (Settings).");
    else if (u.next_check) times.push("Next check " + fmtTime(u.next_check) + ".");
    $("updates-times").textContent = times.join(" ");
    btn.disabled = !!u.checking;
    $("updates-check-state").textContent = u.checking ? "Checking now..." : ((u.check && u.check.error) || "");
  }

  function renderAppOffer(a, st) {
    const box = clear($("app-offer"));
    const offer = a.offer;
    const action = a.state || {};
    const busy = !!action.running || !!a.busy;
    const last = a.last_result;
    if (!offer && !(a.installed && a.previous) && !action.error && !busy && !last) { box.hidden = true; return; }
    box.hidden = false;
    if (last && !busy && !action.error) box.appendChild(el("p", { class: last.ok ? "small" : "warn-text", text: last.message }));
    if (offer) {
      const notes = (offer.notes || "").trim();
      box.appendChild(el("p", { class: "lead", text: "TacoGuard " + offer.version + " is available" +
        (notes ? ": " + notes + (/[.!?]$/.test(notes) ? "" : ".") : ".") }));
    }
    if (busy) {
      box.appendChild(el("p", { text: action.what === "rollback" ? "Going back to the previous version... the page restarts by itself." : "Installing the update... the page restarts by itself." }));
    }
    if (action.error) box.appendChild(el("p", { class: "warn-text", text: action.error }));
    else if (action.message && !busy) box.appendChild(el("p", { class: "small", text: action.message }));
    if (!a.installed) {
      if (offer && a.note) box.appendChild(el("p", { class: "muted small", text: a.note }));
      return;
    }
    const acts = el("div", { class: "actions" });
    if (offer && offer.can_install === false) {
      if (offer.message) box.appendChild(el("p", { class: "muted small", text: offer.message }));
    } else if (offer) {
      acts.appendChild(el("button", { type: "button", class: "btn primary", text: "Install update", disabled: busy,
        onclick: () => installUpdate(offer, a, st) }));
    }
    if (a.previous) {
      acts.appendChild(el("button", { type: "button", class: "btn quiet", text: "Go back to " + a.previous, disabled: busy,
        onclick: () => rollbackApp(a) }));
    }
    if (acts.firstChild) box.appendChild(acts);
  }

  function installUpdate(offer, a, st) {
    act(async () => {
      const scanning = st && (st.active_jobs || []).length;
      const res = await confirmBox({
        title: "Install TacoGuard " + offer.version + "?",
        text: [
          "TacoGuard checks the update's signature again, installs it next to the version you have now (" + a.version + ") and restarts this page. That takes about a minute.",
          scanning ? "A scan is running: let it finish or pause it first. The install won't start while a scan runs."
                   : "Scans must be finished first. Nothing is scanning right now.",
          "If the new version doesn't start properly, TacoGuard goes back to " + a.version + " by itself."],
        ok: "Install update" });
      if (!res.ok) return;
      const out = await api("/api/app/update", { version: offer.version });
      toast(out.message); watchRestart();
    });
  }

  function rollbackApp(a) {
    act(async () => {
      const res = await confirmBox({
        title: "Go back to TacoGuard " + a.previous + "?",
        text: ["TacoGuard switches back to version " + a.previous + " and restarts this page.",
          "Scans must be finished first.",
          "You can install the newer version again later from this card."],
        ok: "Go back" });
      if (!res.ok) return;
      const out = await api("/api/app/rollback", {});
      toast(out.message); watchRestart();
    });
  }

  // After Install update / Go back: the page closes and the other version starts on the same
  // port with a new page key, so wait until it went away and came back, then reload.
  function watchRestart() {
    if (state.restartWatch) return;
    state.restartWatch = true;
    clearTimeout(state.timer);
    const t0 = Date.now();
    let wentDown = false;
    const poll = async () => {
      let up = false;
      try { up = (await fetch("/api/ping", { cache: "no-store" })).ok; } catch (e) { up = false; }
      if (!up) wentDown = true;
      if (up && wentDown) { location.reload(); return; }
      if (up) {
        try {   // still this version: did the install stop with a reason?
          const st = await api("/api/status");
          state.status = st; renderHome();
          const a = (st.updates && st.updates.app && st.updates.app.state) || {};
          if (!a.running && a.error) { state.restartWatch = false; toast(a.error, "warn"); schedule(1500); return; }
        } catch (e) { /* going down */ }
      }
      if (Date.now() - t0 > 180000) {
        state.restartWatch = false;
        toast("TacoGuard's page didn't come back by itself. Start TacoGuard again from its shortcut.", "warn");
        return;
      }
      setTimeout(poll, 2000);
    };
    setTimeout(poll, 1500);
  }

  $("btn-check-updates").addEventListener("click", () => act(async () => {
    $("btn-check-updates").disabled = true;
    const out = await api("/api/updates/check", {});
    toast(out.message);
    schedule(1500);
  }).finally(() => { schedule(1500); }));

  function countsSummary(c) {
    if (!c) return "";
    const parts = [];
    if (c.files !== undefined) parts.push(Number(c.files).toLocaleString() + (Number(c.files) === 1 ? " file" : " files") + " checked");
    if (c.malware) parts.push(c.malware + " malware");
    if (c.suspicious) parts.push(c.suspicious + " suspicious");
    const nc = (Number(c.skipped) || 0) + (Number(c.unreadable) || 0);
    if (nc) parts.push(nc + " not fully checked");
    return parts.join(", ");
  }

  // ---- setup (signatures download) ----------------------------------------------------------
  const STEP_NAMES = { clamav_program: "ClamAV program", clamav_signatures: "ClamAV signatures", yara_rules: "YARA rules" };
  $("btn-setup").addEventListener("click", () => act(async () => {
    $("btn-setup").disabled = true;
    const r = await api("/api/setup", {});
    toast(r.message);
    state.setupWatch = true;
    await refreshSetup();
    schedule(1500);
  }).finally(() => { if (!state.setupWatch) $("btn-setup").disabled = false; }));

  async function refreshSetup() {
    const s = await api("/api/setup");
    $("setup-box").hidden = false;
    $("setup-state").textContent = s.running ? "Working... (started " + fmtTime(s.started) + ")"
      : (s.finished ? "Finished " + fmtTime(s.finished) + "." : "");
    const log = clear($("setup-log"));
    for (const l of (s.lines || []).slice(-12)) log.appendChild(el("li", { text: l.text }));
    const res = clear($("setup-result"));
    if (s.error) res.appendChild(el("li", { class: "warn-text", text: s.error }));
    if (s.result) {
      for (const [k, v] of Object.entries(s.result)) {
        res.appendChild(el("li", {}, el("span", { class: "dot " + (v.ok ? "ok" : "warn") }),
          el("strong", { text: (STEP_NAMES[k] || k) + ": " }), v.ok ? "done. " : "failed. ", v.message || ""));
      }
    }
    if (!s.running) {
      if (state.setupWatch) { state.setupWatch = false; $("btn-setup").disabled = false; }
    }
  }

  // ---- result cards (Scan and Detections) ---------------------------------------------------
  function resultCard(r, after) {
    const card = el("article", { class: "result " + r.level + (r.action ? " handled-" + r.action : "") });
    const head = el("h3", {});
    const body = el("p", { class: "reason", text: r.reason || "" });
    const actions = el("div", { class: "actions" });
    const name = r.short || r.path;
    const btn = (label, cls, fn, title) => el("button", { type: "button", class: "btn " + cls, text: label, title: title, onclick: fn });
    const doQuarantine = () => act(async () => {
      const out = await api("/api/result/" + r.id + "/quarantine", {});
      toast(out.message); after();
    });
    const doTrust = () => act(async () => {
      const res = await confirmBox({
        title: r.level === "malware" ? "Mark as not a threat?" : "Trust this file?",
        text: [name,
          "TacoGuard will remember this exact file by its fingerprint (SHA-256 hash) and won't flag it again, wherever it is. If the file changes, it will be checked again.",
          r.level === "malware" ? "This was a strong match. Only do this if you know where the file came from and trust it." : "Weaker matches like this are often false alarms, for example game mods or tools.",
          "You can undo this any time in the Trusted list."],
        ok: r.level === "malware" ? "Not a threat" : "Trust this file" });
      if (!res.ok) return;
      const out = await api("/api/result/" + r.id + "/trust", {});
      toast(out.message); after();
    });
    const doConfirm = () => act(async () => {
      const out = await api("/api/result/" + r.id + "/confirm", {});
      toast(out.message); after();
    });
    const doRescan = () => act(async () => {
      const out = await api("/api/scan", { targets: [r.path] });
      toast("Scanning " + name + " again.");
      openJob(out.job_id);
    });

    if (r.action === "quarantined") {
      head.textContent = "Quarantined: " + name;
      body.textContent = "It's locked away in encrypted form and can't run. Restore it only if you're sure it's safe. Why it was flagged: " + (r.reason || "");
      actions.appendChild(el("a", { class: "btn quiet", href: "#quarantine", text: "Open quarantine" }));
    } else if (r.action === "deleted") {
      head.textContent = "Deleted for good: " + name;
    } else if (r.action === "trusted") {
      head.textContent = "Trusted: " + name;
      body.textContent = "You said it's not a threat. TacoGuard won't flag this exact file again. You can undo this in the Trusted list.";
    } else if (r.action === "restored") {
      head.textContent = "Restored: " + name;
      body.textContent = "You put this file back from quarantine. Why it was flagged: " + (r.reason || "");
      actions.append(btn("Scan again", "quiet", doRescan));
    } else if (r.level === "malware") {
      head.textContent = "Malware found: " + name;
      actions.append(btn("Quarantine", "danger", doQuarantine), btn("Not a threat", "quiet", doTrust));
      if (r.action !== "confirmed") actions.append(btn("It's a threat", "link", doConfirm, "Records that you agree. TacoGuard remembers your choice."));
    } else {
      head.textContent = "Suspicious (not quarantined): " + name;
      actions.append(btn("Scan again", "quiet", doRescan), btn("Trust this file", "quiet", doTrust), btn("Quarantine", "warn", doQuarantine));
      if (r.action !== "confirmed") actions.append(btn("It's a threat", "link", doConfirm, "Records that you agree. TacoGuard remembers your choice."));
    }
    card.append(head);
    if (r.ml_score !== null && r.ml_score !== undefined) {
      card.appendChild(el("p", { class: "ml-line", text: "ML score " + Number(r.ml_score).toFixed(2) +
        (r.signature_match ? ", and a signature or rule matched too." : ", no signature match.") }));
    }
    card.append(body);
    if (r.action === "confirmed") card.appendChild(el("p", { class: "tag", text: "You confirmed this is a threat." }));
    const meta = [];
    if (r.path && r.path !== name) meta.push(r.path);
    if (r.size) meta.push(fmtBytes(r.size));
    if (r.created) meta.push("found " + fmtTime(r.created));
    if (meta.length) card.appendChild(el("p", { class: "muted small", text: meta.join("  |  ") }));
    if (actions.firstChild) card.appendChild(actions);
    return card;
  }

  function notCheckedItem(r) {
    const what = r.status === "skipped" ? "Skipped" : r.status === "unreadable" ? "Couldn't read" : "Partly checked";
    return el("li", {}, el("span", { class: "nc-kind", text: what }), " ", el("span", { class: "nc-path", text: r.short || r.path }),
      el("span", { class: "muted small block", text: r.reason || (r.notes || []).join(" ") }));
  }

  // ---- Scan ------------------------------------------------------------------------------------
  async function loadQuick() {
    if (state.quickLoaded) return;
    await act(async () => {
      const b = await api("/api/browse?path=");
      state.quickLoaded = true;
      const q = clear($("quick-picks"));
      for (const p of b.quick || []) {
        q.appendChild(el("button", { type: "button", class: "btn quiet pick", title: p.path, text: p.label, onclick: () => addTarget(p.path) }));
      }
      renderBrowse(b);
    });
  }

  async function browseTo(path) {
    await act(async () => {
      $("browse-error").hidden = true;
      const b = await api("/api/browse?path=" + encodeURIComponent(path));
      renderBrowse(b);
    }).catch(() => {});
  }
  function renderBrowse(b) {
    state.browsePath = b.path || "";
    $("browse-add").disabled = !state.browsePath;
    const crumbs = clear($("browse-crumbs"));
    crumbs.appendChild(el("button", { type: "button", class: "crumb", text: "This PC", onclick: () => browseTo("") }));
    if (b.path) {
      const parts = b.path.replace(/\\+$/, "").split("\\");
      let acc = "";
      parts.forEach((p, i) => {
        acc = i === 0 ? p + "\\" : (acc.endsWith("\\") ? acc : acc + "\\") + p;
        const target = acc;
        crumbs.append(el("span", { class: "sep", text: ">" }), el("button", { type: "button", class: "crumb", text: p, onclick: () => browseTo(target) }));
      });
    }
    const list = clear($("browse-list"));
    if (b.parent) list.appendChild(el("li", {}, el("button", { type: "button", class: "folder up", text: ".. (up one level)", onclick: () => browseTo(b.parent) })));
    for (const f of b.folders || []) {
      list.appendChild(el("li", {}, el("button", { type: "button", class: "folder", text: f.name, title: f.path, onclick: () => browseTo(f.path) })));
    }
    if (!(b.folders || []).length) list.appendChild(el("li", { class: "muted small", text: b.drives ? "No drives found." : "No sub-folders here." }));
  }
  $("browse-add").addEventListener("click", () => { if (state.browsePath) addTarget(state.browsePath); });
  $("typed-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const v = $("typed-path").value.trim().replace(/^"|"$/g, "");
    if (v) { addTarget(v); $("typed-path").value = ""; }
  });

  function addTarget(p) {
    if (!state.targets.some((t) => t.toLowerCase() === p.toLowerCase())) state.targets.push(p);
    renderTargets();
  }
  function renderTargets() {
    const ul = clear($("targets"));
    if (!state.targets.length) ul.appendChild(el("li", { class: "muted", text: "Nothing picked yet." }));
    state.targets.forEach((t, i) => {
      ul.appendChild(el("li", { class: "chip" }, el("span", { text: t }),
        el("button", { type: "button", class: "x", "aria-label": "Remove " + t, title: "Remove", text: "x",
          onclick: () => { state.targets.splice(i, 1); renderTargets(); } })));
    });
    $("btn-start").disabled = !state.targets.length;
  }
  $("btn-start").addEventListener("click", () => act(async () => {
    $("btn-start").disabled = true;
    try {
      const out = await api("/api/scan", { targets: state.targets });
      state.targets = []; renderTargets();
      openJob(out.job_id);
    } finally { $("btn-start").disabled = !state.targets.length; }
  }));

  function openJob(id) {
    state.jobId = id; state.jobSig = ""; state.notCheckedShown = 0;
    if (location.hash !== "#scan/" + id) location.hash = "#scan/" + id; else renderScan(true);
    schedule(300);
  }

  async function renderScan(force) {
    const st = state.status;
    if (st) renderHistory(st.recent_jobs || []);
    if (!state.jobId && st) {
      const j = (st.active_jobs || [])[0];
      if (j && j.id !== state.closedJob) state.jobId = j.id;
    }
    const box = $("scan-current");
    if (!state.jobId) { clear(box); return; }
    let data;
    try { data = await api("/api/scan/" + state.jobId); }
    catch (e) { clear(box).appendChild(el("p", { class: "banner warn", text: e.message })); state.jobId = null; return; }
    const sig = JSON.stringify([data.job.status, data.totals, (data.detections || []).map((r) => r.id + r.action)]);
    renderJobHeader(box, data.job);
    if (force || sig !== state.jobSig) { state.jobSig = sig; renderJobResults(data); }
  }

  function renderJobHeader(box, j) {
    let head = box.querySelector(".job");
    if (!head) {
      clear(box);
      head = el("div", { class: "panel job" });
      box.append(head, el("div", { id: "job-results" }));
    }
    clear(head);
    const active = j.status === "running" || j.status === "queued";
    head.appendChild(el("div", { class: "job-title" },
      el("h2", { text: (STATUS_WORDS[j.status] || j.status) + ": " + (j.short_targets || []).join(", ") }),
      el("button", { type: "button", class: "btn link", text: "Close", onclick: () => { state.closedJob = j.id; state.jobId = null; clear(box); if (location.hash !== "#scan") location.hash = "#scan"; } })));
    if (j.message) head.appendChild(el("p", { text: j.message }));
    if (active && j.current_short) head.appendChild(el("p", { class: "current small" }, el("span", { class: "muted", text: "Now checking: " }), el("span", { text: j.current_short })));
    const c = j.counts || {};
    const total = Number(c.total_files || c.files_total || c.total || 0);
    if (total > 0) {
      const pct = Math.min(100, Math.round((Number(c.files) || 0) * 100 / total));
      const bar = el("div", { class: "bar", role: "progressbar", "aria-valuenow": pct, "aria-valuemin": 0, "aria-valuemax": 100 }, el("span", {}));
      bar.firstChild.style.width = pct + "%";
      head.appendChild(bar);
    } else if (active) {
      head.appendChild(el("div", { class: "bar busy", "aria-hidden": "true" }, el("span", {})));
    }
    head.appendChild(countsGrid(c));
    const times = [];
    if (j.started) times.push("Started " + fmtTime(j.started));
    const secs = c.seconds || (j.started ? (j.finished || Date.now() / 1000) - j.started : 0);
    if (secs) times.push((active ? "running for " : "took ") + fmtDuration(secs));
    if (times.length) head.appendChild(el("p", { class: "muted small", text: times.join(", ") }));
    const acts = el("div", { class: "actions" });
    const control = (what, label, cls) => el("button", { type: "button", class: "btn " + cls, text: label, onclick: () => act(async () => {
      const out = await api("/api/scan/" + j.id + "/" + what, {});
      toast(out.message); schedule(300);
    }) });
    if (j.status === "running" || j.status === "queued") acts.append(control("pause", "Pause", "quiet"), control("cancel", "Cancel", "quiet"));
    if (j.status === "paused" || j.status === "interrupted") acts.append(control("resume", "Resume", "primary"), control("cancel", "Cancel", "quiet"));
    if (acts.firstChild) head.appendChild(acts);
  }

  const COUNT_LABELS = { files: "Files checked", bytes: "Data read", clean: "Clean", malware: "Malware", suspicious: "Suspicious",
                         skipped: "Skipped", unreadable: "Couldn't read", trusted: "Trusted, not checked", incomplete: "Partly checked",
                         archives_members: "Files inside archives" };
  function countsGrid(c) {
    const grid = el("dl", { class: "counts" });
    const always = ["files", "bytes", "clean", "malware", "suspicious"];
    const keys = Object.keys(COUNT_LABELS).filter((k) => c[k] !== undefined && (always.includes(k) || Number(c[k])))
      .concat(Object.keys(c).filter((k) => !(k in COUNT_LABELS) && !/total|seconds/.test(k) && typeof c[k] === "number"));
    for (const k of keys) {
      const v = k === "bytes" ? fmtBytes(c[k]) : Number(c[k]).toLocaleString();
      const cls = k === "malware" && c[k] ? "bad-text" : (k === "suspicious" && c[k] ? "warn-text" : "");
      grid.appendChild(el("div", {}, el("dt", { text: COUNT_LABELS[k] || k.replace(/_/g, " ") }), el("dd", { class: cls, text: v })));
    }
    return grid;
  }

  function renderJobResults(data) {
    const box = clear($("job-results"));
    const det = data.detections || [];
    const reload = () => { state.jobSig = ""; renderScan(true); tick(); };
    if (det.length) {
      box.appendChild(el("h2", { text: "Found (" + data.totals.detections + ")" }));
      for (const r of det) box.appendChild(resultCard(r, reload));
    } else if (data.job.status === "done") {
      box.appendChild(el("p", { class: "banner ok", text: "No malware or suspicious files found." }));
    }
    if (data.totals.trusted) box.appendChild(el("p", { class: "muted small", text: plural(data.totals.trusted, "file was", "files were") + " skipped because you trust them." }));
    const nc = data.not_checked || [];
    if (data.totals.not_checked) {
      const det2 = el("details", { class: "notchecked" }, el("summary", { text: "Not fully checked (" + data.totals.not_checked + ")" }));
      det2.appendChild(el("p", { class: "muted small", text: "These files were skipped or could only be checked in part. The reason is next to each one." }));
      const ul = el("ul", { class: "nc-list" });
      for (const r of nc) ul.appendChild(notCheckedItem(r));
      det2.appendChild(ul);
      let shown = nc.length;
      if (data.totals.not_checked > shown) {
        const more = el("button", { type: "button", class: "btn quiet", text: "Show more", onclick: () => act(async () => {
          const page = await api("/api/scan/" + data.job.id + "?section=not_checked&offset=" + shown + "&limit=200");
          for (const r of page.not_checked || []) ul.appendChild(notCheckedItem(r));
          shown += (page.not_checked || []).length;
          if (shown >= data.totals.not_checked) more.remove();
        }) });
        det2.appendChild(more);
      }
      box.appendChild(det2);
    }
  }

  function renderHistory(list) {
    const ul = clear($("scan-history"));
    if (!list.length) { ul.appendChild(el("li", { class: "muted", text: "No scans yet." })); return; }
    for (const j of list) {
      const acts = [el("button", { type: "button", class: "btn quiet", text: "View", onclick: () => openJob(j.id) })];
      if (j.status === "paused" || j.status === "interrupted") {
        acts.push(el("button", { type: "button", class: "btn quiet", text: "Resume", onclick: () => act(async () => {
          const out = await api("/api/scan/" + j.id + "/resume", {}); toast(out.message); openJob(j.id);
        }) }));
      }
      ul.appendChild(el("li", {},
        el("div", {}, el("strong", { text: (j.short_targets || []).join(", ") }),
          el("span", { class: "muted small block", text: [STATUS_WORDS[j.status] || j.status, fmtTime(j.created), countsSummary(j.counts)].filter(Boolean).join(". ") })),
        el("div", { class: "actions tight" }, acts)));
    }
  }

  // ---- Detections ------------------------------------------------------------------------------
  async function loadDetections() {
    await act(async () => {
      const d = await api("/api/detections?limit=500");
      const open = clear($("det-open")), handled = clear($("det-handled"));
      let nOpen = 0, nHandled = 0;
      const rank = (r) => (r.level === "malware" ? 0 : 1);
      const sorted = d.detections.slice().sort((a, b) => rank(a) - rank(b) || b.id - a.id);
      for (const r of sorted) {
        const waiting = !r.action || r.action === "confirmed" || r.action === "restored";
        (waiting ? open : handled).appendChild(resultCard(r, () => { loadDetections(); tick(); }));
        if (waiting) nOpen++; else nHandled++;
      }
      if (!nOpen) open.appendChild(el("p", { class: "muted", text: "Nothing waiting." }));
      $("det-handled-count").textContent = nHandled;
    });
  }

  // ---- Quarantine ------------------------------------------------------------------------------
  async function loadQuarantine() {
    await act(async () => {
      const d = await api("/api/quarantine");
      $("q-summary").textContent = (d.message ? d.message + " " : "") + (d.items.length
        ? plural(d.items.length, "file") + ", using " + fmtBytes(d.bytes) + " of disk space."
        : "Quarantine is empty.");
      const box = clear($("q-list"));
      for (const q of d.items) box.appendChild(quarantineCard(q));
    });
  }
  function quarantineCard(q) {
    const name = q.short || q.original_path;
    const restore = () => act(async () => {
      const res = await confirmBox({
        title: "Put this file back?",
        text: [name,
          "TacoGuard will decrypt it and put it back at " + q.original_path + " (or next to it with a new name if that name is taken now).",
          "Once it's back it can run again. Restore it only if you're sure it's safe."],
        check: "Also trust it, so TacoGuard doesn't flag this exact file again",
        ok: "Restore" });
      if (!res.ok) return;
      const out = await api("/api/quarantine/" + q.id + "/restore", { trust: res.checked });
      toast(out.message); loadQuarantine(); tick();
    });
    const del = () => act(async () => {
      const res = await confirmBox({
        title: "Delete this file for good?",
        text: [name,
          "The encrypted copy in quarantine will be erased. TacoGuard keeps no other copy, so this can't be undone."],
        ok: "Delete for good", danger: true });
      if (!res.ok) return;
      const out = await api("/api/quarantine/" + q.id + "/delete", {});
      toast(out.message); loadQuarantine(); tick();
    });
    return el("article", { class: "result quarantined" },
      el("h3", { text: name }),
      el("p", { class: "reason", text: q.reason || "" }),
      el("p", { class: "muted small", text: ["Quarantined " + fmtTime(q.created), fmtBytes(q.size), q.original_path].join("  |  ") }),
      el("div", { class: "actions" },
        el("button", { type: "button", class: "btn quiet", text: "Restore", onclick: restore }),
        el("button", { type: "button", class: "btn quiet danger-text", text: "Delete for good", onclick: del })));
  }

  // ---- Trusted ---------------------------------------------------------------------------------
  async function loadTrusted() {
    await act(async () => {
      const d = await api("/api/allowlist");
      const box = clear($("trusted-list"));
      if (!d.items.length) { box.appendChild(el("p", { class: "muted", text: "Your trusted list is empty." })); return; }
      const ul = el("ul", { class: "trusted" });
      for (const it of d.items) {
        ul.appendChild(el("li", {},
          el("div", {},
            el("span", { class: "nc-kind", text: it.kind === "folder" ? "Folder" : "File" }), " ",
            el("span", { class: it.kind === "hash" ? "mono" : "", text: it.short, title: it.value }),
            el("span", { class: "muted small block", text: [it.note, "added " + fmtTime(it.created)].filter(Boolean).join(". ") })),
          el("button", { type: "button", class: "btn quiet", text: "Remove", onclick: () => act(async () => {
            const out = await api("/api/allowlist/" + it.id + "/remove", {}); toast(out.message); loadTrusted();
          }) })));
      }
      box.appendChild(ul);
    });
  }
  function trustForm(formId, inputId, kind) {
    $(formId).addEventListener("submit", (e) => {
      e.preventDefault();
      const v = $(inputId).value.trim();
      if (!v) return;
      act(async () => {
        const out = await api("/api/allowlist", { kind: kind, value: v });
        $(inputId).value = ""; toast(out.message); loadTrusted();
      });
    });
  }
  trustForm("trust-folder-form", "trust-folder", "folder");
  trustForm("trust-hash-form", "trust-hash", "hash");

  // ---- Settings --------------------------------------------------------------------------------
  async function loadSettings() {
    await act(async () => {
      const s = await api("/api/settings");
      fillLimits(s);
      fillPhase2(s);
      renderSigners(s.signers || []);
      loadLearned();
      const ep = clear($("endpoints"));
      for (const e of s.endpoints) {
        ep.appendChild(el("div", { class: "endpoint" },
          el("p", {}, el("code", { text: e.host })),
          el("dl", { class: "kv" },
            el("dt", { text: "Why" }), el("dd", { text: e.why }),
            el("dt", { text: "When" }), el("dd", { text: e.when }),
            el("dt", { text: "What it sends" }), el("dd", { text: e.sends }))));
      }
      const lic = clear($("licenses"));
      lic.appendChild(el("p", { class: "muted", text: s.app + " " + s.version + " is open source under the Apache License 2.0. It uses the tools and rule sets below; each keeps its own license." }));
      if (!s.licenses.length) lic.appendChild(el("p", { class: "muted small", text: "The license list (THIRD_PARTY_LICENSES.md) was not found next to the program." }));
      s.licenses.forEach((l, i) => {
        const d = el("details", { class: "license", open: i < 2 }, el("summary", { text: l.name }));
        for (const b of l.blocks || []) d.appendChild(b.type === "table" ? licenseTable(b) : el("p", { class: "small", text: b.text }));
        lic.appendChild(d);
      });
      const paths = clear($("paths"));
      for (const [k, v] of [["Data folder", s.data_dir], ["Quarantine", s.quarantine_dir], ["Logs", s.log_dir], ["Version", s.version]]) {
        paths.append(el("dt", { text: k }), el("dd", { class: "mono", text: v }));
      }
    });
  }
  function cellContent(text) {
    // links in the license table become real links (opened in a new tab); everything else is text
    const m = /^https:\/\/[^\s]+$/.exec(text);
    return m ? el("a", { href: text, target: "_blank", rel: "noopener noreferrer", text: text.replace(/^https:\/\//, "") }) : text;
  }
  function licenseTable(b) {
    const t = el("table", { class: "lic-table" });
    t.appendChild(el("thead", {}, el("tr", {}, b.header.map((h) => el("th", { text: h })))));
    const tb = el("tbody", {});
    for (const row of b.rows) {
      tb.appendChild(el("tr", {}, row.map((c, i) => el("td", { "data-label": b.header[i] || "" }, cellContent(c)))));
    }
    t.appendChild(tb);
    return el("div", { class: "table-wrap" }, t);
  }
  function fillLimits(s) {
    const f = $("limits-form");
    for (const input of f.querySelectorAll("input[type=number]")) {
      const scale = Number(input.dataset.scale || 1);
      const v = s.limits[input.name];
      if (v === undefined) continue;
      input.value = scale > 1 ? Math.round(v / scale) : v;
      const ed = s.editable[input.name];
      if (ed) { input.min = scale > 1 ? Math.ceil(ed.min / scale) : ed.min; input.max = scale > 1 ? Math.floor(ed.max / scale) : ed.max; }
    }
    f.elements.scan_priority.value = s.scan_priority;
    f.elements.clamav_threads.value = s.clamav_threads;
    f.elements.clamav_threads.max = s.clamav_threads_max;
    f.elements.trust_signed_programs.checked = !!s.trust_signed_programs;
  }
  $("limits-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const f = e.target, body = {};
    for (const input of f.querySelectorAll("input[type=number]")) {
      if (input.value === "") continue;
      const scale = Number(input.dataset.scale || 1);
      body[input.name] = Number(input.value) * scale;
    }
    body.scan_priority = f.elements.scan_priority.value;
    body.trust_signed_programs = f.elements.trust_signed_programs.checked;
    act(async () => {
      const out = await api("/api/settings", body);
      $("limits-msg").textContent = out.message;
      fillLimits(out.settings);
    });
  });

  // ---- Settings: updates, ML, learning (Phase 2) ----------------------------------------------
  const MB = 1048576;
  function fillPhase2(s) {
    const f = $("phase2-form");
    f.elements.auto_update.checked = !!s.auto_update;
    f.elements.update_interval_h.value = s.update_interval_h;
    f.elements.ml_enabled.checked = !!s.ml_enabled;
    f.elements.ml_max_file_size.value = Math.round(Number(s.ml_max_file_size) / MB);
    f.elements.learning_enabled.checked = !!s.learning_enabled;
    f.elements.update_interval_h.disabled = !s.auto_update;
  }
  $("phase2-form").elements.auto_update.addEventListener("change", (e) => {
    $("phase2-form").elements.update_interval_h.disabled = !e.target.checked;
  });
  $("phase2-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const f = e.target;
    const body = { auto_update: f.elements.auto_update.checked, ml_enabled: f.elements.ml_enabled.checked,
                   learning_enabled: f.elements.learning_enabled.checked };
    if (f.elements.update_interval_h.value !== "") body.update_interval_h = Number(f.elements.update_interval_h.value);
    if (f.elements.ml_max_file_size.value !== "") body.ml_max_file_size = Number(f.elements.ml_max_file_size.value) * MB;
    act(async () => {
      const out = await api("/api/settings", body);
      $("phase2-msg").textContent = out.message;
      fillPhase2(out.settings);
      loadLearned();
      tick();
    });
  });

  function renderSigners(list) {
    const box = clear($("signers"));
    if (!list.length) return;
    box.appendChild(el("h3", { text: "Who signs TacoGuard's own updates" }));
    box.appendChild(el("p", { class: "muted small", text: "TacoGuard installs its own updates (the app and the ML model) only when they are signed by these keys. They are built into TacoGuard." }));
    const ul = el("ul", { class: "nc-list" });
    for (const k of list) {
      ul.appendChild(el("li", {}, el("span", { class: "mono", text: k.keyid }), " ",
        el("span", { class: "muted small", text: [k.keytype, (k.roles || []).join(" and ")].filter(Boolean).join(", ") })));
    }
    box.appendChild(ul);
  }

  const ENGINE_LABELS = { clamav: "ClamAV", yara: "YARA rule", ml: "ML model", hash: "Known-bad list" };
  async function loadLearned() {
    await act(async () => {
      const d = await api("/api/learning");
      const intro = [];
      if (!d.enabled) intro.push("Learning from your choices is off, so nothing below is used right now.");
      intro.push(d.confirmed_count
        ? "Your own known-bad list holds " + plural(d.confirmed_count, "file") + " you confirmed as a threat."
        : "Your own known-bad list is empty (files you mark \"It's a threat\" go there).");
      if (!d.rules.length) intro.push("No rules yet. When you mark " + d.threshold + " different files that matched the same rule as not a threat, that rule shows up here and counts for less.");
      $("learned-intro").textContent = intro.join(" ");
      const ul = clear($("learned-list"));
      for (const r of d.rules) {
        const forgotten = r.state === "forgotten";
        ul.appendChild(el("li", {},
          el("div", {},
            el("span", { class: "nc-kind", text: ENGINE_LABELS[r.engine] || r.engine }), " ",
            el("span", { class: "mono", text: r.rule }),
            el("span", { class: "muted small block", text: plural(r.safe_files, "file") + " marked safe" +
              (r.since ? ", since " + fmtTime(r.since) : "") + ". " + (r.state_text || "") })),
          el("button", { type: "button", class: "btn quiet", text: forgotten ? "Use again" : "Forget",
            title: forgotten ? "Use what you taught TacoGuard about this rule again" : "This rule counts normally again and TacoGuard stops learning from it",
            onclick: () => act(async () => {
              const out = await api("/api/learning/" + (forgotten ? "restore" : "forget"), { engine: r.engine, rule: r.rule });
              toast(out.message); loadLearned();
            }) })));
      }
    });
  }

  $("btn-quit").addEventListener("click", () => act(async () => {
    const res = await confirmBox({ title: "Stop TacoGuard's page?",
      text: ["This page will stop working until you start TacoGuard again."], ok: "Stop the page" });
    if (!res.ok) return;
    const out = await api("/api/quit", {});
    clearTimeout(state.timer);
    toast(out.message);
  }));

  // ---- start -----------------------------------------------------------------------------------
  showView(location.hash.slice(1) || "home");
  tick();
})();
