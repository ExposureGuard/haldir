// Haldir Cloud Dashboard — client-side logic
//
// Served at /dashboard.js by api.py and loaded by /cloud/overview.
// Auth: ?key=<hld_...> query param on every request; on the first load
// the cloud shell already validated the key in the URL, so we just read
// it back from location.search and attach Authorization: Bearer.
//
// Pages:
//   account   - tenant + tier + active agents + api keys table
//   quotas    - actions quota bar + spend + sessions + secrets
//   sessions  - sessions table
//   audit     - filterable audit trail
//   webhooks  - webhooks list
//   approvals - pending approvals + approve/deny
//   compliance- stat cards + evidence export hint
//   settings  - placeholder
//
// All hash-based navigation is handled by the shell <a href="#/page">
// links; the JS only hydrates the content on show.

(function () {
  "use strict";

  var $ = function (sel) { return document.querySelector(sel); };
  var $$ = function (sel) { return Array.prototype.slice.call(document.querySelectorAll(sel)); };
  var esc = function (s) {
    if (s == null) { return ""; }
    var d = document.createElement("div");
    d.textContent = String(s);
    return d.innerHTML;
  };

  var BASE = location.origin;
  var params = new URLSearchParams(location.search);
  var key = params.get("key") || "";

  var fmt = {
    usd: function (v) { return "$" + (Number(v) || 0).toFixed(2); },
    int: function (v) { return (Number(v) || 0).toLocaleString(); },
    time: function (ts) {
      if (!ts) { return "—"; }
      var d = new Date(ts * 1000);
      var pad = function (n) { return (n < 10 ? "0" : "") + n; };
      return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) +
             " " + pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
    }
  };

  // ── Flash ───────────────────────────────────────────────────────────
  var flashTimer = null;
  window.flash = function (msg) {
    var el = $("#flash");
    if (!el) {
      el = document.createElement("div");
      el.id = "flash";
      el.style.cssText = [
        "position:fixed", "bottom:1rem", "left:50%", "transform:translateX(-50%)",
        "background:rgba(224,221,213,0.08)", "border:1px solid rgba(224,221,213,0.2)",
        "color:var(--w)", "padding:0.5rem 1rem", "border-radius:4px",
        "font-family:var(--mono)", "font-size:0.7rem", "z-index:9999",
        "transition:opacity 0.3s", "pointer-events:none"
      ].join(";");
      document.body.appendChild(el);
    }
    el.textContent = msg;
    el.style.opacity = "1";
    clearTimeout(flashTimer);
    flashTimer = setTimeout(function () { el.style.opacity = "0"; }, 3500);
  };

  // ── API helper ──────────────────────────────────────────────────────
  function api(path, opts) {
    opts = opts || {};
    var headers = { "Content-Type": "application/json" };
    if (key) { headers["Authorization"] = "Bearer " + key; }
    if (opts.key) { headers["Authorization"] = "Bearer " + opts.key; }
    var method = (opts.method || "GET").toUpperCase();
    var r = new Request(BASE + path, {
      method: method,
      headers: headers,
      body: ("POST" === method || "PUT" === method || "PATCH" === method) ?
        (opts.body != null ? JSON.stringify(opts.body) : undefined) : undefined,
    });
    return fetch(r).then(function (resp) {
      if (!resp.ok) { throw new Error(resp.status + " " + resp.url); }
      return resp.json();
    });
  }

  // ── Page routing ────────────────────────────────────────────────────
  var pages = {
    account: $("#page-account"),
    quotas: $("#page-quotas"),
    sessions: $("#page-sessions"),
    audit: $("#page-audit"),
    webhooks: $("#page-webhooks"),
    approvals: $("#page-approvals"),
    compliance: $("#page-compliance"),
    settings: $("#page-settings"),
  };

  var navLabels = {
    account: "Account",
    quotas: "Quotas",
    sessions: "Sessions",
    audit: "Audit trail",
    webhooks: "Webhooks",
    approvals: "Approvals",
    compliance: "Compliance",
    settings: "Settings",
  };

  function showPage(name) {
    $$(".page").forEach(function (p) { p.classList.remove("active"); });
    var el = pages[name];
    if (el) { el.classList.add("active"); }
    $$(".sidebar a").forEach(function (a) {
      a.classList.toggle("active", a.getAttribute("href") === "#/" + name);
    });
    var title = $("#page-title");
    if (title) { title.textContent = navLabels[name] || name; }
  }

  // Sidebar links use href="#/page". Intercept clicks so we stay SPA.
  $$(".sidebar a[href^='#/']").forEach(function (a) {
    a.addEventListener("click", function (e) {
      e.preventDefault();
      var name = a.getAttribute("href").slice(3);
      if (pages[name]) {
        showPage(name);
        history.replaceState(null, "", "#/" + name);
        loadPage(name);
      }
    });
  });

  // Restore page from hash on load and on back/forward.
  function syncFromHash() {
    var h = location.hash.slice(1);
    var m = h.match(/^\/(\w+)$/);
    if (m && pages[m[1]]) {
      showPage(m[1]);
      loadPage(m[1]);
    } else {
      showPage("account");
      loadPage("account");
    }
  }
  window.addEventListener("hashchange", syncFromHash);

  // ── Initial load ────────────────────────────────────────────────────
  function loadInitial() {
    if (!key) { return; }
    loadPage("account");
  }

  // Boot after DOM ready.
  function boot() {
    if (params.get("demo") === "1" && !key) {
      // Demo flow handled server-side via /cloud/login; if we arrive here
      // with ?demo=1 and no key, the server already redirected us.
      showPage("account");
      return;
    }
    if (key) {
      syncFromHash();
      loadInitial();
    } else {
      showPage("account");
    }
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }

  // ── Account page ────────────────────────────────────────────────────
  function loadAccount() {
    var $t = $("#account-keys");
    if (!$t || !key) { return; }
    api("/admin/overview").then(function (o) {
      var tenant = o.tenant || {};
      $("#stat-tenant").textContent = tenant.tenant_id || "—";
      $("#stat-tier").textContent = tenant.tier || "—";
      $("#stat-agents").textContent = fmt.int(tenant.agents_active || 0);
      $("#stat-api-keys").textContent = fmt.int(tenant.api_keys || 0);

      var keys = tenant.api_keys_list || [];
      if (!keys.length) {
        $t.innerHTML = '<tr><td colspan="7" class="empty">No API keys</td></tr>';
        return;
      }
      $t.innerHTML = keys.map(function (k) {
        return '<tr>' +
          '<td class="mono">' + esc(k.key_prefix || "") + '</td>' +
          '<td>' + esc(k.name || "") + '</td>' +
          '<td>' + esc(k.tier || "") + '</td>' +
          '<td>' + esc(String(k.scopes || "—")) + '</td>' +
          '<td>' + (k.revoked ? '<span class="flag">revoked</span>' : '<span class="ok">active</span>') + '</td>' +
          '<td>' + fmt.time(k.created_at) + '</td>' +
          '<td>' + (!k.revoked ? '<button class="btn btn-red btn-sm" data-act="revoke" data-prefix="' + esc(k.key_prefix) + '">Revoke</button>' : '') + '</td>' +
          '</tr>';
      }).join("");
    }).catch(function (e) {
      $t.innerHTML = '<tr><td colspan="7" class="empty">load failed</td></tr>';
      flash("account load failed: " + e.message);
    });
    // Wire revoke buttons
    $$("[data-act='revoke']", $t).forEach(function (b) {
      b.addEventListener("click", function () {
        var prefix = b.getAttribute("data-prefix");
        if (confirm("Revoke key " + esc(prefix) + "? This cannot be undone.")) {
          api("/v1/keys/" + encodeURIComponent(prefix), { method: "DELETE" })
            .then(function () { flash("Key revoked: " + esc(prefix)); loadAccount(); })
            .catch(function (e) { flash("Revoke failed: " + (e.message || "")); });
        }
      });
    });
  }

  // ── Key management ────────────────────────────────────────────────────
  function createKey() {
    var nameInput = $("#key-name");
    var name = (nameInput && nameInput.value.trim()) || "default";
    if (!name) { flash("Enter a key name"); return; }
    api("/v1/keys", {
      method: "POST",
      body: { name: name },
    }).then(function (r) {
      flash("Key created: " + esc(r.key));
      var banner = document.createElement("div");
      banner.style.cssText = [
        "position:fixed", "top:1rem", "right:1rem", "z-index:9999",
        "background:rgba(107,189,107,0.12)", "border:1px solid var(--green)",
        "border-radius:6px", "padding:1rem 1.25rem", "max-width:380px",
        "font-family:var(--mono)", "font-size:0.7rem", "color:var(--w)",
        "box-shadow:0 4px 20px rgba(0,0,0,0.5)"
      ].join(";");
      banner.innerHTML =
        '<div style="font-weight:600;color:var(--green);margin-bottom:0.4rem;font-size:0.75rem;letter-spacing:1px;text-transform:uppercase">New API key created</div>' +
        '<div style="word-break:break-all;font-size:0.85rem;margin-bottom:0.5rem">' + esc(r.key) + '</div>' +
        '<div style="color:var(--w20);font-size:0.65rem">Copy this now — the full key is never shown again.</div>' +
        '<button onclick="this.parentElement.remove()" style="margin-top:0.5rem;background:transparent;border:none;color:var(--w50);cursor:pointer;font-size:0.6rem"> dismiss</button>';
      document.body.appendChild(banner);
      if (nameInput) { nameInput.value = ""; }
      loadAccount();
    }).catch(function (e) {
      flash("Create key failed: " + (e.message || ""));
    });
  }

  var createBtn = $("#key-create");
  if (createBtn) {
    createBtn.addEventListener("click", createKey);
  }

  // ── Webhook management ──────────────────────────────────────────────
  function createWebhook() {
    var urlInput = $("#wh-url");
    var nameInput = $("#wh-name");
    var url = (urlInput && urlInput.value.trim()) || "";
    var name = (nameInput && nameInput.value.trim()) || "";
    if (!url) { flash("Enter a webhook URL"); return; }
    api("/v1/webhooks", {
      method: "POST",
      body: { url: url, name: name },
    }).then(function (r) {
      flash("Webhook created: " + esc(r.webhook_id));
      var banner = document.createElement("div");
      banner.style.cssText = [
        "position:fixed", "top:1rem", "right:1rem", "z-index:9999",
        "background:rgba(107,189,107,0.12)", "border:1px solid var(--green)",
        "border-radius:6px", "padding:1rem 1.25rem", "max-width:380px",
        "font-family:var(--mono)", "font-size:0.7rem", "color:var(--w)",
        "box-shadow:0 4px 20px rgba(0,0,0,0.5)"
      ].join(";");
      banner.innerHTML =
        '<div style="font-weight:600;color:var(--green);margin-bottom:0.4rem;font-size:0.75rem;letter-spacing:1px;text-transform:uppercase">Webhook registered</div>' +
        '<div style="word-break:break-all;font-size:0.85rem;margin-bottom:0.5rem">' + esc(r.url) + '</div>' +
        '<div style="color:var(--w20);font-size:0.65rem">Webhook ID: ' + esc(String(r.webhook_id)) + '</div>' +
        (r.secret ? '<div style="color:var(--gold);word-break:break-all;margin-top:0.3rem">Secret: ' + esc(r.secret) + ' (save now - never shown again)</div>' : '') +
        '<button onclick="this.parentElement.remove()" style="margin-top:0.5rem;background:transparent;border:none;color:var(--w50);cursor:pointer;font-size:0.6rem"> dismiss</button>';
      document.body.appendChild(banner);
      if (urlInput) urlInput.value = "";
      if (nameInput) nameInput.value = "";
      loadWebhooks();
    }).catch(function (e) {
      flash("Create webhook failed: " + (e.message || ""));
    });
  }

  var whCreateBtn = $("#wh-create");
  if (whCreateBtn) {
    whCreateBtn.addEventListener("click", createWebhook);
  }

  // ── Quotas page ─────────────────────────────────────────────────────
  function loadQuotas() {
    if (!key) { return; }
    api("/admin/overview").then(function (o) {
      var usage = o.usage || {};
      var sessions = o.sessions || {};
      var vault = o.vault || {};
      $("#stat-actions").textContent = fmt.int(usage.actions_this_month || 0);
      var pct = (usage.actions_pct_used != null) ? (usage.actions_pct_used * 100) : 0;
      var fill = $("#stat-actions-fill");
      if (fill) {
        fill.style.width = Math.min(100, Math.max(0, pct)) + "%";
        fill.style.background = pct >= 90 ? "var(--red)" : pct >= 70 ? "var(--gold)" : "var(--green)";
      }
      $("#stat-actions-sub").textContent = pct.toFixed(1) + "% of monthly quota";
      $("#stat-spend").textContent = fmt.usd(usage.spend_usd_this_month || 0);
      $("#stat-sessions").textContent = fmt.int(sessions.active_count || 0);
      $("#stat-secrets").textContent = fmt.int(vault.secrets_count || 0);
    }).catch(function (e) {
      flash("quotas load failed: " + e.message);
    });
  }

  // ── Sessions page ───────────────────────────────────────────────────
  function loadSessions() {
    var $t = $("#sessions-body");
    if (!$t || !key) { return; }
    api("/admin/overview").then(function (o) {
      var sessions = o.sessions || {};
      var rows = sessions.sessions || [];
      if (!rows.length) {
        $t.innerHTML = '<tr><td colspan="5" class="empty">No active sessions</td></tr>';
        return;
      }
      rows.sort(function (a, b) { return (b.last_active || 0) - (a.last_active || 0); });
      $t.innerHTML = rows.map(function (r) {
        return '<tr>' +
          '<td class="mono">' + esc(r.session_id || "") + '</td>' +
          '<td>' + esc(r.agent_id || "") + '</td>' +
          '<td>' + esc(String(r.scopes || "—")) + '</td>' +
          '<td class="num">' + fmt.usd(r.spent || 0) + '</td>' +
          '<td class="num">' + fmt.time(r.last_active) + '</td>' +
          '</tr>';
      }).join("");
    }).catch(function (e) {
      $t.innerHTML = '<tr><td colspan="5" class="empty">load failed</td></tr>';
      flash("sessions load failed: " + e.message);
    });
  }

  // ── Audit trail page ────────────────────────────────────────────────
  var auditFilters = {
    session_id: "",
    agent_id: "",
    tool: "",
    flagged: false,
    limit: 100,
  };

  function loadAudit() {
    var $t = $("#audit-body");
    if (!$t || !key) { return; }
    $t.innerHTML = '<tr><td colspan="7" class="empty">loading…</td></tr>';
    var q = new URLSearchParams();
    if (auditFilters.session_id) { q.set("session_id", auditFilters.session_id); }
    if (auditFilters.agent_id) { q.set("agent_id", auditFilters.agent_id); }
    if (auditFilters.tool) { q.set("tool", auditFilters.tool); }
    if (auditFilters.flagged) { q.set("flagged", "true"); }
    q.set("limit", String(auditFilters.limit));
    api("/v1/audit?" + q.toString()).then(function (j) {
      var entries = j.entries || [];
      if (!entries.length) {
        $t.innerHTML = '<tr><td colspan="7" class="empty">No audit entries match the current filters</td></tr>';
        return;
      }
      var showAllDetails = window.__auditShowAll || false;
      $t.innerHTML = entries.map(function (e) {
        var detail_html = "";
        if (e.details) {
          var d = e.details;
          var parts = [];
          if (d.tool) parts.push('<div style="margin-bottom:0.3rem"><span style="color:var(--w20)">tool:</span> <span style="color:var(--w);font-family:var(--mono)">' + esc(String(d.tool)) + '</span></div>');
          if (d.upstream) parts.push('<div style="margin-bottom:0.3rem"><span style="color:var(--w20)">upstream:</span> <span style="color:var(--w);font-family:var(--mono)">' + esc(String(d.upstream)) + '</span></div>');
          if (d.latency_ms != null) parts.push('<div style="margin-bottom:0.3rem"><span style="color:var(--w20)">latency:</span> ' + esc(String(d.latency_ms)) + ' ms</div>');
          if (d.error != null) parts.push('<div style="margin-bottom:0.3rem"><span style="color:var(--w20)">error:</span> ' + (d.error ? '<span style="color:var(--red)">yes</span>' : '<span style="color:var(--green)">no</span>') + '</div>');
          if (d.arguments) parts.push('<div style="margin-bottom:0.3rem"><span style="color:var(--w20)">arguments:</span> <pre style="font-family:var(--mono);font-size:0.6rem;background:var(--w08);padding:0.4rem;border-radius:3px;overflow:auto;margin:0;max-height:120px">' + esc(JSON.stringify(d.arguments, null, 2)) + '</pre></div>');
          if (d.result) parts.push('<div style="margin-bottom:0.3rem"><span style="color:var(--w20)">result:</span> <pre style="font-family:var(--mono);font-size:0.6rem;background:var(--w08);padding:0.4rem;border-radius:3px;overflow:auto;margin:0;max-height:120px">' + esc(JSON.stringify(d.result, null, 2)) + '</pre></div>');
          if (d.reason) parts.push('<div style="margin-bottom:0.3rem"><span style="color:var(--w20)">reason:</span> <span style="color:var(--w);font-family:var(--mono)">' + esc(String(d.reason)) + '</span></div>');
          if (d.flag_reason) parts.push('<div style="margin-bottom:0.3rem"><span style="color:var(--w20)">flag_reason:</span> <span style="color:var(--gold);font-family:var(--mono)">' + esc(String(d.flag_reason)) + '</span></div>');
          if (d.request_id) parts.push('<div style="margin-bottom:0.3rem"><span style="color:var(--w20)">request_id:</span> <span style="color:var(--w);font-family:var(--mono)">' + esc(String(d.request_id)) + '</span></div>');
          detail_html = parts.join("");
        }
        var status_html = e.flagged
          ? '<span class="flag" title="' + esc(e.flag_reason || "flagged") + '">flagged</span>'
          : '<span class="ok">ok</span>';
        var row_class = e.flagged ? "flagged" : "";
        var _eid = esc(String(e.entry_id || ""));
        var row = '' +
          '<tr class="' + row_class + '" data-entry-id="' + _eid + '" data-has-detail="' + (detail_html ? "1" : "0") + '">' +
          '<td>' + fmt.time(e.timestamp) + '</td>' +
          '<td class="mono">' + esc(e.session_id || "") + '</td>' +
          '<td>' + esc(e.agent_id || "") + '</td>' +
          '<td>' + esc(e.tool || "") + '</td>' +
          '<td>' + esc(e.action || "") + '</td>' +
          '<td class="num">' + fmt.usd(e.cost_usd) + '</td>' +
          '<td>' + status_html + '</td>' +
          '</tr>';
        if (detail_html) {
          row += '' +
            '<tr class="detail-row" data-entry-id="' + _eid + '" style="display:' + (showAllDetails ? "" : "none") + '">' +
            '<td colspan="7" style="padding:0.75rem 1rem;background:var(--w08);border-top:1px solid var(--border);border-bottom:1px solid var(--border)">' +
            detail_html +
            '</td></tr>';
        }
        return row;
      }).join("");

      // Wire detail toggle button
      var toggleBtn = $("#audit-toggle-details");
      if (toggleBtn) {
        toggleBtn.addEventListener("click", function () {
          window.__auditShowAll = !window.__auditShowAll;
          toggleBtn.textContent = window.__auditShowAll ? "Hide details" : "Show details";
          var drows = $t.querySelectorAll(".detail-row");
          for (var i = 0; i < drows.length; i++) {
            drows[i].style.display = window.__auditShowAll ? "" : "none";
          }
        });
      }
      // Wire individual row click
      var allRows = $t.querySelectorAll("tr[data-entry-id]");
      for (var i = 0; i < allRows.length; i++) {
        allRows[i].addEventListener("click", function (ev) {
          if (ev.target.tagName === "INPUT" || ev.target.tagName === "BUTTON" || ev.target.closest && ev.target.closest("input, button")) return;
          var id = this.getAttribute("data-entry-id");
          var detail = this.nextElementSibling;
          if (detail && detail.classList && detail.classList.contains("detail-row")) {
            detail.style.display = detail.style.display === "none" ? "" : "none";
          }
        });
      }
    }).catch(function (e) {
      $t.innerHTML = '<tr><td colspan="7" class="empty">audit load failed</td></tr>';
      flash("audit load failed: " + e.message);
    });
  }

  function bindAuditFilters() {
    var session = $("#audit-session");
    var agent = $("#audit-agent");
    var tool = $("#audit-tool");
    var flagged = $("#audit-flagged");
    var limit = $("#audit-limit");
    var search = $("#audit-search");
    var clear = $("#audit-clear");
    if (!session) { return; }

    function readFilters() {
      auditFilters.session_id = session.value.trim();
      auditFilters.agent_id = agent.value.trim();
      auditFilters.tool = tool.value.trim();
      auditFilters.flagged = flagged.checked;
      var n = parseInt(limit.value, 10);
      auditFilters.limit = (n && n > 0) ? Math.min(500, n) : 100;
    }

    function apply() {
      readFilters();
      loadAudit();
    }

    if (search) { search.addEventListener("click", apply); }
    if (clear) {
      clear.addEventListener("click", function () {
        session.value = "";
        agent.value = "";
        tool.value = "";
        flagged.checked = false;
        if (limit) { limit.value = "100"; }
        readFilters();
        loadAudit();
      });
    }
    [session, agent, tool, limit].forEach(function (el) {
      if (!el) { return; }
      el.addEventListener("keydown", function (e) {
        if (e.key === "Enter") { apply(); }
      });
    });
  }

  // ── Webhooks page ───────────────────────────────────────────────────
  function loadWebhooks() {
    var $t = $("#webhooks-body");
    if (!$t || !key) { return; }
    api("/admin/overview").then(function (o) {
      var wh = o.webhooks || {};
      var rows = wh.webhooks || [];
      if (!rows.length) {
        $t.innerHTML = '<tr><td colspan="5" class="empty">No webhooks registered</td></tr>';
        return;
      }
      $t.innerHTML = rows.map(function (w) {
        return '<tr>' +
          '<td class="mono">' + esc(String(w.id || "")) + '</td>' +
          '<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis">' + esc(w.url || "") + '</td>' +
          '<td>' + esc(w.event || "—") + '</td>' +
          '<td class="num">' + esc(String(w.deliveries ?? 0)) + '</td>' +
          '<td class="num">' + esc(String(w.success_rate ?? "—")) + '</td>' +
          '<td>' + '<button class="btn btn-red btn-sm" data-act="revoke-wh" data-id="' + esc(String(w.id || "")) + '" style="font-size:0.6rem;padding:0.2rem 0.5rem">Delete</button>' + '</td>' +
          '</tr>';
      }).join("");
      // Wire delete buttons
      $$("[data-act='revoke-wh']", $t).forEach(function (b) {
        b.addEventListener("click", function () {
          var wid = b.getAttribute("data-id");
          if (confirm("Delete webhook " + esc(wid) + "?")) {
            api("/v1/webhooks/" + encodeURIComponent(wid), { method: "DELETE" })
              .then(function () { flash("Webhook deleted: " + esc(wid)); loadWebhooks(); })
              .catch(function (e) { flash("Delete failed: " + (e.message || "")); });
          }
        });
      });
    }).catch(function (e) {
      $t.innerHTML = '<tr><td colspan="5" class="empty">load failed</td></tr>';
      flash("webhooks load failed: " + e.message);
    });
  }

  // ── Approvals page ──────────────────────────────────────────────────
  function loadApprovals() {
    var $t = $("#approvals-body");
    if (!$t || !key) { return; }
    api("/v1/approvals/pending").then(function (j) {
      var pending = j.requests || [];
      if (!pending.length) {
        $t.innerHTML = '<tr><td colspan="6" class="empty">No pending approvals</td></tr>';
        return;
      }
      $t.innerHTML = pending.map(function (r) {
        var id = r.request_id || "";
        return '<tr>' +
          '<td class="mono">' + esc(id) + '</td>' +
          '<td>' + esc(r.session_id || "") + '</td>' +
          '<td>' + esc(r.requested_by || "") + '</td>' +
          '<td>' + esc(r.reason || "") + '</td>' +
          '<td>' + fmt.time(r.requested_at) + '</td>' +
          '<td>' +
            '<button class="btn-sm ok" data-act="approve" data-id="' + esc(id) + '">Allow</button> ' +
            '<button class="btn-sm" data-act="deny" data-id="' + esc(id) + '">Deny</button>' +
          '</td>' +
          '</tr>';
      }).join("");
      // Wire the allow/deny buttons
      $$("[data-act='approve']", $t).forEach(function (b) {
        b.addEventListener("click", function () { actApproval(b.getAttribute("data-id"), "approve"); });
      });
      $$("[data-act='deny']", $t).forEach(function (b) {
        b.addEventListener("click", function () { actApproval(b.getAttribute("data-id"), "deny"); });
      });
    }).catch(function (e) {
      $t.innerHTML = '<tr><td colspan="7" class="empty">load failed</td></tr>';
      flash("approvals load failed: " + e.message);
    });
  }

  function actApproval(id, decision) {
    if (!key) { return; }
    api("/v1/approvals/" + encodeURIComponent(id) + "/" + decision, {
      method: "POST",
      body: { decided_by: "cloud-dashboard" },
    }).then(function () {
      flash("Approval " + decision + "d: " + esc(id));
      loadApprovals();
    }).catch(function (e) {
      flash("Approval action failed: " + e.message);
    });
  }

  // ── Compliance page ─────────────────────────────────────────────────
  function loadCompliance() {
    if (!key) { return; }
    Promise.all([
      api("/v1/compliance/score"),
      api("/v1/compliance/schedules")
    ]).then(function(results) {
      var score = results[0];
      var schedules = results[1];
      var s = score.score != null ? score.score : 0;
      var scoreEl = $("#stat-compliance-score");
      if (scoreEl) {
        scoreEl.textContent = s + "/100";
        scoreEl.style.color = s >= 80 ? "var(--green)" : s >= 60 ? "var(--gold)" : "var(--red)";
      }
      var schedEl = $("#stat-compliance-schedules");
      if (schedEl) {
        var list = schedules.schedules != null ? schedules.schedules : [];
        schedEl.textContent = list.length;
      }
      var nextEl = $("#stat-compliance-next");
      if (nextEl) {
        var nd = schedules.next_due != null ? schedules.next_due : null;
        nextEl.textContent = nd ? new Date(nd * 1000).toLocaleDateString() : "—";
      }
    }).catch(function(e) {
      flash("compliance load failed: " + (e.message || ""));
    });
  }

  function exportEvidence() {
    if (!key) { return; }
    flash("Generating evidence pack...");
    var since = document.getElementById("evidence-since") && document.getElementById("evidence-since").value || "90d";
    var format = document.getElementById("evidence-format") && document.getElementById("evidence-format").value || "markdown";
    api("/v1/compliance/evidence?since=" + encodeURIComponent(since) + "&format=" + encodeURIComponent(format), {
      method: "GET"
    }).then(function(body) {
      var blob = new Blob([body], { type: "text/markdown; charset=utf-8" });
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url;
      a.download = "haldir-evidence.md";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      flash("Evidence pack exported");
    }).catch(function(e) {
      flash("Evidence export failed: " + (e.message || ""));
    });
  }

  function loadSettings() {
    if (!key) { return; }
    api("/admin/overview").then(function(o) {
      var t = o.tenant || {};
      var tierEl = $("#stat-settings-tier");
      if (tierEl) tierEl.textContent = t.tier || "—";
      var tenantEl = $("#stat-settings-tenant");
      if (tenantEl) tenantEl.textContent = t.tenant_id || "—";
      var keyEl = $("#stat-settings-key");
      if (keyEl) keyEl.textContent = key;
    }).catch(function(e) {
      flash("settings load failed: " + (e.message || ""));
    });
  }

  // ── Page router ─────────────────────────────────────────────────────
  function loadPage(name) {
    if (name === "account") { loadAccount(); }
    else if (name === "quotas") { loadQuotas(); }
    else if (name === "sessions") { loadSessions(); }
    else if (name === "audit") { loadAudit(); }
    else if (name === "webhooks") { loadWebhooks(); }
    else if (name === "approvals") { loadApprovals(); }
    else if (name === "compliance") { loadCompliance(); }
    else if (name === "settings") { loadSettings(); }
  }

  // Bind audit filters on boot
  bindAuditFilters();
})();
