"use strict";
// Every piece of server data is inserted as TEXT (createElement + text nodes). innerHTML and friends are never used (tests enforce it).
const API = "/api/v1";
const $ = (s) => document.querySelector(s);

function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v === true) n.setAttribute(k, "");
    else if (v !== false && v != null) n.setAttribute(k, v);
  }
  for (const c of kids.flat()) n.append(c instanceof Node ? c : String(c ?? ""));
  return n;
}
const field = (label, input) => el("label", {}, label, input);
const clear = (n) => n.replaceChildren();

function say(text, error = false) {
  const box = $("#msg");
  clear(box);
  if (text) box.append(el("p", { class: error ? "error" : "" }, text));
}

class ApiError extends Error { constructor(status, text) { super(text); this.status = status; } }

function detailText(d) {
  if (!d || d.detail == null) return "Request failed";
  if (typeof d.detail === "string") return d.detail;
  if (Array.isArray(d.detail)) return d.detail.map((x) => `${(x.loc || []).slice(1).join(".") || "input"}: ${x.msg}`).join("; ");
  return "Request failed";
}

async function api(path, { method = "GET", json, form } = {}) {
  const opt = { method, credentials: "same-origin", headers: {} };
  if (json !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(json); }
  if (form) opt.body = form;  // the browser sets Origin and the multipart boundary itself
  const r = await fetch(API + path, opt);
  let data = null;
  try { data = await r.json(); } catch (_) { /* empty body */ }
  if (!r.ok) throw new ApiError(r.status, detailText(data));
  return data;
}

// run an action, show errors, never leave an unhandled rejection
const guard = (fn) => async (ev) => {
  if (ev && ev.preventDefault) ev.preventDefault();
  try { await fn(ev); } catch (e) { say(e.message || "Something went wrong", true); }
};

// "12.50" -> 1250 without floating point
function toCents(text) {
  const m = /^(\d{1,9})(?:\.(\d{1,2}))?$/.exec(text.trim());
  if (!m) throw new Error("Amount must look like 12 or 12.50");
  return parseInt(m[1], 10) * 100 + parseInt((m[2] || "").padEnd(2, "0") || "0", 10);
}
const money = (c, cur) => `${Math.floor(c / 100)}.${String(c % 100).padStart(2, "0")} ${cur}`;

// ------------------------------------------------------------------ table with paging
function pagedTable(path, columns, extra = "") {
  const wrap = el("div"), PAGE = 50;
  let offset = 0;
  async function load() {
    const data = await api(`${path}?limit=${PAGE}&offset=${offset}${extra}`);
    const rows = data.items || [];
    const head = el("tr", {}, columns.map((c) => el("th", {}, c.title)));
    const body = rows.map((r) => el("tr", {}, columns.map((c) => el("td", {}, c.cell(r)))));
    clear(wrap);
    wrap.append(el("div", { class: "tablewrap" }, el("table", {}, el("thead", {}, head), el("tbody", {}, body))));
    if (!rows.length) wrap.append(el("p", { class: "muted" }, "Nothing here yet."));
    wrap.append(el("div", { class: "row" },
      el("button", { type: "button", disabled: offset === 0, onclick: guard(async () => { offset = Math.max(0, offset - PAGE); await load(); }) }, "Previous"),
      el("button", { type: "button", disabled: rows.length < PAGE, onclick: guard(async () => { offset += PAGE; await load(); }) }, "Next")));
  }
  wrap.reload = guard(load);
  wrap.reload();
  return wrap;
}

const short = (s) => (s || "").slice(0, 12) + (s && s.length > 12 ? "…" : "");

// ------------------------------------------------------------------ views
function evidenceView(me) {
  const root = el("div");
  const list = pagedTable("/evidence/list", [
    { title: "ID", cell: (r) => r.id }, { title: "Type", cell: (r) => r.file_type }, { title: "Description", cell: (r) => r.description },
    { title: "Location", cell: (r) => r.location || "" }, { title: "Created", cell: (r) => r.created_at },
    { title: "File HMAC", cell: (r) => el("code", {}, short(r.file_hmac)) },
    { title: "", cell: (r) => el("a", { class: "button", href: `${API}/evidence/${Number(r.id)}/download` }, "Download") },
  ]);
  if (me.role === "whistleblower") {
    const file = el("input", { type: "file", required: true, accept: ".jpg,.jpeg,.png,.pdf,.mp4" });
    const desc = el("textarea", { required: true, maxlength: 2000, rows: 3 });
    const loc = el("input", { type: "text", maxlength: 200 });
    root.append(el("h2", {}, "Upload evidence"), el("form", { onsubmit: guard(async () => {
      const f = new FormData();
      f.append("file", file.files[0]); f.append("description", desc.value); if (loc.value) f.append("location", loc.value);
      const r = await api("/evidence/upload", { method: "POST", form: f });
      say(`Uploaded as evidence #${r.id}. Ledger block ${r.ledger_block}.`);
      file.value = desc.value = loc.value = ""; list.reload();
    }) }, field("File (JPEG, PNG, PDF or MP4)", file), field("Description", desc), field("Location (optional)", loc), el("button", { class: "primary", type: "submit" }, "Upload")),
    el("p", { class: "muted" }, "Photo, video and PDF metadata is removed where possible, but not GPS tracks stored inside videos. Remove location at the source for sensitive footage."));
  }
  root.append(el("h2", {}, "Evidence"), list);
  return root;
}

function reliefView(me) {
  const root = el("div");
  const list = pagedTable("/relief/ledger", [
    { title: "ID", cell: (r) => r.id }, { title: "Amount", cell: (r) => money(r.amount_cents, r.currency) }, { title: "Category", cell: (r) => r.category },
    { title: "Recipient", cell: (r) => r.recipient_name }, { title: "Destination", cell: (r) => r.destination }, { title: "Status", cell: (r) => r.status },
    { title: "", cell: (r) => {
      if (me.role !== "relief_worker") return "";
      const act = (status, label) => el("button", { type: "button", onclick: guard(async () => {
        await api(`/relief/${Number(r.id)}/status`, { method: "PUT", json: { status } }); say(`Relief #${r.id}: ${status}`); list.reload();
      }) }, label);
      if (r.status === "pending" && r.worker_id === me.id) return act("in_transit", "Dispatch");
      if (r.status === "in_transit" && r.worker_id !== me.id) return act("delivered", "Confirm delivered");
      return "";
    } },
  ]);
  if (me.role === "relief_worker") {
    const amount = el("input", { type: "text", inputmode: "decimal", required: true });
    const cur = el("select", {}, ["USD", "EUR", "GBP"].map((c) => el("option", {}, c)));
    const cat = el("select", {}, ["food", "medical", "shelter", "cash", "other"].map((c) => el("option", {}, c)));
    const name = el("input", { type: "text", required: true, maxlength: 200 });
    const det = el("input", { type: "text", maxlength: 1000 });
    const dest = el("input", { type: "text", required: true, maxlength: 300 });
    root.append(el("h2", {}, "Allocate relief"), el("form", { onsubmit: guard(async () => {
      const body = { amount_cents: toCents(amount.value), currency: cur.value, category: cat.value, recipient_name: name.value, destination: dest.value };
      if (det.value) body.recipient_details = det.value;
      const r = await api("/relief/allocate", { method: "POST", json: body });
      say(`Allocation #${r.id} recorded (ledger block ${r.ledger_block}).`); list.reload();
    }) }, field("Amount (e.g. 25.50)", amount), field("Currency", cur), field("Category", cat), field("Recipient name", name),
    field("Recipient details (optional)", det), field("Destination", dest), el("button", { class: "primary", type: "submit" }, "Allocate")));
  }
  root.append(el("h2", {}, "Relief ledger"), el("p", { class: "muted" }, "Delivery must be confirmed by a different worker than the one who allocated it."), list);
  return root;
}

function landView(me) {
  const root = el("div");
  const list = pagedTable("/land/list", [
    { title: "ID", cell: (r) => r.id }, { title: "Owner", cell: (r) => r.owner_name }, { title: "Location", cell: (r) => r.location },
    { title: "Area", cell: (r) => r.area_size }, { title: "Status", cell: (r) => r.status },
    { title: "", cell: (r) => {
      if (me.role !== "hr_auditor" || r.status !== "pending") return "";
      const verdict = (status) => el("button", { type: "button", onclick: guard(async () => {
        await api(`/land/verify/${Number(r.id)}`, { method: "PUT", json: { status } }); say(`Land #${r.id}: ${status}. Decisions are final.`); list.reload();
      }) }, status);
      return el("div", { class: "row" }, verdict("verified"), verdict("disputed"), verdict("rejected"));
    } },
  ]);
  if (me.role === "whistleblower" || me.role === "relief_worker") {
    const owner = el("input", { type: "text", required: true, maxlength: 200 });
    const loc = el("input", { type: "text", required: true, maxlength: 300 });
    const area = el("input", { type: "text", required: true, maxlength: 100 });
    root.append(el("h2", {}, "Register land"), el("form", { onsubmit: guard(async () => {
      const r = await api("/land/register", { method: "POST", json: { owner_name: owner.value, location: loc.value, area_size: area.value } });
      say(`Land claim #${r.id} registered.`); owner.value = loc.value = area.value = ""; list.reload();
    }) }, field("Owner name", owner), field("Location", loc), field("Area (e.g. 2 ha)", area), el("button", { class: "primary", type: "submit" }, "Register")));
  }
  root.append(el("h2", {}, "Land claims"), list);
  return root;
}

function usersView(me) {
  const list = pagedTable("/system/users", [
    { title: "ID", cell: (r) => r.id }, { title: "Email", cell: (r) => r.email }, { title: "Name", cell: (r) => r.name },
    { title: "Role", cell: (r) => {
      const sel = el("select", { disabled: r.id === me.id, "aria-label": `Role of user ${Number(r.id)}` },
        ["whistleblower", "relief_worker", "hr_auditor", "admin"].map((x) => el("option", { value: x, selected: x === r.role }, x)));
      sel.addEventListener("change", guard(async () => { await api(`/system/users/${Number(r.id)}/role`, { method: "PUT", json: { role: sel.value } }); say("Role updated."); list.reload(); }));
      return sel;
    } },
    { title: "Active", cell: (r) => {
      const cb = el("input", { type: "checkbox", checked: r.is_active, disabled: r.id === me.id, "aria-label": `Active: user ${Number(r.id)}` });
      cb.addEventListener("change", guard(async () => { await api(`/system/users/${Number(r.id)}/status`, { method: "PUT", json: { is_active: cb.checked } }); say("Status updated."); list.reload(); }));
      return cb;
    } },
    { title: "2FA", cell: (r) => (r.is_2fa_enabled ? "on" : "off") },
    { title: "", cell: (r) => (r.id === me.id ? "" : el("button", { type: "button", onclick: guard(async () => {
      if (!confirm(`Reset 2FA for user ${r.id}? They must enrol again.`)) return;
      await api(`/system/users/${Number(r.id)}/reset-2fa`, { method: "POST" }); say("2FA reset; their sessions were signed out."); list.reload();
    }) }, "Reset 2FA")) },
  ]);
  return el("div", {}, el("h2", {}, "Users"), list);
}

function signupsView() {
  const list = pagedTable("/system/signups", [
    { title: "ID", cell: (r) => r.id }, { title: "Email", cell: (r) => r.email }, { title: "Name", cell: (r) => r.name }, { title: "Requested", cell: (r) => r.created_at },
    { title: "", cell: (r) => {
      const role = el("select", { "aria-label": `Role for sign-up ${Number(r.id)}` }, ["whistleblower", "relief_worker", "hr_auditor", "admin"].map((x) => el("option", {}, x)));
      return el("div", { class: "row" }, role,
        el("button", { type: "button", onclick: guard(async () => { await api(`/system/signups/${Number(r.id)}/approve`, { method: "POST", json: { role: role.value } }); say("Approved."); list.reload(); }) }, "Approve"),
        el("button", { type: "button", onclick: guard(async () => { await api(`/system/signups/${Number(r.id)}/reject`, { method: "POST" }); say("Rejected."); list.reload(); }) }, "Reject"));
    } },
  ]);
  return el("div", {}, el("h2", {}, "Pending sign-ups"), el("p", { class: "muted" }, "Unapproved Google accounts wait here for 7 days."), list);
}

function auditView() {
  return el("div", {}, el("h2", {}, "Audit log"), el("p", { class: "muted" }, "Operational log: useful, but not tamper-evident. The ledger is the tamper-evident record."),
    el("a", { class: "button", href: `${API}/system/audit-logs/csv?limit=100` }, "Download CSV (latest 100)"),
    pagedTable("/system/audit-logs", [
      { title: "Time", cell: (r) => r.timestamp }, { title: "User", cell: (r) => r.user_id }, { title: "Role", cell: (r) => r.role },
      { title: "Action", cell: (r) => r.action }, { title: "Endpoint", cell: (r) => r.endpoint }, { title: "Status", cell: (r) => r.status_code },
    ]));
}

function chainView() {
  const out = el("div", { "aria-live": "polite" });
  return el("div", {}, el("h2", {}, "Ledger check"),
    el("p", { class: "muted" }, "Recomputes every hash and signature and compares the ledger with the database and the stored anchors."),
    el("button", { class: "primary", type: "button", onclick: guard(async () => {
      const r = await api("/system/verify-chain");
      clear(out);
      out.append(el("p", { class: r.is_valid ? "ok" : "bad" }, r.is_valid ? `Ledger is valid: ${r.blocks} blocks, ${r.anchors_checked} anchors checked.` : `PROBLEM: ${r.error_type} at block ${r.broken_at_block ?? "-"}. ${r.detail}`));
      if (r.tip_hash) out.append(el("p", {}, "Tip block ", String(r.tip_block), ": ", el("code", {}, r.tip_hash)), el("p", { class: "muted" }, "Record this tip hash somewhere the server cannot change."));
      if (r.warning) out.append(el("p", { class: "bad" }, r.warning));
    }) }, "Verify now"), out);
}

function accountView(me) {
  const code = el("input", { type: "text", required: true, minlength: 6, maxlength: 12, autocomplete: "off" });
  return el("div", {}, el("h2", {}, "Account"), el("p", {}, `Signed in as user #${me.id} (${me.role}).`),
    el("h2", {}, "Duress code"),
    el("p", { class: "muted" }, "6-12 letters and digits with at least one letter. Typing it instead of your 2FA code opens a decoy workspace. Choose something you will remember under stress, and never write it down."),
    el("form", { onsubmit: guard(async () => { await api("/auth/duress", { method: "PUT", json: { code: code.value } }); code.value = ""; say("Duress code saved."); }) },
      field("New duress code", code), el("button", { type: "submit" }, "Save duress code")),
    el("button", { type: "button", onclick: guard(async () => { await api("/auth/logout", { method: "POST" }); location.reload(); }) }, "Sign out"));
}

const TABS = {
  whistleblower: [["Evidence", evidenceView], ["Land", landView], ["Account", accountView]],
  relief_worker: [["Relief", reliefView], ["Land", landView], ["Account", accountView]],
  hr_auditor: [["Evidence", evidenceView], ["Relief", reliefView], ["Land", landView], ["Ledger check", chainView], ["Account", accountView]],
  admin: [["Evidence", evidenceView], ["Relief", reliefView], ["Land", landView], ["Users", usersView], ["Sign-ups", signupsView], ["Audit log", auditView], ["Ledger check", chainView], ["Account", accountView]],
};

function showApp(me) {
  const app = $("#app"), panel = el("section"), nav = el("nav", { "aria-label": "Sections" });
  $("#who").textContent = `${me.role} #${me.id}`;
  const tabs = TABS[me.role] || [["Account", accountView]];
  const open = (i) => {
    say("");
    [...nav.children].forEach((b, j) => b.setAttribute("aria-current", String(i === j)));
    clear(panel); panel.append(tabs[i][1](me));
  };
  tabs.forEach(([name], i) => nav.append(el("button", { type: "button", onclick: () => open(i) }, name)));
  clear(app); app.append(nav, panel); open(0);
}

function showLogin() {
  const app = $("#app"), out = el("div"), code = el("input", { type: "text", required: true, minlength: 6, maxlength: 12, autocomplete: "one-time-code", inputmode: "text" });
  $("#who").textContent = "";
  clear(app);
  app.append(
    el("h2", {}, "1. Sign in"), el("p", {}, el("a", { class: "button primary", href: "/login" }, "Sign in with Google")),
    el("h2", {}, "2. Two-factor code"),
    el("form", { onsubmit: guard(async () => {
      await api("/auth/2fa/verify", { method: "POST", json: { code: code.value } });
      await start();
    }) }, field("6-digit code from your authenticator app", code), el("button", { class: "primary", type: "submit" }, "Continue")),
    el("h2", {}, "First time?"), el("p", { class: "muted" }, "After signing in with Google, set up your authenticator app once. An admin can reset it if you lose it."),
    el("button", { type: "button", onclick: guard(async () => {
      const r = await api("/auth/2fa/setup", { method: "POST" });
      clear(out);
      out.append(el("p", {}, "Add this secret to your authenticator app, then enter the first code above:"), el("p", {}, el("code", {}, r.secret)), el("p", { class: "muted" }, "Or use this link: "), el("code", {}, r.otpauth_uri));
    }) }, "Set up 2FA"), out);
}

async function start() {
  try { showApp(await api("/auth/me")); } catch (e) { if (e.status === 401) showLogin(); else { showLogin(); say(e.message, true); } }
}
start();
