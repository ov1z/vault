"use strict";

// ---- SVG icon set (Lucide-style, monochrome line icons) --------------------
const ICONS = {
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  more: '<circle cx="12" cy="5" r="1.4"/><circle cx="12" cy="12" r="1.4"/><circle cx="12" cy="19" r="1.4"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>',
  eyeOff: '<path d="M9.9 4.5A9.7 9.7 0 0 1 12 5c6.5 0 10 7 10 7a13 13 0 0 1-2.2 3"/><path d="M6.6 6.7A12.9 12.9 0 0 0 2 12s3.5 7 10 7a9.6 9.6 0 0 0 4.4-1"/><path d="M3 3l18 18"/><path d="M9.4 9.4a3 3 0 0 0 4.2 4.2"/>',
  copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  refresh: '<path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/><path d="M3 21v-5h5"/>',
  trash: '<path d="M3 6h18"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2"/>',
  edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
  key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.5 12.5 20 3"/><path d="m16 7 3 3"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  link: '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14 21 3"/>',
};

function svg(name) {
  return `<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor"
    stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICONS[name] || ""}</svg>`;
}

// ---- bridge helpers --------------------------------------------------------
let API = null;

function whenReady() {
  return new Promise((resolve) => {
    if (window.pywebview && window.pywebview.api) return resolve();
    window.addEventListener("pywebviewready", () => resolve(), { once: true });
  });
}

const $ = (id) => document.getElementById(id);
const show = (el) => el.classList.remove("hidden");
const hide = (el) => el.classList.add("hidden");

let toastTimer = null;
function toast(msg, isError = false) {
  const t = $("toast");
  t.innerHTML = `<span class="dot"></span>${esc(msg)}`;
  t.classList.toggle("err", isError);
  show(t);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => hide(t), 1600);
}

async function copy(text, label = "コピーしました") {
  if (!text) return;
  const res = await API.copy_clipboard(text);
  if (res.ok) toast(label);
  else toast("コピー失敗: " + res.error, true);
}

function esc(s) {
  return (s || "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// SECURITY: only http(s) URLs become clickable links. Anything else
// (javascript:, data:, file:, vbscript: ...) is rendered as inert text, so a
// crafted URL can never execute code in this privileged (api-bearing) context.
function safeUrl(url) {
  const u = (url || "").trim();
  return /^https?:\/\//i.test(u) ? u : null;
}

function paintStaticIcons() {
  document.querySelectorAll("[data-ic]").forEach((el) => {
    el.innerHTML = svg(el.dataset.ic);
  });
}

// ---- state -----------------------------------------------------------------
let items = [];
let selectedId = null;
let totpTimer = null;

// ---- gate (setup / unlock) -------------------------------------------------
function pwStrength(pw) {
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  return Math.min(s, 4);
}
function renderMeter(pw) {
  const s = pwStrength(pw);
  const bar = $("setup-meter-bar");
  bar.style.width = [6, 30, 55, 80, 100][s] + "%";
  bar.style.background = ["#e5484d", "#e5484d", "#d9904a", "#9bbf4a", "#30a46c"][s];
}

// VeraCrypt non-system-volume formula (public; mirrors the backend).
function pimToIterations(pimRaw) {
  const pim = Math.max(0, parseInt(pimRaw || "0", 10) || 0);
  return pim === 0 ? 500000 : 15000 + pim * 1000;
}
function iterHint(pimRaw) {
  const pim = Math.max(0, parseInt(pimRaw || "0", 10) || 0);
  const iters = pimToIterations(pim);
  const n = iters.toLocaleString("en-US");
  if (pim === 0) return `PBKDF2-SHA512 反復回数: ${n}（標準）`;
  // VeraCrypt non-system formula: PIM < 485 gives fewer iters than the 500k default.
  const rel = iters < 500000 ? " — 標準500,000より弱い(速い)"
            : iters > 500000 ? " — 標準より強い(遅い)" : "";
  return `PBKDF2-SHA512 反復回数: ${n}（PIM ${pim}${rel}）`;
}
const pimVal = (id) => Math.max(0, parseInt($(id).value || "0", 10) || 0);

function showGate(initialized) {
  stopTotp();
  hide($("app"));
  show($("gate"));
  if (initialized) {
    hide($("setup-form"));
    show($("unlock-form"));
    $("unlock-pw").focus();
  } else {
    show($("setup-form"));
    hide($("unlock-form"));
    $("setup-pw").focus();
  }
}

// ---- main app --------------------------------------------------------------
async function enterApp() {
  hide($("gate"));
  show($("app"));
  await refreshList();
  $("search").value = "";
  startAutoLock();
  $("search").focus();
}

async function refreshList() {
  const res = await API.list_items();
  if (!res.ok) { toast(res.error, true); return; }
  items = res.items;
  renderList();
}

function filteredItems() {
  const q = $("search").value.trim().toLowerCase();
  if (!q) return items;
  return items.filter((i) =>
    (i.title || "").toLowerCase().includes(q) ||
    (i.username || "").toLowerCase().includes(q) ||
    (i.url || "").toLowerCase().includes(q));
}

function monogram(title) {
  return (title || "?").trim().charAt(0).toUpperCase() || "?";
}

function renderList() {
  const list = filteredItems();
  $("count").textContent = `${items.length} 件`;
  const ul = $("item-list");

  if (items.length === 0) { ul.innerHTML = ""; show($("empty-list")); return; }
  hide($("empty-list"));

  ul.innerHTML = list.map((i) => `
    <li class="item ${i.id === selectedId ? "active" : ""}" data-id="${i.id}">
      <span class="it-mono">${esc(monogram(i.title))}</span>
      <span class="it-text">
        <span class="it-title">${esc(i.title) || "(無題)"}</span>
        <span class="it-sub">${esc(i.username) || esc(i.url) || "&nbsp;"}</span>
      </span>
      ${i.has_totp ? `<span class="it-badge" title="2FA">${svg("clock")}</span>` : ""}
    </li>`).join("");

  ul.querySelectorAll(".item").forEach((el) =>
    el.addEventListener("click", () => selectItem(el.dataset.id)));

  if (selectedId && !list.some((i) => i.id === selectedId)) clearDetail();
}

function clearDetail() {
  selectedId = null;
  stopTotp();
  hide($("detail-body"));
  show($("detail-empty"));
}

async function selectItem(id) {
  selectedId = id;
  renderList();
  const res = await API.get_item(id);
  if (!res.ok) { toast(res.error, true); return; }
  renderDetail(res.item);
}

function copyRow(label, value, isMono) {
  return `
    <div class="field">
      <div class="flbl">${label}</div>
      <div class="val-row">
        <span class="val ${isMono ? "mono" : ""}">${esc(value)}</span>
        <button class="icon-btn" data-copy="${esc(value)}" title="コピー">${svg("copy")}</button>
      </div>
    </div>`;
}

function renderDetail(item) {
  stopTotp();
  hide($("detail-empty"));
  const body = $("detail-body");
  const pwId = "pw-" + item.id;

  const totpField = (item.totp || "").trim() ? `
    <div class="field totp-field">
      <div class="flbl">ワンタイムコード (2FA)</div>
      <div class="totp-row">
        <span class="totp-code" id="totp-code">······</span>
        <span class="totp-secs" id="totp-secs"></span>
        <span class="totp-ring" id="totp-ring"></span>
        <button class="icon-btn" id="totp-copy" title="コピー">${svg("copy")}</button>
      </div>
    </div>` : "";

  const href = safeUrl(item.url);
  const urlField = item.url ? `
    <div class="field">
      <div class="flbl">URL</div>
      <div class="val-row">
        ${href
          ? `<a class="val" href="${esc(href)}" target="_blank" rel="noreferrer noopener">${esc(item.url)}</a>`
          : `<span class="val">${esc(item.url)}</span>`}
        <button class="icon-btn" data-copy="${esc(item.url)}" title="コピー">${svg("copy")}</button>
      </div>
    </div>` : "";

  body.innerHTML = `
    <div class="detail-head">
      <span class="it-mono">${esc(monogram(item.title))}</span>
      <div>
        <h2>${esc(item.title)}</h2>
        <div class="sub">${esc(item.username) || ""}</div>
      </div>
      <div class="detail-actions">
        <button class="icon-btn" id="edit-btn" title="編集">${svg("edit")}</button>
        <button class="icon-btn" id="del-btn" title="削除">${svg("trash")}</button>
      </div>
    </div>

    ${item.username ? copyRow("ユーザー名", item.username, false) : ""}

    <div class="field">
      <div class="flbl">パスワード</div>
      <div class="val-row">
        <span class="val mono" id="${pwId}">••••••••••••</span>
        <button class="icon-btn" id="reveal-btn" title="表示">${svg("eye")}</button>
        <button class="icon-btn" data-copy="${esc(item.password)}" title="コピー">${svg("copy")}</button>
      </div>
    </div>

    ${totpField}

    ${urlField}

    ${item.notes ? `
    <div class="field">
      <div class="flbl">メモ</div>
      <div class="val notes-val">${esc(item.notes)}</div>
    </div>` : ""}

    <div class="meta-line">更新 ${esc(item.updated)} ・ 作成 ${esc(item.created)}</div>
  `;
  show(body);

  let revealed = false;
  $("reveal-btn").addEventListener("click", (e) => {
    revealed = !revealed;
    $(pwId).textContent = revealed ? (item.password || "") : "••••••••••••";
    e.currentTarget.innerHTML = svg(revealed ? "eyeOff" : "eye");
  });
  body.querySelectorAll("[data-copy]").forEach((btn) =>
    btn.addEventListener("click", () => copy(btn.dataset.copy)));
  $("edit-btn").addEventListener("click", () => openEditor(item));
  $("del-btn").addEventListener("click", () => confirmDelete(item));

  if ((item.totp || "").trim()) startTotp(item.id);
}

// ---- TOTP live refresh -----------------------------------------------------
function stopTotp() {
  if (totpTimer) { clearInterval(totpTimer); totpTimer = null; }
}
async function tickTotp(id) {
  const res = await API.totp_code(id);
  const codeEl = $("totp-code"), secsEl = $("totp-secs"), ring = $("totp-ring");
  if (!codeEl) { stopTotp(); return; }
  if (!res.ok) {
    codeEl.textContent = "シークレットが不正";
    codeEl.classList.add("bad");
    if (secsEl) secsEl.textContent = "";
    if (ring) ring.style.setProperty("--p", 0);
    if ($("totp-copy")) $("totp-copy").style.display = "none";
    return;
  }
  const c = res.code;
  codeEl.textContent = c.length > 4 ? c.slice(0, c.length / 2 | 0) + " " + c.slice(c.length / 2 | 0) : c;
  codeEl.classList.remove("bad");
  if (secsEl) secsEl.textContent = res.remaining + "s";
  if (ring) ring.style.setProperty("--p", Math.round(res.remaining / res.period * 100));
  const copyBtn = $("totp-copy");
  if (copyBtn) { copyBtn.style.display = ""; copyBtn.onclick = () => copy(c, "コードをコピー"); }
}
function startTotp(id) {
  stopTotp();
  tickTotp(id);
  totpTimer = setInterval(() => tickTotp(id), 1000);
}

// ---- editor modal ----------------------------------------------------------
function openEditor(item) {
  $("modal-title").textContent = item ? "項目を編集" : "新規項目";
  $("f-id").value = item ? item.id : "";
  $("f-title").value = item ? item.title : "";
  $("f-username").value = item ? item.username : "";
  $("f-password").value = item ? item.password : "";
  $("f-totp").value = item ? (item.totp || "") : "";
  $("f-url").value = item ? item.url : "";
  $("f-notes").value = item ? item.notes : "";
  $("form-error").textContent = "";
  checkTotpField();
  show($("modal"));
  $("f-title").focus();
}
const closeEditor = () => hide($("modal"));

async function checkTotpField() {
  const hint = $("f-totp-hint");
  const val = $("f-totp").value.trim();
  if (!val) { hint.textContent = ""; hint.className = "totp-hint"; return; }
  const res = await API.totp_check(val);
  if (res.ok) { hint.textContent = "✓ 有効 — 現在のコード " + res.code; hint.className = "totp-hint ok"; }
  else { hint.textContent = "シークレットを認識できません"; hint.className = "totp-hint bad"; }
}

async function saveItem(e) {
  e.preventDefault();
  const id = $("f-id").value;
  const data = {
    title: $("f-title").value,
    username: $("f-username").value,
    password: $("f-password").value,
    totp: $("f-totp").value.trim(),
    url: $("f-url").value,
    notes: $("f-notes").value,
  };
  if (!data.title.trim()) { $("form-error").textContent = "タイトルは必須です"; return; }
  const res = id ? await API.update_item(id, data) : await API.add_item(data);
  if (!res.ok) { $("form-error").textContent = res.error; return; }
  closeEditor();
  await refreshList();
  await selectItem(res.item.id);
  toast(id ? "更新しました" : "追加しました");
}

async function genPassword() {
  const res = await API.generate_password({
    length: parseInt($("gen-len").value, 10),
    uppercase: $("gen-upper").checked,
    lowercase: $("gen-lower").checked,
    digits: $("gen-digit").checked,
    symbols: $("gen-sym").checked,
    avoid_ambiguous: $("gen-amb").checked,
  });
  if (res.ok) $("f-password").value = res.password;
  else toast(res.error, true);
}

// ---- delete confirm --------------------------------------------------------
let pendingDelete = null;
function confirmDelete(item) {
  pendingDelete = item.id;
  $("confirm-text").textContent = `「${item.title}」を削除しますか？この操作は取り消せません。`;
  show($("confirm"));
}
async function doDelete() {
  hide($("confirm"));
  if (!pendingDelete) return;
  const res = await API.delete_item(pendingDelete);
  pendingDelete = null;
  if (!res.ok) { toast(res.error, true); return; }
  clearDetail();
  await refreshList();
  toast("削除しました");
}

// ---- auto-lock -------------------------------------------------------------
let autoLockMin = parseInt(localStorage.getItem("vault.autolock") ?? "5", 10);
let lastActivity = 0;
let autoLockTimer = null;

function nowMs() { return performance.now(); }
function bumpActivity() { lastActivity = nowMs(); }

function startAutoLock() {
  bumpActivity();
  if (autoLockTimer) clearInterval(autoLockTimer);
  if (!autoLockMin) return;  // off
  autoLockTimer = setInterval(() => {
    if (!autoLockMin) return;
    if (nowMs() - lastActivity >= autoLockMin * 60000) doLock(true);
  }, 5000);
}
function stopAutoLock() { if (autoLockTimer) { clearInterval(autoLockTimer); autoLockTimer = null; } }

async function doLock(auto = false) {
  stopAutoLock();
  stopTotp();
  await API.lock();
  items = []; selectedId = null;
  document.querySelectorAll(".modal-backdrop").forEach(hide);
  showGate(true);
  if (auto) toast("自動ロックしました");
}

// ---- wiring ----------------------------------------------------------------
function wire() {
  // setup
  $("setup-pw").addEventListener("input", (e) => renderMeter(e.target.value));
  $("setup-iter").textContent = iterHint(0);
  $("setup-pim").addEventListener("input", (e) => ($("setup-iter").textContent = iterHint(e.target.value)));
  $("setup-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = $("setup-pw").value, pw2 = $("setup-pw2").value, err = $("setup-error");
    if (pw.length < 8) { err.textContent = "8文字以上にしてください"; return; }
    if (pw !== pw2) { err.textContent = "パスワードが一致しません"; return; }
    const res = await API.init_vault(pw, pimVal("setup-pim"));
    if (!res.ok) { err.textContent = res.error; return; }
    await enterApp();
  });

  // unlock
  $("unlock-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const res = await API.unlock($("unlock-pw").value, pimVal("unlock-pim"));
    if (!res.ok) { $("unlock-error").textContent = res.error; $("unlock-pw").select(); return; }
    $("unlock-pw").value = ""; $("unlock-pim").value = ""; $("unlock-error").textContent = "";
    await enterApp();
  });

  // top bar
  $("search").addEventListener("input", renderList);
  $("new-btn").addEventListener("click", () => openEditor(null));
  $("empty-new").addEventListener("click", () => openEditor(null));
  $("lock-btn").addEventListener("click", () => doLock(false));
  $("menu-btn").addEventListener("click", (e) => { e.stopPropagation(); $("menu").classList.toggle("hidden"); });
  document.addEventListener("click", (e) => {
    if (!$("menu").contains(e.target) && e.target !== $("menu-btn")) hide($("menu"));
  });
  $("menu-changepw").addEventListener("click", () => {
    hide($("menu"));
    ["cpw-old", "cpw-old-pim", "cpw-new", "cpw-new2", "cpw-new-pim"].forEach((id) => ($(id).value = ""));
    $("cpw-error").textContent = "";
    $("cpw-iter").textContent = iterHint(0);
    show($("cpw-modal"));
  });
  $("cpw-new-pim").addEventListener("input", (e) => ($("cpw-iter").textContent = iterHint(e.target.value)));

  // auto-lock setting
  const sel = $("autolock-sel");
  sel.value = String(autoLockMin);
  sel.addEventListener("change", () => {
    autoLockMin = parseInt(sel.value, 10);
    localStorage.setItem("vault.autolock", String(autoLockMin));
    startAutoLock();
    toast(autoLockMin ? `自動ロック: ${autoLockMin}分` : "自動ロック: オフ");
  });

  // editor
  $("item-form").addEventListener("submit", saveItem);
  $("modal-cancel").addEventListener("click", closeEditor);
  $("f-gen").addEventListener("click", genPassword);
  $("f-totp").addEventListener("input", checkTotpField);
  $("gen-len").addEventListener("input", (e) => ($("gen-len-val").textContent = e.target.value));

  // change password
  $("cpw-cancel").addEventListener("click", () => hide($("cpw-modal")));
  $("cpw-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const oldp = $("cpw-old").value, np = $("cpw-new").value, np2 = $("cpw-new2").value, err = $("cpw-error");
    if (np.length < 8) { err.textContent = "新しいパスワードは8文字以上"; return; }
    if (np !== np2) { err.textContent = "新しいパスワードが一致しません"; return; }
    const res = await API.change_password(oldp, np, pimVal("cpw-old-pim"), pimVal("cpw-new-pim"));
    if (!res.ok) { err.textContent = res.error; return; }
    hide($("cpw-modal"));
    toast("マスターパスワード / PIM を変更しました");
  });

  // confirm
  $("confirm-no").addEventListener("click", () => { pendingDelete = null; hide($("confirm")); });
  $("confirm-yes").addEventListener("click", doDelete);

  // modal backdrop / escape
  document.querySelectorAll(".modal-backdrop").forEach((bd) =>
    bd.addEventListener("mousedown", (e) => { if (e.target === bd) hide(bd); }));
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") document.querySelectorAll(".modal-backdrop").forEach(hide);
    if (e.key === "l" && e.ctrlKey && !$("app").classList.contains("hidden")) { e.preventDefault(); doLock(false); }
  });

  // activity tracking for auto-lock
  ["mousemove", "keydown", "click", "input", "wheel"].forEach((ev) =>
    document.addEventListener(ev, bumpActivity, { passive: true }));
}

// ---- boot ------------------------------------------------------------------
(async function boot() {
  await whenReady();
  API = window.pywebview.api;
  paintStaticIcons();
  wire();
  const res = await API.status();
  showGate(res.initialized);
})();
