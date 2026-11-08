"use strict";

/*
 * Offline BIP39 web UI - client logic.
 *
 * All cryptographic work happens server-side (seed_server.py, which
 * reuses seed_generator.py). This file only handles UI state and
 * per-cell input validation. It never prints transcript/entropy/
 * mnemonic values to the console and never uses any storage or
 * clipboard API. The last generated mnemonic is kept in page memory
 * only so it can be handed to the Verify tab; Clear Session and a
 * page reload wipe it.
 */

// Display-only hints; the server re-validates everything authoritatively.
const REQUIRED_COUNT = {
  dice: { 128: 50, 256: 100 },
  cards: { 128: 35, 256: 70 },
};
const MAX_VALUE = { dice: 6, cards: 13 };

const state = {
  mode: "dice",
  bits: 128,
  cells: [],        // <input> elements in order
  busy: false,
};

// In-page cache of the last generated mnemonic, used only for the
// Generate -> Verify tab handoff. Wiped by Clear Session; gone on
// page reload; never stored, copied, or sent anywhere else.
let lastMnemonic = "";
// 600 ms debounce timer for auto-verify in the Verify tab.
let verifyTimer = 0;
// In-flight guard so a manual click and the debounce never overlap.
let verifying = false;

const $ = (id) => document.getElementById(id);

const inputGrid = $("input-grid");
const progressFill = $("progress-fill");
const progressLabel = $("progress-label");
const requiredInfo = $("required-info");
const inputError = $("input-error");
const btnGenerate = $("btn-generate");
const btnClear = $("btn-clear");
const resultSection = $("result");
const checksumBadge = $("checksum-badge");
const resultMeta = $("result-meta");
const wordGrid = $("word-grid");
const verifyInput = $("verify-input");
const verifyError = $("verify-error");
const verifyResult = $("verify-result");
const verifyBadge = $("verify-badge");
const verifyDetail = $("verify-detail");
const btnVerify = $("btn-verify");
const btnClearVerify = $("btn-clear-verify");
const tabGenerate = $("tab-generate");
const tabVerify = $("tab-verify");
const panelGenerate = $("panel-generate");
const panelVerify = $("panel-verify");
const btnSendVerify = $("btn-send-verify");
const verifyCount = $("verify-count");

// ---------------------------------------------------------------------------
// Per-cell validation (UX only; the server is authoritative)
// ---------------------------------------------------------------------------

function cellPattern() {
  return state.mode === "dice" ? /^[1-6]$/
    : (/^(?:[1-9]|1[0-3])$|^[ajqkAJQK]$/);
}

function isCellValid(value) {
  return cellPattern().test(value);
}

function requiredCount() {
  return REQUIRED_COUNT[state.mode][state.bits];
}

function updateRequiredInfo() {
  const n = requiredCount();
  const max = MAX_VALUE[state.mode];
  const noun = state.mode === "dice" ? "dice rolls" : "card outcomes";
  const alias = state.mode === "cards" ? ", or A/J/Q/K" : "";
  requiredInfo.textContent =
    `Required: exactly ${n} ${noun} (values 1\u2013${max}${alias}). ` +
    `${state.bits}-bit entropy \u2192 ${state.bits === 128 ? 12 : 24} words.`;
}

function buildGrid() {
  inputGrid.innerHTML = "";
  state.cells = [];
  const n = requiredCount();
  for (let i = 0; i < n; i += 1) {
    const cell = document.createElement("label");
    cell.className = "cell";

    const idx = document.createElement("span");
    idx.className = "cell-idx";
    idx.textContent = String(i + 1);

    const input = document.createElement("input");
    input.type = "text";
    input.maxLength = 2;
    input.autocomplete = "off";
    input.spellcheck = false;
    input.setAttribute("aria-label", `outcome ${i + 1}`);
    input.addEventListener("input", onCellInput);

    cell.append(idx, input);
    inputGrid.append(cell);
    state.cells.push(input);
  }
  updateRequiredInfo();
  onCellInput();
}

function onCellInput() {
  let allValid = true;
  for (const inp of state.cells) {
    const value = inp.value.trim();
    const ok = value === "" || isCellValid(value);
    inp.classList.toggle("invalid", !ok);
    inp.closest(".cell").classList.toggle("invalid", !ok);
    if (value !== "" && !ok) allValid = false;
  }
  updateProgress();
  return allValid;
}

function updateProgress() {
  const n = requiredCount();
  const filled = state.cells
    .filter((inp) => isCellValid(inp.value.trim())).length;
  progressLabel.textContent = `${filled} / ${n} entered`;
  progressFill.style.width = `${(filled / n) * 100}%`;
  btnGenerate.disabled = state.busy || filled !== n;
}

// ---------------------------------------------------------------------------
// Configuration changes (mode / bit size)
// ---------------------------------------------------------------------------

function onConfigChanged() {
  const mode = document.querySelector('input[name="mode"]:checked').value;
  const bits = Number(document.querySelector('input[name="bits"]:checked').value);
  if (mode === state.mode && bits === state.bits) return;

  const hasContent = state.cells.some((inp) => inp.value.trim() !== "");
  if (hasContent && !window.confirm(
      "Changing mode or bit size clears all entered values. Continue?")) {
    // Restore the previous radio selections.
    document.querySelector(
      `input[name="mode"][value="${state.mode}"]`).checked = true;
    document.querySelector(
      `input[name="bits"][value="${state.bits}"]`).checked = true;
    return;
  }

  state.mode = mode;
  state.bits = bits;
  clearResult();
  hideInputError();
  buildGrid();
}

// ---------------------------------------------------------------------------
// Generate
// ---------------------------------------------------------------------------

async function generate() {
  if (state.busy) return;
  const values = state.cells.map((inp) => inp.value.trim());
  const badIndex = values.findIndex((v) => v === "" || !isCellValid(v));
  if (badIndex !== -1) {
    showInputError(
      `Fill every cell with a valid ${state.mode} value ` +
      `(cell ${badIndex + 1}).`);
    return;
  }

  hideInputError();
  state.busy = true;
  btnGenerate.disabled = true;
  try {
    const resp = await fetch("/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // Loopback-only; the transcript never appears in a URL or log.
      body: JSON.stringify({
        mode: state.mode,
        bits: state.bits,
        transcript: values.join(" "),
      }),
    });
    let data = null;
    try { data = await resp.json(); } catch (_) { data = null; }
    if (!resp.ok || !data) {
      showInputError(
        data && data.error ? data.error : `Server error (HTTP ${resp.status}).`);
      return;
    }
    renderResult(data);
  } catch (_) {
    showInputError("Could not reach the local server. Is it running?");
  } finally {
    state.busy = false;
    updateProgress();
  }
}

function renderResult(data) {
  wordGrid.innerHTML = "";
  wordGrid.className = `word-grid words-${data.word_count}`;
  data.words.forEach((word, i) => {
    const item = document.createElement("div");
    item.className = "word-item";
    const num = document.createElement("span");
    num.className = "word-idx";
    num.textContent = String(i + 1);
    const span = document.createElement("span");
    span.className = "word";
    span.textContent = word;
    item.append(num, span);
    wordGrid.append(item);
  });
  checksumBadge.textContent =
    data.checksum_valid ? "BIP39 checksum: VALID" : "BIP39 checksum: INVALID";
  checksumBadge.className = `badge ${data.checksum_valid ? "ok" : "bad"}`;
  resultMeta.textContent =
    `${data.mode} mode \u00b7 ${data.bits}-bit entropy \u00b7 ` +
    `${data.word_count} words \u00b7 checksum auto-verified`;
  resultSection.hidden = false;
  // Remember the result (in page memory only) for the Verify-tab handoff.
  lastMnemonic = data.words.join(" ");
  btnSendVerify.disabled = false;
}

function clearResult() {
  wordGrid.innerHTML = "";
  resultSection.hidden = true;
  lastMnemonic = "";
  btnSendVerify.disabled = true;
}


// ---------------------------------------------------------------------------
// Verify tab
// ---------------------------------------------------------------------------

async function verify() {
  const mnemonic = verifyInput.value.trim();
  if (!mnemonic) {
    showVerifyError("Paste a 12- or 24-word mnemonic first.");
    return;
  }
  if (verifying) return;
  verifying = true;
  hideVerifyError();
  try {
    const resp = await fetch("/api/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mnemonic }),
    });
    let data = null;
    try { data = await resp.json(); } catch (_) { data = null; }
    if (!resp.ok || !data) {
      showVerifyError(
        data && data.error ? data.error : `Server error (HTTP ${resp.status}).`);
      return;
    }
    if (data.valid) {
      verifyBadge.textContent = "VALID BIP39 CHECKSUM";
      verifyBadge.className = "badge ok";
      verifyDetail.textContent =
        `${data.word_count} words \u00b7 ${data.entropy_size_bits}-bit entropy.`;
    } else {
      verifyBadge.textContent = "INVALID";
      verifyBadge.className = "badge bad";
      verifyDetail.textContent = data.reason || "Unknown error.";
    }
    verifyResult.hidden = false;
  } catch (_) {
    showVerifyError("Could not reach the local server. Is it running?");
  } finally {
    verifying = false;
  }
}

function updateVerifyCount() {
  const text = verifyInput.value.trim();
  const n = text ? text.split(/\s+/).length : 0;
  if (n === 0) {
    verifyCount.hidden = true;
    return;
  }
  verifyCount.hidden = false;
  verifyCount.textContent =
    (n === 12 || n === 24)
      ? `${n} words \u2014 ready to verify`
      : `${n} words (need exactly 12 or 24)`;
}

function onVerifyInput() {
  updateVerifyCount();
  clearTimeout(verifyTimer);
  const text = verifyInput.value.trim();
  const n = text ? text.split(/\s+/).length : 0;
  // Auto-verify shortly after the last keystroke once the word count
  // is exactly 12 or 24.
  if (n === 12 || n === 24) {
    verifyTimer = setTimeout(verify, 600);
  }
}

function clearVerify() {
  clearTimeout(verifyTimer);
  verifyInput.value = "";
  verifyResult.hidden = true;
  hideVerifyError();
  verifyCount.hidden = true;
}

async function sendToVerify() {
  if (!lastMnemonic) return;
  clearTimeout(verifyTimer);
  verifyInput.value = lastMnemonic;
  updateVerifyCount();
  showTab("verify");
  await verify();
}

// ---------------------------------------------------------------------------
// Clear session / tabs / error helpers
// ---------------------------------------------------------------------------

async function clearSession() {
  if (!window.confirm(
      "Clear all inputs and results? This cannot be undone.")) return;
  for (const inp of state.cells) inp.value = "";
  onCellInput();
  hideInputError();
  clearResult();
  clearVerify();
  try {
    await fetch("/api/reset", { method: "POST" });
  } catch (_) {
    /* best effort; the server is stateless */
  }
}

function showTab(name) {
  const showGenerate = name === "generate";
  tabGenerate.classList.toggle("active", showGenerate);
  tabVerify.classList.toggle("active", !showGenerate);
  tabGenerate.setAttribute("aria-selected", showGenerate ? "true" : "false");
  tabVerify.setAttribute("aria-selected", showGenerate ? "false" : "true");
  panelGenerate.hidden = !showGenerate;
  panelVerify.hidden = showGenerate;
}

function showInputError(msg) {
  inputError.textContent = msg;
  inputError.hidden = false;
}
function hideInputError() {
  inputError.hidden = true;
}
function showVerifyError(msg) {
  verifyError.textContent = msg;
  verifyError.hidden = false;
}
function hideVerifyError() {
  verifyError.hidden = true;
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  tabGenerate.addEventListener("click", () => showTab("generate"));
  tabVerify.addEventListener("click", () => showTab("verify"));
  document.querySelectorAll('input[name="mode"], input[name="bits"]')
    .forEach((el) => el.addEventListener("change", onConfigChanged));
  btnGenerate.addEventListener("click", generate);
  btnClear.addEventListener("click", clearSession);
  btnVerify.addEventListener("click", verify);
  btnClearVerify.addEventListener("click", clearVerify);
  btnSendVerify.addEventListener("click", sendToVerify);
  verifyInput.addEventListener("input", onVerifyInput);
  buildGrid();
});
