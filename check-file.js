// Check a file: AFTER-GEN draft (spec/drafts/after-gen.md, "How a verifier checks a file").
// Everything runs here. The file never leaves the device; when it carries no record, only its
// media/1 hash goes to the registries of the signed directory.
import { loadDirectory, mediaHash, readAfterGen, checkAfterGen, checkAfterGenStatus } from "/packages/verify-js/index.js";

const TEST_STEWARD = "78c95e45a79c5e271fdec762b92c2ec1b27d6d08e512b7a94779de2429868ef0"; // signs only the test directory
const $ = (id) => document.getElementById(id);
const result = $("result");

function step(id, state, note) {
  const li = $(id);
  li.dataset.state = state;
  li.textContent = li.dataset.label + (note ? ": " + note : "");
}

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function say(verdict, why) {
  result.replaceChildren(el("p", verdict, "cf-verdict"));
  if (why) result.append(el("p", why, "cf-why"));
}

const when = (t) => (t == null ? "" : new Date(t * 1000).toISOString().slice(0, 16).replace("T", " ") + " UTC");
const list = (xs) => (xs.length === 1 && xs[0] === "*" ? "anywhere" : xs.join(", "));

async function getJson(url) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 8000);
  try {
    const res = await fetch(url, { signal: ctl.signal, redirect: "error", credentials: "omit" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } finally { clearTimeout(t); }
}

// The registry's own API, from the signed directory: a record's status is asked there and nowhere else.
function apiFor(directory, code) {
  const r = directory.registryFor(code);
  return r && /^https:\/\//.test(r.api) ? r.api.replace(/\/$/, "") : null;
}

async function findByHash(directory, hash) {
  const found = [];
  await Promise.all(directory.registries.filter((r) => /^https:\/\//.test(r.api || "")).map(async (r) => {
    try {
      const api = r.api.replace(/\/$/, "");
      const { records } = await getJson(`${api}/v2/after-gen?media=${hash}`);
      for (const id of Array.isArray(records) ? records.slice(0, 20) : []) {
        if (!/^[0-9a-f]{64}$/.test(id)) continue;
        const { record } = await getJson(`${api}/v2/after-gen/${id}`);
        found.push(record);
      }
    } catch { /* a registry that does not answer is skipped */ }
  }));
  return found;
}

function show(summary, status) {
  const s = summary.scope;
  const state = status.state === "active" ? "In force"
    : status.state === "withdrawn" ? `Withdrawn by the person on ${when(status.withdrawn_at)}`
    : status.state === "expired" ? `Expired on ${when(status.not_after)}`
    : "Not confirmed by the registry today";
  say(status.state === "active" ? "Approved after generation" : "Approved after generation, no longer in force",
    `${summary.approvedBy} The registry signed this record on ${when(summary.issued_at)}.`);
  const rows = [
    ["Status today", state],
    ["Person", summary.subject_ref],
    ["Registry", summary.prefix],
    ["Who may publish it", summary.holder],
    ["Licence", summary.licence],
    ["Use of the licence", summary.use.of == null ? `use ${summary.use.n}` : `use ${summary.use.n} of ${summary.use.of}`],
    ["Project", s.project],
    ["Purposes", s.purposes.join(", ")],
    ["Content categories declared", s.categories.length ? s.categories.join(", ") : "none"],
    ["Territories", list(s.territories)],
    ["Channels", list(s.channels)],
    ["Until", when(s.not_after)],
    ["Approved by", summary.approvedBy],
    ["File fingerprint", `${summary.content.binding} ${summary.content.hash}`],
    ["Record", summary.id],
  ];
  const table = el("table", undefined, "cf-table");
  for (const [k, v] of rows) {
    const tr = el("tr");
    tr.append(el("th", k), el("td", String(v)));
    table.append(tr);
  }
  result.append(table, el("p", summary.notice, "meta"));
}

async function check(file) {
  result.replaceChildren();
  $("steps").hidden = false;
  for (const id of ["s-hash", "s-find", "s-sign", "s-status"]) step(id, "", "");
  const sandbox = $("sandbox").checked;

  step("s-hash", "busy");
  let media;
  try {
    media = await mediaHash(file);
    step("s-hash", "ok", media.hash.slice(0, 16) + "…");
  } catch (e) {
    step("s-hash", "fail");
    return say("This file cannot be checked", `${e.message}. This version checks MP4 and MOV files that are not fragmented or encrypted.`);
  }

  let directory;
  try {
    directory = await loadDirectory(sandbox ? { url: "/test/registries.json", stewardPublicKeyHex: TEST_STEWARD }
                                            : { url: "/registries.json" });
  } catch (e) {
    return say("The list of registries could not be loaded", e.message);
  }

  step("s-find", "busy");
  let records = [];
  try {
    const inFile = await readAfterGen(file);
    records = [inFile.c2pa, inFile.xmp].filter(Boolean);
  } catch { /* unreadable metadata: look the hash up instead */ }
  const fromFile = records.length > 0;
  if (!fromFile) records = await findByHash(directory, media.hash);
  if (!records.length) {
    step("s-find", "fail");
    return say("No approval found for this file",
      "The file carries no AFTER-GEN record, and no registry holds one for its fingerprint. This says nothing about whether the video is permitted, generated or real.");
  }
  step("s-find", "ok", fromFile ? "in the file's metadata" : "at the registry, by the file's fingerprint");

  step("s-sign", "busy");
  let summary, env, lastError;
  for (const r of records) {
    try { summary = await checkAfterGen(r, { directory, media }); env = r; break; } catch (e) { lastError = e; }
  }
  if (!summary) {
    step("s-sign", "fail");
    const msg = lastError?.message || "";
    if (/not for this file/.test(msg)) {
      return say("The record in this file belongs to another file",
        "The record names a different video. A record copied into another file approves nothing.");
    }
    if (/may not sign|unknown_issuer|revoked|not listed|directory/.test(msg)) {
      say("The record is not signed by a listed registry",
        sandbox ? "No registry in the test directory signed it. It approves nothing."
                : "No registry in the signed list of registries signed it, so it approves nothing. A record from a test registry checks only with \"Test registries only\" ticked.");
      return result.append(el("p", msg, "meta"));
    }
    say("The record does not check out", "It approves nothing.");
    return result.append(el("p", msg, "meta"));
  }
  step("s-sign", "ok", `registry ${summary.prefix}`);

  step("s-status", "busy");
  try {
    const api = apiFor(directory, summary.subject_ref);
    if (!api) throw new Error("the registry has no https API in the directory");
    const { status } = await getJson(`${api}/v2/after-gen/${summary.id}`);
    const st = await checkAfterGenStatus(status, env, { directory });
    step("s-status", "ok", st.state);
    show(summary, st);
  } catch (e) {
    step("s-status", "fail");
    show(summary, { state: "unknown", not_after: summary.scope.not_after });
    result.firstChild.textContent = "Approved after generation, status not confirmed";
    result.insertBefore(el("p", `The registry did not confirm the status today (${e.message}). It may have been withdrawn.`, "cf-why"), result.children[1]);
  }
}

for (const li of $("steps").children) li.dataset.label = li.textContent;
$("file").addEventListener("change", (e) => { if (e.target.files[0]) check(e.target.files[0]); });
const drop = $("drop");
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("over");
  if (e.dataTransfer.files[0]) check(e.dataTransfer.files[0]);
});
