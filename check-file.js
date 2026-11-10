// Check a file: AFTER-GEN draft (spec/drafts/after-gen.md, "How a verifier checks a file").
// Everything runs here. The file never leaves the device; when it carries no record, only its
// media/1 hash goes to the registries of the signed directory.
import { loadDirectory, mediaHash, readAfterGen, checkAfterGen, checkAfterGenStatus, afterGenCodes } from "/packages/verify-js/index.js";

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

// The PG- spelling is no longer issued: never shown, also not inside a library's error message.
const noPg = (m) => String(m).replace(/\bPG-[0-9A-Z*~$=!-]+/g, "the person's code");

// One block per record that checks out: a file may show several people. `codes` are computed from the record.
function show(summary, status, error, codes) {
  const s = summary.scope;
  const state = status.state === "active" ? "In force"
    : status.state === "withdrawn" ? `Withdrawn by the person on ${when(status.withdrawn_at)}`
    : status.state === "expired" ? `Expired on ${when(status.not_after)}`
    : "Not confirmed by the registry today";
  // Nothing is shown in the PG- spelling, which is no longer issued: the person is named by the approval's ToG code
  // until the PG to TOG folding rule lands.
  const who = codes.Code || `a person at registry ${summary.prefix}`;
  const block = el("section", undefined, "cf-record");
  block.append(el("p", status.state === "active" ? `Approved after generation: ${who}`
    : status.state === "unknown" ? `A record for ${who} was found, but whether it stands today could not be confirmed`
    : `Approved after generation, no longer in force: ${who}`, "cf-verdict"));
  block.append(el("p", error
    ? `The registry did not answer for its status (${error}). The person may have withdrawn it. Treat it as not confirmed until the registry answers.`
    : `${summary.approvedBy} The registry signed this record on ${when(summary.issued_at)}.`, "cf-why"));
  const rows = [
    ["Status today", state],
    ...(codes.Code ? [["Approval code", codes.Code]] : []),
    ["Registry", summary.prefix],
    ["Who may publish it", summary.holder],
    ...(summary.basis.kind === "terms" ? [["Basis: the person's terms", summary.basis.terms]] : [
      ["Licence", summary.basis.licence.id],
      ...(codes.Licence ? [["Licence code", codes.Licence]] : []),
      ["Use of the licence", summary.basis.use.of == null ? `use ${summary.basis.use.n}` : `use ${summary.basis.use.n} of ${summary.basis.use.of}`],
    ]),
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
  block.append(table, el("p", summary.notice, "meta"));
  result.append(block);
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

  // Every record is collected, from the file and from the registries by the fingerprint, so a planted record cannot
  // hide a real one, and a file that shows several people shows every record.
  step("s-find", "busy");
  // The readable codes in XMP are copies beside its record: checked with that record only.
  let inFile = [];
  try {
    const found = await readAfterGen(file);
    inFile = [found.c2pa && { env: found.c2pa }, found.xmp && { env: found.xmp, codes: found.codes }].filter(Boolean);
  } catch { /* unreadable metadata: the registries are asked anyway */ }
  const held = await findByHash(directory, media.hash);
  const records = inFile.concat(held.map((env) => ({ env })));
  if (!records.length) {
    step("s-find", "fail");
    return say("No approval found for this file",
      "The file carries no AFTER-GEN record, and no registry holds one for its fingerprint. This says nothing about whether the video is permitted, generated or real.");
  }
  step("s-find", "ok", [inFile.length && "in the file's metadata", held.length && "at the registry, by the file's fingerprint"]
    .filter(Boolean).join("; "));

  step("s-sign", "busy");
  const good = new Map();
  let lastError;
  for (const { env, codes } of records) {
    try {
      const summary = await checkAfterGen(env, { directory, media, codes });
      if (!good.has(summary.id)) good.set(summary.id, { summary, env, codes: await afterGenCodes(env) });
    } catch (e) { lastError = e; }
  }
  if (!good.size) {
    step("s-sign", "fail");
    const msg = noPg(lastError?.message || "");
    if (/not for this file/.test(msg)) {
      return say("The record in this file belongs to another file",
        "The record names a different video. A record copied into another file approves nothing.");
    }
    if (/readable code/.test(msg)) {
      return say("The code written in this file does not match its record",
        "A code is a copy for people to read: it must be the one computed from the signed record. It approves nothing.");
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
  step("s-sign", "ok", good.size === 1 ? "1 record" : `${good.size} records`);
  if (lastError) result.append(el("p", `Some records found for this file do not check out and are not shown (${noPg(lastError.message)}).`, "meta"));

  step("s-status", "busy");
  let confirmed = 0;
  for (const { summary, env, codes } of good.values()) {
    try {
      const api = apiFor(directory, summary.subject_ref);
      if (!api) throw new Error("the registry has no https API in the directory");
      const { status } = await getJson(`${api}/v2/after-gen/${summary.id}`);
      show(summary, await checkAfterGenStatus(status, env, { directory }), undefined, codes);
      confirmed++;
    } catch (e) {
      show(summary, { state: "unknown", not_after: summary.scope.not_after }, noPg(e.message), codes);
    }
  }
  step("s-status", confirmed === good.size ? "ok" : "fail", `${confirmed} of ${good.size} confirmed`);
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
