// Draft after-gen (spec/drafts/after-gen.md): media/1, the C2PA and XMP carriers, the record and its status.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AFTER_GEN_LABEL, AFTER_GEN_NOTICE, AFTER_GEN_NOT, mediaHash, readAfterGen, embedXmp, c2paAssertion, checkAfterGen,
  checkAfterGenStatus, canonicalJson, messageId, signEnvelope, verifyDirectory, fingerprint, publicKeyHex, newPrivateKeyHex,
  sha256Hex, PregenError } from "../index.js";

// ── a box writer, and an independent media/1 (elements, leaves, RFC 6962) to check the library against ──

const B = (...parts) => Buffer.concat(parts.map((p) => (typeof p === "string" ? Buffer.from(p, "latin1") : Buffer.from(p))));
const u16 = (v) => { const b = Buffer.alloc(2); b.writeUInt16BE(v); return b; };
const i16 = (v) => { const b = Buffer.alloc(2); b.writeInt16BE(v); return b; };
const u32 = (v) => { const b = Buffer.alloc(4); b.writeUInt32BE(v); return b; };
const i32 = (v) => { const b = Buffer.alloc(4); b.writeInt32BE(v); return b; };
const u64 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(v)); return b; };
const box = (type, ...parts) => { const body = B(...parts); return B(u32(8 + body.length), type, body); };
const full = (type, version, flags, ...parts) => box(type, Buffer.from([version, flags >> 16, (flags >> 8) & 255, flags & 255]), ...parts);
const uuidBox = (uuidHex, ...parts) => box("uuid", Buffer.from(uuidHex, "hex"), ...parts);
const XMP_UUID = "be7acfcb97a942e89c71999491e3afac", C2PA_UUID = "d8fec3d61b0e483c92975828877ec481";

const MATRIX = [0, 0x10000, 0, -0x10000, 0, 0, 0, 0, 0x40000000]; // rotated 90 degrees: negative values are signed
const sha = (b) => createHash("sha256").update(b).digest();
const el = (code, value) => B(code, u64(value.length), value);
const ints = (vals) => B(...vals.map((v) => { const b = Buffer.alloc(8); b.writeBigInt64BE(BigInt(v)); return b; }));
function rfc6962(hashes) {
  if (hashes.length === 1) return hashes[0];
  let k = 1;
  while (k * 2 < hashes.length) k *= 2;
  return sha(B([1], rfc6962(hashes.slice(0, k)), rfc6962(hashes.slice(k))));
}

// A small MP4: ftyp, mdat (every track's samples, one chunk per track), moov at the end. Each track:
// {id, handler, samples, durations, ctts, edits, tref, entry, extraStbl, offset, stszCount, timescale}.
function mp4({ tracks = [], extraTop = [], moovExtra = [] } = {}) {
  const ftyp = box("ftyp", "isom", u32(0x200), "isom");
  let at = ftyp.length + 8;
  const offsets = tracks.map((t) => { const o = at; at += t.samples.reduce((n, s) => n + s.length, 0); return o; });
  const mdat = box("mdat", ...tracks.flatMap((t) => t.samples));
  const mvhd = full("mvhd", 0, 0, u32(0), u32(0), u32(1000), u32(0), i32(0x10000), i16(0x100), Buffer.alloc(10),
    ...MATRIX.map(i32), Buffer.alloc(24), u32(tracks.length + 1));
  const traks = tracks.map((t, i) => {
    const n = t.samples.length, durations = t.durations ?? t.samples.map(() => 100);
    const entry = t.entry ?? box(t.handler === "soun" ? "mp4a" : "avc1", Buffer.alloc(6), u16(1), "entry-bytes");
    const stbl = box("stbl",
      full("stsd", 0, 0, u32(1), entry),
      full("stts", 0, 0, u32(durations.length), ...durations.flatMap((d) => [u32(1), u32(d)])),
      ...(t.ctts ? [full("ctts", 1, 0, u32(n), ...t.ctts.flatMap((c) => [u32(1), i32(c)]))] : []),
      full("stsc", 0, 0, u32(n ? 1 : 0), ...(n ? [u32(1), u32(n), u32(1)] : [])),
      full("stsz", 0, 0, u32(0), u32(t.stszCount ?? n), ...t.samples.map((s) => u32(s.length))),
      full("stco", 0, 0, u32(n ? 1 : 0), ...(n ? [u32(t.offset ?? offsets[i])] : [])),
      ...(t.extraStbl ?? []));
    const mhd = t.handler === "soun" ? full("smhd", 0, 0, i16(0), u16(0)) : full("vmhd", 0, 1, u16(0), u16(0), u16(0), u16(0));
    return box("trak",
      full("tkhd", 0, 3, u32(0), u32(0), u32(t.id), u32(0), u32(0), Buffer.alloc(8), i16(0), i16(0),
        i16(t.handler === "soun" ? 0x100 : 0), u16(0), ...MATRIX.map(i32), u32(64 << 16), u32(48 << 16)),
      ...(t.tref ? [box("tref", ...t.tref.map((r) => box(r.type, ...r.ids.map(u32))))] : []),
      ...(t.edits ? [box("edts", full("elst", 0, 0, u32(t.edits.length), ...t.edits.flatMap((e) => [u32(e[0]), i32(e[1]), i16(e[2]), i16(e[3])])))] : []),
      box("mdia", full("mdhd", 0, 0, u32(0), u32(0), u32(t.timescale ?? 90000), u32(0), u16(0), u16(0)),
        full("hdlr", 0, 0, u32(0), t.handler ?? "vide", Buffer.alloc(12), "\0"),
        box("minf", mhd, stbl)));
  });
  return new Uint8Array(B(ftyp, mdat, box("moov", mvhd, ...traks, ...moovExtra), ...extraTop));
}

// media/1 of a file mp4() built, computed from what was put in (spec, "The tree").
function expected(tracks) {
  const leaves = [B("PREGEN-MEDIA\0media/1\0", el("FRMT", B("isobmff")), el("tmsc", ints([1000])), el("rate", ints([0x10000])),
    el("volu", ints([0x100])), el("mtrx", ints(MATRIX)))];
  const listed = tracks.filter((t) => !["meta", "hint"].includes(t.handler)).sort((a, b) => a.id - b.id);
  for (const t of listed) {
    const soun = t.handler === "soun";
    const entry = t.entry ?? box(soun ? "mp4a" : "avc1", Buffer.alloc(6), u16(1), "entry-bytes");
    leaves.push(B(el("hdlr", B(t.handler ?? "vide")),
      el("tref", B(...(t.tref ?? []).map((r) => el(r.type, ints(r.ids.map((id) => listed.findIndex((x) => x.id === id))))))),
      soun ? el("smhd", B(i16(0), u16(0))) : el("vmhd", B(u16(0), u16(0), u16(0), u16(0))),
      el("mdts", ints([t.timescale ?? 90000])),
      el("sent", el(entry.subarray(4, 8).toString("latin1"), entry.subarray(8))),
      el("tkhd", ints([1, 0, 0, soun ? 0x100 : 0, ...MATRIX, 64 << 16, 48 << 16])),
      el("elst", ints((t.edits ?? []).flat()))));
    let dtim = 0;
    t.samples.forEach((s, j) => {
      const d = (t.durations ?? [])[j] ?? 100;
      leaves.push(B(el("sdsc", ints([1])), el("dtim", ints([dtim])), el("ctso", ints([(t.ctts ?? [])[j] ?? 0])),
        el("sdur", ints([d])), el("data", s)));
      dtim += d;
    });
  }
  return { binding: "media/1", hash: rfc6962(leaves.map((l) => sha(B([0], l)))).toString("hex"), leaves: leaves.length };
}

const VIDEO = { id: 1, handler: "vide", samples: [B("frame-one"), B("frame-two!"), B("f3")], durations: [100, 200, 100],
  ctts: [200, -100, 0], edits: [[400, 0, 1, 0], [100, -1, 1, 0]] };
const AUDIO = { id: 2, handler: "soun", samples: [B("audio-a"), B("audio-bb")], timescale: 48000, tref: [{ type: "sync", ids: [1] }] };

test("media/1: 1, 2, 3 and 5 leaves match an independent RFC 6962 tree", async () => {
  for (const tracks of [[], [{ id: 1, samples: [] }], [{ id: 1, samples: [B("x")] }], [VIDEO]]) {
    const want = expected(tracks);
    assert.deepEqual(await mediaHash(mp4({ tracks })), want);
  }
  assert.deepEqual((await Promise.all([[], [{ id: 1, samples: [] }], [{ id: 1, samples: [B("x")] }], [VIDEO]]
    .map((tracks) => mediaHash(mp4({ tracks }))))).map((r) => r.leaves), [1, 2, 3, 5]);
});

test("media/1: tracks in track_ID order, tref by position, meta and hint left out", async () => {
  const meta = { id: 3, handler: "meta", samples: [B("timed metadata")], tref: [{ type: "cdsc", ids: [1] }] };
  const tracks = [{ ...AUDIO, id: 7, tref: [{ type: "sync", ids: [1] }] }, meta, VIDEO];
  assert.deepEqual(await mediaHash(mp4({ tracks })), expected(tracks));
  assert.equal((await mediaHash(mp4({ tracks }))).leaves, 1 + 4 + 3);
});

test("media/1: the same from a Uint8Array, a Blob and a reader, without reading the whole file", async () => {
  const file = mp4({ tracks: [VIDEO, AUDIO] });
  let largest = 0;
  const reader = { size: file.length, read: async (o, n) => { largest = Math.max(largest, n); return file.slice(o, o + n); } };
  const want = await mediaHash(file);
  assert.deepEqual(await mediaHash(new Blob([file])), want);
  assert.deepEqual(await mediaHash(reader), want);
  assert.ok(largest < file.length);
  await assert.rejects(mediaHash({ size: 10, read: async () => new Uint8Array(3) }), PregenError);
  await assert.rejects(mediaHash("not a file"), PregenError);
});

test("media/1: one changed coded byte changes it; metadata does not", async () => {
  const file = mp4({ tracks: [VIDEO, AUDIO] }), want = await mediaHash(file);
  const flipped = Uint8Array.from(file);
  flipped[file.indexOf(0x2d, 30)] ^= 1; // a byte of "frame-one" in mdat
  assert.notEqual((await mediaHash(flipped)).hash, want.hash);
  const more = mp4({ tracks: [VIDEO, AUDIO], extraTop: [box("free", "padding"), uuidBox(XMP_UUID, "<x/>")],
    moovExtra: [box("udta", box("name", "a title"))] });
  assert.deepEqual(await mediaHash(more), want);
});

// Every refusal of "One reading only", each with its reason.
const bump = (bytes, type, delta, nth = 0) => { // add delta to the size of the nth box of this type
  const out = Uint8Array.from(bytes), tag = Buffer.from(type, "latin1");
  let at = -1;
  for (let i = 0; i <= nth; i++) at = Buffer.from(out).indexOf(tag, at + 1);
  const v = new DataView(out.buffer);
  v.setUint32(at - 4, v.getUint32(at - 4) + delta);
  return out;
};
const plain = mp4({ tracks: [VIDEO] });
const mvhdOnly = box("moov", full("mvhd", 0, 0, u32(0), u32(0), u32(1000), u32(0), i32(0x10000), i16(0x100), Buffer.alloc(10),
  ...MATRIX.map(i32), Buffer.alloc(24), u32(2)));
const REFUSED = [
  ["no moov", new Uint8Array(box("ftyp", "isom", u32(0))), /no moov/],
  ["two moov", new Uint8Array(B(plain, mvhdOnly)), /more than one moov/],
  ["a moof", new Uint8Array(B(plain, box("moof", full("mfhd", 0, 0, u32(1))))), /fragmented/],
  ["mvex in moov", mp4({ tracks: [VIDEO], moovExtra: [box("mvex", full("trex", 0, 0, Buffer.alloc(20)))] }), /fragmented/],
  ["an encv entry", mp4({ tracks: [{ ...VIDEO, entry: box("encv", Buffer.alloc(6), u16(1)) }] }), /encrypted/],
  ["a sinf in an entry", mp4({ tracks: [{ ...VIDEO, entry: box("avc1", Buffer.alloc(6), u16(1), Buffer.alloc(70), box("sinf", box("frma", "avc1"))) }] }), /encrypted/],
  ["stz2", mp4({ tracks: [{ ...VIDEO, extraStbl: [full("stz2", 0, 0, u32(8), u32(0))] }] }), /stz2/],
  ["overlapping samples", mp4({ tracks: [{ ...VIDEO }, { ...AUDIO, offset: 30 }] }), /overlap/],
  ["a sample past the end of the file", mp4({ tracks: [{ ...VIDEO, offset: 1e6 }] }), /outside the file/],
  ["a top-level box past the file", bump(plain, "moov", 1), /past its parent/],
  ["a box past its parent", bump(plain, "stco", 1), /past its parent/],
  ["a tref to a track that is not listed", mp4({ tracks: [VIDEO, { ...AUDIO, tref: [{ type: "sync", ids: [9] }] }] }), /not listed/],
  ["a tref to a hint track", mp4({ tracks: [VIDEO, { ...AUDIO, tref: [{ type: "hint", ids: [5] }] }, { id: 5, handler: "hint", samples: [] }] }), /not listed/],
  ["more samples in stsz than stts describes", mp4({ tracks: [{ ...VIDEO, stszCount: 4, samples: [...VIDEO.samples, B("4")], durations: [100, 200, 100] }] }), /stts, ctts and stsz count different samples/],
  ["more samples in stts than stsz", mp4({ tracks: [{ ...VIDEO, stszCount: 2, samples: VIDEO.samples.slice(0, 2), durations: [100, 200, 100], ctts: undefined }] }), /stts, ctts and stsz count different samples/],
  ["two tracks with one id", mp4({ tracks: [VIDEO, { ...AUDIO, id: 1, tref: undefined }] }), /one track_ID/],
];
for (const [name, file, reason] of REFUSED) {
  test(`media/1 refuses ${name}`, async () => {
    await assert.rejects(mediaHash(file), (e) => e instanceof PregenError && e.message.startsWith("media/1: ") && reason.test(e.message));
  });
}

// ── carriers: XMP and C2PA ──

const NOW = 1794200100;
const steward = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const stewardPub = Buffer.from(await crypto.subtle.exportKey("raw", steward.publicKey)).toString("hex");
const KEY = newPrivateKeyHex(), OTHER = newPrivateKeyHex(), STRAY = newPrivateKeyHex();
const kid = async (k) => fingerprint(await publicKeyHex(k));
const API = "https://registry.test.example", OTHER_API = "https://other.test.example";
async function makeDirectory({ revoked = false, falseClaim = false } = {}) {
  const d = { schema: "pregen.registries.v2", sequence: 1, steward_key_id: await fingerprint(stewardPub), registries: [
    { name: "Test", prefix: "TEST", api: API, keys: API + "/keys", key_fingerprints: [await kid(KEY)],
      ...(revoked ? { revoked: { at: "2026-10-04T00:00:00Z", reason: "test" } } : {}) },
    { name: "Other", prefix: "NWRD", api: OTHER_API, keys: OTHER_API + "/keys", key_fingerprints: [await kid(OTHER)] }],
  ...(falseClaim ? { false_claims: [{ anchor: "wikidata:Q42", code: "PG-TEST-000001N", at: "2026-10-02T00:00:00Z", reason: "test" }] } : {}) };
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, steward.privateKey, new TextEncoder().encode(canonicalJson(d)));
  return verifyDirectory({ ...d, signature: Buffer.from(sig).toString("hex") }, { stewardPublicKeyHex: stewardPub, now: NOW });
}
const directory = await makeDirectory();
const KEY_SETS = {
  [API + "/keys"]: { keys: [{ key_id: await kid(KEY), public_key_hex: await publicKeyHex(KEY) },
    { key_id: await kid(STRAY), public_key_hex: await publicKeyHex(STRAY) }] },
  [OTHER_API + "/keys"]: { keys: [{ key_id: await kid(OTHER), public_key_hex: await publicKeyHex(OTHER) }] },
};
const getJson = async (url) => KEY_SETS[url];
const fetch = async (url) => ({ ok: url in KEY_SETS, status: url in KEY_SETS ? 200 : 404, json: async () => KEY_SETS[url] });

const FILE = mp4({ tracks: [VIDEO, AUDIO] }), MEDIA = await mediaHash(FILE);
const DROP = Symbol("drop");
function change(obj, path, value) { // a copy of obj with obj[path] set, or deleted with DROP
  const out = structuredClone(obj), keys = path.split(".");
  const parent = keys.slice(0, -1).reduce((o, k) => o[k], out);
  if (value === DROP) delete parent[keys.at(-1)]; else parent[keys.at(-1)] = value;
  return out;
}
async function baseBody(key = KEY) {
  return { signers: [{ role: "registry", key_id: await kid(key) }], kind: "ratification", label: AFTER_GEN_LABEL,
    notice: AFTER_GEN_NOTICE, not: [...AFTER_GEN_NOT], subject_ref: "PG-TEST-000001N", content: { ...MEDIA },
    request: "a".repeat(64), holder: "https://studio.example", licence: { format: "pg.grant.v1", id: "b".repeat(64) },
    use: { n: 3, of: 10 }, scope: { purposes: ["commercial"], categories: ["advertising"], territories: ["ES", "IT"],
      channels: ["online-video", "social"], project: "Spring campaign 2027", not_after: 1830000000 },
    approval: { assent: "agent", agent: "https://agency.example", mandate: "c".repeat(64), decision: "d".repeat(64), factor: "signature" },
    issued_at: 1794200000 };
}
async function record(changes = {}, key = KEY) {
  let body = await baseBody(key);
  for (const [path, value] of Object.entries(changes)) body = change(body, path, value);
  return signEnvelope("pg.after_gen.v1", body, key);
}
const RECORD = await record();

test("XMP: embedded at the end, read back, and media/1 unchanged", async () => {
  const out = await embedXmp(FILE, RECORD);
  assert.deepEqual(out.subarray(0, FILE.length), FILE);
  assert.deepEqual(await readAfterGen(out), { c2pa: null, xmp: RECORD });
  assert.deepEqual(await mediaHash(out), MEDIA);
  const id = await messageId("pg.after_gen.v1", RECORD.body);
  const packet = Buffer.from(out.subarray(FILE.length + 24)).toString();
  assert.ok(packet.includes(`<pgag:Id>${id}</pgag:Id>`) && packet.includes("<pgag:Registry>TEST</pgag:Registry>"));
  assert.ok(packet.includes('xmlns:pgag="https://pregen.org/ns/after-gen/1/"') && !packet.includes("pgag:Status"));
  const withStatus = Buffer.from(await embedXmp(FILE, RECORD, { directory })).toString("latin1");
  assert.ok(withStatus.includes(`<pgag:Status>${API}/v2/after-gen/${id}</pgag:Status>`)); // built, never read
  assert.deepEqual(await readAfterGen(FILE), { c2pa: null, xmp: null });
});

test("XMP: the record under any prefix bound to the namespace; only canonical JSON of an envelope", async () => {
  const packet = (inner, attrs = "") => new Uint8Array(B(FILE, uuidBox(XMP_UUID, '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
    + '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
    + `<rdf:Description rdf:about="" xmlns:pg="https://pregen.org/ns/after-gen/1/"${attrs}>${inner}</rdf:Description></rdf:RDF></x:xmpmeta>`)));
  const text = canonicalJson(RECORD).replace(/&/g, "&amp;").replace(/</g, "&lt;");
  assert.deepEqual((await readAfterGen(packet(`<pg:Record>${text}</pg:Record>`))).xmp, RECORD);
  assert.deepEqual((await readAfterGen(packet("", ` pg:Record="${text.replace(/"/g, "&quot;")}"`))).xmp, RECORD);
  assert.equal((await readAfterGen(packet(`<pgag:Record>${text}</pgag:Record>`))).xmp, null); // pgag is not bound here
  await assert.rejects(readAfterGen(packet(`<pg:Record>${JSON.stringify(RECORD, null, 1)}</pg:Record>`)), /canonical JSON/);
  await assert.rejects(readAfterGen(packet("<pg:Record>[1]</pg:Record>")), /canonical JSON/);
  await assert.rejects(readAfterGen(packet(`<pg:Record>${text}</pg:Record><pg:Record>${text}</pg:Record>`)), /more than one/);
});

test("XMP: an existing box keeps its properties and becomes free of the same size", async () => {
  const old = '<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/">'
    + '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:dc="http://purl.org/dc/elements/1.1/">'
    + '<rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmp:CreatorTool="Editor &amp; Co"/>'
    + '<rdf:Description rdf:about=""><dc:title><rdf:Alt><rdf:li xml:lang="x-default">A > B</rdf:li></rdf:Alt></dc:title></rdf:Description>'
    + '<rdf:Description rdf:about="" xmlns:pgag="https://pregen.org/ns/after-gen/1/"><pgag:Record>{"old":1}</pgag:Record></rdf:Description>'
    + '</rdf:RDF></x:xmpmeta><?xpacket end="w"?>';
  const xmpBox = uuidBox(XMP_UUID, old);
  const withXmp = new Uint8Array(B(FILE, xmpBox, box("free", "tail")));
  const out = await embedXmp(withXmp, RECORD);
  const start = FILE.length, freed = out.subarray(start, start + xmpBox.length);
  assert.equal(Buffer.from(freed.subarray(0, 8)).toString("latin1"), B(u32(xmpBox.length), "free").toString("latin1"));
  assert.ok(freed.subarray(8).every((x) => x === 0));
  assert.deepEqual(out.subarray(start + xmpBox.length, withXmp.length), withXmp.subarray(start + xmpBox.length));
  const packet = Buffer.from(out.subarray(withXmp.length + 24)).toString();
  assert.ok(packet.includes('xmp:CreatorTool="Editor &amp; Co"') && packet.includes("A > B") && packet.includes("xmlns:dc="));
  assert.equal(packet.match(/pgag:Record>/g).length, 2); // one element: the new record only
  assert.deepEqual((await readAfterGen(out)).xmp, RECORD);
  assert.deepEqual(await mediaHash(out), MEDIA);
  // embedding again replaces the record, keeps the rest
  const again = await embedXmp(out, await record({ "use.n": 4 }));
  assert.equal((await readAfterGen(again)).xmp.body.use.n, 4);
  assert.ok(Buffer.from(again).toString().includes('xmp:CreatorTool="Editor &amp; Co"'));
});

test("XMP: a last box of size 0 gets its real size; two XMP boxes and a packet without rdf:RDF are refused", async () => {
  const open = box("ftyp", "isom", u32(0x200), "isom");
  const tail = new Uint8Array(B(open, u32(0), "mdat", "unbounded media data"));
  const out = await embedXmp(tail, RECORD);
  assert.equal(new DataView(out.buffer).getUint32(open.length), 8 + 20);
  assert.deepEqual((await readAfterGen(out)).xmp, RECORD);
  await assert.rejects(embedXmp(new Uint8Array(B(FILE, uuidBox(XMP_UUID, "<a/>"), uuidBox(XMP_UUID, "<b/>"))), RECORD), /more than one XMP/);
  await assert.rejects(embedXmp(new Uint8Array(B(FILE, uuidBox(XMP_UUID, "<x:xmpmeta/>"))), RECORD), /rdf:RDF/);
  await assert.rejects(embedXmp(FILE, { type: "pg.answer.v1", body: {} }), PregenError);
});

// A C2PA manifest store, by hand: JUMBF superboxes with their descriptions.
const TYPE = { store: "6332706100110010800000aa00389b71", manifest: "63326d6100110010800000aa00389b71",
  assertions: "6332617300110010800000aa00389b71", json: "6a736f6e00110010800000aa00389b71", cbor: "63626f7200110010800000aa00389b71" };
const jumb = (type, label, ...kids) => box("jumb", box("jumd", Buffer.from(TYPE[type], "hex"), [3], label, "\0"), ...kids);
function cborEncode(v) {
  const head = (major, n) => (n < 24 ? Buffer.from([major << 5 | n]) : n < 256 ? Buffer.from([major << 5 | 24, n])
    : n < 65536 ? B([major << 5 | 25], u16(n)) : B([major << 5 | 26], u32(n)));
  if (v === null) return Buffer.from([0xf6]);
  if (v === true || v === false) return Buffer.from([v ? 0xf5 : 0xf4]);
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") { const b = Buffer.from(v); return B(head(3, b.length), b); }
  if (Array.isArray(v)) return B(head(4, v.length), ...v.map(cborEncode));
  const keys = Object.keys(v);
  return B(head(5, keys.length), ...keys.flatMap((k) => [cborEncode(k), cborEncode(v[k])]));
}
const assertion = (label, content) => jumb(content[4] === 0x63 ? "cbor" : "json", label, content);
const jsonBox = (env) => box("json", canonicalJson(env)), cborBox = (env) => box("cbor", cborEncode(env));
const manifest = (...assertionBoxes) => jumb("manifest", "urn:uuid:00000000-0000-4000-8000-000000000000",
  jumb("assertions", "c2pa.assertions", ...assertionBoxes), jumb("json", "c2pa.claim", box("json", "{}")));
const c2paBox = (...manifests) => uuidBox(C2PA_UUID, [0, 0, 0, 0], "manifest\0", u64(0), jumb("store", "c2pa", ...manifests));
const withC2pa = (box) => new Uint8Array(B(FILE, box));

test("C2PA: the assertion from the active manifest, as JSON or CBOR", async () => {
  const label = c2paAssertion(RECORD).label;
  assert.deepEqual(c2paAssertion(RECORD), { label: "org.pregen.after_gen", data: RECORD });
  assert.deepEqual((await readAfterGen(withC2pa(c2paBox(manifest(assertion(label, jsonBox(RECORD))))))).c2pa, RECORD);
  assert.deepEqual((await readAfterGen(withC2pa(c2paBox(manifest(assertion(label, cborBox(RECORD))))))).c2pa, RECORD);
  assert.deepEqual((await readAfterGen(withC2pa(c2paBox(manifest(assertion("org.pregen.after_gen__1", cborBox(RECORD))))))).c2pa, RECORD);
  const older = await record({ "use.n": 1 });
  const two = c2paBox(manifest(assertion(label, jsonBox(older))), manifest(assertion(label, cborBox(RECORD))));
  assert.deepEqual((await readAfterGen(withC2pa(two))).c2pa, RECORD); // the last manifest is the active one
  const none = c2paBox(manifest(assertion(label, jsonBox(RECORD))), manifest(assertion("c2pa.actions", jsonBox({ a: 1 }))));
  assert.equal((await readAfterGen(withC2pa(none))).c2pa, null);
  assert.deepEqual(await readAfterGen(new Blob([await embedXmp(withC2pa(two), RECORD)])), { c2pa: RECORD, xmp: RECORD });
});

test("C2PA: a malformed store or assertion is refused", async () => {
  const label = "org.pregen.after_gen";
  const bad = [
    c2paBox(box("jumb", box("json", "{}"))),                                             // a superbox without jumd
    c2paBox(manifest(assertion(label, box("cbor", [0xfb, 0, 0, 0, 0, 0, 0, 0, 0])))),    // a CBOR float
    c2paBox(manifest(assertion(label, box("cbor", [0x42, 1, 2])))),                      // CBOR bytes
    c2paBox(manifest(assertion(label, box("cbor", [0xa1, 1, 1])))),                      // a map key that is not text
    c2paBox(manifest(assertion(label, box("cbor", [0x9f, 0xff])))),                      // indefinite length
    c2paBox(manifest(assertion(label, box("cbor", [0xa2, 0x61, 0x61, 1, 0x61, 0x61, 2])))), // a key twice
    c2paBox(manifest(assertion(label, box("cbor", [0x01, 0x02])))),                      // bytes after the item
    c2paBox(manifest(assertion(label, box("json", "{not json")))),
    c2paBox(manifest(assertion(label, jsonBox(RECORD)), assertion(label + "__1", jsonBox(RECORD)))),
    c2paBox(manifest(assertion(label, box("bidb", "x")))),
    uuidBox(C2PA_UUID, [0, 0, 0, 0], "manifest"),
  ];
  for (const b of bad) await assert.rejects(readAfterGen(withC2pa(b)), PregenError);
  await assert.rejects(readAfterGen(withC2pa(B(c2paBox(manifest()), c2paBox(manifest())))), /more than one C2PA/);
});

// ── checking the record (vectors 6, 9, 10, 13) ──

const check = (env, options = {}) => checkAfterGen(env, { directory, getJson, ...options });

test("a valid record checks out, with the three statements and who approved", async () => {
  const s = await check(RECORD, { media: MEDIA });
  assert.equal(s.id, await messageId("pg.after_gen.v1", RECORD.body));
  assert.deepEqual([s.label, s.notice, s.not], [AFTER_GEN_LABEL, AFTER_GEN_NOTICE, [...AFTER_GEN_NOT]]);
  assert.equal(s.prefix, "TEST");
  assert.equal(s.licence, "b".repeat(64));
  assert.equal(s.approvedBy, `approved by agency.example under mandate ${"c".repeat(64)}`);
  assert.equal(s.fileMatch, true);
  assert.equal((await check(RECORD, { media: MEDIA.hash })).fileMatch, true);
  assert.equal((await checkAfterGen(RECORD, { directory, fetch })).fileMatch, null);
  const self = await check(await record({ approval: { assent: "self", decision: "d".repeat(64) } }));
  assert.equal(self.approvedBy, "approved by the person");
  const reg = await check(await record({ approval: { assent: "registry", instruction: "e".repeat(64), factor: "email" } }));
  assert.equal(reg.approvedBy, "approved on the person's instruction at the registry");
  await check(await record({ "use.of": null, "scope.categories": [], "scope.territories": ["*"], "scope.channels": ["*"] }));
});

test("vector 6: a record checked against another file is not for this file", async () => {
  const other = await mediaHash(mp4({ tracks: [VIDEO] }));
  await assert.rejects(check(RECORD, { media: other }), (e) => e instanceof PregenError && e.message === "not for this file");
  await assert.rejects(check(RECORD, { media: "0".repeat(64) }), /not for this file/);
});

const MUTATIONS = [ // vectors 9 and 13, the shape, and the approval forms
  ["label in another case", { label: "Approved after generation" }],
  ["notice with other spacing", { notice: AFTER_GEN_NOTICE.replace(". ", ".  ") }],
  ["not in another order", { not: ["statement_of_origin", "pre_generation_permission"] }],
  ["not missing one", { not: ["pre_generation_permission"] }],
  ["kind not ratification", { kind: "release" }],
  ["an unknown body member", { origin: "ai" }],
  ["a missing member", { request: DROP }],
  ["an unknown member in content", { "content.extra": 1 }],
  ["an unknown member in licence", { "licence.license_id": "PG-TEST-000001N" }],
  ["an unknown member in use", { "use.left": 7 }],
  ["an unknown member in scope", { "scope.media": ["video"] }],
  ["an unknown member in approval", { "approval.note": "x" }],
  ["an unknown member in signers", { signers: [{ role: "registry", key_id: "pg-ed25519:" + "0".repeat(32), name: "x" }] }],
  ["a binding other than media/1", { "content.binding": "sha256" }],
  ["content naming two files", { "content.hash": ["a".repeat(64), "b".repeat(64)] }],
  ["an upper-case hash", { "content.hash": "A".repeat(64) }],
  ["leaves 0", { "content.leaves": 0 }],
  ["an intimate category", { "scope.categories": ["advertising", "sexual"] }],
  ["adult", { "scope.categories": ["adult"] }],
  ["an unknown category", { "scope.categories": ["advertising", "cars"] }],
  ["a category in another case", { "scope.categories": ["Advertising"] }],
  ["an unsorted list", { "scope.territories": ["IT", "ES"] }],
  ["a repeated list entry", { "scope.channels": ["social", "social"] }],
  ["empty purposes", { "scope.purposes": [] }],
  ["an unknown purpose", { "scope.purposes": ["marketing"] }],
  ["empty territories", { "scope.territories": [] }],
  ["a bad territory", { "scope.territories": ["es"] }],
  ["a three-letter territory", { "scope.territories": ["ESP"] }],
  ["star with a territory", { "scope.territories": ["*", "ES"] }],
  ["a bad channel", { "scope.channels": ["Online Video"] }],
  ["empty project", { "scope.project": "" }],
  ["a project of 201 characters", { "scope.project": "x".repeat(201) }],
  ["a project with a newline", { "scope.project": "Spring\ncampaign" }],
  ["not_after not an integer", { "scope.not_after": "2028" }],
  ["use n 0", { "use.n": 0 }],
  ["use n beyond of", { "use.n": 11 }],
  ["self naming a factor", { approval: { assent: "self", decision: "d".repeat(64), factor: "email" } }],
  ["registry without a factor", { approval: { assent: "registry", instruction: "e".repeat(64) } }],
  ["registry with factor signature", { approval: { assent: "registry", instruction: "e".repeat(64), factor: "signature" } }],
  ["agent without a mandate", { "approval.mandate": DROP }],
  ["agent with factor email", { "approval.factor": "email" }],
  ["an agent that is the holder", { "approval.agent": "https://studio.example" }],
  ["an approval by the holder", { approval: { assent: "holder", decision: "d".repeat(64) } }],
  ["no approval", { approval: DROP }],
  ["a holder that is not a party id", { holder: "studio.example" }],
  ["a licence of another format", { "licence.format": "pg.terms.v1" }],
  ["a status_url member (the verifier builds the address)", { status_url: API + "/v2/after-gen/x" }],
  ["not_after 0", { "scope.not_after": 0 }],
  ["a holder with a path", { holder: "https://studio.example/x" }],
];
for (const [name, changes] of MUTATIONS) {
  test(`checkAfterGen refuses ${name}`, async () => {
    await assert.rejects(check(await record(changes)), (e) => e instanceof PregenError && /^after-gen: /.test(e.message));
  });
}

test("vector 10: a bad signature, an unknown key, another registry's key, a revoked registry", async () => {
  await assert.rejects(check({ ...RECORD, body: { ...RECORD.body, holder: "https://other.example" } }), /bad signature/);
  await assert.rejects(check(await record({}, STRAY)), /issuer_mismatch/);       // in the key set, not in the directory
  await assert.rejects(check(await record({}, OTHER)), /issuer_mismatch/);       // NWRD's key for a TEST subject
  await assert.rejects(checkAfterGen(RECORD, { directory: await makeDirectory({ revoked: true }), getJson }), /revoked/);
  await assert.rejects(checkAfterGen(RECORD, { directory: await makeDirectory({ falseClaim: true }), getJson }), /false claim/);
  await assert.rejects(check({ ...RECORD, signatures: [] }), /exactly one registry key/);
  await assert.rejects(check({ ...RECORD, extra: 1 }), /envelope/);
  await assert.rejects(check({ ...RECORD, type: "pg.answer.v1" }), /envelope/);
});

// ── the status (vector 16) ──

async function status(changes = {}, { key = KEY, rec = RECORD } = {}) {
  let body = { signers: [{ role: "registry", key_id: await kid(key) }], record: await messageId("pg.after_gen.v1", rec.body),
    state: "active", approved_at: rec.body.issued_at, withdrawn_at: null, not_after: rec.body.scope.not_after,
    issued_at: NOW - 10, expires_at: NOW + 290 };
  for (const [path, value] of Object.entries(changes)) body = change(body, path, value);
  return signEnvelope("pg.after_gen_status.v1", body, key);
}
const checkStatus = (s, r = RECORD, now = NOW) => checkAfterGenStatus(s, r, { directory, getJson, now });

test("a current status checks out: active, and withdrawn with its time", async () => {
  assert.deepEqual(await checkStatus(await status()), { state: "active", approved_at: 1794200000, withdrawn_at: null, not_after: 1830000000 });
  const w = await checkStatus(await status({ state: "withdrawn", withdrawn_at: 1794200050 }));
  assert.deepEqual([w.state, w.withdrawn_at], ["withdrawn", 1794200050]);
  const late = await record({ "scope.not_after": NOW - 100 });
  assert.equal((await checkStatus(await status({ state: "expired" }, { rec: late }), late)).state, "expired");
});

const BAD_STATUS = [
  ["for another record", () => status({ record: "f".repeat(64) }), /another record/],
  ["expired", () => status({ issued_at: NOW - 400, expires_at: NOW - 100 }), /expired/],
  ["issued in the future", () => status({ issued_at: NOW + 61, expires_at: NOW + 300 }), /future/],
  ["living more than 300 seconds", () => status({ issued_at: NOW - 10, expires_at: NOW + 291 }), /300/],
  ["signed by another registry", () => status({}, { key: OTHER }), /issuer_mismatch/],
  ["signed by an unlisted key", () => status({}, { key: STRAY }), /issuer_mismatch/],
  ["withdrawn without withdrawn_at", () => status({ state: "withdrawn" }), /withdrawn_at/],
  ["active with a withdrawn_at", () => status({ withdrawn_at: NOW - 20 }), /withdrawn_at/],
  ["a not_after other than the record's", () => status({ not_after: 1830000001 }), /not_after/],
  ["an approved_at other than the record's issued_at", () => status({ approved_at: 1794200001 }), /approved_at/],
  ["an unknown state", () => status({ state: "paused" }), /state/],
  ["an unknown member", () => status({ reason: "x" }), /member/],
  ["active after not_after", async () => status({}, { rec: await record({ "scope.not_after": NOW - 100 }) }), /not_after|agree/],
];
for (const [name, make, reason] of BAD_STATUS) {
  test(`checkAfterGenStatus refuses a status ${name}`, async () => {
    const s = await make();
    const rec = name === "active after not_after" ? await record({ "scope.not_after": NOW - 100 }) : RECORD;
    await assert.rejects(checkStatus(s, rec), (e) => e instanceof PregenError && reason.test(e.message));
  });
}

test("checkAfterGenStatus refuses a bad signature and a stale directory", async () => {
  const s = await status();
  await assert.rejects(checkStatus({ ...s, body: { ...s.body, state: "expired" } }), /bad signature/);
  await assert.rejects(checkStatus(s, RECORD, NOW + 86_401), /24 hours/);
});

// ── media/1 on real files made with ffmpeg ──

const FFMPEG = spawnSync("ffmpeg", ["-version"]).status === 0;
const ffmpeg = (...args) => {
  const r = spawnSync("ffmpeg", ["-v", "error", "-y", ...args]);
  if (r.status !== 0) throw new Error(String(r.stderr));
};

// Insert a top-level box before moov and move every stco/co64 entry past it.
function insertBeforeMoov(file, extra) {
  const buf = Buffer.from(file), v = new DataView(buf.buffer, buf.byteOffset);
  let moov = 0;
  while (buf.toString("latin1", moov + 4, moov + 8) !== "moov") moov += v.getUint32(moov);
  const patch = (start, end) => {
    for (let at = start; at < end;) {
      const size = v.getUint32(at), type = buf.toString("latin1", at + 4, at + 8);
      if (["moov", "trak", "mdia", "minf", "stbl"].includes(type)) patch(at + 8, at + size);
      if (type === "stco" || type === "co64") {
        const n = v.getUint32(at + 12), w = type === "stco" ? 4 : 8;
        for (let i = 0; i < n; i++) {
          const p = at + 16 + w * i;
          if (w === 4) v.setUint32(p, v.getUint32(p) + extra.length); else v.setBigUint64(p, v.getBigUint64(p) + BigInt(extra.length));
        }
      }
      at += size;
    }
  };
  patch(moov, moov + v.getUint32(moov));
  return new Uint8Array(B(buf.subarray(0, moov), extra, buf.subarray(moov)));
}

test("media/1 of an ffmpeg file: unchanged by a faststart remux, XMP, a C2PA box; changed by one sample byte", { skip: !FFMPEG && "ffmpeg not found" }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "after-gen-"));
  try {
    const p = (f) => join(dir, f);
    ffmpeg("-f", "lavfi", "-i", "testsrc=duration=2:size=64x48:rate=25", "-f", "lavfi", "-i", "sine=duration=2",
      "-c:v", "libx264", "-c:a", "aac", "-shortest", p("encoded.mp4"));
    // ffmpeg's first remux rewrites playable parameters of its own encode (movie timescale, edit list, btrt): start from one.
    ffmpeg("-i", p("encoded.mp4"), "-c", "copy", p("a.mp4"));
    ffmpeg("-i", p("a.mp4"), "-c", "copy", "-movflags", "+faststart", p("fast.mp4"));
    const a = new Uint8Array(readFileSync(p("a.mp4"))), fast = new Uint8Array(readFileSync(p("fast.mp4")));
    const want = await mediaHash(a);
    assert.ok(want.leaves > 100);
    assert.deepEqual(await mediaHash(fast), want);
    assert.deepEqual(await mediaHash(await embedXmp(a, RECORD)), want);
    const c2pa = insertBeforeMoov(fast, c2paBox(manifest(assertion("org.pregen.after_gen", cborBox(RECORD)))));
    assert.deepEqual(await mediaHash(c2pa), want);
    assert.deepEqual((await readAfterGen(c2pa)).c2pa, RECORD);
    assert.deepEqual(await mediaHash(new Blob([fast])), want);
    let largest = 0;
    assert.deepEqual(await mediaHash({ size: fast.length, read: async (o, n) => { largest = Math.max(largest, n); return fast.slice(o, o + n); } }), want);
    assert.ok(largest < fast.length / 2);
    // one coded byte: the last byte of mdat is the last byte of a sample
    const mdatEnd = (() => { const v = new DataView(a.buffer); let at = 0;
      while (true) { const s = v.getUint32(at); if (Buffer.from(a.subarray(at + 4, at + 8)).toString() === "mdat") return at + s; at += s; } })();
    const flipped = Uint8Array.from(a);
    flipped[mdatEnd - 1] ^= 0xff;
    assert.notEqual((await mediaHash(flipped)).hash, want.hash);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── shared vectors with verify-py, when they exist ──

const VECTORS = new URL("../../../spec/test-vectors/after-gen/vectors.json", import.meta.url);
test("spec/test-vectors/after-gen/vectors.json: every file's media/1 or refusal, and what its record says", { skip: !existsSync(VECTORS) && "no vectors yet" }, async () => {
  const V = JSON.parse(readFileSync(VECTORS));
  const A = JSON.parse(readFileSync(new URL("../../../spec/test-vectors/answers.json", import.meta.url)));
  const dir = await verifyDirectory(A.directory, { stewardPublicKeyHex: A.steward_public_key_hex, now: V.now });
  const keys = async (url) => A.key_sets[url];
  const file = (name) => new Uint8Array(readFileSync(new URL(`../../../spec/test-vectors/after-gen/${name}`, import.meta.url)));
  const hashes = {};
  for (const v of V.files) {
    // A refusal's wording is verify-py's: compare refused or not, and the hash and leaves.
    if (v.refused) await assert.rejects(mediaHash(file(v.file)), (e) => e instanceof PregenError && e.message.startsWith("media/1: "), v.file);
    else assert.deepEqual(hashes[v.file] = await mediaHash(file(v.file)), v.media, v.file);
  }
  for (const v of V.read) {
    const got = await readAfterGen(file(v.file));
    for (const via of ["c2pa", "xmp"]) {
      assert.equal(got[via] && await messageId(got[via].type, got[via].body), v[via], `${v.file} ${via}`);
      if (!(via in v.check)) continue;
      const media = hashes[v.file] ?? await mediaHash(file(v.file));
      const said = await checkAfterGen(got[via], { directory: dir, getJson: keys, media }).then((s) => s.id, (e) => e.message);
      if (/^[0-9a-f]{64}$/.test(v.check[via]) || v.check[via] === "not for this file") assert.equal(said, v.check[via], `${v.file} ${via}`);
      else assert.doesNotMatch(said, /^[0-9a-f]{64}$/, `${v.file} ${via}: refused`);
    }
  }
});
