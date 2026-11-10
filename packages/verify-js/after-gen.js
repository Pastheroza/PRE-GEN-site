// AFTER-GEN (spec/drafts/after-gen.md): a registry's record that the rights holder approved one existing file.
// media/1 hashes every byte of an ISO base media file a player could read; readAfterGen and embedXmp carry the record;
// checkAfterGen and checkAfterGenStatus check it. No Node-only API: Web Crypto, Uint8Array and DataView, so it runs in
// browsers too.
// Bindings of index.js are used only inside functions: index.js re-exports this module, so neither runs the other first.
import { PregenError, canonicalJson, messageId, issuerOf, checkProviderUrl, loadDirectory, registrySigned, CATEGORIES,
  INTIMATE, DIRECTORY_MAX_AGE } from "./index.js";

/** The three statements every record carries, exactly (What a record never says). */
export const AFTER_GEN_LABEL = "approved after generation";
export const AFTER_GEN_NOTICE = "Recorded after the content existed. Not a PRE-GEN permission given before generation. Says nothing about whether the content is AI-generated.";
export const AFTER_GEN_NOT = Object.freeze(["pre_generation_permission", "statement_of_origin"]);

const RECORD = "pg.after_gen.v1", STATUS = "pg.after_gen_status.v1", ASSERTION = "org.pregen.after_gen";
const XMP_UUID = "be7acfcb97a942e89c71999491e3afac", C2PA_UUID = "d8fec3d61b0e483c92975828877ec481";
const NS = "https://pregen.org/ns/after-gen/1/";
const fail = (message) => { throw new PregenError(message); };
const M = (reason) => fail("media/1: " + reason);
const utf8 = new TextEncoder(), UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }); // keeps a BOM, as Python
const view = (b) => new DataView(b.buffer, b.byteOffset, b.byteLength);
const latin1 = (b, at, n) => String.fromCharCode(...b.subarray(at, at + n));
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const sha256 = async (b) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));

// ── reading a file in ranges ──

function reader(source) {
  if (source instanceof Uint8Array) return { size: source.length, read: async (o, n) => source.subarray(o, o + n) };
  if (typeof Blob !== "undefined" && source instanceof Blob) {
    return { size: source.size, read: async (o, n) => new Uint8Array(await source.slice(o, o + n).arrayBuffer()) };
  }
  if (source && Number.isSafeInteger(source.size) && source.size >= 0 && typeof source.read === "function") {
    return { size: source.size, read: async (o, n) => {
      const b = await source.read(o, n);
      if (!(b instanceof Uint8Array) || b.length !== n) fail(`read(${o}, ${n}) did not return ${n} bytes`);
      return b;
    } };
  }
  fail("give a Uint8Array, a Blob or {size, read(offset, length)}");
}

// One box header at the start of `b`, with `room` bytes left in its parent. Size 0 (to the end) only at the top level.
function head(b, room, top, err) {
  if (room < 8 || b.length < 8) err("a box runs past its parent");
  const v = view(b), type = latin1(b, 4, 4);
  let size = v.getUint32(0), hdr = 8;
  if (size === 1) {
    if (room < 16 || b.length < 16) err("a box runs past its parent");
    const big = v.getBigUint64(8);
    size = big > BigInt(Number.MAX_SAFE_INTEGER) ? Infinity : Number(big);
    hdr = 16;
  } else if (size === 0) {
    if (!top) err("a box runs past its parent"); // size 0 (to the end) is for a top-level box only
    size = room;
  }
  if (size < hdr + (type === "uuid" ? 16 : 0)) err("a box is shorter than its header"); // a uuid box: its user type too
  if (size > room) err("a box runs past its parent");
  return { type, size, hdr, zero: v.getUint32(0) === 0, uuid: type === "uuid" ? hex(b.subarray(hdr, hdr + 16)) : null };
}

async function topBoxes(r, err) {
  const out = [];
  for (let at = 0; at < r.size;) {
    const h = head(await r.read(at, Math.min(32, r.size - at)), r.size - at, true, err);
    out.push({ ...h, start: at });
    at += h.size;
  }
  return out;
}

// The child boxes of an in-memory payload.
function boxesIn(b, err = M) {
  const out = [];
  for (let at = 0; at < b.length;) {
    const h = head(b.subarray(at, at + 32), b.length - at, false, err);
    out.push({ ...h, start: at, data: b.subarray(at + h.hdr, at + h.size) });
    at += h.size;
  }
  return out;
}

// ── media/1 elements and the RFC 6962 tree ──

const code = (c) => Uint8Array.from(c, (x) => x.charCodeAt(0));
function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}
/** An element: four-byte code, value length (u64 big-endian), value. */
function el(c, value) {
  const out = new Uint8Array(12 + value.length);
  out.set(code(c));
  view(out).setBigUint64(4, BigInt(value.length));
  out.set(value, 12);
  return out;
}
/** Integers as eight bytes each, big-endian, two's complement. */
function ints(values) {
  const out = new Uint8Array(8 * values.length), v = view(out);
  values.forEach((x, i) => {
    const n = BigInt(x);
    if (n !== BigInt.asIntN(64, n)) M("a value does not fit in a signed 64-bit integer");
    v.setBigInt64(8 * i, n);
  });
  return out;
}
const leafHash = (leaf) => sha256(concat([new Uint8Array([0]), leaf]));

// RFC 6962 without holding the leaves: a stack of perfect subtrees; the root folds them from the right.
async function push(stack, hash) {
  let node = { hash, n: 1 };
  while (stack.length && stack.at(-1).n === node.n) {
    const left = stack.pop();
    node = { hash: await sha256(concat([new Uint8Array([1]), left.hash, node.hash])), n: 2 * node.n };
  }
  stack.push(node);
}
async function root(stack) {
  let h = stack.pop().hash;
  while (stack.length) h = await sha256(concat([new Uint8Array([1]), stack.pop().hash, h]));
  return h;
}

const bytesText = (b) => { // one character per byte
  let s = "";
  for (let i = 0; i < b.length; i += 8192) s += String.fromCharCode(...b.subarray(i, i + 8192));
  return s;
};

const PIECE = 1 << 20;
const PATH = { moov: "trak", trak: "mdia", mdia: "minf", minf: "stbl" }; // a value of its children's elements
const PCM = ["raw ", "twos", "sowt", "in24", "in32", "fl32", "fl64", "lpcm", "ipcm", "fpcm", "ulaw", "alaw"];
const TABLES = /(?=(stco|co64|stsc|stsz|stz2|stts|ctts|iloc|saio|saiz|sidx|ssix|tfra|mfra|trun|tfhd))/;

// An unsigned big-endian field of a box's bytes.
function u(b, at, n = 4) {
  if (b.length < at + n) M("a box shorter than its own fields");
  let x = 0;
  for (let i = 0; i < n; i++) x = x * 256 + b[at + i];
  return x;
}

const MOVIE = /(cmov|hoov)/, MPEG = /(hdlr[\s\S]{4}mhlrMPEG)/, CARRIER_MAX = 64 << 20;
const NUT = /(NMzV\x1f_\x04\xad)/; // NUT main startcode: its probe ties with MP4, the file opens as neither
const SAMPLE_TABLES = ["stts", "ctts", "stsc", "stsz", "stz2", "stco", "co64"]; // the only boxes the table scan skips
const PROBED_AWAY = ["jp2 ", "jpx ", "jxl "]; // major brands a player's MP4 probe scores low (One reading only)

// Any of the codes of `rx` at any byte position of `b` (One reading only).
function scan(b, rx = TABLES, why = (c) => `${c} outside its place`) {
  const x = bytesText(b).match(rx);
  if (x) M(why(x[1]));
}

// scan over [s, e) of the file in pieces, each overlapping the last by `keep` bytes.
async function scanFile(r, s, e, rx = TABLES, why = undefined, keep = 3) {
  for (let carry = new Uint8Array(0); s < e; s += PIECE) {
    const chunk = concat([carry, await r.read(s, Math.min(PIECE, e - s))]);
    scan(chunk, rx, why);
    carry = chunk.subarray(Math.max(0, chunk.length - keep));
  }
}

const exact = (ok) => ok || M("a table whose length is not exactly what its count gives");

// A sample size table (stsz or stz2): {count, fixed size or 0, table}.
function sizes(type, b) {
  const count = u(b, 8);
  if (type === "stsz") {
    const fixed = u(b, 4);
    exact(b.length === 12 + (fixed ? 0 : 4 * count));
    return { count, fixed, table: fixed ? [] : Array.from({ length: count }, (_, j) => u(b, 12 + 4 * j)) };
  }
  const bits = u(b, 7, 1);
  if (![4, 8, 16].includes(bits)) M("an stz2 field size other than 4, 8 or 16");
  exact(b.length === 12 + Math.ceil(count * bits / 8));
  return { count, fixed: 0, table: Array.from({ length: count },
    (_, j) => (bits === 4 ? (b[12 + (j >> 1)] >> (j % 2 ? 0 : 4)) & 15 : u(b, 12 + (bits / 8) * j, bits / 8))) };
}

const WIDTH = { "raw ": 1, ulaw: 1, alaw: 1, in24: 3, in32: 4, fl32: 4, fl64: 8 }; // bytes a sample

// The frame size players take from a sound entry read by chunk (One reading only), or null: bytes per frame (v1, one
// sample a packet), bytes per packet (v2, one frame a packet), or channels x the codec's bytes a sample (v0), which v1
// and v2 must agree with where the codec has a width.
function frame(e) {
  const b = e.data, v = u(b, 8, 2);
  if (!PCM.includes(e.type)) return null;
  let width = ["twos", "sowt"].includes(e.type) ? Math.floor(u(b, 18, 2) / 8) : WIDTH[e.type] ?? null;
  if (["ipcm", "fpcm"].includes(e.type)) {
    const pcmc = boxesIn(b.subarray({ 1: 44, 2: 64 }[v] ?? 28)).find((k) => k.type === "pcmC");
    width = pcmc ? Math.floor(u(pcmc.data, 5, 1) / 8) : null;
  }
  let size, channels;
  if (v === 1) [size, channels] = u(b, 28) === 1 ? [u(b, 36), u(b, 16, 2)] : [null, 0];
  else if (v === 2) [size, channels] = u(b, 60) === 1 ? [u(b, 56), u(b, 40)] : [null, 0];
  else return width === null ? null : u(b, 16, 2) * width;
  return size === null || (width !== null && size !== channels * width) ? null : size;
}

// Checks an stbl on the path (One reading only) and returns its chunk offset table as hashed, by start: per offset, the
// position of the mdat whose data holds it and the offset within that data.
function stbl(kids, mdats, video) {
  const one = new Map();
  for (const k of kids) {
    const key = { stz2: "stsz", co64: "stco" }[k.type] ?? k.type;
    if (["stsd", "stts", "stsc", "stsz", "stco", "ctts"].includes(key)) {
      if (one.has(key)) M(`two ${k.type} tables in one stbl`);
      one.set(key, k);
    }
  }
  if (["stsd", "stts", "stsc", "stsz", "stco"].some((k) => !one.has(k))) M("an stbl without its stsd, stts, stsc, stsz or stz2, and stco or co64");
  const entries = boxesIn(one.get("stsd").data.subarray(8));
  exact(entries.length === u(one.get("stsd").data, 4));
  for (const e of entries) if (["encv", "enca", "encs"].includes(e.type) || bytesText(e.data).includes("sinf")) M("encrypted samples");
  let b = one.get("stts").data;
  exact(b.length === 8 + 8 * u(b, 4));
  const durations = Array.from({ length: u(b, 4) }, (_, i) => [u(b, 8 + 8 * i), u(b, 12 + 8 * i)]);
  if (one.has("ctts")) { b = one.get("ctts").data; exact(b.length === 8 + 8 * u(b, 4)); }
  b = one.get("stsc").data;
  exact(b.length === 8 + 12 * u(b, 4));
  const runs = Array.from({ length: u(b, 4) }, (_, i) => [u(b, 8 + 12 * i), u(b, 12 + 12 * i), u(b, 16 + 12 * i)]);
  const z = sizes(one.get("stsz").type, one.get("stsz").data), co = one.get("stco");
  b = co.data;
  const w = co.type === "stco" ? 4 : 8, n = u(b, 4);
  exact(b.length === 8 + w * n);
  let total = 0;
  runs.forEach(([first, per, sdi], j) => {
    const last = j + 1 < runs.length ? runs[j + 1][0] : n + 1;
    if ((j === 0 ? first !== 1 : first <= runs[j - 1][0]) || first > n || per === 0 || sdi < 1 || sdi > entries.length) {
      M("an stsc that reads two ways");
    }
    total += (last - first) * per;
  });
  if (n && !runs.length) M("an stsc that reads two ways");
  if (total !== z.count || durations.reduce((s, [c]) => s + c, 0) !== z.count) M("stsc, stts and the sample sizes count different samples");
  if (!video && z.count && durations.every(([c, d]) => !c || d === 1)) { // sound read by chunk
    for (const e of entries) {
      if (one.get("stsz").type !== "stsz" || !z.fixed || frame(e) !== z.fixed) {
        M("a sound track read by chunk whose entry does not give its sample size");
      }
    }
  }
  const value = [b.subarray(0, 4), ints([n])];
  for (let c = 0, r = 0, s = 0; c < n; c++) {
    while (r + 1 < runs.length && runs[r + 1][0] <= c + 1) r++;
    const per = runs[r][1], o = u(b, 8 + w * c, w);
    let length = z.fixed * per;
    if (!z.fixed) for (let j = s; j < s + per; j++) length += z.table[j];
    s += per;
    let lo = 0, hi = mdats.length; // the last mdat whose data starts at or before o
    while (lo < hi) { const mid = (lo + hi) >> 1; if (mdats[mid][0] <= o) lo = mid + 1; else hi = mid; }
    const j = lo - 1;
    if (j < 0 || o >= mdats[j][1]) M("a chunk offset outside the data of an mdat");
    if (o + length > mdats[j][1]) M("a chunk whose samples run past its mdat's data");
    value.push(ints([j, o - mdats[j][0]]));
  }
  return new Map([[co.start, concat(value)]]);
}

// The value of the element of a box on the path moov/trak/mdia/minf/stbl: its children's elements. The direct children
// of an stbl are added to `zones` ([start, end) in the movie box's content), the bytes the table scan leaves out.
function value(data, type, mdats, zones, at = 0, hdlrs = []) {
  const kids = boxesIn(data);
  if (type === "moov" && kids.some((k) => k.type === "mvex")) M("a fragmented file (mvex)");
  if (type === "mdia" || type === "minf") { // the handler types of the track, in mdia and in minf alike
    hdlrs = [...hdlrs, ...kids.filter((k) => k.type === "hdlr").map((k) => latin1(k.data, 8, 4))];
  }
  if (type === "minf") {
    for (const d of kids.filter((k) => k.type === "dinf")) {
      for (const r of boxesIn(d.data).filter((k) => k.type === "dref")) {
        for (const e of boxesIn(r.data.subarray(8))) {
          const ok = ["url ", "urn "].includes(e.type) && e.data.length >= 4 || e.type === "alis" && e.data.length === 4; // Apple: empty alis
          if (!ok || !(e.data[3] & 1)) M("a data reference that is not a self-contained url, urn or alis");
        }
      }
    }
  }
  let offsets = new Map();
  if (type === "stbl") {
    const media = hdlrs.filter((h) => !["url ", "urn ", "alis"].includes(h)); // a data handler (MOV's minf hdlr) sets no track type
    offsets = stbl(kids, mdats, media.length > 0 && media.every((h) => h === "vide"));
    for (const k of kids) { // only the sample tables are skipped: stsd and the rest are searched too
      if (SAMPLE_TABLES.includes(k.type)) zones.push([at + k.start, at + k.start + k.size]);
    }
  }
  return concat(kids.map((k) => el(k.type, PATH[type] === k.type ? value(k.data, k.type, mdats, zones, at + k.start + k.hdr, hdlrs)
    : offsets.get(k.start) ?? k.data)));
}

/** media/1 of an ISO base media file (MP4, MOV, M4V): {binding: "media/1", hash, leaves}, the RFC 6962 root over the 1 MiB
 * pieces of the stream of every top-level box but the two carriers, chunk offsets counted within their mdat. `source` is
 * a Uint8Array, a Blob or File, or {size, read(offset, length) -> Promise<Uint8Array>}; the movie box is read whole, the
 * rest in ranges. Throws PregenError("media/1: <reason>") for every file "One reading only" refuses. */
export async function mediaHash(source) {
  const r = reader(source);
  const top = await topBoxes(r, M);
  if (top[0]?.type !== "ftyp") M("the first box is not ftyp");
  if (top[0].size - top[0].hdr < 4 || PROBED_AWAY.includes(latin1(await r.read(top[0].hdr, 4), 0, 4))) {
    M("an ftyp major brand that players do not read as MP4");
  }
  for (const [uuid, name] of [[XMP_UUID, "XMP"], [C2PA_UUID, "C2PA"]]) { // carriers that are not what they claim
    const boxes = top.filter((b) => b.uuid === uuid);
    if (boxes.length > 1) M(`more than one ${name} box`);
    for (const b of boxes) {
      if (b.size > CARRIER_MAX) M(`an ${name} box larger than 64 MiB`);
      const data = (await r.read(b.start, b.size)).subarray(b.hdr);
      if (name === "XMP") {
        let ok = true;
        try { UTF8.decode(data.subarray(16)); } catch { ok = false; }
        if (!ok || data.subarray(16).includes(0)) M("an XMP box whose packet is not UTF-8 text free of NUL bytes");
      } else {
        let ok;
        try { ok = c2paStore({ ...b, data }) !== undefined; } catch { ok = false; }
        if (!ok) M("a C2PA box that does not parse as a JUMBF manifest store");
      }
    }
  }
  const moovs = top.filter((b) => b.type === "moov");
  if (moovs.length !== 1) M(moovs.length ? "more than one moov box" : "no moov box");
  if (top.some((b) => b.type === "moof")) M("a fragmented file (moof)");
  const mdats = top.filter((b) => b.type === "mdat").map((b) => [b.start + b.hdr, b.start + b.size]);
  const whole = await r.read(moovs[0].start, moovs[0].size), h = moovs[0].hdr, zones = [];
  const moov = el("moov", value(whole.subarray(h), "moov", mdats, zones));
  let at = 0; // the table scan: the movie box but the direct children of each stbl
  for (const [zs, ze] of zones.sort((a, b) => a[0] - b[0])) { scan(whole.subarray(at, h + zs)); at = h + ze; }
  scan(whole.subarray(at));
  const carrier = (b) => b.uuid === XMP_UUID || b.uuid === C2PA_UUID;
  for (const b of top) if (b.type !== "moov" && b.type !== "mdat" && !carrier(b)) await scanFile(r, b.start, b.start + b.size);
  let from = 0; // a second movie: outside mdat data, carriers included
  for (const [s, e] of mdats) { await scanFile(r, from, s, MOVIE, (c) => `${c}: a second movie`); from = e; }
  await scanFile(r, from, r.size, MOVIE, (c) => `${c}: a second movie`);
  await scanFile(r, 0, r.size, MPEG, () => "the pattern hdlr ... mhlr MPEG, which makes players read the file as another format", 15);
  await scanFile(r, 0, r.size, NUT, () => "a NUT startcode, which makes players read the file as another format", 7);

  const stack = [], buf = new Uint8Array(PIECE); // the stream, cut into pieces of 1 MiB: a leaf each
  let fill = 0, leaves = 0;
  const add = async (b) => {
    for (let at = 0; at < b.length;) {
      const n = Math.min(PIECE - fill, b.length - at);
      buf.set(b.subarray(at, at + n), fill);
      fill += n;
      at += n;
      if (fill === PIECE) { await push(stack, await leafHash(buf)); leaves++; fill = 0; }
    }
  };
  await add(utf8.encode("PREGEN-MEDIA\0media/1\0"));
  for (const b of top) {
    if (carrier(b)) continue;
    if (b.type === "moov") { await add(moov); continue; }
    const end = b.start + b.size, head = new Uint8Array(12);
    head.set(code(b.type));
    view(head).setBigUint64(4, BigInt(end - b.start - b.hdr));
    await add(head);
    for (let at = b.start + b.hdr; at < end; at += PIECE) await add(await r.read(at, Math.min(PIECE, end - at)));
  }
  if (fill) { await push(stack, await leafHash(buf.subarray(0, fill))); leaves++; }
  return { binding: "media/1", hash: hex(await root(stack)), leaves };
}

// ── carrying the record: C2PA and XMP ──

/** The C2PA assertion to add with your own C2PA tool and signing certificate. */
export function c2paAssertion(envelope) {
  return { label: ASSERTION, data: envelope };
}

const A = (reason) => fail("after-gen: " + reason);

// A strict minimal CBOR: text-keyed maps, arrays, text, integers, true, false, null. Nothing else.
function cbor(b) {
  const v = view(b);
  let at = 0;
  const take = (n) => { if (at + n > b.length) A("CBOR ends early"); at += n; return at - n; };
  const arg = (info) => {
    if (info < 24) return info;
    if (info === 24) return b[take(1)];
    if (info === 25) return v.getUint16(take(2));
    if (info === 26) return v.getUint32(take(4));
    if (info === 27) {
      const n = v.getBigUint64(take(8));
      if (n > BigInt(Number.MAX_SAFE_INTEGER)) A("a CBOR integer beyond 2^53");
      return Number(n);
    }
    A("indefinite or reserved CBOR length");
  };
  const item = (depth) => {
    if (depth > 64) A("CBOR nested too deep");
    const first = b[take(1)], major = first >> 5, info = first & 31;
    if (major === 7) {
      const simple = { 20: false, 21: true, 22: null }[info];
      if (simple === undefined) A("a CBOR float or simple value");
      return simple;
    }
    const n = arg(info);
    if (major <= 1 && n > Number.MAX_SAFE_INTEGER - major) A("a CBOR integer beyond 2^53 - 1");
    if (major >= 4 && n > b.length - at) A("CBOR ends early"); // every item takes at least one byte
    if (major === 0) return n;
    if (major === 1) return -1 - n;
    if (major === 3) { const s = take(n); try { return UTF8.decode(b.subarray(s, s + n)); } catch { A("CBOR text is not UTF-8"); } }
    if (major === 4) return Array.from({ length: n }, () => item(depth + 1));
    if (major === 5) {
      const entries = [];
      for (let i = 0; i < n; i++) {
        const k = item(depth + 1);
        if (typeof k !== "string") A("a CBOR map key is not text");
        if (entries.some(([x]) => x === k)) A("a CBOR map key twice");
        entries.push([k, item(depth + 1)]);
      }
      return Object.fromEntries(entries);
    }
    A("CBOR bytes or tags");
  };
  const out = item(0);
  if (at !== b.length) A("bytes after the CBOR item");
  return out;
}

// A JUMBF superbox, every superbox in it checked: {type (UUID hex), label, kids}, kids being superboxes or content boxes.
function jumbf(box, depth = 0) {
  if (depth > 64) A("JUMBF nested too deep");
  const kids = boxesIn(box.data, A);
  const d = kids[0];
  if (!d || d.type !== "jumd" || d.data.length < 17) A("a JUMBF superbox without its description");
  const toggles = d.data[16];
  let label = null;
  if (toggles & 2) {
    const end = d.data.indexOf(0, 17);
    if (end < 0) A("a JUMBF label without its NUL");
    try { label = UTF8.decode(d.data.subarray(17, end)); } catch { A("a JUMBF label is not UTF-8"); }
  }
  return { type: hex(d.data.subarray(0, 16)), label, kids: kids.slice(1).map((k) => (k.type === "jumb" ? jumbf(k, depth + 1) : k)) };
}

// A C2PA box's manifest store, every superbox in it checked; undefined for another purpose.
function c2paStore(box) {
  const p = box.data.subarray(16); // after the usertype: version and flags, purpose, [offset], store
  const end = p.indexOf(0, 4);
  if (p.length < 5 || end < 0) A("a C2PA box without its purpose");
  const purpose = latin1(p, 4, end - 4);
  if (purpose !== "manifest") return undefined;
  const boxes = boxesIn(p.subarray(end + 1 + 8), A);
  if (boxes.length !== 1 || boxes[0].type !== "jumb") A("a C2PA box holds one JUMBF store");
  const store = jumbf(boxes[0]);
  if (store.label !== "c2pa") A("not a C2PA manifest store");
  if (!store.kids.length || store.kids.some((k) => !k.kids)) A("a C2PA store holds manifests only");
  return store;
}

function fromC2pa(box) {
  const store = c2paStore(box);
  if (store === undefined) return undefined;
  const manifest = store.kids.at(-1); // the active manifest is the last
  const assertions = manifest.kids.filter((k) => k.kids && k.label === "c2pa.assertions");
  if (assertions.length !== 1) A("a C2PA manifest holds one assertion store");
  const ours = assertions[0].kids.filter((k) => k.kids && /^org\.pregen\.after_gen(?:__[0-9]+)?$/.test(k.label ?? ""));
  if (!ours.length) return null;
  if (ours.length > 1) A(`more than one ${ASSERTION} assertion`);
  const c = ours[0].kids[0];
  if (ours[0].kids.length !== 1 || c.kids) A(`${ASSERTION} holds one content box and no superbox`);
  if (c.type !== "json" && c.type !== "cbor") A(`${ASSERTION} is stored as JSON or CBOR`);
  const env = c.type === "cbor" ? cbor(c.data) : exactEnvelope(c.data);
  if (!isObject(env)) A(`${ASSERTION} is not an envelope (as JSON, exactly its canonical JSON)`);
  return env;
}

const escapeXml = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const deep = (v, d = 0) => d > 64 || (Boolean(v) && typeof v === "object" && Object.values(v).some((x) => deep(x, d + 1)));

// The envelope whose canonical JSON is exactly these bytes, or null.
function exactEnvelope(bytes) {
  try {
    const text = UTF8.decode(bytes), env = JSON.parse(text);
    return isObject(env) && !deep(env) && canonicalJson(env) === text ? env : null;
  } catch { return null; }
}

// pgag:Record by the fixed lexical rule (Carrying the record), never by an XML parser, so that every reader finds the
// same record: the envelope, or null for a packet that breaks the rule and so carries no record.
function fromXmp(packet) {
  const p = bytesText(packet), n = (x) => p.split(x).length - 1, pis = [n("<?xpacket begin="), n("<?xpacket end=")];
  if (["<!--", "<![CDATA[", "<!DOCTYPE", "<!ENTITY"].some((x) => p.includes(x)) || Math.max(...pis) > 1
      || n("<?") !== pis[0] + pis[1] || n(NS) !== 1 || n(`xmlns:pgag="${NS}"`) !== 1 || n("xmlns:pgag=") !== 1
      || n("<pgag:Record>") !== 1 || p.includes("pgag:Record=")) return null;
  const start = p.indexOf("<pgag:Record>") + 13, end = p.indexOf("</pgag:Record>", start), text = p.slice(start, end);
  if (end < 0 || text.includes("<") || /&(?!(?:amp|lt|gt|quot|apos);)/.test(text)) return null;
  const XML = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
  return exactEnvelope(Uint8Array.from(text.replace(/&(amp|lt|gt|quot|apos);/g, (_, e) => XML[e]), (c) => c.charCodeAt(0)));
}

async function carriers(r) {
  const top = await topBoxes(r, A), uuid = (u) => top.filter((b) => b.type === "uuid" && b.uuid === u);
  const read = async (b) => ({ ...b, data: (await r.read(b.start, b.size)).subarray(b.hdr) });
  return { top, xmp: await Promise.all(uuid(XMP_UUID).map(read)), c2pa: await Promise.all(uuid(C2PA_UUID).map(read)) };
}

/** The records a file carries, unchecked: {c2pa, xmp}, each an envelope or null. C2PA: the org.pregen.after_gen
 * assertion of the active (last) manifest. XMP: pgag:Record of the top-level XMP uuid box. Check each with checkAfterGen. */
export async function readAfterGen(source) {
  const { xmp, c2pa } = await carriers(reader(source));
  if (xmp.length > 1) A("more than one XMP box");
  const stores = c2pa.map(fromC2pa).filter((x) => x !== undefined);
  if (stores.length > 1) A("more than one C2PA manifest store");
  return { c2pa: stores[0] ?? null, xmp: xmp.length ? fromXmp(xmp[0].data.subarray(16)) : null };
}

const XPACKET = '<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
  + '<x:xmpmeta xmlns:x="adobe:ns:meta/">\n<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
  + "</rdf:RDF>\n</x:xmpmeta>\n<?xpacket end=\"w\"?>";

// The packet without its top-level rdf:Description elements that use the pgag namespace.
function dropPgag(packet) {
  const tags = /<(\/?)rdf:Description\b(?:[^>"']|"[^"]*"|'[^']*')*?(\/?)>/g;
  let depth = 0, start = 0, out = "", from = 0;
  for (const m of packet.matchAll(tags)) {
    if (m[1]) depth--;
    else if (!m[2]) { if (depth++ === 0) start = m.index; continue; }
    else if (depth === 0) start = m.index;
    if (depth === 0) {
      const end = m.index + m[0].length;
      if (packet.slice(start, end).includes(NS)) { out += packet.slice(from, start); from = end; }
    }
    if (depth < 0) A("the existing XMP packet is not well formed");
  }
  return out + packet.slice(from);
}

/** The file with the record in XMP. With no XMP box, a top-level uuid box is appended at the end, so no offset moves; a
 * last box of size 0 ("to the end of the file") gets its real size written first, and one larger than 4 GiB is refused.
 * An existing XMP box keeps its properties (an earlier pgag description is dropped) and is rewritten in place: as the
 * last box it may grow; elsewhere the new packet must fit in it, padded with spaces, or embedding is refused. pgag:Id, pgag:Registry and, given the
 * directory, pgag:Status ({api}/v2/after-gen/{id}) are copies for people, never read as the record. */
export async function embedXmp(bytes, envelope, { directory } = {}) {
  if (!(bytes instanceof Uint8Array)) A("embedXmp takes the file as a Uint8Array");
  if (envelope?.type !== RECORD || !envelope.body || typeof envelope.body !== "object") A(`not a ${RECORD} envelope`);
  const { top, xmp } = await carriers(reader(bytes));
  if (xmp.length > 1) A("more than one XMP box");
  const out = Uint8Array.from(bytes), last = top.at(-1), old = xmp[0];
  if (last?.zero && !old) {
    if (last.size > 0xffffffff) A("the last box runs to the end of the file and is larger than 4 GiB");
    view(out).setUint32(last.start, last.size);
  }
  let packet = XPACKET;
  if (old) {
    try { packet = UTF8.decode(old.data.subarray(16)); } catch { A("the existing XMP packet is not UTF-8"); }
    if (["<!--", "<![CDATA[", "<!DOCTYPE", "<!ENTITY"].some((x) => packet.includes(x))) {
      A("the existing XMP packet holds a comment, CDATA or a DTD, which the lexical rule refuses");
    }
    packet = dropPgag(packet).replace(/[ \t\r\n]+(?=<\?xpacket end=)/, ""); // its old padding: the room to fill again
  }
  const at = packet.search(/<rdf:RDF\b(?:[^>"']|"[^"]*"|'[^']*')*>/);
  if (at < 0) A("the existing XMP packet has no rdf:RDF");
  const open = packet.slice(at).match(/^<rdf:RDF\b(?:[^>"']|"[^"]*"|'[^']*')*>/)[0];
  const body = envelope.body, id = await messageId(RECORD, body), api = directory?.registryFor(body.subject_ref)?.api;
  const description = `\n<rdf:Description rdf:about="" xmlns:pgag="${NS}">\n`
    + `<pgag:Record>${escapeXml(canonicalJson(envelope))}</pgag:Record>\n`
    + `<pgag:Id>${id}</pgag:Id>\n`
    + `<pgag:Registry>${escapeXml(issuerOf(body.subject_ref))}</pgag:Registry>\n`
    + (api ? `<pgag:Status>${escapeXml(api.replace(/\/+$/, ""))}/v2/after-gen/${id}</pgag:Status>\n` : "")
    + "</rdf:Description>";
  let text = utf8.encode(packet.slice(0, at + open.length) + description + packet.slice(at + open.length));
  const back = fromXmp(text);
  if (!back || canonicalJson(back) !== canonicalJson(envelope)) {
    A("the packet would not carry the record under the lexical rule: an existing property spells pgag:Record= or "
      + "xmlns:pgag=, or the record is not canonical JSON");
  }
  const uuid = Uint8Array.from(XMP_UUID.match(/../g), (h) => parseInt(h, 16));
  if (old && old.start + old.size < bytes.length) { // in place, the same size, padded before the trailer
    const room = old.size - old.hdr - 16, end = bytesText(text).lastIndexOf("<?xpacket end=");
    if (text.length > room) A("the new packet does not fit in the existing XMP box, which is not the last box");
    const cut = end < 0 ? text.length : end;
    text = concat([text.subarray(0, cut), new Uint8Array(room - text.length).fill(0x20), text.subarray(cut)]);
    out.set(text, old.start + old.hdr + 16);
    return out;
  }
  const big = old?.hdr === 16, head = new Uint8Array(big ? 16 : 8); // the last box, rewritten or appended
  view(head).setUint32(0, big ? 1 : 24 + text.length);
  head.set(code("uuid"), 4);
  if (big) view(head).setBigUint64(8, BigInt(32 + text.length));
  return concat([out.subarray(0, old ? old.start : out.length), head, uuid, text]);
}

// ── checking the record and its status ──

const PURPOSES = ["personal", "educational", "research", "editorial", "commercial"]; // likeness/1, as index.js
const UNPRINTABLE = /(?! )[\p{C}\p{Z}]/u; // as index.js: Python's str.isprintable
const printable = (v) => (Array.isArray(v) ? v.every(printable)
  : v && typeof v === "object" ? Object.entries(v).every(([k, x]) => printable(k) && printable(x))
  : typeof v !== "string" || !UNPRINTABLE.test(v));
const isObject = (v) => Boolean(v) && typeof v === "object" && !Array.isArray(v);
const members = (o, names) => isObject(o) && canonicalJson(Object.keys(o).sort()) === canonicalJson([...names].sort());
const hex64 = (v) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
const time = (v) => Number.isSafeInteger(v) && v >= 1;
const sortedUnique = (v) => Array.isArray(v) && v.every((x) => typeof x === "string")
  && canonicalJson(v) === canonicalJson([...new Set(v)].sort());
const wordsOrAll = (v, re, most) => sortedUnique(v) && v.length > 0
  && (canonicalJson(v) === '["*"]' || (v.length <= most && v.every((x) => re.test(x))));
const BODY = ["signers", "kind", "label", "notice", "not", "subject_ref", "content", "request", "holder", "licence", "use",
  "scope", "approval", "issued_at"]; // no status_url: the id hashes the body, so a verifier builds {api}/v2/after-gen/{id}
const APPROVAL = { self: ["assent", "decision"], registry: ["assent", "instruction", "factor"],
  agent: ["assent", "agent", "mandate", "decision", "factor"] };

function partyId(v, what) {
  try { return checkProviderUrl(v, { allowPort: true }); } catch { A(`${what} is not a party id (https://<domain>)`); }
}

function fetchOf({ fetch: fetchFn, getJson }) {
  if (getJson) return async (url) => ({ ok: true, status: 200, json: async () => getJson(url) });
  return fetchFn ?? globalThis.fetch;
}

// Shape and constants of a pg.after_gen.v1 body: exactly the spec's members, at every level.
function recordShape(b) {
  if (!members(b, BODY) || !printable(b)) A("not a pg.after_gen.v1 body: a member missing or unknown, or a control character");
  if (!Array.isArray(b.signers) || b.signers.length !== 1 || !members(b.signers[0], ["role", "key_id"])) A("signers is one registry key");
  if (b.kind !== "ratification") A("kind must be ratification: other kinds are not in after-gen/1");
  if (b.label !== AFTER_GEN_LABEL || b.notice !== AFTER_GEN_NOTICE || canonicalJson(b.not) !== canonicalJson(AFTER_GEN_NOT)) {
    A("label, notice and not must be the exact constants");
  }
  issuerOf(b.subject_ref);
  const c = b.content;
  if (!members(c, ["binding", "hash", "leaves"]) || c.binding !== "media/1" || !hex64(c.hash) || !Number.isSafeInteger(c.leaves)
      || c.leaves < 1) A("content names one file by its media/1 hash and its leaves");
  if (!hex64(b.request)) A("request is a message id");
  partyId(b.holder, "holder");
  if (!members(b.licence, ["format", "id"]) || b.licence.format !== "pg.grant.v1" || !hex64(b.licence.id)) {
    A("licence is {format: pg.grant.v1, id}");
  }
  const u = b.use;
  if (!members(u, ["n", "of"]) || !Number.isSafeInteger(u.n) || u.n < 1
      || !(u.of === null || (Number.isSafeInteger(u.of) && u.of >= u.n))) A("use is {n from 1, of: max_uses or null}");
  const s = b.scope;
  if (!members(s, ["purposes", "categories", "territories", "channels", "project", "not_after"])) A("scope has exactly its six members");
  if (!sortedUnique(s.purposes) || !s.purposes.length || !s.purposes.every((p) => PURPOSES.includes(p))) {
    A("scope.purposes: a sorted list of likeness/1 purposes, never empty");
  }
  if (!sortedUnique(s.categories)) A("scope.categories: a sorted list without repeats");
  if (s.categories.some((x) => INTIMATE.includes(x))) A("scope.categories names an intimate category");
  if (s.categories.some((x) => !CATEGORIES.includes(x))) A("scope.categories names a word outside the closed vocabulary");
  if (!wordsOrAll(s.territories, /^[A-Z]{2}$/, 250)) A('scope.territories: at most 250 sorted ISO 3166-1 alpha-2 codes, or ["*"]');
  if (!wordsOrAll(s.channels, /^[a-z0-9-]{1,32}$/, 64)) A('scope.channels: at most 64 sorted words of [a-z0-9-]{1,32}, or ["*"]');
  if (typeof s.project !== "string" || [...s.project].length < 1 || [...s.project].length > 200) A("scope.project: 1 to 200 printable characters");
  if (!time(s.not_after)) A("scope.not_after is an integer time");
  const a = b.approval; // assent is one of the three words, never a list (which Object.hasOwn would read as a string)
  const form = isObject(a) && typeof a.assent === "string" && Object.hasOwn(APPROVAL, a.assent) ? APPROVAL[a.assent] : null;
  if (!form || !members(a, form)) A("approval is exactly one of its three forms: self, registry or agent");
  if (a.assent === "self" && !hex64(a.decision)) A("approval self names the subject's decision");
  if (a.assent === "registry" && (!hex64(a.instruction) || !["authenticator", "email"].includes(a.factor))) {
    A("approval registry names the instruction and its second factor: authenticator or email");
  }
  if (a.assent === "agent") {
    if (!hex64(a.mandate) || !hex64(a.decision) || a.factor !== "signature") A("approval agent names the mandate, the decision and factor signature");
    partyId(a.agent, "approval.agent");
    if (new URL(a.agent).hostname === new URL(b.holder).hostname) A("a representative is never the holder of the same record");
  }
  if (!time(b.issued_at)) A("issued_at is an integer time");
  if (s.not_after <= b.issued_at) A("scope.not_after is later than issued_at");
}

const approvedBy = (a) => (a.assent === "self" ? "approved by the person"
  : a.assent === "registry" ? "approved on the person's instruction at the registry"
  : `approved by ${new URL(a.agent).hostname} under mandate ${a.mandate}`);

/** Steps 3 and 4 of "How a verifier checks a file": the record's shape and constants, its signature by exactly one
 * registry key the directory lists for the subject's prefix at issued_at (a revoked registry's records fail), the
 * approval form, the floor; then, given `media` (a mediaHash result or its hex hash), that it is this file. Throws
 * PregenError; returns what to show, with the three statements. */
export async function checkAfterGen(env, { directory, getJson, fetch: fetchFn, media } = {}) {
  const f = fetchOf({ fetch: fetchFn, getJson });
  if (!isObject(env) || env.type !== RECORD || !isObject(env.body)) A(`not a ${RECORD} envelope`);
  recordShape(env.body);
  directory ??= await loadDirectory({ fetch: f });
  const code = env.body.subject_ref;
  if (directory.isFalseClaim(code)) A(`${code} is a false claim the steward recorded`);
  const b = await registrySigned(env, RECORD, code, directory, f);
  let fileMatch = null;
  if (media !== undefined && media !== null) {
    const m = typeof media === "string" ? { binding: "media/1", hash: media, leaves: b.content.leaves } : media;
    if (m.binding !== b.content.binding || m.hash !== b.content.hash || m.leaves !== b.content.leaves) fail("not for this file");
    fileMatch = true;
  }
  return { id: await messageId(RECORD, b), subject_ref: b.subject_ref, prefix: issuerOf(b.subject_ref), label: b.label,
    notice: b.notice, not: [...b.not], holder: b.holder, licence: b.licence.id, use: b.use, scope: b.scope,
    approval: b.approval, approvedBy: approvedBy(b.approval), issued_at: b.issued_at,
    content: b.content, fileMatch };
}

/** Step 5: the registry's live status of this record. Signed by a registry key the directory lists for the record's
 * subject prefix, naming this record, issued no later than now + 60, not expired, living at most 300 seconds; its
 * not_after and approved_at those of the record. Throws PregenError; returns {state, approved_at, withdrawn_at, not_after}. */
export async function checkAfterGenStatus(statusEnv, recordEnv, { directory, getJson, fetch: fetchFn,
  now = Math.floor(Date.now() / 1000) } = {}) {
  const f = fetchOf({ fetch: fetchFn, getJson });
  directory ??= await loadDirectory({ fetch: f });
  if (now - directory.loadedAt > DIRECTORY_MAX_AGE) A("the directory was loaded more than 24 hours ago: load it again");
  const record = await checkAfterGen(recordEnv, { directory, fetch: f });
  if (!isObject(statusEnv) || statusEnv.type !== STATUS || !isObject(statusEnv.body)) A(`not a ${STATUS} envelope`);
  const s = statusEnv.body;
  if (!members(s, ["signers", "record", "state", "approved_at", "withdrawn_at", "not_after", "issued_at", "expires_at"])
      || !Array.isArray(s.signers) || s.signers.length !== 1 || !members(s.signers[0], ["role", "key_id"])) {
    A("not a pg.after_gen_status.v1 body: a member missing or unknown");
  }
  await registrySigned(statusEnv, STATUS, record.subject_ref, directory, f);
  if (s.record !== record.id) A("the status is for another record");
  if (![s.issued_at, s.expires_at, s.approved_at, s.not_after].every(time)) A("status times are integers");
  if (s.issued_at > now + 60) A("the status is issued in the future");
  if (s.expires_at <= now) A("the status has expired");
  if (s.expires_at <= s.issued_at || s.expires_at - s.issued_at > 300) A("a status lives at most 300 seconds");
  if (!["active", "withdrawn", "expired"].includes(s.state)) A(`unknown state: ${s.state}`);
  if (s.state === "withdrawn" ? !(time(s.withdrawn_at) && s.withdrawn_at >= s.approved_at && s.withdrawn_at <= s.issued_at)
    : s.withdrawn_at !== null) A("withdrawn_at is the time of withdrawal when withdrawn, and null otherwise");
  if (s.not_after !== record.scope.not_after) A("the status's not_after is not the record's");
  if (s.approved_at !== record.issued_at) A("the status's approved_at is not the record's issued_at");
  if ((s.state === "active" && s.issued_at >= s.not_after) || (s.state === "expired" && s.issued_at < s.not_after)) {
    A("the state does not agree with not_after");
  }
  return { state: s.state, approved_at: s.approved_at, withdrawn_at: s.withdrawn_at, not_after: s.not_after };
}
