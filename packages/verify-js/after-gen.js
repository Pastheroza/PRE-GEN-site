// AFTER-GEN (spec/drafts/after-gen.md): a registry's record that the rights holder approved one existing file.
// media/1 hashes what plays in an ISO base media file; readAfterGen and embedXmp carry the record; checkAfterGen and
// checkAfterGenStatus check it. No Node-only API: Web Crypto, Uint8Array and DataView, so it runs in browsers too.
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
    out.push({ ...h, start: at, data: b.subarray(at + h.hdr, at + h.size), whole: b.subarray(at, at + h.size) });
    at += h.size;
  }
  return out;
}

function one(boxes, type, where, optional = false) {
  const found = boxes.filter((x) => x.type === type);
  if (found.length > 1) M(`two ${type} boxes in ${where}`);
  if (!found.length && !optional) M(`no ${type} in ${where}`);
  return found[0] ?? null;
}

function need(box, length) {
  if (box.data.length < length) M(`${box.type} is too short`);
  return view(box.data);
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

const MEDIA_HEADERS = { vmhd: 12, smhd: 8, sthd: 4, hmhd: 20, nmhd: 4 }; // each with its layout's length
const READ_LIMIT = 8 * 1024 * 1024; // a chunk larger than this is read sample by sample

// A full box of version 0 or 1; `layout` (version 0, version 1) is the length of its fixed fields.
function fullBox(box, layout = [4, 4]) {
  const v = need(box, 4), version = box.data[0];
  if (version > 1) M(`${box.type} version ${version} is not read`);
  need(box, layout[version]);
  return { v, version, flags: v.getUint32(0) & 0xffffff };
}

function table(box, header, entry, where) {
  const v = need(box, header), n = v.getUint32(header - 4);
  if (box.data.length !== header + n * entry) M(`the ${box.type} count in ${where} does not agree with its size`);
  return { v, n };
}

// A track's boxes, its id and its handler.
function trackHead(trak) {
  const kids = boxesIn(trak.data);
  const tkhd = one(kids, "tkhd", "trak"), mdia = one(kids, "mdia", "trak");
  const { v, version, flags } = fullBox(tkhd, [84, 96]);
  const mk = boxesIn(mdia.data), hdlr = one(mk, "hdlr", "mdia");
  need(hdlr, 12);
  const tref = one(kids, "tref", "trak", true);
  const refs = tref ? boxesIn(tref.data).map((b) => {
    if (b.data.length % 4) M(`tref ${b.type} is not a list of track ids`);
    return { type: b.type, ids: Array.from({ length: b.data.length / 4 }, (_, i) => view(b.data).getUint32(4 * i)) };
  }) : [];
  return { kids, mk, tkhd: { v, version, flags }, id: v.getUint32(version ? 20 : 12),
    hdlrBytes: hdlr.data.subarray(8, 12), refs, edts: one(kids, "edts", "trak", true) };
}

// A track's first leaf and its samples as chunks, {off, len, sdi, n, first}, added to `ranges`; its tables must agree.
function trackBody(t, position, ranges, fileSize) {
  const where = `track ${t.id}`;
  const mdhd = fullBox(one(t.mk, "mdhd", "mdia"), [24, 36]);
  const timescale = mdhd.v.getUint32(mdhd.version ? 20 : 12);
  const nk = boxesIn(one(t.mk, "minf", "mdia").data);
  const mhd = nk.find((b) => Object.hasOwn(MEDIA_HEADERS, b.type));
  if (mhd) need(mhd, MEDIA_HEADERS[mhd.type]);
  const dinf = one(nk, "dinf", "minf", true), dref = dinf && one(boxesIn(dinf.data), "dref", "dinf", true);
  if (dref) {
    const n = need(dref, 8).getUint32(4), refs = boxesIn(dref.data.subarray(8));
    if (refs.length !== n) M(`the dref count in ${where} does not agree with its entries`);
    if (refs.some((x) => !(need(x, 4) && x.data[3] & 1))) M("a data reference that is not in the same file");
  }
  const sk = boxesIn(one(nk, "stbl", "minf").data);
  if (sk.some((b) => b.type === "stz2")) M("stz2 is not read");

  const stsd = one(sk, "stsd", "stbl"), sv = need(stsd, 8);
  const entries = boxesIn(stsd.data.subarray(8));
  if (entries.length !== sv.getUint32(4)) M(`stsd in ${where} holds ${entries.length} entries, not ${sv.getUint32(4)}`);
  for (const e of entries) {
    const body = e.whole.subarray(8);
    if (["encv", "enca", "encs"].includes(e.type) || body.some((_, i) => latin1(body, i, 4) === "sinf")) {
      M("encrypted samples");
    }
  }

  // tkhd: enabled, layer, alternate group, volume, matrix, width, height (signed except width and height).
  const tv = t.tkhd.v, base = t.tkhd.version ? 44 : 32;
  const tk = [t.tkhd.flags & 1, tv.getInt16(base), tv.getInt16(base + 2), tv.getInt16(base + 4),
    ...Array.from({ length: 9 }, (_, i) => tv.getInt32(base + 8 + 4 * i)), tv.getUint32(base + 44), tv.getUint32(base + 48)];

  const edits = [];
  if (t.edts) {
    const elst = one(boxesIn(t.edts.data), "elst", "edts", true);
    if (elst) {
      const { version } = fullBox(elst), size = version ? 20 : 12, { v, n } = table(elst, 8, size, where);
      for (let i = 0, at = 8; i < n; i++, at += size) {
        edits.push(...(version ? [v.getBigUint64(at), v.getBigInt64(at + 8)] : [v.getUint32(at), v.getInt32(at + 4)]),
          v.getInt16(at + size - 4), v.getInt16(at + size - 2));
      }
    }
  }

  const leaf = concat([
    el("hdlr", t.hdlrBytes),
    el("tref", concat(t.refs.map((r) => el(r.type, ints(r.ids.map((id) => position.get(id))))))),
    ...(mhd ? [el(mhd.type, mhd.data.subarray(4))] : []),
    el("mdts", ints([timescale])),
    ...entries.map((e) => el("sent", el(e.type, e.whole.subarray(8)))),
    el("tkhd", ints(tk)),
    el("elst", ints(edits)),
  ]);

  // Sample tables. Counts must agree everywhere: one reading only.
  const stszBox = one(sk, "stsz", "stbl"), zv = need(stszBox, 12), fixed = zv.getUint32(4), count = zv.getUint32(8);
  if (stszBox.data.length !== 12 + (fixed ? 0 : 4 * count)) M(`the stsz count in ${where} does not agree with its size`);
  if (fixed * count > fileSize) M("a sample range falls outside the file"); // before any loop over the samples
  const sizeOf = fixed ? () => fixed : (i) => zv.getUint32(12 + 4 * i);
  const stts = table(one(sk, "stts", "stbl"), 8, 8, where);
  let total = 0;
  for (let i = 0; i < stts.n; i++) total += stts.v.getUint32(8 + 8 * i);
  if (total !== count) M("stts, ctts and stsz count different samples");
  const cttsBox = one(sk, "ctts", "stbl", true);
  const ctts = cttsBox ? { ...table(cttsBox, 8, 8, where), signed: fullBox(cttsBox).version === 1 } : null;
  if (ctts) {
    let c = 0;
    for (let i = 0; i < ctts.n; i++) c += ctts.v.getUint32(8 + 8 * i);
    if (c !== count) M("stts, ctts and stsz count different samples");
  }
  const stco = one(sk, "stco", "stbl", true), co64 = one(sk, "co64", "stbl", true);
  if (!stco === !co64) M(`${where} needs exactly one of stco and co64`);
  const co = table(stco || co64, 8, stco ? 4 : 8, where);
  const offset = stco ? (i) => co.v.getUint32(8 + 4 * i) : (i) => Number(co.v.getBigUint64(8 + 8 * i));
  const stsc = table(one(sk, "stsc", "stbl"), 8, 12, where);
  const sc = (i, k) => stsc.v.getUint32(8 + 12 * i + 4 * k);
  if (co.n && !stsc.n) M(`stsc in ${where} is empty`);
  for (let i = 0; i < stsc.n; i++) {
    if ((i === 0 ? sc(0, 0) !== 1 : sc(i, 0) <= sc(i - 1, 0)) || sc(i, 0) > co.n) M(`stsc in ${where} names chunks out of order`);
    if (sc(i, 1) < 1) M(`stsc in ${where} names a chunk without samples`);
    if (sc(i, 2) < 1 || sc(i, 2) > entries.length) M(`stsc in ${where} names a sample entry stsd does not have`);
  }
  const chunks = [];
  let s = 0;
  for (let c = 0, e = 0; c < co.n; c++) {
    while (e + 1 < stsc.n && sc(e + 1, 0) - 1 <= c) e++;
    const n = sc(e, 1);
    if (s + n > count) M("stsc and stsz count different samples");
    let len = fixed * n;
    if (!fixed) for (let j = 0; j < n; j++) len += sizeOf(s + j);
    chunks.push({ off: offset(c), len, n, sdi: sc(e, 2), first: s });
    s += n;
  }
  if (s !== count) M("stsc and stsz count different samples");
  ranges.push(...chunks);
  return { leaf, chunks, sizeOf, stts, ctts };
}

// A cursor over a run-length table (stts, ctts): value for each sample in turn.
function runs(t, signed) {
  let i = 0, left = 0;
  return () => {
    while (left === 0) { left = t.v.getUint32(8 + 8 * i); i++; }
    left--;
    return signed ? t.v.getInt32(8 * i + 4) : t.v.getUint32(8 * i + 4);
  };
}

// Every box in its place: the boxes media/1 reads, by the listed box that holds them (the others are read whole).
const LISTED = { moov: ["mvhd", "trak"], trak: ["tkhd", "tref", "edts", "mdia"], edts: ["elst"],
  mdia: ["mdhd", "hdlr", "minf"], minf: ["dinf", "stbl"], dinf: ["dref"],
  stbl: ["stsd", "stts", "ctts", "stsc", "stsz", "stco", "co64"] };
const PLACED = /(?=(mvhd|trak|tkhd|tref|edts|elst|mdia|mdhd|minf|vmhd|smhd|sthd|hmhd|nmhd|dinf|dref|stbl|stsd|stts|ctts|stsc|stsz|stz2|stco|co64|avcC|hvcC|av1C|vpcC|esds|dOps|dfLa|colr|pasp|clap|hdlr))/g;
const DATA_HANDLERS = ["mdir", "mdta", "ID32", "alis", "url ", "mp7t", "mp7b"];
const bytesText = (b) => { // one character per byte
  let s = "";
  for (let i = 0; i < b.length; i += 8192) s += String.fromCharCode(...b.subarray(i, i + 8192));
  return s;
};

// The ranges [start, end) of `b`, the content of a listed box of this type, that media/1 does not read: every box there
// that it does not list, whole, adjacent ones joined. The first media header of minf is listed.
function unread(b, type, at = 0, out = []) {
  let header = type === "minf";
  for (const k of boxesIn(b)) {
    if (LISTED[type].includes(k.type) || (header && Object.hasOwn(MEDIA_HEADERS, k.type))) {
      header &&= !Object.hasOwn(MEDIA_HEADERS, k.type);
      if (Object.hasOwn(LISTED, k.type)) unread(k.data, k.type, at + k.start + k.hdr, out);
    } else if (out.at(-1)?.[1] === at + k.start) out.at(-1)[1] = at + k.start + k.size;
    else out.push([at + k.start, at + k.start + k.size]);
  }
  return out;
}

// A player may act on a table, an edit list or a track box wherever it finds one in moov: refuse any such code in the
// bytes media/1 did not read, except hdlr of a metadata or data-reference handler.
function misplaced(moov) {
  for (const [s, e] of unread(moov, "moov")) {
    for (const x of bytesText(moov.subarray(s, e)).matchAll(PLACED)) {
      if (x[1] !== "hdlr" || !DATA_HANDLERS.includes(latin1(moov, s + x.index + 12, 4))) M(`${x[1]} outside its place in moov`);
    }
  }
}

/** media/1 of an ISO base media file (MP4, MOV, M4V): {binding: "media/1", hash, leaves}. `source` is a Uint8Array, a
 * Blob or File, or {size, read(offset, length) -> Promise<Uint8Array>}; boxes and samples are read in ranges, never the
 * whole file at once. Throws PregenError("media/1: <reason>") for every file "One reading only" refuses. */
export async function mediaHash(source) {
  const r = reader(source);
  const top = await topBoxes(r, M);
  if (top.some((b) => b.type === "moof")) M("a fragmented file (moof)");
  const moovs = top.filter((b) => b.type === "moov");
  if (moovs.length !== 1) M(moovs.length ? "more than one moov box" : "no moov box");
  const moovBox = moovs[0], moovBytes = await r.read(moovBox.start, moovBox.size);
  const moov = boxesIn(moovBytes.subarray(moovBox.hdr));
  if (moov.some((b) => b.type === "mvex")) M("a fragmented file (mvex)");

  const mvhd = fullBox(one(moov, "mvhd", "moov"), [100, 112]);
  const mv = mvhd.v, ts = mvhd.version ? 20 : 12, rate = ts + (mvhd.version ? 12 : 8);
  const movie = concat([utf8.encode("PREGEN-MEDIA\0media/1\0"), el("FRMT", utf8.encode("isobmff")),
    el("tmsc", ints([mv.getUint32(ts)])), el("rate", ints([mv.getInt32(rate)])), el("volu", ints([mv.getInt16(rate + 4)])),
    el("mtrx", ints(Array.from({ length: 9 }, (_, i) => mv.getInt32(rate + 16 + 4 * i))))]);

  // Every track, whatever its handler: a player may play a track whose handler says meta or hint.
  const tracks = moov.filter((b) => b.type === "trak").map(trackHead);
  if (new Set(tracks.map((t) => t.id)).size !== tracks.length) M("two tracks with one track_ID");
  const listed = [...tracks].sort((a, b) => a.id - b.id);
  const position = new Map(listed.map((t, i) => [t.id, i]));
  for (const t of listed) {
    for (const ref of t.refs) if (ref.ids.some((id) => !position.has(id))) M("a tref names a track that is not listed");
  }
  const ranges = [], bodies = listed.map((t) => trackBody(t, position, ranges, r.size));
  misplaced(moovBytes.subarray(moovBox.hdr));

  // Every sample inside the file, none sharing a byte with another (a chunk's samples are contiguous). An empty sample
  // has no byte to place or share.
  const spans = ranges.filter((c) => c.len > 0).sort((a, b) => a.off - b.off);
  for (const c of spans) if (c.off + c.len > r.size) M("a sample range falls outside the file");
  for (let i = 1; i < spans.length; i++) if (spans[i].off < spans[i - 1].off + spans[i - 1].len) M("sample ranges overlap");

  const stack = [];
  let leaves = 1;
  await push(stack, await leafHash(movie));
  for (const b of bodies) {
    await push(stack, await leafHash(b.leaf));
    leaves++;
    const dur = runs(b.stts, false), cto = b.ctts ? runs(b.ctts, b.ctts.signed) : () => 0;
    let dtim = 0n;
    for (const c of b.chunks) {
      const whole = c.len <= READ_LIMIT ? await r.read(c.off, c.len) : null;
      const pending = [];
      for (let j = 0, at = 0; j < c.n; j++) {
        const size = b.sizeOf(c.first + j);
        const data = whole ? whole.subarray(at, at + size) : await r.read(c.off + at, size);
        const sdur = dur();
        const leaf = concat([new Uint8Array([0]), el("sdsc", ints([c.sdi])), el("dtim", ints([dtim])),
          el("ctso", ints([cto()])), el("sdur", ints([sdur])), el("data", data)]);
        pending.push(sha256(leaf));
        if (!whole) await pending.at(-1); // a large chunk: one sample in memory at a time
        dtim += BigInt(sdur);
        at += size;
      }
      for (const h of await Promise.all(pending)) await push(stack, h);
      leaves += c.n;
    }
  }
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

function fromC2pa(box) {
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
  const p = bytesText(packet), n = (x) => p.split(x).length - 1;
  if (["<!--", "<![CDATA[", "<!DOCTYPE", "<!ENTITY"].some((x) => p.includes(x)) || n(`xmlns:pgag="${NS}"`) !== 1
      || n("xmlns:pgag=") !== 1 || n("<pgag:Record>") !== 1 || p.includes("pgag:Record=")) return null;
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

/** The file with the record in XMP: a top-level XMP uuid box appended at the end, so no offset moves. An existing XMP
 * box keeps its properties: they move into the new packet (an earlier pgag description is dropped) and the old box
 * becomes a `free` box of the same size, its payload zeroed. A last box of size 0 ("to the end of the file") gets its
 * real size written, so the new box follows it; one larger than 4 GiB is refused. pgag:Id, pgag:Registry and, given the
 * directory, pgag:Status ({api}/v2/after-gen/{id}) are copies for people, never read as the record. */
export async function embedXmp(bytes, envelope, { directory } = {}) {
  if (!(bytes instanceof Uint8Array)) A("embedXmp takes the file as a Uint8Array");
  if (envelope?.type !== RECORD || !envelope.body || typeof envelope.body !== "object") A(`not a ${RECORD} envelope`);
  const { top, xmp } = await carriers(reader(bytes));
  if (xmp.length > 1) A("more than one XMP box");
  const out = new Uint8Array(bytes.length);
  out.set(bytes);
  const last = top.at(-1);
  if (last?.zero) {
    if (last.size > 0xffffffff) A("the last box runs to the end of the file and is larger than 4 GiB");
    view(out).setUint32(last.start, last.size);
  }
  let packet = XPACKET;
  if (xmp.length) {
    const old = xmp[0];
    try { packet = UTF8.decode(old.data.subarray(16)); } catch { A("the existing XMP packet is not UTF-8"); }
    if (["<!--", "<![CDATA[", "<!DOCTYPE", "<!ENTITY"].some((x) => packet.includes(x))) {
      A("the existing XMP packet holds a comment, CDATA or a DTD, which the lexical rule refuses");
    }
    packet = dropPgag(packet);
    out.set(code("free"), old.start + 4);
    out.fill(0, old.start + old.hdr, old.start + old.size); // keep the size fields, zero the usertype and the packet
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
  const text = utf8.encode(packet.slice(0, at + open.length) + description + packet.slice(at + open.length));
  const back = fromXmp(text);
  if (!back || canonicalJson(back) !== canonicalJson(envelope)) {
    A("the packet would not carry the record under the lexical rule: an existing property spells pgag:Record= or "
      + "xmlns:pgag=, or the record is not canonical JSON");
  }
  const box = new Uint8Array(24 + text.length);
  view(box).setUint32(0, box.length);
  box.set(code("uuid"), 4);
  box.set(Uint8Array.from(XMP_UUID.match(/../g), (h) => parseInt(h, 16)), 8);
  box.set(text, 24);
  return concat([out, box]);
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
