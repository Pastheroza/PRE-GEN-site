"""AFTER-GEN v1 (spec/drafts/after-gen.md): the rights holder's registry approves a file that already exists. The
media/1 hash of an ISO base media file, the record carried in C2PA or XMP, and the checks of the record and its
status. A record is never a PRE-GEN permission given before generation, and says nothing about whether the content is
AI-generated."""

import hashlib
import io
import json
import os
import re
import shutil
import struct
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit
from xml.sax.saxutils import escape, quoteattr

from . import (CATEGORIES, INTIMATE, _HEX64, _PURPOSES, _count, _get_json, _ints, _printable, _registry_signed,
               _words, check_provider_url, canonical_json, fingerprint, issuer_of, load_directory, message_id,
               public_key_hex, sign_envelope, PregenError, DIRECTORY_MAX_AGE)

# What a record never says (the three statements): fixed constants, shown wherever the record is shown.
AFTER_GEN_LABEL = "approved after generation"
AFTER_GEN_NOTICE = ("Recorded after the content existed. Not a PRE-GEN permission given before generation. "
                    "Says nothing about whether the content is AI-generated.")
AFTER_GEN_NOT = ["pre_generation_permission", "statement_of_origin"]

_TYPE, _STATUS = "pg.after_gen.v1", "pg.after_gen_status.v1"
_XMP_UUID = bytes.fromhex("BE7ACFCB97A942E89C71999491E3AFAC")
_C2PA_UUID = bytes.fromhex("D8FEC3D61B0E483C92975828877EC481")
_PGAG, _RDF, _X = "https://pregen.org/ns/after-gen/1/", "http://www.w3.org/1999/02/22-rdf-syntax-ns#", "adobe:ns:meta/"
_XML_NS = "http://www.w3.org/XML/1998/namespace"
_C2PA_LABEL = re.compile(r"org\.pregen\.after_gen(?:__[0-9]+)?")
_MAX_STATUS_LIFETIME = 300


# ── media/1 (Which bytes the hash covers) ──────────────────────────────────────────────────────

def _boxes(f, start, end, top=False, who="media/1"):
    """The boxes in [start, end) as (type, start, content start, end). Size 0 (to the end) only at the top level."""
    pos = start
    while pos < end:
        f.seek(pos)
        h = f.read(8)
        if end - pos < 8 or len(h) < 8:
            raise PregenError(f"{who}: a box runs past its parent")
        size, t = struct.unpack(">I4s", h)
        hl = 8
        if size == 1:
            big = f.read(8)
            if end - pos < 16 or len(big) < 8:
                raise PregenError(f"{who}: a box runs past its parent")
            size, hl = struct.unpack(">Q", big)[0], 16
        elif size == 0:
            if not top:
                raise PregenError(f"{who}: a box runs past its parent")
            size = end - pos
        if size < hl or pos + size > end:
            raise PregenError(f"{who}: a box runs past its parent")
        yield t, pos, pos + hl, pos + size
        pos += size


def _kids(m, s, e):
    out = {}
    for t, _, cs, ce in _boxes(m, s, e):
        out.setdefault(t, []).append((cs, ce))
    return out


def _one(kids, t, where):
    if len(kids.get(t, ())) != 1:
        raise PregenError(f"media/1: {where} needs exactly one {t.decode('latin-1')}")
    return kids[t][0]


def _opt(kids, t, where):
    if len(kids.get(t, ())) > 1:
        raise PregenError(f"media/1: {where} has more than one {t.decode('latin-1')}")
    return kids[t][0] if t in kids else None


def _el(code, value: bytes) -> bytes:
    """An element: four-byte code, u64 length, value."""
    return code + len(value).to_bytes(8, "big") + value


def _i(*xs) -> bytes:
    try:
        return b"".join(x.to_bytes(8, "big", signed=True) for x in xs)
    except OverflowError:
        raise PregenError("media/1: a value does not fit in a signed 64-bit integer") from None


def _full(m, box):
    """A full box's version and its bytes."""
    m.seek(box[0])
    b = m.read(box[1] - box[0])
    if len(b) < 4:
        raise PregenError("media/1: a box is too short")
    return b[0], b


def _table(m, box, entry, where):
    """A table box: version, then (count, entries); the entries must fill the box exactly."""
    v, b = _full(m, box)
    (n,) = struct.unpack_from(">I", b, 4)
    size = struct.calcsize(entry)
    if len(b) != 8 + n * size:
        raise PregenError(f"media/1: the {where} table's count does not agree with its size")
    return v, list(struct.iter_unpack(entry, b[8:]))


def _track(m, trak, file_size):
    """One trak: (track_ID, handler, the fields of its first leaf except tref, tref ids, samples)."""
    k = _kids(m, *trak)
    v, tkhd = _full(m, _one(k, b"tkhd", "trak"))
    if v not in (0, 1):
        raise PregenError("media/1: unknown tkhd version")
    tid = struct.unpack_from(">I", tkhd, 20 if v else 12)[0]
    layer, alt, vol, _, *rest = struct.unpack_from(">hhhH9iII", tkhd, 44 if v else 32)
    tkhd_el = _el(b"tkhd", _i(tkhd[3] & 1, layer, alt, vol, *rest))
    edits = []
    edts = _opt(k, b"edts", "trak")
    if edts:
        elst = _opt(_kids(m, *edts), b"elst", "edts")
        if elst:
            if _full(m, elst)[0] not in (0, 1):
                raise PregenError("media/1: unknown elst version")
            for row in _table(m, elst, ">Qqhh" if _full(m, elst)[0] == 1 else ">Iihh", "elst")[1]:
                edits += row
    tref = []
    tr = _opt(k, b"tref", "trak")
    if tr:
        for t, _, cs, ce in _boxes(m, *tr):
            m.seek(cs)
            b = m.read(ce - cs)
            if len(b) % 4:
                raise PregenError("media/1: a tref box is not a list of track ids")
            tref.append((t, [x for (x,) in struct.iter_unpack(">I", b)]))
    mk = _kids(m, *_one(k, b"mdia", "trak"))
    v, mdhd = _full(m, _one(mk, b"mdhd", "mdia"))
    if v not in (0, 1):
        raise PregenError("media/1: unknown mdhd version")
    mdts = struct.unpack_from(">I", mdhd, 20 if v else 12)[0]
    hdlr = _full(m, _one(mk, b"hdlr", "mdia"))[1][8:12]
    if len(hdlr) != 4:
        raise PregenError("media/1: a box is too short")
    minf = _one(mk, b"minf", "mdia")
    head = b""
    for t, _, cs, ce in _boxes(m, *minf):
        if t in (b"vmhd", b"smhd", b"sthd", b"hmhd", b"nmhd"):
            head = _el(t, _full(m, (cs, ce))[1][4:])
            break
    sk = _kids(m, *_one(_kids(m, *minf), b"stbl", "minf"))
    stsd = _one(sk, b"stsd", "stbl")
    _, b = _full(m, stsd)
    (n,) = struct.unpack_from(">I", b, 4)
    entries = list(_boxes(m, stsd[0] + 8, stsd[1]))
    if len(entries) != n:
        raise PregenError("media/1: the stsd count does not agree with its entries")
    sents = b""
    for t, s, _, e in entries:
        m.seek(s + 8)
        body = m.read(e - s - 8)
        if t in (b"encv", b"enca", b"encs") or b"sinf" in body:
            raise PregenError("media/1: encrypted samples")
        sents += _el(b"sent", _el(t, body))
    if b"stz2" in sk:
        raise PregenError("media/1: stz2 is not read")
    _, b = _full(m, _one(sk, b"stsz", "stbl"))
    fixed, count = struct.unpack_from(">II", b, 4)
    if len(b) != 12 + (0 if fixed else 4 * count):
        raise PregenError("media/1: the stsz count does not agree with its size")
    if fixed * count > file_size:            # before a list of `count` sizes is made
        raise PregenError("media/1: a sample range falls outside the file")
    sizes = [fixed] * count if fixed else [x for (x,) in struct.iter_unpack(">I", b[12:])]

    def expand(rows):                          # counted before expanded: a table cannot claim 2^32 samples for free
        if sum(c for c, _ in rows) != count:
            raise PregenError("media/1: stts, ctts and stsz count different samples")
        return [x for c, x in rows for _ in range(c)]
    durs = expand(_table(m, _one(sk, b"stts", "stbl"), ">II", "stts")[1])
    ctts = _opt(sk, b"ctts", "stbl")
    offs = [0] * count
    if ctts:
        if _full(m, ctts)[0] not in (0, 1):
            raise PregenError("media/1: unknown ctts version")
        offs = expand(_table(m, ctts, ">Ii" if _full(m, ctts)[0] == 1 else ">II", "ctts")[1])
    stco, co64 = _opt(sk, b"stco", "stbl"), _opt(sk, b"co64", "stbl")
    if (stco is None) == (co64 is None):
        raise PregenError("media/1: stbl needs exactly one stco or co64")
    chunks = [c for (c,) in _table(m, stco or co64, ">I" if stco else ">Q", "chunk offset")[1]]
    runs = _table(m, _one(sk, b"stsc", "stbl"), ">III", "stsc")[1]
    pos, sdis = [], []
    for j, (first, per, sdi) in enumerate(runs):
        last = runs[j + 1][0] if j + 1 < len(runs) else len(chunks) + 1
        if not (j or first == 1) or first >= last or last > len(chunks) + 1 or per < 1 or not 1 <= sdi <= n:
            raise PregenError("media/1: the stsc table does not agree with the chunks")
        for c in range(first - 1, last - 1):
            o = chunks[c]
            for _ in range(per):
                if len(pos) == count:
                    raise PregenError("media/1: stsc and stsz count different samples")
                pos.append(o)
                sdis.append(sdi)
                o += sizes[len(pos) - 1]
    if len(pos) != count or (chunks and not runs):
        raise PregenError("media/1: stsc and stsz count different samples")
    samples, t = [], 0
    for j in range(count):
        samples.append((sdis[j], t, offs[j], durs[j], pos[j], sizes[j]))
        t += durs[j]
    first = head + _el(b"mdts", _i(mdts)) + sents + tkhd_el + _el(b"elst", _i(*edits))
    return tid, hdlr, first, tref, samples


def _root(f):
    """RFC 6962 Merkle tree root of the leaf hashes `f` yields, without holding them (split at the largest power of
    two smaller than the count: a stack of full subtrees, folded from the right at the end)."""
    stack, n = [], 0
    for h in f:
        n += 1
        stack.append((1, h))
        while len(stack) > 1 and stack[-1][0] == stack[-2][0]:
            (s, r), (_, l) = stack.pop(), stack.pop()
            stack.append((2 * s, hashlib.sha256(b"\x01" + l + r).digest()))
    while len(stack) > 1:
        (s, r), (t, l) = stack.pop(), stack.pop()
        stack.append((s + t, hashlib.sha256(b"\x01" + l + r).digest()))
    return stack[0][1], n


def _leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def media_hash(f) -> dict:
    """media/1 of an ISO base media file (MP4, MOV, M4V): the RFC 6962 root over the movie, each listed track and each
    of its samples (spec/drafts/after-gen.md, Which bytes the hash covers). `f` is a path or a seekable binary file;
    sample data is read with seek/read, never the whole file. Refuses, with the reason, every file "One reading only"
    lists. Returns {"binding": "media/1", "hash", "leaves"}."""
    if isinstance(f, (str, os.PathLike)):
        with open(f, "rb") as fh:
            return media_hash(fh)
    f.seek(0, 2)
    size = f.tell()
    top = list(_boxes(f, 0, size, top=True))
    moovs = [b for b in top if b[0] == b"moov"]
    if not moovs:
        raise PregenError("media/1: no moov box")
    if len(moovs) > 1:
        raise PregenError("media/1: more than one moov box")
    if any(b[0] == b"moof" for b in top):
        raise PregenError("media/1: a fragmented file (moof)")
    _, _, cs, ce = moovs[0]
    f.seek(cs)
    m = io.BytesIO(f.read(ce - cs))
    try:
        mk = _kids(m, 0, ce - cs)
        if b"mvex" in mk:
            raise PregenError("media/1: a fragmented file (mvex)")
        v, mvhd = _full(m, _one(mk, b"mvhd", "moov"))
        if v not in (0, 1):
            raise PregenError("media/1: unknown mvhd version")
        tmsc = struct.unpack_from(">I", mvhd, 20 if v else 12)[0]
        rate, volu, *mtrx = struct.unpack_from(">ih10x9i", mvhd, 32 if v else 20)
        tracks = [_track(m, t, size) for t in mk.get(b"trak", [])]
    except struct.error:
        raise PregenError("media/1: a box is too short") from None
    if len({t[0] for t in tracks}) != len(tracks):
        raise PregenError("media/1: two tracks with one track_ID")
    tracks = sorted((t for t in tracks if t[1] not in (b"meta", b"hint")), key=lambda t: t[0])
    where = {t[0]: i for i, t in enumerate(tracks)}
    ranges = sorted((s[4], s[4] + s[5]) for t in tracks for s in t[4] if s[5])
    for j, (a, b) in enumerate(ranges):
        if b > size:
            raise PregenError("media/1: a sample range falls outside the file")
        if j and a < ranges[j - 1][1]:
            raise PregenError("media/1: sample ranges overlap")
    movie = b"PREGEN-MEDIA\x00media/1\x00" + _el(b"FRMT", b"isobmff") + _el(b"tmsc", _i(tmsc)) \
        + _el(b"rate", _i(rate)) + _el(b"volu", _i(volu)) + _el(b"mtrx", _i(*mtrx))
    trefs = []
    for tid, hdlr, first, tref, _ in tracks:
        if any(x not in where for _, ids in tref for x in ids):
            raise PregenError("media/1: a tref names a track that is not listed")
        trefs.append(_el(b"hdlr", hdlr) + _el(b"tref", b"".join(_el(t, _i(*(where[x] for x in ids))) for t, ids in tref))
                     + first)

    def leaves():
        yield _leaf(movie)
        for (_, _, _, _, samples), head in zip(tracks, trefs):
            yield _leaf(head)
            for sdi, dt, ct, dur, off, n in samples:
                h = hashlib.sha256(b"\x00" + _el(b"sdsc", _i(sdi)) + _el(b"dtim", _i(dt)) + _el(b"ctso", _i(ct))
                                   + _el(b"sdur", _i(dur)) + b"data" + n.to_bytes(8, "big"))
                f.seek(off)
                while n:
                    chunk = f.read(min(n, 1 << 20))
                    if not chunk:
                        raise PregenError("media/1: a sample range falls outside the file")
                    h.update(chunk)
                    n -= len(chunk)
                yield h.digest()
    root, n = _root(leaves())
    return {"binding": "media/1", "hash": root.hex(), "leaves": n}


# ── carrying the record: C2PA and XMP ───────────────────────────────────────────────────────────

def _no_dupes(pairs):
    d = dict(pairs)
    if len(d) != len(pairs):
        raise PregenError("a JSON object names a member twice")
    return d


def _cbor(b: bytes):
    """A minimal strict CBOR reader: maps with text keys, arrays, text, integers, true, false, null; nothing else."""
    def item(p, depth):
        if depth > 64 or p >= len(b):
            raise PregenError("c2pa: CBOR too deep or cut short")
        major, ai = b[p] >> 5, b[p] & 31
        p += 1
        if major == 7:
            if ai in (20, 21, 22):
                return (False, True, None)[ai - 20], p
            raise PregenError("c2pa: a CBOR value that is not JSON")
        if ai < 24:
            n = ai
        elif ai < 28:
            w = 1 << (ai - 24)
            if p + w > len(b):
                raise PregenError("c2pa: CBOR cut short")
            n, p = int.from_bytes(b[p:p + w], "big"), p + w
        else:
            raise PregenError("c2pa: an indefinite or reserved CBOR length")
        if major == 0:
            return n, p
        if major == 1:
            return -1 - n, p
        if major == 3:
            if p + n > len(b):
                raise PregenError("c2pa: CBOR cut short")
            try:
                return b[p:p + n].decode("utf-8"), p + n
            except UnicodeDecodeError:
                raise PregenError("c2pa: CBOR text is not UTF-8") from None
        if major == 4:
            out = []
            for _ in range(n):
                v, p = item(p, depth + 1)
                out.append(v)
            return out, p
        if major == 5:
            out = {}
            for _ in range(n):
                k, p = item(p, depth + 1)
                if not isinstance(k, str) or k in out:
                    raise PregenError("c2pa: a CBOR map key that is not text, or named twice")
                out[k], p = item(p, depth + 1)
            return out, p
        raise PregenError("c2pa: a CBOR value that is not JSON")
    v, p = item(0, 0)
    if p != len(b):
        raise PregenError("c2pa: bytes after the CBOR value")
    return v


def _superbox(m, s, e):
    """A JUMBF superbox's label and its content boxes."""
    kids = list(_boxes(m, s, e, who="c2pa"))
    if not kids or kids[0][0] != b"jumd":
        raise PregenError("c2pa: a JUMBF superbox without its description")
    m.seek(kids[0][2])
    d = m.read(kids[0][3] - kids[0][2])
    if len(d) < 17:
        raise PregenError("c2pa: a JUMBF description cut short")
    label = None
    if d[16] & 2:
        end = d.find(b"\x00", 17)
        if end < 0:
            raise PregenError("c2pa: a JUMBF label without its end")
        try:
            label = d[17:end].decode("utf-8")
        except UnicodeDecodeError:
            raise PregenError("c2pa: a JUMBF label is not UTF-8") from None
    return label, kids[1:]


def _c2pa(f, box):
    _, _, cs, ce = box
    f.seek(cs + 16)
    p = f.read(ce - cs - 16)
    end = p.find(b"\x00", 4)
    if end < 0:
        raise PregenError("c2pa: a C2PA box without its purpose")
    if p[4:end] != b"manifest":
        return False
    if len(p) < end + 9:
        raise PregenError("c2pa: a manifest box without its offset")
    m = io.BytesIO(p[end + 9:])
    store = list(_boxes(m, 0, len(p) - end - 9, who="c2pa"))
    if len(store) != 1 or store[0][0] != b"jumb":
        raise PregenError("c2pa: the box does not hold one JUMBF manifest store")
    label, manifests = _superbox(m, store[0][2], store[0][3])
    if label != "c2pa" or not manifests or any(t != b"jumb" for t, *_ in manifests):
        raise PregenError("c2pa: not a manifest store")
    stores = [k for k in _superbox(m, *manifests[-1][2:])[1] if k[0] == b"jumb"]
    stores = [k for k in stores if _superbox(m, *k[2:])[0] == "c2pa.assertions"]
    if len(stores) != 1:
        raise PregenError("c2pa: the active manifest needs exactly one assertion store")
    found = []
    for t, _, s, e in _superbox(m, *stores[0][2:])[1]:
        if t == b"jumb":
            label, content = _superbox(m, s, e)
            if label and _C2PA_LABEL.fullmatch(label):
                found.append(content)
    if not found:
        return None
    if len(found) > 1 or len(found[0]) != 1 or found[0][0][0] not in (b"json", b"cbor"):
        raise PregenError("c2pa: more than one org.pregen.after_gen assertion, or not one json or cbor box")
    t, _, s, e = found[0][0]
    m.seek(s)
    data = m.read(e - s)
    try:
        env = json.loads(data, object_pairs_hook=_no_dupes) if t == b"json" else _cbor(data)
    except ValueError as err:
        raise PregenError(f"c2pa: the assertion is not JSON: {err}") from None
    if not isinstance(env, dict):
        raise PregenError("c2pa: the assertion is not an envelope")
    return env


def _xmp_tree(packet: bytes):
    if b"<!DOCTYPE" in packet or b"<!ENTITY" in packet:
        raise PregenError("xmp: a packet with a DTD")
    try:
        root = ET.fromstring(packet)
    except ET.ParseError as e:
        raise PregenError(f"xmp: not XML: {e}") from None
    rdf = root if root.tag == f"{{{_RDF}}}RDF" else root.find(f"{{{_RDF}}}RDF")
    if rdf is None:
        raise PregenError("xmp: no rdf:RDF")
    return root, rdf


def _xmp(f, box):
    _, _, cs, ce = box
    f.seek(cs + 16)
    _, rdf = _xmp_tree(f.read(ce - cs - 16))
    rec = f"{{{_PGAG}}}Record"
    found = [el.text or "" for el in rdf.iter(rec)] + [el.attrib[rec] for el in rdf.iter() if rec in el.attrib]
    if not found:
        return None
    if len(found) > 1:
        raise PregenError("xmp: more than one pgag:Record")
    try:
        env = json.loads(found[0], object_pairs_hook=_no_dupes)
    except ValueError as e:
        raise PregenError(f"xmp: pgag:Record is not JSON: {e}") from None
    if not isinstance(env, dict) or canonical_json(env) != found[0].encode("utf-8"):
        raise PregenError("xmp: pgag:Record is not an envelope in canonical JSON")
    return env


def _top(f, uuid):
    """The top-level uuid boxes of this user type."""
    f.seek(0, 2)
    out = []
    for b in list(_boxes(f, 0, f.tell(), top=True, who="file")):
        f.seek(b[2])
        if b[0] == b"uuid" and f.read(16) == uuid:
            out.append(b)
    return out


def read_after_gen(f) -> dict:
    """Step 2 of How a verifier checks a file: the record in the file's C2PA manifest (the org.pregen.after_gen
    assertion of the active, last, manifest; JSON or CBOR) and in its XMP (pgag:Record). Only extracts: check what it
    returns with check_after_gen. Returns {"c2pa": envelope or None, "xmp": envelope or None}."""
    if isinstance(f, (str, os.PathLike)):
        with open(f, "rb") as fh:
            return read_after_gen(fh)
    stores = [e for e in (_c2pa(f, b) for b in _top(f, _C2PA_UUID)) if e is not False]
    xmp = _top(f, _XMP_UUID)
    if len(stores) > 1:
        raise PregenError("c2pa: more than one manifest store")
    if len(xmp) > 1:
        raise PregenError("xmp: more than one XMP box")
    return {"c2pa": stores[0] if stores else None, "xmp": _xmp(f, xmp[0]) if xmp else None}


def _serialize(el, names, out, decl=""):
    def q(n):
        if n.startswith("{"):
            uri, local = n[1:].split("}", 1)
            return f"{names[uri]}:{local}"
        return n
    attrs = "".join(f" {q(k)}={quoteattr(v)}" for k, v in el.attrib.items())
    out.append(f"<{q(el.tag)}{decl}{attrs}>{escape(el.text or '')}")
    for c in el:
        _serialize(c, names, out)
    out.append(f"</{q(el.tag)}>{escape(el.tail or '')}")


def _packet(old, env) -> bytes:
    """An XMP packet holding the record, keeping every property of `old` (the existing packet, or None)."""
    names = {_X: "x", _RDF: "rdf", _PGAG: "pgag", _XML_NS: "xml"}
    if old is None:
        root = ET.Element(f"{{{_X}}}xmpmeta")
        rdf = ET.SubElement(root, f"{{{_RDF}}}RDF")
    else:
        root, rdf = _xmp_tree(old)
        for _, (prefix, uri) in ET.iterparse(io.BytesIO(old), events=("start-ns",)):
            if uri not in names:
                names[uri] = prefix if prefix and prefix not in names.values() else f"ns{len(names)}"
        for d in list(rdf):
            if any(e.tag.startswith(f"{{{_PGAG}}}") or any(k.startswith(f"{{{_PGAG}}}") for k in e.attrib)
                   for e in d.iter()):
                rdf.remove(d)
    body = env["body"]
    d = ET.SubElement(rdf, f"{{{_RDF}}}Description", {f"{{{_RDF}}}about": ""})
    for k, v in (("Record", canonical_json(env).decode("utf-8")), ("Id", message_id(_TYPE, body)),
                 ("Registry", issuer_of(body.get("subject_ref")))):
        ET.SubElement(d, f"{{{_PGAG}}}{k}").text = v
    decl = "".join(f" xmlns:{p}={quoteattr(u)}" for u, p in names.items() if u != _XML_NS)
    out = ['<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>']
    _serialize(root, names, out, decl)
    out.append('<?xpacket end="w"?>')
    return "".join(out).encode("utf-8")


def embed_xmp(src, dst, envelope: dict) -> None:
    """Write `dst` = `src` with the record in XMP (Carrying the record): a top-level uuid box appended at the end, so no
    offset moves. An existing XMP box keeps its properties, moved into the new packet, and becomes a `free` box of the
    same size with a zeroed payload. A last box that runs to the end of the file (size 0) gets its real size written
    first, when it fits in 32 bits. Refuses a record whose content hash is not dst's media/1 hash."""
    if not isinstance(envelope, dict) or envelope.get("type") != _TYPE or not isinstance(envelope.get("body"), dict):
        raise PregenError(f"not a {_TYPE} envelope")
    if os.path.exists(dst) and os.path.samefile(src, dst):
        raise PregenError("dst must be another file than src")
    with open(src, "rb") as fs:
        fs.seek(0, 2)
        top = list(_boxes(fs, 0, fs.tell(), top=True, who="file"))
        old = _top(fs, _XMP_UUID)
        if len(old) > 1:
            raise PregenError("xmp: more than one XMP box")
        packet = None
        if old:
            fs.seek(old[0][2] + 16)
            packet = fs.read(old[0][3] - old[0][2] - 16)
        to_end = None                            # (offset, size) of a last box whose size field is 0
        if top:
            fs.seek(top[-1][1])
            if fs.read(4) == bytes(4):
                to_end = top[-1][1], top[-1][3] - top[-1][1]
                if to_end[1] >= 1 << 32:
                    raise PregenError("file: the last box runs to the end and does not fit in 32 bits")
        new = _packet(packet, envelope)
        fs.seek(0)
        with open(dst, "wb") as fd:
            shutil.copyfileobj(fs, fd)
            if to_end:
                fd.seek(to_end[0])
                fd.write(struct.pack(">I", to_end[1]))
            if old:
                _, s, cs, e = old[0]
                fd.seek(s + 4)
                fd.write(b"free")
                fd.seek(cs)
                fd.write(bytes(e - cs))
            fd.seek(0, 2)
            fd.write(struct.pack(">I4s", 8 + 16 + len(new), b"uuid") + _XMP_UUID + new)
    content = envelope["body"].get("content")
    try:
        if not isinstance(content, dict) or media_hash(dst)["hash"] != content.get("hash"):
            raise PregenError("not for this file")
    except PregenError:
        os.remove(dst)
        raise


def c2pa_assertion(envelope: dict) -> dict:
    """The assertion a production adds with its own C2PA tool and its own certificate (Carrying the record)."""
    return {"label": "org.pregen.after_gen", "data": envelope}


# ── the record and its status ──────────────────────────────────────────────────────────────────

_MEMBERS = {"signers", "kind", "label", "notice", "not", "subject_ref", "content", "request", "holder", "licence",
            "use", "scope", "approval", "issued_at"}
_SCOPE = {"purposes", "categories", "territories", "channels", "project", "not_after"}
_APPROVAL = {"self": {"assent", "decision"}, "registry": {"assent", "instruction", "factor"},
             "agent": {"assent", "agent", "mandate", "decision", "factor"}}
_STATUS_MEMBERS = {"signers", "record", "state", "approved_at", "withdrawn_at", "not_after", "issued_at", "expires_at"}


def _obj(v, members, where):
    if not isinstance(v, dict) or set(v) != members:
        raise PregenError(f"{where}: exactly the members {', '.join(sorted(members))}")
    return v


def _hex(v) -> bool:
    return isinstance(v, str) and bool(_HEX64.fullmatch(v))


def _star(v, pattern) -> bool:
    return v == ["*"] or isinstance(v, list) and len(v) >= 1 and v == sorted(set(v)) \
        and all(isinstance(x, str) and re.fullmatch(pattern, x) for x in v)


def _scope(s):
    _obj(s, _SCOPE, "scope")
    if not _words(s["purposes"], _PURPOSES, 1):
        raise PregenError("scope.purposes: a sorted list of likeness/1 purposes, never empty")
    if not isinstance(s["categories"], list) or not all(isinstance(c, str) for c in s["categories"]):
        raise PregenError("scope.categories: a list of words")
    if set(s["categories"]) & INTIMATE:
        raise PregenError("scope.categories: an intimate category is never approved after generation")
    if not _words(s["categories"], CATEGORIES):
        raise PregenError("scope.categories: sorted, without repeats, in the closed vocabulary")
    if not _star(s["territories"], r"[A-Z]{2}"):
        raise PregenError('scope.territories: sorted ISO 3166-1 alpha-2 codes or ["*"]')
    if not _star(s["channels"], r"[a-z0-9-]{1,32}"):
        raise PregenError('scope.channels: sorted words of [a-z0-9-]{1,32} or ["*"]')
    p = s["project"]
    if not (isinstance(p, str) and 1 <= len(p) <= 200 and p.isprintable()):
        raise PregenError("scope.project: printable text of 1 to 200 characters")
    if not _count(s["not_after"], 1):
        raise PregenError("scope.not_after: an integer time")


def _approval(a, holder):
    form = a.get("assent") if isinstance(a, dict) else None
    if form not in _APPROVAL:
        raise PregenError("approval.assent: self, registry or agent")
    _obj(a, _APPROVAL[form], f"approval ({form})")
    if form == "self" and not _hex(a["decision"]):
        raise PregenError("approval: the message id of the subject's decision")
    if form == "registry" and not (_hex(a["instruction"]) and a["factor"] in ("authenticator", "email")):
        raise PregenError("approval: the instruction's SHA-256 and the second factor (authenticator or email)")
    if form == "agent":
        check_provider_url(a["agent"], allow_port=True)     # a sandbox id may carry a port; a registry decides who is a party
        if not (_hex(a["mandate"]) and _hex(a["decision"]) and a["factor"] == "signature"):
            raise PregenError("approval: the mandate's and the decision's message ids, factor signature")
        if a["agent"] == holder:
            raise PregenError("approval: a representative is never the holder of the same record")


def _approved_by(a) -> str:
    if a["assent"] == "self":
        return "approved by the person"
    if a["assent"] == "registry":
        return "approved on the person's instruction at the registry"
    return f"approved by {urlsplit(a['agent']).hostname} under mandate {a['mandate']}"


def check_after_gen(env: dict, directory=None, get_json=_get_json, media=None) -> dict:
    """Steps 3-4 of How a verifier checks a file: a pg.after_gen.v1 record in shape (exactly its members, in the body
    and every object of it; the constants; the closed vocabularies; one of the three approval forms), signed by exactly
    one registry key the directory lists for the subject's prefix at issued_at (a revoked registry's records fail),
    and, given `media` (a media_hash result or its hash), naming that file. Raises PregenError; returns a summary.
    It says nothing about whether the record still stands: check_after_gen_status."""
    directory = directory or load_directory(get_json=get_json)
    code = (env.get("body") or {}).get("subject_ref") if isinstance(env, dict) else None
    if isinstance(code, str) and directory.is_false_claim(code):
        raise PregenError(f"{code} is a false claim the steward recorded")
    b = _registry_signed(env, _TYPE, code, directory, get_json)
    _obj(b, _MEMBERS, _TYPE)
    if not _printable(b) or set(b["signers"][0]) != {"role", "key_id"}:
        raise PregenError(f"{_TYPE}: a control or format character, or a signer that is not {{role, key_id}}")
    if b["kind"] != "ratification":
        raise PregenError("kind: ratification, the only kind of after-gen/1")
    if b["label"] != AFTER_GEN_LABEL or b["notice"] != AFTER_GEN_NOTICE or b["not"] != AFTER_GEN_NOT:
        raise PregenError("label, notice and not are the fixed constants of what a record never says")
    c = _obj(b["content"], {"binding", "hash", "leaves"}, "content")
    if c["binding"] != "media/1" or not _hex(c["hash"]) or not _count(c["leaves"]):
        raise PregenError("content: one file by its media/1 hash and number of leaves")
    lic = _obj(b["licence"], {"format", "id"}, "licence")
    if lic["format"] != "pg.grant.v1" or not _hex(lic["id"]):
        raise PregenError("licence: a pg.grant.v1 by its message id")
    use = _obj(b["use"], {"n", "of"}, "use")
    if not _count(use["n"]) or not (use["of"] is None or _count(use["of"]) and use["n"] <= use["of"]):
        raise PregenError("use: n from 1, of the licence's max_uses or null")
    if not _hex(b["request"]) or not _count(b["issued_at"]):
        raise PregenError("request is a message id and issued_at an integer time")
    check_provider_url(b["holder"], allow_port=True)
    _scope(b["scope"])
    _approval(b["approval"], b["holder"])
    rid = message_id(_TYPE, b)
    status_url = directory.registry_for(code)["api"].rstrip("/") + "/v2/after-gen/" + rid  # The status: never from the record
    match = None
    if media is not None:
        want = media.get("hash") if isinstance(media, dict) else media
        if want != c["hash"] or isinstance(media, dict) and (media.get("binding"), media.get("leaves")) != \
                ("media/1", c["leaves"]):
            raise PregenError("not for this file")
        match = True
    return {"id": rid, "subject_ref": code, "prefix": issuer_of(code), "label": b["label"],
            "notice": b["notice"], "not": b["not"], "holder": b["holder"], "licence_id": lic["id"], "use": b["use"],
            "scope": b["scope"], "approval": b["approval"], "approved_by": _approved_by(b["approval"]),
            "status_url": status_url, "issued_at": b["issued_at"], "content": c, "file_match": match}


def check_after_gen_status(status_env: dict, record_env: dict, directory=None, get_json=_get_json, now=None) -> dict:
    """Step 5: a pg.after_gen_status.v1 for this record (The status), signed by a registry key the directory lists for
    the record's subject prefix, current (at most 300 seconds of life), its state one of active, withdrawn, expired.
    Check the record itself with check_after_gen. Raises PregenError; returns {state, approved_at, withdrawn_at,
    not_after}."""
    import time
    now = int(time.time()) if now is None else now
    directory = directory or load_directory(get_json=get_json)
    if now - directory.loaded_at > DIRECTORY_MAX_AGE:
        raise PregenError("the directory was loaded more than 24 hours ago: load it again")
    rec = _ints(record_env.get("body")) if isinstance(record_env, dict) and record_env.get("type") == _TYPE else None
    if not isinstance(rec, dict) or not isinstance(rec.get("scope"), dict):
        raise PregenError(f"record must be the {_TYPE} envelope")
    s = _registry_signed(status_env, _STATUS, rec.get("subject_ref"), directory, get_json)
    _obj(s, _STATUS_MEMBERS, _STATUS)
    if s["record"] != message_id(_TYPE, rec):
        raise PregenError("a status for another record")
    iat, exp = s["issued_at"], s["expires_at"]
    if not (_count(iat) and _count(exp)) or not 0 < exp - iat <= _MAX_STATUS_LIFETIME:
        raise PregenError(f"a status lives at most {_MAX_STATUS_LIFETIME} seconds")
    if iat > now + 60:
        raise PregenError("a status issued in the future")
    if exp <= now:
        raise PregenError("the status expired")
    if s["approved_at"] != rec.get("issued_at") or s["not_after"] != rec["scope"].get("not_after"):
        raise PregenError("the status does not repeat the record's issued_at and not_after")
    state, w = s["state"], s["withdrawn_at"]
    if state not in ("active", "withdrawn", "expired") \
            or (w is not None if state != "withdrawn" else not (_count(w) and s["approved_at"] <= w <= iat)) \
            or state == "active" and iat >= s["not_after"] or state == "expired" and iat < s["not_after"]:
        raise PregenError("state: active, withdrawn (with withdrawn_at) or expired (after not_after)")
    return {"state": state, "approved_at": s["approved_at"], "withdrawn_at": w, "not_after": s["not_after"]}


# ── for clients: the request and the decision ──────────────────────────────────────────────────

def after_gen_request(requester: str, private_key_hex: str, subject_ref: str, licence_id: str, media, scope: dict,
                      now=None, nonce=None) -> dict:
    """A pg.after_gen_request.v1 (The procedure, 1) signed with the requester's key from its own domain. `media` is a
    media_hash result, or the file. One file per request; a request permits nothing."""
    import time
    content = media if isinstance(media, dict) else media_hash(media)
    body = {"signers": [{"role": "requester", "key_id": fingerprint(public_key_hex(private_key_hex))}],
            "requester": check_provider_url(requester, allow_port=True), "subject_ref": subject_ref,
            "licence": {"format": "pg.grant.v1", "id": licence_id},
            "content": {k: content[k] for k in ("binding", "hash", "leaves")}, "scope": scope,
            "issued_at": int(time.time() if now is None else now), "nonce": nonce or os.urandom(16).hex()}
    return sign_envelope("pg.after_gen_request.v1", body, private_key_hex)


def after_gen_decision(request_id: str, outcome: str, scope, private_key_hex: str, role: str, now=None) -> dict:
    """A pg.after_gen_decision.v1 (The decision): the subject's (role "subject") or the representative's (role
    "agent") approval or refusal of one request. `scope` is the approved scope for "approve", None for "refuse"."""
    import time
    if role not in ("subject", "agent") or outcome not in ("approve", "refuse") \
            or (scope is None) != (outcome == "refuse") or not _hex(request_id):
        raise PregenError("a decision: role subject or agent, outcome approve (with a scope) or refuse (without)")
    body = {"signers": [{"role": role, "key_id": fingerprint(public_key_hex(private_key_hex))}],
            "request": request_id, "outcome": outcome, "issued_at": int(time.time() if now is None else now)}
    if scope is not None:
        body["scope"] = scope
    return sign_envelope("pg.after_gen_decision.v1", body, private_key_hex)
