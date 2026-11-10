"""AFTER-GEN v1 (spec/drafts/after-gen.md): the rights holder's registry approves a file that already exists. The
media/1 hash of an ISO base media file, the record carried in C2PA or XMP, and the checks of the record and its
status. A record is never a PRE-GEN permission given before generation, and says nothing about whether the content is
AI-generated."""

import bisect
import hashlib
import io
import json
import os
import re
import shutil
import struct
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape, quoteattr

from . import (CATEGORIES, INTIMATE, _HEX64, _MAX_INT, _PURPOSES, _count, _get_json, _printable, _registry_signed,
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
        if size < hl + (16 if t == b"uuid" else 0):              # a uuid box: its 16-byte user type too
            raise PregenError(f"{who}: a box is shorter than its header")
        if pos + size > end:
            raise PregenError(f"{who}: a box runs past its parent")
        yield t, pos, pos + hl, pos + size
        pos += size


def _el(code, value: bytes) -> bytes:
    """An element: four-byte code, u64 length, value."""
    return code + len(value).to_bytes(8, "big") + value


def _i(*xs) -> bytes:
    try:
        return b"".join(x.to_bytes(8, "big", signed=True) for x in xs)
    except OverflowError:
        raise PregenError("media/1: a value does not fit in a signed 64-bit integer") from None


_PIECE = 1 << 20
_PATH = {b"moov": b"trak", b"trak": b"mdia", b"mdia": b"minf", b"minf": b"stbl"}   # a value of its children's elements
_PCM = {b"raw ", b"twos", b"sowt", b"in24", b"in32", b"fl32", b"fl64", b"lpcm", b"ipcm", b"fpcm", b"ulaw", b"alaw"}
_TABLES = re.compile(rb"(?=(stco|co64|stsc|stsz|stz2|stts|ctts|iloc|saio|saiz|sidx|ssix|tfra|mfra|trun|tfhd))")


def _u(b, at, n=4):
    if len(b) < at + n:
        raise PregenError("media/1: a box shorter than its own fields")
    return int.from_bytes(b[at:at + n], "big")


_MOVIE = re.compile(rb"(cmov|hoov)")
_MPEG = re.compile(rb"(hdlr[\s\S]{4}mhlrMPEG)")
_NUT = re.compile(rb"(NMzV\x1f_\x04\xad)")           # NUT main startcode: its probe ties with MP4, the file opens as neither
_DATA_HANDLERS = {b"url ", b"urn ", b"alis"}
_NOT_MEDIA = _DATA_HANDLERS | {b"mdir", b"mdta", b"ID32", b"mp7t", b"mp7b"}  # handlers that set no track type
_SAMPLE_TABLES = {b"stts", b"ctts", b"stsc", b"stsz", b"stz2", b"stco", b"co64"}  # the only boxes the table scan skips
_PROBED_AWAY = {b"jp2 ", b"jpx ", b"jxl "}             # major brands a player's MP4 probe scores low (One reading only)
_CARRIER_MAX = 64 << 20


def _scan(b, rx=_TABLES, why="{} outside its place"):
    """Any of the codes of `rx` at any byte position of `b` (One reading only)."""
    x = rx.search(b)
    if x:
        raise PregenError("media/1: " + why.format(x[1].decode("latin-1")))


def _scan_file(f, s, e, rx=_TABLES, why="{} outside its place", keep=3):
    """_scan over [s, e) of the file in pieces, each overlapping the last by `keep` bytes."""
    carry = b""
    while s < e:
        f.seek(s)
        chunk = carry + f.read(min(_PIECE, e - s))
        _scan(chunk, rx, why)
        carry, s = chunk[-keep:], s + _PIECE


def _exact(ok):
    if not ok:
        raise PregenError("media/1: a table whose length is not exactly what its count gives")


def _sizes(t, b):
    """A sample size table (stsz or stz2): (count, the fixed size or 0, the sizes)."""
    count = _u(b, 8)
    if t == b"stsz":
        fixed = _u(b, 4)
        _exact(len(b) == 12 + (0 if fixed else 4 * count))
        return count, fixed, [] if fixed else [x for (x,) in struct.iter_unpack(">I", b[12:])]
    bits = _u(b, 7, 1)
    if bits not in (4, 8, 16):
        raise PregenError("media/1: an stz2 field size other than 4, 8 or 16")
    _exact(len(b) == 12 + (count * bits + 7) // 8)
    if bits == 4:
        return count, 0, [b[12 + j // 2] >> (0 if j % 2 else 4) & 15 for j in range(count)]
    w = bits // 8
    return count, 0, [int.from_bytes(b[12 + w * j:12 + w * j + w], "big") for j in range(count)]


_WIDTH = {b"raw ": 1, b"ulaw": 1, b"alaw": 1, b"in24": 3, b"in32": 4, b"fl32": 4, b"fl64": 8}  # bytes a sample


def _frame(m, mv, t, s, e):
    """The frame size players take from a sound entry read by chunk (One reading only), or None: bytes per frame
    (v1, one sample a packet), bytes per packet (v2, one frame a packet), or channels x the codec's bytes a sample (v0),
    which v1 and v2 must agree with where the codec has a width."""
    b, v = mv[s:e], _u(mv[s:e], 8, 2)
    if t not in _PCM:
        return None
    width = _u(b, 18, 2) // 8 if t in (b"twos", b"sowt") else _WIDTH.get(t)
    if t in (b"ipcm", b"fpcm"):
        pcmc = [k for k in _boxes(m, s + {1: 44, 2: 64}.get(v, 28), e) if k[0] == b"pcmC"]
        width = _u(mv[pcmc[0][2]:pcmc[0][3]], 5, 1) // 8 if pcmc else None
    if v == 1:
        frame, channels = (_u(b, 36), _u(b, 16, 2)) if _u(b, 28) == 1 else (None, 0)
    elif v == 2:
        frame, channels = (_u(b, 56), _u(b, 40)) if _u(b, 60) == 1 else (None, 0)
    else:
        return None if width is None else _u(b, 16, 2) * width
    return None if frame is None or width is not None and frame != channels * width else frame


def _stbl(m, mv, kids, mdats, video):
    """Checks an stbl on the path (One reading only) and returns its chunk offset table as hashed, by start: per offset,
    the position of the mdat whose data holds it and the offset within that data."""
    one = {}
    for t, _, cs, ce in kids:
        key = {b"stz2": b"stsz", b"co64": b"stco"}.get(t, t)
        if key in (b"stsd", b"stts", b"stsc", b"stsz", b"stco", b"ctts"):
            if key in one:
                raise PregenError(f"media/1: two {t.decode()} tables in one stbl")
            one[key] = t, mv[cs:ce], cs, ce
    if any(k not in one for k in (b"stsd", b"stts", b"stsc", b"stsz", b"stco")):
        raise PregenError("media/1: an stbl without its stsd, stts, stsc, stsz or stz2, and stco or co64")
    _, b, cs, ce = one[b"stsd"]
    entries = list(_boxes(m, cs + 8, ce))
    _exact(len(entries) == _u(b, 4))
    for et, _, ecs, ece in entries:
        if et in (b"encv", b"enca", b"encs") or b"sinf" in mv[ecs:ece]:
            raise PregenError("media/1: encrypted samples")
    b = one[b"stts"][1]
    _exact(len(b) == 8 + 8 * _u(b, 4))
    durations = list(struct.iter_unpack(">II", b[8:]))
    if b"ctts" in one:
        b = one[b"ctts"][1]
        _exact(len(b) == 8 + 8 * _u(b, 4))
    b = one[b"stsc"][1]
    _exact(len(b) == 8 + 12 * _u(b, 4))
    runs = list(struct.iter_unpack(">III", b[8:]))
    sizes = _sizes(*one[b"stsz"][:2])
    t, b, cs, _ = one[b"stco"]
    w, n = 4 if t == b"stco" else 8, _u(b, 4)
    _exact(len(b) == 8 + w * n)
    total = 0
    for j, (first, per, sdi) in enumerate(runs):
        last = runs[j + 1][0] if j + 1 < len(runs) else n + 1
        if (first != 1 if j == 0 else first <= runs[j - 1][0]) or first > n or per == 0 or not 1 <= sdi <= len(entries):
            raise PregenError("media/1: an stsc that reads two ways")
        total += (last - first) * per
    if n and not runs:
        raise PregenError("media/1: an stsc that reads two ways")
    if total != sizes[0] or sum(c for c, _ in durations) != sizes[0]:
        raise PregenError("media/1: stsc, stts and the sample sizes count different samples")
    if not video and sizes[0] and all(d == 1 for c, d in durations if c):      # sound read by chunk
        for et, _, ecs, ece in entries:
            if one[b"stsz"][0] != b"stsz" or not sizes[1] or _frame(m, mv, et, ecs, ece) != sizes[1]:
                raise PregenError("media/1: a sound track read by chunk whose entry does not give its sample size")
    starts, value, s, r = [mdat[0] for mdat in mdats], [b[:4], _i(n)], 0, 0
    for c in range(n):
        while r + 1 < len(runs) and runs[r + 1][0] <= c + 1:
            r += 1
        per = runs[r][1]
        o = int.from_bytes(b[8 + w * c:8 + w * c + w], "big")
        length = sizes[1] * per if sizes[1] else sum(sizes[2][s:s + per])
        s += per
        j = bisect.bisect_right(starts, o) - 1
        if j < 0 or o >= mdats[j][1]:
            raise PregenError("media/1: a chunk offset outside the data of an mdat")
        if o + length > mdats[j][1]:
            raise PregenError("media/1: a chunk whose samples run past its mdat's data")
        value.append(_i(j, o - starts[j]))
    return {cs: b"".join(value)}


def _value(m, mv, t, s, e, mdats, zones, hdlrs=()):
    """The value of the element of a box on the path moov/trak/mdia/minf/stbl: its children's elements. The direct
    children of an stbl are added to `zones`, the bytes the table scan leaves out."""
    kids = list(_boxes(m, s, e))
    names = [k for k, *_ in kids]
    if t == b"moov" and b"mvex" in names:
        raise PregenError("media/1: a fragmented file (mvex)")
    if t == b"trak":                             # a player acts on a hdlr anywhere in a track: every one counts
        hdlrs = tuple(mv[s + x.start() + 12:min(s + x.start() + 16, e)] for x in re.finditer(b"hdlr", mv[s:e]))
    if t == b"minf":
        for _, _, cs, ce in (k for k in kids if k[0] == b"dinf"):
            for _, _, rcs, rce in (k for k in _boxes(m, cs, ce) if k[0] == b"dref"):
                for et, _, ecs, ece in _boxes(m, rcs + 8, rce):
                    ok = et in (b"url ", b"urn ") and ece - ecs >= 4 or et == b"alis" and ece - ecs == 4  # Apple: empty alis
                    if not ok or not mv[ecs + 3] & 1:
                        raise PregenError("media/1: a data reference that is not a self-contained url, urn or alis")
    offsets = {}
    if t == b"stbl":
        media = [h for h in hdlrs if h not in _NOT_MEDIA]       # data and metadata handlers set no track type
        offsets = _stbl(m, mv, kids, mdats, bool(media) and all(h == b"vide" for h in media))
        zones += [(ks, ke) for k, ks, _, ke in kids if k in _SAMPLE_TABLES]   # stsd and the rest are searched too
    return b"".join(_el(k, _value(m, mv, k, cs, ce, mdats, zones, hdlrs) if _PATH.get(t) == k
                        else offsets.get(cs, mv[cs:ce])) for k, _, cs, ce in kids)


# ── Known boxes only: inside moov, only these boxes, where listed, each exactly as long as its fields make it ──

def _n(t):
    return t.decode("latin-1")


def _whole(ok, t, where):
    if not ok:
        raise PregenError(f"media/1: {_n(t)} in {_n(where)} is not whole")


def _ver(b, *sizes):
    """Exactly the length its version gives."""
    v = _u(b, 0, 1)
    return v < len(sizes) and len(b) == sizes[v]


def _walk(b, p, n, step):
    """`n` entries from `p`, each `step(p)` bytes long, filling `b` exactly."""
    for _ in range(n):
        p += step(p)
        if p > len(b):
            return False
    return p == len(b)


def _sgpd(b):
    """Version 1 or 2, where each entry's length is known; a sync entry holds the byte FFmpeg reads of it."""
    v = _u(b, 0, 1)
    if v not in (1, 2):
        return False
    p, default, sync = 16 + 4 * (v == 2), _u(b, 8), b[4:8] == b"sync"
    for _ in range(_u(b, p - 4)):
        size = default or _u(b, p)
        if sync and not size:
            return False
        p += size + (0 if default else 4)
        if p > len(b):
            return False
    return p == len(b)


def _esds(b):
    """The descriptors FFmpeg reads (ES, decoder config, decoder specific info), each inside the box."""
    def descr(p):
        tag, n, i = _u(b, p, 1), 0, 0
        for i in range(4):
            c = _u(b, p + 1 + i, 1)
            n = n << 7 | c & 127
            if not c & 128:
                break
        return tag, p + 2 + i, n
    tag, p, n = descr(4)
    if tag != 3 or p + n != len(b):
        return False
    flags = _u(b, p + 2, 1)
    p += 3 + 2 * (flags >> 7)
    if flags & 64:
        p += 1 + _u(b, p, 1)
    tag, p, n = descr(p + 2 * (flags >> 5 & 1))
    if tag != 4 or p + n > len(b):
        return False
    end = p + n
    tag, p, n = descr(p + 13)                     # FFmpeg reads the next descriptor whatever the config's length
    return tag != 5 or 0 < n and p + n <= end


_FIXED = {b"vmhd": 12, b"smhd": 8, b"sthd": 4, b"nmhd": 4, b"hmhd": 20, b"gmin": 16, b"text": 36, b"clef": 12,
          b"prof": 12, b"enof": 12, b"vpcC": 12, b"dac3": 3, b"pcmC": 6, b"pasp": 8, b"clap": 32, b"btrt": 12,
          b"fiel": 2, b"gama": 4, b"chrm": 2, b"mdcv": 24, b"clli": 4, b"st3d": 5, b"dvcC": 24, b"dvvC": 24,
          b"frma": 4, b"enda": 2, b"mp4a": 4, b"\0\0\0\0": 0}   # mp4a and the terminator: in wave
_LEAST = {b"hdlr": 24, b"dOps": 11, b"dfLa": 42, b"dec3": 5, b"elng": 4, b"data": 8, b"mean": 4, b"name": 4,
          b"xml ": 4}
_LEAF = {
    b"mvhd": lambda b: _ver(b, 100, 112), b"tkhd": lambda b: _ver(b, 84, 96), b"mdhd": lambda b: _ver(b, 24, 36),
    b"cslg": lambda b: _ver(b, 24, 44), b"elst": lambda b: _u(b, 0, 1) < 2 and len(b) == 8 + (12 + 8 * b[0]) * _u(b, 4),
    b"stss": lambda b: len(b) == 8 + 4 * _u(b, 4), b"stps": lambda b: len(b) == 8 + 4 * _u(b, 4),
    b"sbgp": lambda b: _u(b, 0, 1) < 2 and len(b) == 12 + 4 * b[0] + 8 * _u(b, 8 + 4 * b[0]),
    b"subs": lambda b: _u(b, 0, 1) < 2 and _walk(b, 8, _u(b, 4), lambda p: 6 + (8 + 2 * b[0]) * _u(b, p + 4, 2)),
    b"keys": lambda b: _walk(b, 8, _u(b, 4), lambda p: _u(b, p) if _u(b, p) >= 8 else len(b) + 1),
    b"chpl": lambda b: _walk(b, 5 + 4 * (_u(b, 0, 1) > 0), _u(b, 4 + 4 * (b[0] > 0), 1), lambda p: 9 + _u(b, p + 8, 1)),
    b"chan": lambda b: len(b) == 16 + 20 * _u(b, 12),
    b"colr": lambda b: len(b) == {b"nclx": 11, b"nclc": 10}.get(b[:4], -1) or b[:4] == b"prof",
    b"sgpd": _sgpd, b"esds": _esds,
    **{t: (lambda n: lambda b: len(b) == n)(n) for t, n in _FIXED.items()},
    **{t: (lambda n: lambda b: len(b) >= n)(n) for t, n in _LEAST.items()},
}
_FREE = (b"free", b"skip")
_HEADERS = {b"vmhd", b"smhd", b"sthd", b"hmhd", b"nmhd", b"gmhd"}
_TREF = {b"hint", b"cdsc", b"font", b"hind", b"vdep", b"vplx", b"subt", b"thmb", b"auxl", b"sbas", b"sync", b"chap",
         b"tmcd", b"scpt", b"ssrc", b"forc", b"folw", b"fall", b"mpod", b"ipir", b"dpnd"}
_ITUNES = {b"aART", b"akID", b"apID", b"atID", b"catg", b"cmID", b"cnID", b"covr", b"cpil", b"cprt", b"desc", b"disk",
           b"egid", b"geID", b"gnre", b"hdvd", b"keyw", b"ldes", b"ownr", b"pcst", b"pgap", b"plID", b"purd", b"purl",
           b"rtng", b"sfID", b"soaa", b"soal", b"soar", b"soco", b"sonm", b"sosn", b"stik", b"tmpo", b"trkn", b"tven",
           b"tves", b"tvnn", b"tvsh", b"tvsn", b"xid ", b"----"}
_VISUAL = {b"avc1", b"avc3", b"hvc1", b"hev1", b"av01", b"vp08", b"vp09", b"mp4v", b"jpeg", b"mjpa", b"mjpb", b"png ",
           b"apcn", b"apch", b"apcs", b"apco", b"ap4h", b"ap4x", b"dvh1", b"dvhe", b"dvav", b"dva1"}
_SOUND = _PCM | {b"mp4a", b"Opus", b"fLaC", b"alac", b"ac-3", b"ec-3"}
_OTHER = {b"tmcd": 26, b"tx3g": 38, b"text": 38}          # fixed fields, the 8 bytes of every sample entry included
_ENTRY_BOXES = {b"avcC", b"hvcC", b"av1C", b"vpcC", b"esds", b"dOps", b"dfLa", b"alac", b"dac3", b"dec3", b"pcmC",
                b"colr", b"pasp", b"clap", b"btrt", b"fiel", b"gama", b"chan", b"wave", b"mdcv", b"clli", b"st3d",
                b"sv3d", b"dvcC", b"dvvC", b"glbl", b"tcmi", b"name",
                b"chrm", b"uuid", b"ftab"}               # widened: Apple's chroma location, the iPod uuid, a font table
_WAVE = {b"frma", b"enda", b"esds", b"alac", b"chan", b"\0\0\0\0", b"mp4a", b"dac3", b"dec3"}  # widened (ffmpeg)
_ITEM_VALUE = {**dict.fromkeys((b"trkn", b"disk", b"tves", b"tvsn"), 4), b"gnre": 2,       # value bytes FFmpeg reads
               **dict.fromkeys((b"stik", b"rtng", b"cpil", b"pgap", b"hdvd", b"pcst", b"akID", b"egid"), 1)}
_IPOD = bytes.fromhex("6b6840f25f244fc5ba39a51bcf0323f3")


def _kids(m, s, e, where, known, one=(), multi=lambda t: False, free=True):
    """The child boxes of a container [s, e): whole, of known types, at most one of each but `multi`, `one` there."""
    kids, seen = [], set()
    for k in list(_boxes(m, s, e)):
        t = k[0]
        if free and t in _FREE:
            continue
        if not known(t):
            raise PregenError(f"media/1: {_n(t)} in {_n(where)} is not a known box")
        if t in seen and not multi(t):
            raise PregenError(f"media/1: two {_n(t)} boxes in {_n(where)}")
        seen.add(t)
        kids.append(k)
    for t in one:
        if t not in seen:
            raise PregenError(f"media/1: {_n(where)} without its {_n(t)}")
    return kids


def _fits(rule, b):
    """`rule` of a box's payload; fields it would read past the box make it not whole."""
    try:
        return rule(b)
    except PregenError:
        return False


def _leaves(mv, kids, where):
    for t, _, cs, ce in kids:
        _whole(_fits(_LEAF.get(t, lambda b: True), mv[cs:ce]), t, where)


def _records(b):
    """A text atom: (length, language, text) records, filling it."""
    p = 0
    while p < len(b):
        p += 4 + _u(b, p, 2)
    return p == len(b)


def _known(m, mv, zones):
    """Known boxes only (spec): the movie box holds only the boxes listed, where listed, each exactly as long as its
    fields, version and counts make it, each container exactly filled. The payloads players read as text are added to
    `zones`, the bytes the table scan leaves out."""
    def udta(s, e):
        for t, _, cs, ce in _kids(m, s, e, b"udta", lambda t: t[0] == 0xA9 or t in {
                b"meta", b"XMP_", b"chpl", b"name", b"loci", b"Xtra"}):
            if t == b"meta":
                meta(cs, ce, b"udta")
            elif t[0] == 0xA9 or t == b"name":
                _whole(_fits(_records, mv[cs:ce]), t, b"udta")
            else:
                _leaves(mv, [(t, 0, cs, ce)], b"udta")
            if t[0] == 0xA9 or t == b"XMP_":
                zones.append((cs, ce))

    def meta(s, e, where):
        b = mv[s:e]
        at = s if b[4:8] == b"hdlr" and b[:4] != b"hdlr" else s + 4 if b[:4] == bytes(4) and b[8:12] == b"hdlr" else -1
        if at < 0:
            raise PregenError(f"media/1: a meta in {_n(where)} that does not begin with its hdlr")
        for t, _, cs, ce in _kids(m, at, e, b"meta", {b"hdlr", b"keys", b"ilst", b"xml "}.__contains__, (b"hdlr",)):
            if t == b"hdlr" and mv[cs + 8:cs + 12] not in (b"mdir", b"mdta", b"ID32"):
                raise PregenError(f"media/1: a {_n(mv[cs + 8:cs + 12])} hdlr in meta is not a known box")
            if t == b"ilst":
                for it, _, ics, ice in _kids(m, cs, ce, b"ilst", lambda t: t[0] in (0, 0xA9) or t in _ITUNES,
                                             multi=lambda t: True):
                    items = _kids(m, ics, ice, it, {b"data", b"mean", b"name"}.__contains__, multi=lambda t: True,
                                  free=False)
                    _leaves(mv, items, it)
                    need = _ITEM_VALUE.get(it, 0)              # FFmpeg reads these fixed values whatever the length
                    if any(k[0] == b"data" and k[3] - k[2] < 8 + need for k in items):
                        raise PregenError(f"media/1: data in {_n(it)} is not whole")
                    zones.extend((k[2], k[3]) for k in items if k[0] == b"data")
            else:
                _leaves(mv, [(t, 0, cs, ce)], b"meta")

    def entry(t, cs, ce, handler, drefs):
        b = mv[cs:ce]
        kind = (b"vide" if handler == b"vide" else b"soun" if handler == b"soun" else b"soun" if t in _SOUND
                else b"vide" if t in _VISUAL else t if t in _OTHER else None)    # as FFmpeg reads it
        if kind is None:
            raise PregenError(f"media/1: a {_n(t)} sample entry under a {_n(handler)} handler is not a known box")
        fixed = 78 if kind == b"vide" else {0: 28, 1: 44, 2: 64}.get(_u(b, 8, 2)) if kind == b"soun" else _OTHER[kind]
        _whole(fixed is not None and len(b) >= fixed, t, b"stsd")
        if not 1 <= _u(b, 6, 2) <= drefs:
            raise PregenError("media/1: a sample entry whose data reference index names no entry")
        if kind == b"vide" and _u(b, 74, 2) & 31 in (1, 2, 4, 8) and not _u(b, 74, 2) & 32 and not _u(b, 76, 2):
            raise PregenError("media/1: a sample entry whose palette players read after its fields")
        if kind == b"tmcd" and b[fixed:] == bytes(2):           # ffmpeg's timecode entry ends with two zero bytes
            return
        end = ce
        if b[-4:] == bytes(4) and len(b) >= fixed + 4:           # QuickTime ends the boxes with a 32-bit 0, skipped
            try:
                list(_boxes(m, cs + fixed, ce))
            except PregenError:
                end = ce - 4
        for k, _, s, e in _kids(m, cs + fixed, end, t, _ENTRY_BOXES.__contains__):
            if k == b"wave":
                _leaves(mv, _kids(m, s, e, b"wave", _WAVE.__contains__), b"wave")
            elif k == b"sv3d":                  # FFmpeg reads svhd, proj, prhd and one projection in a row
                (h, _, hs, he), (_, _, ps, pe) = _kids(m, s, e, b"sv3d", {b"svhd", b"proj"}.__contains__,
                                                       (b"svhd", b"proj"), free=False)
                proj = [(x[0], x[3] - x[2]) for x in _kids(m, ps, pe, b"proj", {b"prhd", b"equi", b"cbmp"}.__contains__,
                                                             free=False)]
                _whole(h == b"svhd" and he - hs > 4 and proj in ([(b"prhd", 16), (b"equi", 20)],
                                                                 [(b"prhd", 16), (b"cbmp", 12)]), k, t)
            elif k == b"uuid":
                _whole(mv[s:s + 16] == _IPOD and e - s == 20, k, t)
            else:
                _leaves(mv, [(k, 0, s, e)], t)

    def stbl(s, e, handler, drefs):
        groups = {b"sgpd": set(), b"sbgp": set()}
        kids = _kids(m, s, e, b"stbl", {b"stsd", b"stts", b"ctts", b"stsc", b"stsz", b"stz2", b"stco", b"co64",
                                        b"stss", b"stps", b"sdtp", b"sgpd", b"sbgp", b"cslg", b"subs"}.__contains__,
                     multi=groups.__contains__)
        samples = next((_u(mv[cs:ce], 8) for t, _, cs, ce in kids if t in (b"stsz", b"stz2")), 0)
        for t, _, cs, ce in kids:
            b = mv[cs:ce]
            if t in groups:
                if b[4:8] in groups[t]:
                    raise PregenError(f"media/1: two {_n(t)} boxes of one grouping type in stbl")
                groups[t].add(b[4:8])
            if t == b"stsd":
                entries = list(_boxes(m, cs + 8, ce))
                if _u(b, 0, 1) or len({x[0] for x in entries}) > 1:
                    raise PregenError("media/1: an stsd of another version, or with entries of more than one format")
                for x in entries:
                    entry(x[0], x[2], x[3], handler, drefs)
            elif t == b"sdtp":
                _whole(len(b) == 4 + samples, t, b"stbl")
            else:
                _leaves(mv, [(t, 0, cs, ce)], b"stbl")

    def minf(s, e, handler):
        kids = _kids(m, s, e, b"minf", (_HEADERS | {b"hdlr", b"dinf", b"stbl"}).__contains__, (b"dinf", b"stbl"))
        if sum(k[0] in _HEADERS for k in kids) != 1:
            raise PregenError("media/1: a minf without exactly one media header")
        drefs = 0
        for t, _, cs, ce in kids:
            if t == b"hdlr" and mv[cs + 8:cs + 12] not in _DATA_HANDLERS:
                raise PregenError(f"media/1: a {_n(mv[cs + 8:cs + 12])} hdlr in minf is not a known box")
            if t == b"dinf":
                (_, _, rs, re_), = _kids(m, cs, ce, b"dinf", {b"dref"}.__contains__, (b"dref",), free=False)
                refs, drefs = list(_boxes(m, rs + 8, re_)), _u(mv[rs:re_], 4)
                if not drefs or drefs != len(refs):
                    raise PregenError("media/1: a dref whose entry count is not the number of its entries, or 0")
                for rt, _, ecs, ece in refs:
                    ok = rt in (b"url ", b"urn ") and ece - ecs >= 4 or rt == b"alis" and ece - ecs == 4
                    if not ok or not mv[ecs + 3] & 1:
                        raise PregenError("media/1: a data reference that is not a self-contained url, urn or alis")
            elif t == b"gmhd":
                for g, _, gs, ge in _kids(m, cs, ce, b"gmhd", {b"gmin", b"text", b"tmcd"}.__contains__):
                    _leaves(mv, _kids(m, gs, ge, g, {b"tcmi"}.__contains__) if g == b"tmcd" else [(g, 0, gs, ge)],
                            b"gmhd")
            elif t != b"stbl":
                _leaves(mv, [(t, 0, cs, ce)], b"minf")
        for t, _, cs, ce in kids:
            if t == b"stbl":
                stbl(cs, ce, handler, drefs)

    def trak(s, e):
        for t, _, cs, ce in _kids(m, s, e, b"trak", {b"tkhd", b"edts", b"tref", b"mdia", b"udta", b"meta",
                                                     b"tapt"}.__contains__, (b"tkhd", b"mdia")):
            if t == b"edts":
                _leaves(mv, _kids(m, cs, ce, b"edts", {b"elst"}.__contains__, (b"elst",)), b"edts")
            elif t == b"tref":
                for r, _, rs, re_ in _kids(m, cs, ce, b"tref", _TREF.__contains__):
                    _whole((re_ - rs) % 4 == 0, r, b"tref")
            elif t == b"tapt":
                _leaves(mv, _kids(m, cs, ce, b"tapt", {b"clef", b"prof", b"enof"}.__contains__), b"tapt")
            elif t == b"mdia":
                kids = _kids(m, cs, ce, b"mdia", {b"mdhd", b"hdlr", b"minf", b"elng", b"udta"}.__contains__,
                             (b"mdhd", b"hdlr", b"minf"))
                names = [k[0] for k in kids]
                if names.index(b"hdlr") > names.index(b"minf"):     # FFmpeg reads the sample entries by the hdlr
                    raise PregenError("media/1: an mdia whose hdlr comes after its minf")
                h = kids[names.index(b"hdlr")][2]
                for k, _, ks, ke in kids:
                    if k == b"minf":
                        minf(ks, ke, mv[h + 8:h + 12])
                    elif k == b"udta":
                        udta(ks, ke)
                    else:
                        _leaves(mv, [(k, 0, ks, ke)], b"mdia")
            elif t == b"udta":
                udta(cs, ce)
            elif t == b"meta":
                meta(cs, ce, b"trak")
            else:
                _leaves(mv, [(t, 0, cs, ce)], b"trak")

    for t, _, cs, ce in _kids(m, 0, len(mv), b"moov", {b"mvhd", b"trak", b"udta", b"meta", b"iods"}.__contains__,
                              (b"mvhd",), multi={b"trak"}.__contains__):
        if t == b"trak":
            trak(cs, ce)
        elif t == b"udta":
            udta(cs, ce)
        elif t == b"meta":
            meta(cs, ce, b"moov")
        else:
            _leaves(mv, [(t, 0, cs, ce)], b"moov")


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


def _pieces(chunks):
    """The leaf hashes of the stream cut into pieces of 1 MiB, the last one shorter."""
    buf = b""
    for c in chunks:
        buf += c
        while len(buf) >= _PIECE:
            yield _leaf(buf[:_PIECE])
            buf = buf[_PIECE:]
    if buf:
        yield _leaf(buf)


def _carrier(f, box):
    f.seek(box[2])
    return box[0] == b"uuid" and f.read(16) in (_XMP_UUID, _C2PA_UUID)


def media_hash(f) -> dict:
    """media/1 of an ISO base media file (MP4, MOV, M4V): the RFC 6962 root over the 1 MiB pieces of the stream of
    every top-level box but the two carriers, chunk offsets counted within their mdat (spec/drafts/after-gen.md, Which
    bytes the hash covers). `f` is a path or a seekable binary file; the movie box is read whole, the rest in ranges.
    Refuses, with the reason, every file "One reading only" lists. Returns {"binding": "media/1", "hash", "leaves"}."""
    if isinstance(f, (str, os.PathLike)):
        with open(f, "rb") as fh:
            return media_hash(fh)
    f.seek(0, 2)
    size = f.tell()
    top = list(_boxes(f, 0, size, top=True))
    if not top or top[0][0] != b"ftyp":
        raise PregenError("media/1: the first box is not ftyp")
    f.seek(top[0][2])
    if top[0][3] - top[0][2] < 4 or f.read(4) in _PROBED_AWAY:
        raise PregenError("media/1: an ftyp major brand that players do not read as MP4")
    for uuid, name in ((_XMP_UUID, "XMP"), (_C2PA_UUID, "C2PA")):      # carriers that are not what they claim
        boxes = _top(f, uuid)
        if len(boxes) > 1:
            raise PregenError(f"media/1: more than one {name} box")
        for _, bs, cs, be in boxes:
            if be - bs > _CARRIER_MAX:
                raise PregenError(f"media/1: an {name} box larger than 64 MiB")
            f.seek(cs + 16)
            if name == "XMP":
                packet = f.read(be - cs - 16)
                try:
                    packet.decode("utf-8")
                except UnicodeDecodeError:
                    packet = b"\x00"
                if b"\x00" in packet:
                    raise PregenError("media/1: an XMP box whose packet is not UTF-8 text free of NUL bytes")
            else:
                try:
                    if _store(f, boxes[0]) is None:
                        raise PregenError("c2pa: not a manifest")
                except PregenError:
                    raise PregenError("media/1: a C2PA box that does not parse as a JUMBF manifest store") from None
    moovs = [b for b in top if b[0] == b"moov"]
    if not moovs:
        raise PregenError("media/1: no moov box")
    if len(moovs) > 1:
        raise PregenError("media/1: more than one moov box")
    if any(b[0] == b"moof" for b in top):
        raise PregenError("media/1: a fragmented file (moof)")
    mdats = [(cs, ce) for t, _, cs, ce in top if t == b"mdat"]
    _, bs, cs, ce = moovs[0]
    f.seek(bs)
    whole = f.read(ce - bs)
    mv, zones, m = whole[cs - bs:], [], io.BytesIO(whole[cs - bs:])
    moov = _el(b"moov", _value(m, mv, b"moov", 0, len(mv), mdats, zones))
    at = 0                                       # a second movie: outside mdat data, carriers included
    for s, e in mdats:
        _scan_file(f, at, s, _MOVIE, "{}: a second movie")
        at = e
    _scan_file(f, at, size, _MOVIE, "{}: a second movie")
    _scan_file(f, 0, size, _MPEG, "the pattern hdlr ... mhlr MPEG, which makes players read the file as another format",
               15)
    _scan_file(f, 0, size, _NUT, "a NUT startcode, which makes players read the file as another format", 7)
    _known(m, mv, zones)
    at = 0                                       # the table scan: the movie box but the sample tables and metadata text
    for zs, ze in sorted(zones):
        _scan(whole[at:cs - bs + zs])
        at = cs - bs + ze
    _scan(whole[at:])
    for box in top:
        if box[0] not in (b"moov", b"mdat") and not _carrier(f, box):
            _scan_file(f, box[1], box[3])

    def stream():
        yield b"PREGEN-MEDIA\x00media/1\x00"
        for box in top:
            t, _, cs, be = box
            if _carrier(f, box):
                continue
            if t == b"moov":
                yield moov
                continue
            yield t + (be - cs).to_bytes(8, "big")
            f.seek(cs)
            n = be - cs
            while n:
                chunk = f.read(min(n, _PIECE))
                if not chunk:
                    raise PregenError("media/1: a box runs past the file")
                yield chunk
                n -= len(chunk)
    root, n = _root(_pieces(stream()))
    return {"binding": "media/1", "hash": root.hex(), "leaves": n}


# ── carrying the record: C2PA and XMP ───────────────────────────────────────────────────────────

def _no_dupes(pairs):
    d = dict(pairs)
    if len(d) != len(pairs):
        raise PregenError("a JSON object names a member twice")
    return d


def _deep(v, d=0) -> bool:
    """Nested more than 64 levels: as the CBOR reader, so both libraries read the same values."""
    return d > 64 or isinstance(v, (dict, list)) and any(_deep(x, d + 1)
                                                         for x in (v.values() if isinstance(v, dict) else v))


def _envelope(text: bytes):
    """The envelope whose canonical JSON is exactly `text`, or None."""
    try:
        env = json.loads(text.decode("utf-8"), object_pairs_hook=_no_dupes)
        return env if isinstance(env, dict) and not _deep(env) and canonical_json(env) == text else None
    except (ValueError, RecursionError, PregenError):            # UnicodeError is a ValueError
        return None


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
        if major in (0, 1) and n > _MAX_INT - major:
            raise PregenError("c2pa: a CBOR integer beyond 2^53 - 1")
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


def _jumbf(m, s, e, depth=0):
    """A JUMBF superbox, every superbox in it checked: (label, kids), each kid (type, start, end, superbox or None)."""
    if depth > 64:
        raise PregenError("c2pa: JUMBF nested too deep")
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
    return label, [(t, cs, ce, _jumbf(m, cs, ce, depth + 1) if t == b"jumb" else None) for t, _, cs, ce in kids[1:]]


def _store(f, box):
    """A C2PA box's manifest store: (its bytes, the manifests), every superbox in it checked; None for another
    purpose."""
    _, _, cs, ce = box
    f.seek(cs + 16)
    p = f.read(ce - cs - 16)
    end = p.find(b"\x00", 4)
    if end < 0:
        raise PregenError("c2pa: a C2PA box without its purpose")
    if p[4:end] != b"manifest":
        return None
    if len(p) < end + 9:
        raise PregenError("c2pa: a manifest box without its offset")
    m = io.BytesIO(p[end + 9:])
    store = list(_boxes(m, 0, len(p) - end - 9, who="c2pa"))
    if len(store) != 1 or store[0][0] != b"jumb":
        raise PregenError("c2pa: the box does not hold one JUMBF manifest store")
    label, manifests = _jumbf(m, store[0][2], store[0][3])        # the whole store: a malformed superbox refuses
    if label != "c2pa" or not manifests or any(k[3] is None for k in manifests):
        raise PregenError("c2pa: not a manifest store")
    return m, manifests


def _c2pa(f, box):
    store = _store(f, box)
    if store is None:
        return False
    m, manifests = store
    stores = [k[3] for k in manifests[-1][3][1] if k[3] and k[3][0] == "c2pa.assertions"]
    if len(stores) != 1:
        raise PregenError("c2pa: the active manifest needs exactly one assertion store")
    found = [k[3][1] for k in stores[0][1] if k[3] and k[3][0] and _C2PA_LABEL.fullmatch(k[3][0])]
    if not found:
        return None
    if len(found) > 1 or len(found[0]) != 1 or found[0][0][3] or found[0][0][0] not in (b"json", b"cbor"):
        raise PregenError("c2pa: more than one org.pregen.after_gen assertion, or not one json or cbor box")
    t, s, e, _ = found[0][0]
    m.seek(s)
    data = m.read(e - s)
    env = _envelope(data) if t == b"json" else _cbor(data)
    if not isinstance(env, dict):
        raise PregenError("c2pa: the assertion is not an envelope (as JSON, exactly its canonical JSON)")
    return env


_XMP_NOT = (b"<!--", b"<![CDATA[", b"<!DOCTYPE", b"<!ENTITY")
_XMP_DECL = b'xmlns:pgag="https://pregen.org/ns/after-gen/1/"'
_XMP_ESC = {b"amp": b"&", b"lt": b"<", b"gt": b">", b"quot": b'"', b"apos": b"'"}


def _xmp_record(p: bytes):
    """pgag:Record by the fixed lexical rule (Carrying the record), never by an XML library, so that every reader finds
    the same record: the envelope, or None for a packet that breaks the rule and so carries no record."""
    pis = (p.count(b"<?xpacket begin="), p.count(b"<?xpacket end="))
    if any(x in p for x in _XMP_NOT) or max(pis) > 1 or p.count(b"<?") != sum(pis) or p.count(_PGAG.encode()) != 1 \
            or p.count(_XMP_DECL) != 1 or p.count(b"xmlns:pgag=") != 1:
        return None
    text = _xmp_text(p, b"Record")
    return _envelope(text) if text else None


def _xmp_text(p: bytes, name: bytes):
    """The unescaped text of the one <pgag:name> element by the lexical rule; None when there is none; False when the
    rule is broken (a second element, an attribute form, a `<` or another entity in it, no end tag)."""
    tag = b"<pgag:" + name + b">"
    if p.count(tag) > 1 or b"pgag:" + name + b"=" in p:
        return False
    if tag not in p:
        return None
    start = p.index(tag) + len(tag)
    end = p.find(b"</pgag:" + name + b">", start)
    text = p[start:end]
    if end < 0 or b"<" in text or re.search(rb"&(?!(?:amp|lt|gt|quot|apos);)", text):
        return False
    return re.sub(rb"&(amp|lt|gt|quot|apos);", lambda x: _XMP_ESC[x[1]], text)


def _xmp_codes(p: bytes):
    """pgag:Code and pgag:Licence, the copies present, by the same rule; None when either breaks it."""
    out = {}
    for k in ("Code", "Licence"):
        v = _xmp_text(p, k.encode())
        if v is False:
            return None
        if v is not None:
            try:
                out[k] = v.decode("utf-8")
            except UnicodeDecodeError:
                return None
    return out


def _xmp_tree(packet: bytes):
    if any(x in packet for x in _XMP_NOT):
        raise PregenError("xmp: the existing packet holds a comment, CDATA or a DTD, which the lexical rule refuses")
    try:
        root = ET.fromstring(packet)
    except ET.ParseError as e:
        raise PregenError(f"xmp: not XML: {e}") from None
    rdf = root if root.tag == f"{{{_RDF}}}RDF" else root.find(f"{{{_RDF}}}RDF")
    if rdf is None:
        raise PregenError("xmp: no rdf:RDF")
    return root, rdf


def _xmp(f, box):
    """(the record, its readable copies): (None, {}) for a packet that carries no record."""
    _, _, cs, ce = box
    f.seek(cs + 16)
    p = f.read(ce - cs - 16)
    env, codes = _xmp_record(p), _xmp_codes(p)
    return (env, codes) if env is not None and codes is not None else (None, {})


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
    returns with check_after_gen. Returns {"c2pa": envelope or None, "xmp": envelope or None, "codes": the readable
    copies beside the XMP record, {"Code"?, "Licence"?}; pass them to check_after_gen with that record}."""
    if isinstance(f, (str, os.PathLike)):
        with open(f, "rb") as fh:
            return read_after_gen(fh)
    stores = [e for e in (_c2pa(f, b) for b in _top(f, _C2PA_UUID)) if e is not False]
    xmp = _top(f, _XMP_UUID)
    if len(stores) > 1:
        raise PregenError("c2pa: more than one manifest store")
    if len(xmp) > 1:
        raise PregenError("xmp: more than one XMP box")
    env, codes = _xmp(f, xmp[0]) if xmp else (None, {})
    return {"c2pa": stores[0] if stores else None, "xmp": env, "codes": codes}


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


def _written_codes(env) -> dict:
    """The readable codes embed_xmp writes: those that can be formed."""
    return {k: v for k, v in after_gen_codes(env).items() if v}


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
                 ("Registry", issuer_of(_pg(body.get("subject_ref")))), *_written_codes(env).items()):
        ET.SubElement(d, f"{{{_PGAG}}}{k}").text = v
    decl = "".join(f" xmlns:{p}={quoteattr(u)}" for u, p in names.items() if u != _XML_NS)
    out = ['<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>']
    _serialize(root, names, out, decl)
    out.append('<?xpacket end="w"?>')
    return "".join(out).encode("utf-8")


def _pad(packet: bytes, room: int) -> bytes:
    """The packet padded with spaces to `room` bytes, as XMP pads: before its trailer."""
    at = packet.rfind(b"<?xpacket end=")
    at = len(packet) if at < 0 else at
    return packet[:at] + b" " * (room - len(packet)) + packet[at:]


def embed_xmp(src, dst, envelope: dict) -> None:
    """Write `dst` = `src` with the record in XMP (Carrying the record). With no XMP box, a top-level uuid box is
    appended at the end, so no offset moves; a last box that runs to the end of the file (size 0) gets its real size
    written first, when it fits in 32 bits. An existing XMP box keeps its properties and is rewritten in place: as the
    last box it may grow; elsewhere the new packet must fit in it, padded with spaces, or embedding is refused, since
    anything else would move or change hashed bytes. Refuses a record whose content hash is not dst's media/1 hash.
    Beside pgag:Record it writes the readable codes that can be formed: pgag:Code, and pgag:Licence under a licence."""
    if not isinstance(envelope, dict) or envelope.get("type") != _TYPE or not isinstance(envelope.get("body"), dict):
        raise PregenError(f"not a {_TYPE} envelope")
    if os.path.exists(dst) and os.path.samefile(src, dst):
        raise PregenError("dst must be another file than src")
    with open(src, "rb") as fs:
        fs.seek(0, 2)
        size = fs.tell()
        top = list(_boxes(fs, 0, size, top=True, who="file"))
        old = _top(fs, _XMP_UUID)
        if len(old) > 1:
            raise PregenError("xmp: more than one XMP box")
        packet = None
        if old:
            fs.seek(old[0][2] + 16)
            packet = fs.read(old[0][3] - old[0][2] - 16)
        to_end = None                            # (offset, size) of a last box whose size field is 0
        if top and not old:
            fs.seek(top[-1][1])
            if fs.read(4) == bytes(4):
                to_end = top[-1][1], top[-1][3] - top[-1][1]
                if to_end[1] >= 1 << 32:
                    raise PregenError("file: the last box runs to the end and does not fit in 32 bits")
        new = _packet(packet, envelope)
        if _xmp_record(new) != envelope or _xmp_codes(new) != _written_codes(envelope):
            raise PregenError("xmp: the packet would not carry the record under the lexical rule: an existing property "
                              "spells pgag:Record=, pgag:Code=, pgag:Licence= or xmlns:pgag=, or the record is not canonical "
                              "JSON")
        _, s, cs, e = old[0] if old else (None, size, size, size)
        if old and e < size:
            if len(new) > e - cs - 16:
                raise PregenError("xmp: the new packet does not fit in the existing XMP box, which is not the last box")
            new = _pad(new, e - cs - 16)
        fs.seek(0)
        with open(dst, "wb") as fd:
            shutil.copyfileobj(fs, fd)
            if to_end:
                fd.seek(to_end[0])
                fd.write(struct.pack(">I", to_end[1]))
            if old and e < size:                 # in place, the same size
                fd.seek(cs + 16)
                fd.write(new)
            else:                                # the last box, rewritten or appended
                fd.seek(s)
                fd.truncate()
                big = cs - s == 16
                fd.write((struct.pack(">I4sQ", 1, b"uuid", 32 + len(new)) if big
                          else struct.pack(">I4s", 24 + len(new), b"uuid")) + _XMP_UUID + new)
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


# ── the readable codes ───────────────────────────────────────────────────────────────────────────

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_TOG_VALUES = _CROCKFORD + "ILOU"          # the TOG check table: I L O U take 32-35
_TOG_KINDS = ("PG", "PG-LIC", "AG", "AG-LIC", "LIC")   # kind digits 1-5


def _tog_check(body: str) -> str:
    """PG-CODE 4.1 over the TOG table: the sum of value x 1-based position, mod 37."""
    return (_CROCKFORD + "*~$=!")[sum(_TOG_VALUES.index(c) * (i + 1) for i, c in enumerate(body)) % 37]


def _tog_code(kind: str, prefix, mid):
    """The one-prefix ToG event code (The readable codes): TOG-<kind>-<prefix>-XXXX-XXXX-XXXX, the tail the first 55
    bits of the message id `mid`. None where no code exists: no prefix, a tail starting ZZZZ, a check * ~ $ = !."""
    if not prefix or not _hex(mid):
        return None
    n = int(mid, 16) >> 201
    tail = "".join(_CROCKFORD[(n >> 5 * (10 - i)) & 31] for i in range(11))
    check = _tog_check(f"{len(prefix)}0{_TOG_KINDS.index(kind) + 1}{prefix}{tail}")
    if tail.startswith("ZZZZ") or check not in _CROCKFORD:
        return None
    t = tail + check
    return f"TOG-{kind}-{prefix}-{t[:4]}-{t[4:8]}-{t[8:]}"


# The person's code has one spelling, TOG (TOG-CODE.md §7.3): a record writes only it; a request may still name the
# person in the PG spelling, which folds by its marker. ponytail: persons only, beside a core that still reads PG;
# when claude/tog-code merges, pregen.code_key replaces code_key and _pg goes.
_P = r"(?!LIC|L[A-Z]IC(?![A-Z])|LI[A-Z]C(?![A-Z]))[A-Z]{4,8}(?<!LIC)"
_PERSON = [re.compile(p) for p in (rf"TOG-({_P})-([1-9][0-9]{{8}})([0-9A-HJKMNP-TV-Z])",
                                   r"TOG-([A-HJKMNP-TV-Z]{4})-([0-9]{6,7})([0-9A-HJKMNP-TV-Z*~$=!])",
                                   r"TOG-()([0-9]{6,})([0-9A-HJKMNP-TV-Z*~$=!])",
                                   r"TOG-(STD|SUB)-([0-9]{6,})()")]


def code_key(code) -> str:
    """A person's code in its one spelling, TOG: a TOG code is its own key, a PG one folds by its marker and must then
    be a valid TOG code. Raises PregenError for anything else, never repairs."""
    s = code
    if isinstance(code, str) and code.startswith("PG-"):
        try:
            issuer_of(code)                                 # the frozen PG grammar first: a PG prefix has 4 letters
            s = "TOG-" + code[3:]
        except PregenError:
            s = None
    for p in _PERSON:
        m = p.fullmatch(s) if isinstance(s, str) else None
        if m and (m[3] == "" or _tog_check(m[1] + m[2]) == m[3]):
            return s
    raise PregenError(f"{code!r} is not a person's code (TOG-CODE.md §7.3)")


def _pg(code):
    """The PG spelling, for the core's directory and prefix functions until claude/tog-code merges."""
    return "PG-" + code[4:] if isinstance(code, str) and code.startswith("TOG-") else code


def after_gen_codes(env: dict) -> dict:
    """The readable codes of a pg.after_gen.v1 record, computed from it: {"Code": the approval's, "Licence": the
    licence's under a licence basis}, each None where it cannot be formed (and Licence None under a terms basis)."""
    try:
        b = env["body"]
        prefix, basis = issuer_of(_pg(b["subject_ref"])) or "PRAM", b.get("basis")   # the bare namespace is PRAMPTA's
        licence = isinstance(basis, dict) and basis.get("kind") == "licence"
        lic = basis.get("licence") if licence else None
        lic_id = lic.get("id") if isinstance(lic, dict) else None
        return {"Code": _tog_code("AG-LIC" if licence else "AG", prefix, message_id(_TYPE, b)),
                "Licence": _tog_code("LIC", prefix, lic_id) if licence else None}
    except (KeyError, TypeError, PregenError):
        return {"Code": None, "Licence": None}


# ── the record and its status ──────────────────────────────────────────────────────────────────

_MEMBERS = {"signers", "kind", "label", "notice", "not", "subject_ref", "content", "request", "holder", "basis",
            "scope", "approval", "issued_at", "nonce"}
_SCOPE = {"purposes", "categories", "territories", "channels", "project", "not_after"}
_BASIS = {"licence": {"kind", "licence", "use"}, "terms": {"kind", "terms"}}
_APPROVAL = {"self": {"assent", "decision"}, "registry": {"assent", "instruction", "factor"}}  # a mandate never approves
_STATUS_MEMBERS = {"signers", "record", "state", "approved_at", "withdrawn_at", "not_after", "issued_at", "expires_at"}


def _obj(v, members, where):
    if not isinstance(v, dict) or set(v) != members:
        raise PregenError(f"{where}: exactly the members {', '.join(sorted(members))}")
    return v


def _hex(v) -> bool:
    return isinstance(v, str) and bool(_HEX64.fullmatch(v))


def _star(v, pattern, most) -> bool:
    return v == ["*"] or isinstance(v, list) and 1 <= len(v) <= most \
        and all(isinstance(x, str) and re.fullmatch(pattern, x) for x in v) and v == sorted(set(v))


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
    if not _star(s["territories"], r"[A-Z]{2}", 250):
        raise PregenError('scope.territories: at most 250 sorted ISO 3166-1 alpha-2 codes or ["*"]')
    if not _star(s["channels"], r"[a-z0-9-]{1,32}", 64):
        raise PregenError('scope.channels: at most 64 sorted words of [a-z0-9-]{1,32} or ["*"]')
    p = s["project"]
    if not (isinstance(p, str) and 1 <= len(p) <= 200 and p.isprintable()):
        raise PregenError("scope.project: printable text of 1 to 200 characters")
    if not _count(s["not_after"], 1):
        raise PregenError("scope.not_after: an integer time")


def _approval(a):
    form = a.get("assent") if isinstance(a, dict) else None
    if type(form) is not str or form not in _APPROVAL:                  # never a list or any other type
        raise PregenError("approval.assent: self or registry; only the person approves, never under a mandate")
    _obj(a, _APPROVAL[form], f"approval ({form})")
    if form == "self" and not _hex(a["decision"]):
        raise PregenError("approval: the message id of the subject's decision")
    if form == "registry" and not (_hex(a["instruction"]) and a["factor"] in ("authenticator", "email")):
        raise PregenError("approval: the instruction's SHA-256 and the second factor (authenticator or email)")


def _approved_by(a) -> str:
    return "approved by the person" if a["assent"] == "self" else "approved on the person's own instruction at the registry"


def check_after_gen(env: dict, directory=None, get_json=_get_json, media=None, codes=None) -> dict:
    """Steps 3-4 of How a verifier checks a file: a pg.after_gen.v1 record in shape (exactly its members, in the body
    and every object of it; the constants; the closed vocabularies; one of the two approval forms), signed by exactly
    one registry key the directory lists for the subject's prefix at issued_at (a revoked registry's records fail),
    and, given `media` (a media_hash result or its hash), naming that file. Given `codes` (the copies read beside the
    record, read_after_gen's "codes"), each present copy must be the code computed from the record (The readable
    codes); a missing copy is fine. Raises PregenError; returns a summary. It says nothing about whether the record
    still stands: check_after_gen_status."""
    directory = directory or load_directory(get_json=get_json)
    body = env.get("body") if isinstance(env, dict) else None
    code = body.get("subject_ref") if isinstance(body, dict) else None
    if isinstance(code, str) and (directory.is_false_claim(code) or directory.is_false_claim(_pg(code))):
        raise PregenError(f"{code} is a false claim the steward recorded")
    b = _registry_signed(env, _TYPE, _pg(code), directory, get_json)
    _obj(b, _MEMBERS, _TYPE)
    if code_key(code) != code:
        raise PregenError("subject_ref: the person's code in its one spelling, TOG (a record never writes PG-)")
    if not _printable(b) or set(b["signers"][0]) != {"role", "key_id"}:
        raise PregenError(f"{_TYPE}: a control or format character, or a signer that is not {{role, key_id}}")
    if b["kind"] != "ratification":
        raise PregenError("kind: ratification, the only kind of after-gen/1")
    if b["label"] != AFTER_GEN_LABEL or b["notice"] != AFTER_GEN_NOTICE or b["not"] != AFTER_GEN_NOT:
        raise PregenError("label, notice and not are the fixed constants of what a record never says")
    c = _obj(b["content"], {"binding", "hash", "leaves"}, "content")
    if c["binding"] != "media/1" or not _hex(c["hash"]) or not _count(c["leaves"]):
        raise PregenError("content: one file by its media/1 hash and number of leaves")
    basis = b["basis"]
    kind = basis.get("kind") if isinstance(basis, dict) else None
    if type(kind) is not str or kind not in _BASIS:
        raise PregenError("basis.kind: licence or terms")
    _obj(basis, _BASIS[kind], f"basis ({kind})")
    if kind == "terms" and not _hex(basis["terms"]):
        raise PregenError("basis.terms: the message id of the pg.terms.v1 version in force")
    if kind == "licence":
        lic = _obj(basis["licence"], {"format", "id"}, "licence")
        if lic["format"] != "pg.grant.v1" or not _hex(lic["id"]):
            raise PregenError("licence: a pg.grant.v1 by its message id")
        use = _obj(basis["use"], {"n", "of"}, "use")
        if not _count(use["n"]) or not (use["of"] is None or _count(use["of"]) and use["n"] <= use["of"]):
            raise PregenError("use: n from 1, of the licence's max_uses or null")
    if not _hex(b["request"]) or not _count(b["issued_at"]):
        raise PregenError("request is a message id and issued_at an integer time")
    if not (isinstance(b["nonce"], str) and re.fullmatch(r"[0-9a-f]{32}", b["nonce"])):
        raise PregenError("nonce: 32 lowercase hex characters")
    check_provider_url(b["holder"], allow_port=True)
    _scope(b["scope"])
    if b["scope"]["not_after"] <= b["issued_at"]:
        raise PregenError("scope.not_after: later than issued_at")
    _approval(b["approval"])
    rid = message_id(_TYPE, b)
    status_url = directory.registry_for(_pg(code))["api"].rstrip("/") + "/v2/after-gen/" + rid  # The status: never from the record
    match = None
    if media is not None:
        want = media.get("hash") if isinstance(media, dict) else media
        if want != c["hash"] or isinstance(media, dict) and (media.get("binding"), media.get("leaves")) != \
                ("media/1", c["leaves"]):
            raise PregenError("not for this file")
        match = True
    if codes:
        want = after_gen_codes(env)
        if any(k not in want or want[k] is None or want[k] != v for k, v in codes.items()):
            raise PregenError("the readable code does not match the record")
    return {"id": rid, "subject_ref": code, "prefix": issuer_of(_pg(code)), "label": b["label"],
            "notice": b["notice"], "not": b["not"], "holder": b["holder"], "basis": basis,
            "scope": b["scope"], "approval": b["approval"], "approved_by": _approved_by(b["approval"]),
            "status_url": status_url, "issued_at": b["issued_at"], "content": c, "file_match": match}


def check_after_gen_status(status_env: dict, record_env: dict, directory=None, get_json=_get_json, now=None) -> dict:
    """Step 5: a pg.after_gen_status.v1 for this record (The status), signed by a registry key the directory lists for
    the record's subject prefix, current (at most 300 seconds of life), its state one of active, withdrawn, expired.
    The record is checked first with check_after_gen. Raises PregenError; returns {state, approved_at, withdrawn_at,
    not_after}."""
    import time
    now = int(time.time()) if now is None else now
    directory = directory or load_directory(get_json=get_json)
    if now - directory.loaded_at > DIRECTORY_MAX_AGE:
        raise PregenError("the directory was loaded more than 24 hours ago: load it again")
    r = check_after_gen(record_env, directory, get_json)
    s = _registry_signed(status_env, _STATUS, _pg(r["subject_ref"]), directory, get_json)
    _obj(s, _STATUS_MEMBERS, _STATUS)
    if set(s["signers"][0]) != {"role", "key_id"}:
        raise PregenError(f"{_STATUS}: a signer that is not {{role, key_id}}")
    if s["record"] != r["id"]:
        raise PregenError("a status for another record")
    iat, exp = s["issued_at"], s["expires_at"]
    if not all(_count(x) for x in (iat, exp, s["approved_at"], s["not_after"])):
        raise PregenError("status times are integers")
    if not 0 < exp - iat <= _MAX_STATUS_LIFETIME:
        raise PregenError(f"a status lives at most {_MAX_STATUS_LIFETIME} seconds")
    if iat > now + 60:
        raise PregenError("a status issued in the future")
    if exp <= now:
        raise PregenError("the status expired")
    if s["approved_at"] != r["issued_at"] or s["not_after"] != r["scope"]["not_after"]:
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
            "requester": check_provider_url(requester, allow_port=True), "subject_ref": code_key(subject_ref),
            "licence": {"format": "pg.grant.v1", "id": licence_id},
            "content": {k: content[k] for k in ("binding", "hash", "leaves")}, "scope": scope,
            "issued_at": int(time.time() if now is None else now), "nonce": nonce or os.urandom(16).hex()}
    return sign_envelope("pg.after_gen_request.v1", body, private_key_hex)


def after_gen_decision(request_id: str, outcome: str, scope, private_key_hex: str, role: str, now=None) -> dict:
    """A pg.after_gen_decision.v1 (The decision): the subject's (role "subject") approval or refusal of one request,
    or a representative's (role "agent") refusal only. `scope` is the approved scope for "approve", None for "refuse"."""
    import time
    if role not in ("subject", "agent") or outcome not in ("approve", "refuse") \
            or (scope is None) != (outcome == "refuse") or not _hex(request_id):
        raise PregenError("a decision: role subject or agent, outcome approve (with a scope) or refuse (without)")
    if role == "agent" and outcome == "approve":
        raise PregenError("a decision: a mandate never approves; a representative may only refuse")
    body = {"signers": [{"role": role, "key_id": fingerprint(public_key_hex(private_key_hex))}],
            "request": request_id, "outcome": outcome, "issued_at": int(time.time() if now is None else now)}
    if scope is not None:
        body["scope"] = scope
    return sign_envelope("pg.after_gen_decision.v1", body, private_key_hex)
