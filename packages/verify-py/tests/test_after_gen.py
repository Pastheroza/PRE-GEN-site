"""Draft after-gen (spec/drafts/after-gen.md): media/1, the record in C2PA and XMP, the record and its status, and the
must-reject vectors 6, 7, 9, 10, 11, 13 and 16 at library level. spec/test-vectors/after-gen holds the files and
vectors.json for both libraries; `python tests/test_after_gen.py` rewrites the files derived from the ffmpeg ones."""
import hashlib
import io
import json
import re
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

import pregen
from pregen import after_gen as ag

ROOT = Path(__file__).resolve().parents[3]
DIR = ROOT / "spec/test-vectors/after-gen"
V = json.loads((ROOT / "spec/test-vectors/answers.json").read_text())
NOW, CODE = V["now"], "PG-TEST-000001N"
D = pregen.verify_directory(V["directory"], V["steward_public_key_hex"], now=NOW)
get_json = V["key_sets"].__getitem__
DROP = object()
FFMPEG = shutil.which("ffmpeg") or (Path("/opt/homebrew/bin/ffmpeg").exists() and "/opt/homebrew/bin/ffmpeg")


def seed(name):
    return hashlib.sha256(f"pregen-answer-vector-{name}".encode()).hexdigest()


# ── a tiny ISO BMFF writer ──────────────────────────────────────────────────────

def box(t, *parts):
    p = b"".join(parts)
    return struct.pack(">I4s", 8 + len(p), t) + p


def full(t, v, flags, *parts):
    return box(t, bytes([v]) + flags.to_bytes(3, "big"), *parts)


def U(*xs):
    return struct.pack(f">{len(xs)}I", *xs)


MATRIX = (0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000)
FTYP = box(b"ftyp", b"isom", U(512), b"isomiso2mp41")
DATA_AT = len(FTYP) + 8                       # the first sample's offset: right after the mdat header


AVC1 = box(b"avc1", bytes(6), b"\x00\x01", bytes(70))       # a visual sample entry's fields, data reference 1
DINF = box(b"dinf", full(b"dref", 0, 0, U(1), full(b"url ", 0, 1)))     # one self-contained data reference
VMHD = full(b"vmhd", 0, 1, bytes(8))


def trak(tid=1, hdlr=b"vide", samples=(b"abc", b"de"), offset=DATA_AT, tref=b"", stbl=None, entry=None, minf=b"",
         dinf=DINF, mhd=VMHD, mdhd=None):
    sizes = [len(s) for s in samples]
    tables = {b"stsd": full(b"stsd", 0, 0, U(1), entry or AVC1),
              b"stts": full(b"stts", 0, 0, U(1, len(sizes), 10)),
              b"stsc": full(b"stsc", 0, 0, U(1, 1, len(sizes), 1)),
              b"stsz": full(b"stsz", 0, 0, U(0, len(sizes), *sizes)),
              b"stco": full(b"stco", 0, 0, U(1, offset))}
    tables.update(stbl or {})
    minf = box(b"minf", mhd, minf, dinf, box(b"stbl", *(v for v in tables.values() if v is not None)))
    mdia = box(b"mdia", mdhd or full(b"mdhd", 0, 0, U(0, 0, 1000, 10 * len(sizes)), bytes(4)),
               full(b"hdlr", 0, 0, U(0), hdlr, bytes(12), b"\x00"), minf)
    tkhd = full(b"tkhd", 0, 3, U(0, 0, tid, 0, 0), bytes(8), bytes(8), struct.pack(">9i", *MATRIX), U(64 << 16, 48 << 16))
    return box(b"trak", tkhd, tref, mdia)


MVHD = full(b"mvhd", 0, 0, U(0, 0, 1000, 20), struct.pack(">ih", 0x10000, 0x100), bytes(10),
            struct.pack(">9i", *MATRIX), bytes(24), U(9))


def mp4(tracks=({},), moov_extra=b"", top=b"", moov=True):
    """ftyp, mdat with every track's samples in turn, moov; `tracks` are trak() arguments."""
    data, traks, at = b"", [], DATA_AT
    for t in tracks:
        t = {"samples": (b"abc", b"de"), **t}
        traks.append(trak(offset=at, **t))
        at += sum(map(len, t["samples"]))
        data += b"".join(t["samples"])
    return FTYP + box(b"mdat", data) + (box(b"moov", MVHD, *traks, moov_extra) if moov else b"") + top


def el(code, value):
    return code + len(value).to_bytes(8, "big") + value


def i64(*xs):
    return b"".join(x.to_bytes(8, "big", signed=True) for x in xs)


def mth(leaves):
    """RFC 6962 Merkle Tree Hash, written from the RFC, apart from the library's."""
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return hashlib.sha256(b"\x01" + mth(leaves[:k]) + mth(leaves[k:])).digest()


def H(path_or_bytes):
    f = io.BytesIO(path_or_bytes) if isinstance(path_or_bytes, bytes) else path_or_bytes
    return pregen.media_hash(f)


def refused(data):
    with pytest.raises(pregen.PregenError) as e:
        H(data)
    return str(e.value)


# ── patching real files as a C2PA tool would ────────────────────────────────────

CONTAINERS = {b"moov", b"trak", b"mdia", b"minf", b"stbl"}


def top_boxes(data):
    out, p = [], 0
    while p < len(data):
        size, t = struct.unpack_from(">I4s", data, p)
        size = size or len(data) - p
        out.append((t, p, size))
        p += size
    return out


def shift_offsets(data, start, end, delta):
    """Add `delta` to every stco/co64 entry under [start, end) (box contents)."""
    data, p = bytearray(data), start
    while p < end:
        size, t = struct.unpack_from(">I4s", data, p)
        if t in CONTAINERS:
            data[:] = shift_offsets(bytes(data), p + 8, p + size, delta)
        elif t in (b"stco", b"co64"):
            (n,) = struct.unpack_from(">I", data, p + 12)
            fmt, w = (">I", 4) if t == b"stco" else (">Q", 8)
            for j in range(n):
                q = p + 16 + j * w
                struct.pack_into(fmt, data, q, struct.unpack_from(fmt, data, q)[0] + delta)
        p += size
    return bytes(data)


def insert_after_ftyp(data, blob):
    """`blob` inserted after ftyp, chunk offsets moved, as c2patool does with its manifest box."""
    _, p, size = next(b for b in top_boxes(data) if b[0] == b"moov")
    moved = shift_offsets(data, p + 8, p + size, len(blob))
    n = top_boxes(data)[0][2]
    return moved[:n] + blob + moved[n:]


def jumd(label, toggles=3):
    return box(b"jumd", bytes(16), bytes([toggles]), label.encode() + b"\x00" if toggles & 2 else b"")


def jumb(label, *kids):
    return box(b"jumb", jumd(label), *kids)


def c2pa_box(*manifests, purpose=b"manifest"):
    return box(b"uuid", ag._C2PA_UUID, bytes(4), purpose + b"\x00", bytes(8), jumb("c2pa", *manifests))


def manifest(n, *assertions):
    return jumb(f"urn:uuid:00000000-0000-4000-8000-00000000000{n}", jumb("c2pa.assertions", *assertions),
                jumb("c2pa.claim", box(b"cbor", b"\xa0")), jumb("c2pa.signature", box(b"cbor", b"\xa0")))


def cbor(v):
    """A plain CBOR encoder for the test (definite lengths, shortest heads)."""
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for ai, w in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * w):
                return bytes([major << 5 | ai]) + n.to_bytes(w, "big")
    if v is None or isinstance(v, bool):
        return bytes([0xF6 if v is None else 0xF5 if v else 0xF4])
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(map(cbor, v))
    return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())


def assertion(env, kind="json", label="org.pregen.after_gen"):
    return jumb(label, box(b"json", pregen.canonical_json(env)) if kind == "json" else box(b"cbor", cbor(env)))


def xmp_box(packet):
    return box(b"uuid", ag._XMP_UUID, packet)


FOREIGN_XMP = ('<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/">'
               '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="" '
               'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmp="http://ns.adobe.com/xap/1.0/" '
               'xmp:CreatorTool="Studio &amp; Co"><dc:title><rdf:Alt><rdf:li xml:lang="x-default">Spring &lt;cut&gt;'
               '</rdf:li></rdf:Alt></dc:title></rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>').encode()


# ── records and statuses ────────────────────────────────────────────────────────

KEY = seed("registry")
API = "https://registry.test.example/v2/after-gen/"
SCOPE = {"purposes": ["commercial"], "categories": ["advertising"], "territories": ["ES", "IT"],
         "channels": ["online-video", "social"], "project": "Spring campaign 2027", "not_after": NOW + 10**6}
APPROVAL = {"assent": "registry", "instruction": "b" * 64, "factor": "authenticator"}
AGENT = {"assent": "agent", "agent": "https://agency.example", "mandate": "b" * 64, "decision": "c" * 64,
         "factor": "signature"}                                # the old form: a mandate never approves
BASIS = {"kind": "licence", "licence": {"format": "pg.grant.v1", "id": "e" * 64}, "use": {"n": 3, "of": 10}}
TERMS = {"kind": "terms", "terms": "f" * 64}


def signer(key):
    return [{"role": "registry", "key_id": pregen.fingerprint(pregen.public_key_hex(key))}]


def record(media, key=KEY, **change):
    body = {"signers": signer(key), "kind": "ratification", "label": pregen.AFTER_GEN_LABEL,
            "notice": pregen.AFTER_GEN_NOTICE, "not": pregen.AFTER_GEN_NOT, "subject_ref": CODE,
            "content": {k: media[k] for k in ("binding", "hash", "leaves")}, "request": "a" * 64,
            "holder": "https://studio.example", "basis": BASIS, "scope": SCOPE, "approval": APPROVAL,
            "issued_at": NOW - 100}
    body.update(change)
    return pregen.sign_envelope("pg.after_gen.v1", {k: v for k, v in body.items() if v is not DROP}, key)


def status(rec, key=KEY, **change):
    body = {"signers": signer(key), "record": pregen.message_id("pg.after_gen.v1", rec["body"]), "state": "active",
            "approved_at": rec["body"]["issued_at"], "withdrawn_at": None, "not_after": rec["body"]["scope"]["not_after"],
            "issued_at": NOW - 10, "expires_at": NOW + 290}
    body.update(change)
    return pregen.sign_envelope("pg.after_gen_status.v1", body, key)


def check(env, media=None, directory=D, codes=None):
    return pregen.check_after_gen(env, directory, get_json, media=media, codes=codes)


def coded(media, **change):
    """A record as a registry signs it: issued_at a second later while its code would not exist (The readable codes)."""
    t = change.pop("issued_at", NOW - 100)
    while not pregen.after_gen_codes(rec := record(media, issued_at=t, **change))["Code"]:
        t += 1
    return rec


def with_codes(env, **codes):
    """embed_xmp's packet for `env` with its readable copies replaced: a value, or None to drop the copy."""
    p = ag._packet(None, env)
    for k, v in codes.items():
        p = re.sub(rf"<pgag:{k}>[^<]*</pgag:{k}>".encode(), b"", p)
        if v is not None:
            p = p.replace(b"</pgag:Record>", f"</pgag:Record><pgag:{k}>{v}</pgag:{k}>".encode())
    return p


def relabel(code, kind):
    """The same tail under another kind, with the check of that kind: a well-formed code of another meaning."""
    prefix, tail = code.split("-")[-4], code[-14:].replace("-", "")[:-1]
    t = tail + ag._tog_check(f"{len(prefix)}0{ag._TOG_KINDS.index(kind) + 1}{prefix}{tail}")
    return f"TOG-{kind}-{prefix}-{t[:4]}-{t[4:8]}-{t[8:]}"


# ── the vector files ────────────────────────────────────────────────────────────

# Made once with ffmpeg 9.0.2, B="-fflags +bitexact -map_metadata -1":
#   ffmpeg -f lavfi -i testsrc=size=64x48:rate=10 -f lavfi -i sine=frequency=440 -t 1 -c:v libx264 -preset ultrafast \
#          -pix_fmt yuv420p -c:a aac -b:a 32k $B a.mp4
#   ffmpeg -i a.mp4 -c copy $B a-remux.mp4; ffmpeg -i a-remux.mp4 -c copy -movflags +faststart $B a-remux-faststart.mp4
#   b.mov: the same with testsrc2=size=64x48:rate=12 and sine=frequency=220; b-remux.mov, b-remux-faststart.mov alike
#   ffmpeg -f lavfi -i testsrc=size=32x24:rate=5 -t 1 -c:v libx264 -preset ultrafast -bf 2 -pix_fmt yuv420p $B c.mp4
FFMPEG_FILES = ("a.mp4", "a-remux.mp4", "a-remux-faststart.mp4", "b.mov", "b-remux.mov", "b-remux-faststart.mov",
                "c.mp4",
                # made outside this script: an AVAssetWriter MOV (timescale = frame rate, empty alis), and a file with a
                # chunk offset table hidden in its sample entry, which FFmpeg reads in place of the real one
                "apple-writer-ts-fps.mov", "attack-stco-in-entry.mp4",
                # an ilst trkn whose data is shorter than the 4 value bytes FFmpeg reads, last in a moov at the end
                "attack-ilst-short-data.mp4")


HUGE = {b"stsz": full(b"stsz", 0, 0, U(1, 2**32 - 1)), b"stts": full(b"stts", 0, 0, U(1, 2**32 - 1, 1)),
        b"stsc": full(b"stsc", 0, 0, U(1, 1, 2**32 - 1, 1))}


CMOV = box(b"cmov", box(b"dcom", b"zlib"), box(b"cmvd", U(0)))
PCM = box(b"sowt", bytes(6), b"\x00\x01", struct.pack(">HHIHH", 0, 0, 0, 2, 16), bytes(8))     # 4 bytes a frame


def CHUNKS(size):
    """Durations of 1 (sound read by chunk) and a fixed sample size."""
    return {b"stts": full(b"stts", 0, 0, U(1, 2, 1)), b"stsz": full(b"stsz", 0, 0, U(size, 2))}


GMHD_KEPT = mp4(({"tref": box(b"tapt", full(b"clef", 0, 0, U(64 << 16, 48 << 16)))
                  + box(b"edts", full(b"elst", 0, 0, U(1, 20, 0), struct.pack(">hh", 1, 0))),
                  "minf": full(b"hdlr", 0, 0, U(0), b"alis", bytes(12)), "mhd": box(b"gmhd", full(b"gmin", 0, 0, bytes(12))),
                  "stbl": {b"stss": full(b"stss", 0, 0, U(0))}},))
TITLE = b"Costco spring sale"                            # metadata text that spells stco: read as text, not searched
TITLED = box(b"udta", box(b"\xa9nam", struct.pack(">HH", len(TITLE), 0x55C4), TITLE),
             full(b"meta", 0, 0, full(b"hdlr", 0, 0, U(0), b"mdir", b"appl", bytes(8), b"\x00"),
                  box(b"ilst", box(b"\xa9nam", box(b"data", U(1, 0), TITLE)))))


def derived():
    """Every vector file made here from the ffmpeg ones, by name; deterministic (Ed25519 signs deterministically)."""
    a = (DIR / "a.mp4").read_bytes()
    A = H(a)
    rec, other, terms = coded(A), coded(H((DIR / "b.mov").read_bytes())), coded(A, basis=TERMS)
    code, lic = pregen.after_gen_codes(rec).values()
    flip = bytearray(a)
    flip[DATA_AT + 100] ^= 1                  # inside the first video sample of a.mp4 (mdat starts at 40)
    out = {
        "a-meta.mp4": a + box(b"free", bytes(100)) + full(b"meta", 0, 0, full(b"hdlr", 0, 0, U(0), b"mdir", bytes(13))),
        "a-flip.mp4": bytes(flip),
        "a-xmp.mp4": a + xmp_box(ag._packet(None, rec)),
        "a-xmp-foreign.mp4": a + xmp_box(FOREIGN_XMP),
        "a-c2pa-json.mp4": insert_after_ftyp(a, c2pa_box(manifest(1, assertion(rec)))),
        "a-c2pa-cbor.mp4": insert_after_ftyp(a, c2pa_box(manifest(1, assertion(other)),
                                                         manifest(2, assertion(rec, "cbor", "org.pregen.after_gen__1")))),
        "a-c2pa-earlier.mp4": insert_after_ftyp(a, c2pa_box(manifest(1, assertion(rec)), manifest(2))),
        "b-copied-record.mov": (DIR / "b.mov").read_bytes() + xmp_box(ag._packet(None, rec)),
        "tiny.mp4": mp4(),
        "tiny-kept.mp4": GMHD_KEPT,
        "tiny-tref.mp4": mp4(({}, {"tid": 2, "hdlr": b"meta"},
                              {"tid": 5, "hdlr": b"soun", "entry": PCM, "tref": box(b"tref", box(b"sync", U(1)))})),
        "x-no-moov.mp4": mp4(moov=False),
        "x-two-moov.mp4": mp4(top=box(b"moov", MVHD)),
        "x-moof.mp4": mp4(top=box(b"moof", full(b"mfhd", 0, 0, U(1)))),
        "x-mvex.mp4": mp4(moov_extra=box(b"mvex", full(b"trex", 0, 0, U(1, 1, 0, 0, 0)))),
        "x-encv.mp4": mp4(({"entry": box(b"encv", bytes(78))},)),
        "x-sinf.mp4": mp4(({"entry": box(b"avc1", bytes(78), box(b"sinf", box(b"frma", b"avc1")))},)),
        "x-stz2.mp4": mp4(({"stbl": {b"stsz": None, b"stz2": full(b"stz2", 0, 0, bytes(3) + b"\x08", U(2), b"\x03\x02")}},)),
        "x-overlap.mp4": mp4(({"stbl": {b"stsc": full(b"stsc", 0, 0, U(1, 1, 1, 1)),
                                        b"stco": full(b"stco", 0, 0, U(2, DATA_AT, DATA_AT + 1))}},)),
        "x-past-eof.mp4": mp4(({"stbl": {b"stco": full(b"stco", 0, 0, U(1, 10**6))}},)),
        "x-box-past-parent.mp4": mp4(moov_extra=struct.pack(">I4s", 100, b"free")),
        "x-tref-unlisted.mp4": mp4(({"tref": box(b"tref", box(b"cdsc", U(9)))},)),
        "x-stts-stsz.mp4": mp4(({"stbl": {b"stts": full(b"stts", 0, 0, U(1, 3, 10))}},)),
        # the adversarial review's files, small: a track relabelled meta and an added meta track are hashed like any
        # other; a box media/1 reads, out of its place, a short uuid, a data reference elsewhere and 20 tracks of 2^32
        # samples each are refused (the last one at once); a record the lexical rule does not see, and a malformed store
        "attack-meta-red.mp4": mp4(({"hdlr": b"meta", "samples": (b"red",)},)),
        "attack-meta-blue.mp4": mp4(({"hdlr": b"meta", "samples": (b"blu",)},)),
        "attack-hidden-track.mp4": mp4(({}, {"tid": 2, "hdlr": b"meta", "samples": (b"other footage",)})),
        "attack-stray-stco.mp4": mp4(({"tref": full(b"stco", 0, 0, U(1, DATA_AT + 1))},)),
        "attack-elst-in-udta.mp4": mp4(({"tref": box(b"udta", full(b"elst", 0, 0, U(1, 5, 0), struct.pack(">hh", 1, 0)))},)),
        "attack-short-uuid.mp4": mp4(top=struct.pack(">I4s", 20, b"uuid") + bytes(12)),
        "attack-dref-external.mp4": mp4(({"dinf": box(b"dinf", full(b"dref", 0, 0, U(1), full(b"url ", 0, 0, b"https://x.example/a\0")))},)),
        "attack-dos.mp4": mp4(tuple({"tid": j, "hdlr": b"meta", "stbl": HUGE} for j in range(1, 21))),
        # round 3: what a player reads outside media/1's boxes is kept as is (other hash), or the file is refused
        "attack-top-trak.mp4": mp4(top=trak(tid=2)),
        "attack-top-udta-trak.mp4": mp4(top=box(b"udta", trak(tid=2))),
        "attack-top-cmov.mp4": mp4(top=CMOV),
        "attack-cmov.mp4": mp4(moov_extra=CMOV),
        "attack-udta-cmov.mp4": mp4(moov_extra=box(b"udta", CMOV)),
        "attack-udta-mvex-moof.mp4": mp4(moov_extra=box(b"udta", box(b"mvex", full(b"trex", 0, 0, U(1, 1, 10, 3, 0))),
                                                        box(b"moof", full(b"mfhd", 0, 0, U(1))))),
        "attack-glbl.mp4": mp4(({"stbl": {b"glbl": box(b"glbl", b"\x01\x64\x00\x0a")}},)),
        "attack-stss.mp4": mp4(({"stbl": {b"stss": full(b"stss", 0, 0, U(1, 2))}},)),
        "attack-st3d-clli.mp4": mp4(({"stbl": {b"st3d": full(b"st3d", 0, 0, b"\x01"), b"clli": box(b"clli", U(0x03e80000))}},)),
        "attack-two-stco.mp4": mp4(({"stbl": {b"stco2": full(b"stco", 0, 0, U(1, DATA_AT))}},)),
        "attack-two-tkhd.mp4": mp4(({"tref": full(b"tkhd", 0, 3, bytes(80))},)),
        "attack-two-media-headers.mp4": mp4(({"minf": full(b"smhd", 0, 0, bytes(4))},)),
        "attack-dinf-extra.mp4": mp4(({"dinf": box(b"dinf", full(b"dref", 0, 0, U(1), full(b"url ", 0, 1)), box(b"udta"))},)),
        "attack-dref-alis.mp4": mp4(({"dinf": box(b"dinf", full(b"dref", 0, 0, U(1), full(b"alis", 0, 1, bytes(150))))},)),
        "dref-alis-empty.mp4": mp4(({"dinf": box(b"dinf", full(b"dref", 0, 0, U(1), full(b"alis", 0, 1)))},)),  # Apple
        # round 4: fields players act on (track order, the file type, durations, language) are hashed like any byte
        "attack-trak-order.mp4": mp4(({"tid": 2}, {"tid": 1})),
        "attack-ftyp-qt.mp4": mp4().replace(b"ftypisom", b"ftypqt  ", 1),
        "attack-mvhd-duration.mp4": mp4().replace(b"mvhd" + bytes(4) + U(0, 0, 1000, 20), b"mvhd" + bytes(4) + U(0, 0, 1000, 5)),
        "attack-mdhd-language.mp4": mp4().replace(b"mdhd" + bytes(4) + U(0, 0, 1000, 20) + bytes(4),
                                                  b"mdhd" + bytes(4) + U(0, 0, 1000, 20) + b"\x15\xc7\x00\x00"),
        "attack-pcm-ok.mp4": mp4(({"hdlr": b"soun", "entry": PCM, "samples": (b"abcd", b"efgh"), "stbl": CHUNKS(4)},)),
        "attack-pcm-stsz1.mp4": mp4(({"hdlr": b"soun", "entry": PCM, "samples": (b"abcd", b"efgh"), "stbl": CHUNKS(1)},)),
        # round 5: tables that read two ways, tables outside their place, sound read by chunk
        "attack-stsc-first2.mp4": mp4(({"stbl": {b"stsc": full(b"stsc", 0, 0, U(1, 2, 2, 1))}},)),
        "attack-stsc-count0.mp4": mp4(({"stbl": {b"stsc": full(b"stsc", 0, 0, U(2, 1, 2, 1, 2, 0, 1)),
                                                 b"stco": full(b"stco", 0, 0, U(2, DATA_AT, DATA_AT + 5))}},)),
        "attack-two-stsz.mp4": mp4(({"stbl": {b"stsz2": full(b"stsz", 0, 0, U(5, 1))}},)),
        "attack-trak-udta-stco.mp4": mp4(({"tref": box(b"udta", full(b"stco", 0, 0, U(1, DATA_AT + 1)))},)),
        "attack-free-tables.mp4": mp4(top=box(b"free", full(b"stsz", 0, 0, U(1, 1)))),
        "attack-iloc-meta.mp4": mp4(top=full(b"meta", 0, 0, full(b"iloc", 0, 0, bytes(8)))),
        "attack-chunkmode-none.mp4": mp4(({"hdlr": b"soun", "entry": PCM.replace(b"sowt", b"NONE"),
                                           "samples": (b"abcd", b"efgh"), "stbl": CHUNKS(4)},)),
        "attack-chunkmode-stz2.mp4": mp4(({"hdlr": b"soun", "entry": PCM, "samples": (b"abcd", b"efgh"),
                                           "stbl": {**CHUNKS(4), b"stsz": None,
                                                    b"stz2": full(b"stz2", 0, 0, bytes(3) + b"\x08", U(2), b"\x04\x04")}},)),
        "attack-offset-in-moov.mp4": mp4(({"stbl": {b"stco": full(b"stco", 0, 0, U(1, DATA_AT + 13))}},)),
        "attack-chunk-past-mdat.mp4": mp4(({"stbl": {b"stco": full(b"stco", 0, 0, U(1, DATA_AT + 3))}},)),
        # round 6: a second movie, a carrier first or not what it claims, the chunk rule whatever the handler says
        "attack-ftyp-not-first.mp4": xmp_box(b"<x/>") + mp4(),
        "attack-xmp-nul.mp4": mp4(top=xmp_box(b"<x/>\x00")),
        "attack-c2pa-not-a-store.mp4": mp4(top=c2pa_box(manifest(1), purpose=b"other")),
        "attack-two-c2pa.mp4": mp4(top=c2pa_box(manifest(1)) + c2pa_box(manifest(2))),
        "attack-hoov.mp4": mp4(top=box(b"hoov", b"x")),
        "attack-hoov-in-xmp.mp4": mp4(top=xmp_box(b"<x>hoov</x>")),
        "attack-mpeg-hdlr.mp4": mp4(top=xmp_box(b"hdlr\x01\x02\x03\x04mhlrMPEG")),
        "attack-mpeg-hdlr-in-mdat.mp4": mp4(top=box(b"mdat", b"hdlr" + bytes(4) + b"mhlrMPEG")),
        "attack-nut.mp4": mp4(top=box(b"free", b"NMzV\x1f_\x04\xad")),
        "attack-ftyp-jp2.mp4": box(b"ftyp", b"jp2 ", U(0), b"isom") + mp4()[len(FTYP):],
        "attack-chunkmode-meta.mp4": mp4(({"hdlr": b"meta", "entry": PCM, "samples": (b"abcd", b"efgh"), "stbl": CHUNKS(1)},)),
        "attack-chunkmode-minf-soun.mp4": mp4(({"entry": PCM, "samples": (b"abcd", b"efgh"), "stbl": CHUNKS(1),
                                                "minf": full(b"hdlr", 0, 0, U(0), b"soun", bytes(12))},)),
        "attack-xmp-pi.mp4": mp4(top=xmp_box(ag._packet(None, rec).replace(b"<x:xmpmeta", b"<?note ?><x:xmpmeta", 1))),
        "attack-xmp-ns-twice.mp4": mp4(top=xmp_box(ag._packet(None, rec).replace(
            b"</rdf:RDF>", b'<rdf:Description xmlns:p2="https://pregen.org/ns/after-gen/1/"/></rdf:RDF>'))),
        "attack-xmp-comment.mp4": mp4(top=xmp_box(ag._packet(None, rec).replace(b"</rdf:RDF>", b"<!-- a note --></rdf:RDF>"))),
        "attack-xmp-rebound.mp4": mp4(top=xmp_box(ag._packet(None, rec).replace(b"<pgag:Record>",
                                                                               b'<pgag:Record xmlns:pgag="https://x.example/">'))),
        "attack-xmp-attribute.mp4": mp4(top=xmp_box(ag._packet(None, rec).replace(b"<pgag:Id>", b"<pgag:Id pgag:Record=\"x\">"))),
        "attack-c2pa-nested.mp4": mp4(top=c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"json", pregen.canonical_json(rec)),
                                                                    jumb("x"))))),
        "attack-c2pa-older-bad.mp4": mp4(top=c2pa_box(jumb("urn:old", box(b"jumb", box(b"free"))), manifest(2, assertion(rec)))),
        "attack-c2pa-not-canonical.mp4": mp4(top=c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"json", json.dumps(rec).encode()))))),
        # round 10, known boxes only: a player reads a box's fields past its end, a count past its entries, a hdlr
        # anywhere in a track, and any box by its type; text in metadata is read as text
        "attack-mdhd-short.mp4": mp4(({"mdhd": full(b"mdhd", 0, 0, U(0, 0))},)),
        "attack-dref-count.mp4": mp4(({"dinf": box(b"dinf", full(b"dref", 0, 0, U(2), full(b"url ", 0, 1)))},)),
        "attack-hdlr-in-stbl.mp4": mp4(({"entry": PCM, "samples": (b"abcd", b"efgh"),
                                         "stbl": {**CHUNKS(1), b"hdlr": full(b"hdlr", 0, 0, U(0), b"soun", bytes(12))}},)),
        "attack-unknown-box-in-trak.mp4": mp4(({"tref": box(b"xyz1", U(1))},)),
        "tiny-title-stco.mp4": mp4(moov_extra=TITLED),
        # the readable codes: copies beside the record, recomputed from it; one that differs refuses the file
        "a-xmp-terms.mp4": a + xmp_box(ag._packet(None, terms)),
        "a-xmp-code-symbol.mp4": a + xmp_box(with_codes(rec, Code=code[:-2] + ("0" if code[-2] != "0" else "1") + code[-1])),
        "a-xmp-code-other.mp4": a + xmp_box(with_codes(rec, Code=pregen.after_gen_codes(other)["Code"])),
        "a-xmp-code-ag.mp4": a + xmp_box(with_codes(rec, Code=relabel(code, "AG"))),
        "a-xmp-licence-is-code.mp4": a + xmp_box(with_codes(rec, Licence=code)),
        "a-xmp-terms-licence.mp4": a + xmp_box(with_codes(terms, Licence=lic)),
        "attack-xmp-code-twice.mp4": a + xmp_box(with_codes(rec, Code=code).replace(
            b"</rdf:RDF>", f"<rdf:Description><pgag:Code>{code}</pgag:Code></rdf:Description></rdf:RDF>".encode())),
        "attack-xmp-code-attribute.mp4": a + xmp_box(with_codes(rec, Code=None).replace(
            b"<rdf:Description", f'<rdf:Description pgag:Code="{code}"'.encode())),
    }
    out["a-xmp-foreign-pg.mp4"] = a + xmp_box(ag._packet(FOREIGN_XMP, rec))           # the last box, rewritten
    return out, rec


def vectors():
    files, rec = derived()
    names = sorted(set(FFMPEG_FILES) | set(files))
    entries, reads = [], []
    for n in names:
        try:
            entries.append({"file": n, "media": pregen.media_hash(DIR / n)})
        except pregen.PregenError as e:
            entries.append({"file": n, "refused": str(e)})
        if n.startswith(("a-xmp", "a-c2pa", "b-copied", "attack-xmp", "attack-c2pa")):
            try:
                got = pregen.read_after_gen(DIR / n)
            except pregen.PregenError as e:
                reads.append({"file": n, "refused": str(e)})
                continue
            ids = {k: got[k] and pregen.message_id(got[k]["type"], got[k]["body"]) for k in ("c2pa", "xmp")}
            res = {}
            for k in ("c2pa", "xmp"):
                if got[k] is not None:
                    try:
                        res[k] = check(got[k], pregen.media_hash(DIR / n), codes=got["codes"] if k == "xmp" else None)["id"]
                    except pregen.PregenError as e:
                        res[k] = str(e)
            reads.append({"file": n, **ids, "codes": got["codes"], "check": res})
    terms = coded(H((DIR / "a.mp4").read_bytes()), basis=TERMS)
    return {"description": "after-gen/1 (spec/drafts/after-gen.md): media/1 of each file, or its refusal; for files "
                           "carrying a record, the message id read from C2PA and XMP, the readable copies read beside the XMP "
                           "record, and what check_after_gen says against the file's own media/1 (and, for the XMP "
                           "record, its copies); a record of the terms kind for a.mp4 and its summary's id "
                           "and basis. The directory and key sets are those of answers.json.",
            "now": NOW, "record": rec, "files": entries, "read": reads,
            "terms_record": {"record": terms, "file": "a.mp4",
                             "check": {k: check(terms, pregen.media_hash(DIR / "a.mp4"))[k] for k in ("id", "basis")}}}


def write_vectors():
    for n, data in derived()[0].items():
        (DIR / n).write_bytes(data)
    (DIR / "vectors.json").write_text(json.dumps(vectors(), indent=1) + "\n")


# ── media/1 ──────────────────────────────────────────────────────────────────────

def test_the_committed_vectors_hold():
    files, _ = derived()
    for n, data in files.items():
        assert (DIR / n).read_bytes() == data, n
    assert json.loads((DIR / "vectors.json").read_text()) == json.loads(json.dumps(vectors()))
    assert all((DIR / n).stat().st_size < 100_000 for n in FFMPEG_FILES)


def media(n):
    return pregen.media_hash(DIR / n)


NEST = {b"moov": b"trak", b"trak": b"mdia", b"mdia": b"minf", b"minf": b"stbl"}


def kids(d, s, e):
    out = []
    while s < e:
        size, t = struct.unpack_from(">I4s", d, s)
        h = 8
        if size == 1:
            size, h = struct.unpack_from(">Q", d, s + 8)[0], 16
        elif size == 0:
            size = e - s
        out.append((t, s + h, s + size))
        s += size
    return out


def ref_value(d, t, s, e, mdats):
    out = b""
    for k, cs, ce in kids(d, s, e):
        if NEST.get(t) == k:
            v = ref_value(d, k, cs, ce, mdats)
        elif t == b"stbl" and k in (b"stco", b"co64"):
            w, n = 4 if k == b"stco" else 8, int.from_bytes(d[cs + 4:cs + 8], "big")
            v = d[cs:cs + 4] + i64(n)
            for j in range(n):
                o = int.from_bytes(d[cs + 8 + w * j:cs + 8 + w * j + w], "big")
                m = max(i for i, (a, _) in enumerate(mdats) if a <= o)
                v += i64(m, o - mdats[m][0])
        else:
            v = d[cs:ce]
        out += el(k, v)
    return out


def ref_stream(d):
    """media/1's stream, from the spec, apart from the library and without its checks."""
    top = kids(d, 0, len(d))
    mdats = [(s, e) for t, s, e in top if t == b"mdat"]
    return b"PREGEN-MEDIA\x00media/1\x00" + b"".join(
        el(t, ref_value(d, t, s, e, mdats) if t == b"moov" else d[s:e]) for t, s, e in top
        if not (t == b"uuid" and d[s:s + 16] in (ag._XMP_UUID, ag._C2PA_UUID)))


def ref_hash(d):
    s = ref_stream(d)
    pieces = [s[i:i + (1 << 20)] for i in range(0, len(s), 1 << 20)]
    return {"binding": "media/1", "hash": mth(pieces).hex(), "leaves": len(pieces)}


def test_the_stream_by_hand():
    for n in sorted(set(FFMPEG_FILES) | set(derived()[0])):
        d = (DIR / n).read_bytes()
        try:
            got = H(d)
        except pregen.PregenError:
            continue
        assert got == ref_hash(d), n
    with open(DIR / "c.mp4", "rb") as f:                                    # a file object too
        assert pregen.media_hash(f) == media("c.mp4")
    # pieces of 1 MiB, the last one shorter; a stream of exactly one piece has no empty second one
    big = lambda n: mp4(top=box(b"mdat", bytes(n)))
    exact = (1 << 20) - len(ref_stream(big(0))) % (1 << 20)
    assert len(ref_stream(big(exact))) == 1 << 20
    assert [H(big(3 << 20))["leaves"], H(big(exact))["leaves"], media("a.mp4")["leaves"]] == [4, 1, 1]
    assert H(big(3 << 20)) == ref_hash(big(3 << 20)) and H(big(exact)) == ref_hash(big(exact))


def test_what_keeps_the_hash_and_what_changes_it():
    for n in ("a-xmp.mp4", "a-xmp-foreign-pg.mp4", "a-c2pa-json.mp4", "a-c2pa-cbor.mp4", "a-c2pa-earlier.mp4"):
        assert media(n) == media("a.mp4"), n                                 # the carriers
    a = (DIR / "a.mp4").read_bytes()
    _, p, size = next(b for b in top_boxes(a) if b[0] == b"free")          # ffmpeg's free box before mdat
    assert H(a[:p] + box(b"skip", bytes(size - 8)) + a[p + size:]) != H(a)  # padding is hashed like any box
    f = (DIR / "a-remux-faststart.mp4").read_bytes()                      # moov before mdat: every offset moves
    assert H(insert_after_ftyp(f, c2pa_box(manifest(1)))) == H(f) != H(insert_after_ftyp(f, box(b"free", bytes(3))))
    big = bytearray(mp4())                                                  # a size-0 last box runs to EOF
    struct.pack_into(">I", big, top_boxes(bytes(big))[-1][1], 0)
    assert H(bytes(big)) == H(mp4())
    # a remux, moving the movie box, metadata, any other byte: another hash
    hashes = [media(n)["hash"] for n in ("a.mp4", "a-remux.mp4", "a-remux-faststart.mp4", "a-meta.mp4", "a-flip.mp4")]
    assert len(set(hashes)) == 5
    assert media("b-remux.mov")["hash"] != media("b-remux-faststart.mov")["hash"]
    assert media("a-flip.mp4")["leaves"] == media("a.mp4")["leaves"]


@pytest.mark.skipif(not FFMPEG, reason="ffmpeg not installed")
def test_a_remux_by_ffmpeg_now(tmp_path):
    dst = tmp_path / "out.mp4"
    subprocess.run([FFMPEG, "-v", "error", "-y", "-i", str(DIR / "a-remux.mp4"), "-c", "copy", "-movflags", "+faststart",
                    str(dst)], check=True)
    assert pregen.media_hash(dst)["hash"] != media("a-remux.mp4")["hash"]


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 13])
def test_the_tree_is_rfc_6962(n):
    leaves = [bytes([j]) * j for j in range(n)]
    root, count = ag._root(hashlib.sha256(b"\x00" + x).digest() for x in leaves)
    assert (root, count) == (mth(leaves), n)


def test_the_tree_by_hand():
    l0, l1, l2, l3, l4 = (hashlib.sha256(b"\x00" + bytes([j])).digest() for j in range(5))
    node = lambda a, b: hashlib.sha256(b"\x01" + a + b).digest()
    assert ag._root(iter([l0]))[0] == l0
    assert ag._root(iter([l0, l1]))[0] == node(l0, l1)
    assert ag._root(iter([l0, l1, l2]))[0] == node(node(l0, l1), l2)
    assert ag._root(iter([l0, l1, l2, l3, l4]))[0] == node(node(node(l0, l1), node(l2, l3)), l4)


REFUSALS = [
    ("x-no-moov.mp4", "no moov"), ("x-two-moov.mp4", "more than one moov"), ("x-moof.mp4", "fragmented"),
    ("x-mvex.mp4", "fragmented"), ("x-encv.mp4", "encrypted"), ("x-sinf.mp4", "encrypted"),
    ("x-past-eof.mp4", "outside the data of an mdat"), ("x-box-past-parent.mp4", "past its parent"),
    ("attack-short-uuid.mp4", "shorter than its header"), ("attack-dref-external.mp4", "self-contained"),
    ("attack-dos.mp4", "read by chunk"), ("attack-cmov.mp4", "a second movie"),
    ("attack-top-cmov.mp4", "a second movie"), ("attack-udta-cmov.mp4", "a second movie"),
    ("attack-ftyp-not-first.mp4", "first box is not ftyp"), ("attack-xmp-nul.mp4", "NUL"),
    ("attack-c2pa-not-a-store.mp4", "manifest store"), ("attack-two-c2pa.mp4", "more than one C2PA"),
    ("attack-hoov.mp4", "a second movie"), ("attack-hoov-in-xmp.mp4", "a second movie"),
    ("attack-mpeg-hdlr.mp4", "mhlr MPEG"), ("attack-mpeg-hdlr-in-mdat.mp4", "mhlr MPEG"),
    ("attack-nut.mp4", "NUT startcode"), ("attack-ftyp-jp2.mp4", "major brand"),
    ("attack-chunkmode-meta.mp4", "read by chunk"), ("attack-chunkmode-minf-soun.mp4", "read by chunk"), ("attack-dref-alis.mp4", "self-contained"),
    ("attack-pcm-stsz1.mp4", "read by chunk"), ("attack-offset-in-moov.mp4", "outside the data of an mdat"),
    ("attack-chunk-past-mdat.mp4", "run past"), ("x-stts-stsz.mp4", "count different samples"),
    ("attack-stray-stco.mp4", "stco in trak is not a known box"), ("attack-top-trak.mp4", "stts outside its place"),
    ("attack-top-udta-trak.mp4", "stts outside its place"), ("attack-two-stco.mp4", "two stco"),
    ("attack-stsc-first2.mp4", "stsc"), ("attack-stsc-count0.mp4", "stsc"), ("attack-two-stsz.mp4", "two stsz"),
    ("attack-trak-udta-stco.mp4", "stco in udta is not a known box"), ("attack-free-tables.mp4", "stsz outside its place"),
    ("attack-iloc-meta.mp4", "iloc outside its place"), ("attack-chunkmode-none.mp4", "read by chunk"),
    ("attack-chunkmode-stz2.mp4", "read by chunk"), ("attack-stco-in-entry.mp4", "stco in mp4v is not a known box"),
    ("attack-ilst-short-data.mp4", "data in trkn is not whole"),
    # known boxes only
    ("attack-mdhd-short.mp4", "mdhd in mdia is not whole"), ("attack-dref-count.mp4", "entry count"),
    ("attack-hdlr-in-stbl.mp4", "read by chunk"), ("attack-unknown-box-in-trak.mp4", "xyz1 in trak is not a known box"),
    ("attack-dinf-extra.mp4", "udta in dinf is not a known box"), ("attack-elst-in-udta.mp4", "elst in udta"),
    ("attack-glbl.mp4", "glbl in stbl"), ("attack-st3d-clli.mp4", "in stbl is not a known box"),
    ("attack-two-media-headers.mp4", "one media header"), ("attack-two-tkhd.mp4", "two tkhd"),
    ("attack-udta-mvex-moof.mp4", "mvex in udta")]


@pytest.mark.parametrize("name,why", REFUSALS)
def test_one_reading_only(name, why):
    msg = refused((DIR / name).read_bytes())
    assert msg.startswith("media/1: ") and why in msg


def test_an_apple_writer_mov_hashes():
    """AVAssetWriter's MOV: an empty self-contained alis data reference, a data handler hdlr in minf, and a video
    timescale equal to its frame rate (every duration 1). None of it is a reason to refuse."""
    assert media("apple-writer-ts-fps.mov")["leaves"] == 1
    assert media("dref-alis-empty.mp4")["binding"] == "media/1"


def test_every_byte_a_player_could_read_counts():
    tiny = media("tiny.mp4")["hash"]
    hashed = [n for n in derived()[0] if n.startswith("attack-") and "xmp" not in n and "c2pa" not in n
              and n not in {r[0] for r in REFUSALS}]
    assert len({media(n)["hash"] for n in hashed} | {tiny}) == len(hashed) + 1, hashed   # each its own hash
    assert media("attack-pcm-ok.mp4")["leaves"] == 1
    assert all(media(n)["leaves"] == 1 for n in derived()[0] if n.startswith(("tiny", "dref-", "a-")))


def test_more_refusals():
    assert "past its parent" in refused(mp4() + b"\x00\x00\x00")                       # a trailing partial header
    assert "past its parent" in refused(FTYP + struct.pack(">I4s", 1 << 20, b"mdat"))
    assert "not exactly what its count gives" in refused(mp4(({"stbl": {b"stco": full(b"stco", 0, 0, U(2, DATA_AT))}},)))
    assert "run past" in refused(mp4(({"stbl": HUGE},)))                              # 2^32 samples: at once
    assert "run past" in refused(mp4(({"stbl": {b"stsz": None, b"stz2": full(b"stz2", 0, 0, bytes(3) + b"\x04", U(2),
                                                                              b"\x3f")}},)))     # 3 and 15 bytes
    assert H(mp4(({"stbl": {b"stsz": None, b"stz2": full(b"stz2", 0, 0, bytes(3) + b"\x04", U(2), b"\x32")}},)))
    assert "field size" in refused(mp4(({"stbl": {b"stsz": None, b"stz2": full(b"stz2", 0, 0, bytes(3) + b"\x05", U(0))}},)))
    assert "outside the data" in refused(mp4(({"stbl": {b"stco": None, b"co64": full(b"co64", 0, 0, U(1), struct.pack(">Q", 2**64 - 1))}},)))
    assert "not exactly what its count gives" in refused(mp4(({"stbl": {b"stsc": full(b"stsc", 0, 0, U(2, 1, 2, 1))}},)))
    for stbl in ({b"stts": None}, {b"ctts2": full(b"ctts", 0, 0, U(0)), b"ctts": full(b"ctts", 0, 0, U(0))},
                 {b"stsc": full(b"stsc", 0, 0, U(1, 1, 2, 2))},                                # no sample entry 2
                 {b"stco": full(b"stco", 0, 0, U(2, DATA_AT, DATA_AT + 3))},                    # stsc counts 4 samples
                 {b"stsd": full(b"stsd", 0, 0, U(2), box(b"avc1", bytes(78)))}):
        assert refused(mp4(({"stbl": stbl},))).startswith("media/1: "), stbl
    assert "shorter than its header" in refused(mp4(moov_extra=box(b"uuid", bytes(8))))
    # sound read by chunk: stsz one fixed size, the frame size players take from the entry (and its codec's width)
    v0 = lambda ch, bits: struct.pack(">HHIHH", 0, 0, 0, ch, bits) + bytes(8)
    v1 = lambda ch, spf, bpf: struct.pack(">HHIHH", 1, 0, 0, ch, 16) + bytes(8) + U(spf, bpf, bpf, 2)
    v2 = lambda ch, bpp, fpp: (struct.pack(">HHIHH", 2, 0, 0, 3, 16) + bytes(8) + U(72) + bytes(8)
                               + U(ch, 0x7F000000, 16, 0, bpp, fpp))
    pcmc = full(b"pcmC", 0, 0, b"\x01\x18")                                              # 24 bits a sample
    for t, fields, size, ok in (
            (b"sowt", v0(2, 16), 4, True), (b"twos", v0(1, 8), 1, True), (b"in24", v0(2, 16), 6, True),
            (b"ulaw", v0(1, 16), 1, True), (b"fl64", v0(1, 32), 8, True), (b"ipcm", v0(2, 16) + pcmc, 6, True),
            (b"lpcm", v0(2, 16), 4, False),                                          # no codec width in v0
            (b"in24", v1(1, 1, 3), 3, True), (b"in24", v1(1, 1, 2), 2, False),          # against the codec width
            (b"lpcm", v1(1, 1, 5), 5, True), (b"lpcm", v1(1, 0, 5), 5, False),
            (b"lpcm", v2(1, 6, 1), 6, True), (b"fl32", v2(2, 8, 1), 8, True), (b"fl32", v2(1, 8, 1), 8, False),
            (b"lpcm", v2(1, 6, 0), 6, False), (b"ima4", v1(1, 1, 3), 3, False), (b"NONE", v0(2, 16), 4, False)):
        def pcm(n, hdlr=b"soun"):
            return mp4(({"hdlr": hdlr, "entry": box(t, bytes(6), b"\x00\x01", fields), "samples": (b"x" * size,) * 2,
                         "stbl": CHUNKS(n)},))
        if ok:
            assert H(pcm(size))["leaves"] == 1, t
            assert "read by chunk" in refused(pcm(size + 1)), t
        else:
            assert "read by chunk" in refused(pcm(size)), t
        assert "not whole" in refused(pcm(size, b"vide")), t                  # under vide, its fields are a visual one's
    # not a sound track: read by stsz, its entry as a visual one whatever its four-character code
    assert H(mp4(({"entry": box(b"sowt", bytes(6), b"\x00\x01", bytes(70)), "samples": (b"xyz",) * 2, "stbl": CHUNKS(1)},)))


def esds(dsi=b"\x12\x10", n=None):
    """An ES descriptor: decoder config, its specific info (`n` the length it states), SL config."""
    dec = bytes([0x40, 0x15]) + bytes(11) + bytes([5, len(dsi) if n is None else n]) + dsi
    es = b"\x00\x01\x00" + bytes([4, len(dec)]) + dec + (bytes([6, 1, 2]) if n is None else b"")
    return full(b"esds", 0, 0, bytes([3, len(es)]) + es)


def mp4a(version=0, *boxes):
    fields = struct.pack(">HHIHHHHI", version, 0, 0, 2, 16, 0, 0, 44100 << 16) + (U(1024, 0, 0, 2) if version else b"")
    return box(b"mp4a", bytes(6), b"\x00\x01", fields, *boxes)


WAVE = box(b"wave", box(b"frma", b"mp4a"), box(b"mp4a", bytes(4)), esds(), struct.pack(">I4s", 8, bytes(4)))
MDTA = full(b"meta", 0, 0, full(b"hdlr", 0, 0, U(0), b"mdta", bytes(12), b"\x00"),
            full(b"keys", 0, 0, U(1), struct.pack(">I4s", 12, b"mdta"), b"titl"),
            box(b"ilst", box(U(1), box(b"data", U(1, 0), b"x"))))
KNOWN = [  # trak() arguments, or a box for moov: None when the file hashes, else a part of its refusal
    ({"mdhd": full(b"mdhd", 1, 0, bytes(32))}, None), ({"mdhd": full(b"mdhd", 0, 0, bytes(24))}, "mdhd in mdia is not whole"),
    ({"mdhd": full(b"mdhd", 2, 0, bytes(32))}, "mdhd in mdia is not whole"),
    ({"tref": box(b"edts", full(b"elst", 0, 0, U(2, 20, 0), struct.pack(">hh", 1, 0)))}, "elst in edts is not whole"),
    ({"tref": box(b"edts", full(b"elst", 1, 0, U(1), bytes(20)))}, None),
    ({"stbl": {b"stss": full(b"stss", 0, 0, U(2, 1))}}, "stss in stbl is not whole"),
    ({"stbl": {b"sdtp": full(b"sdtp", 0, 0, b"\x20\x10")}}, None), ({"stbl": {b"sdtp": full(b"sdtp", 0, 0, b"\x20")}}, "sdtp"),
    ({"stbl": {b"sgpd": full(b"sgpd", 1, 0, b"roll", U(2, 1), b"\xff\xff"), b"sbgp": full(b"sbgp", 0, 0, b"roll", U(1, 2, 1))}}, None),
    ({"stbl": {b"sgpd": full(b"sgpd", 0, 0, b"roll", U(1), b"\xff\xff")}}, "sgpd in stbl is not whole"),
    ({"tref": box(b"tref", box(b"chap", U(2) + b"\x00\x01"))}, "chap in tref is not whole"),
    ({"tref": box(b"tref", box(b"stco", U(1)))}, "stco in tref is not a known box"),
    ({"tref": full(b"meta", 0, 0, full(b"hdlr", 0, 0, U(0), b"soun", bytes(12), b"\x00"))}, "soun hdlr in meta"),
    ({"tref": box(b"udta", box(b"\xa9nam", struct.pack(">HH", 9, 0), b"title"))}, "\xa9nam in udta is not whole"),
    ({"tref": box(b"udta", box(b"name", struct.pack(">HH", 5, 0), b"title"), box(b"Xtra", b"x"), box(b"free"))}, None),
    (box(b"udta", full(b"meta", 0, 0, full(b"hdlr", 0, 0, U(0), b"mdir", bytes(12)), box(b"ilst", box(b"stco", box(b"data", U(1, 0), b"x"))))), "stco in ilst"),
    (box(b"udta", full(b"meta", 0, 0, full(b"hdlr", 0, 0, U(0), b"mdir", bytes(12)), box(b"ilst", box(b"\xa9nam", box(b"free"))))), "free in \xa9nam"),
    (box(b"udta", full(b"chpl", 0, 0, b"\x01", bytes(8), b"\x04stco")), "stco outside its place"),   # chapter names are searched
    (box(b"udta", full(b"chpl", 0, 0, b"\x02", bytes(8), b"\x04stco")), "chpl in udta is not whole"),
    (MDTA, None), (MDTA.replace(U(1, 12), U(2, 12)), "keys in meta is not whole"), (box(b"iods", b"x"), None),
    (box(b"wide"), "wide in moov is not a known box"),
    ({"hdlr": b"meta", "entry": mp4a(0, esds())}, None), ({"hdlr": b"soun", "entry": mp4a(1, WAVE, box(b"chan", bytes(16)))}, None),
    ({"hdlr": b"soun", "entry": mp4a(0, esds(n=3))}, "esds in mp4a is not whole"),
    ({"hdlr": b"soun", "entry": mp4a(0, box(b"chan", bytes(12), U(1)))}, "chan in mp4a is not whole"),
    ({"hdlr": b"soun", "entry": mp4a(1, box(b"wave", box(b"frma", b"mp4a"), box(b"mdhd")))}, "mdhd in wave"),
    ({"hdlr": b"meta", "entry": box(b"rtp ", bytes(6), b"\x00\x01")}, "rtp  sample entry under a meta handler"),
    ({"hdlr": b"text", "entry": box(b"tx3g", bytes(6), b"\x00\x01", bytes(30), box(b"ftab", b"\x00\x01\x00\x01\x00"))}, None),
    ({"hdlr": b"tmcd", "entry": box(b"tmcd", bytes(6), b"\x00\x01", bytes(18), bytes(2))}, None),
    ({"hdlr": b"vide", "entry": box(b"tx3g", bytes(6), b"\x00\x01", bytes(30))}, "tx3g in stsd is not whole"),  # read as visual
    ({"entry": box(b"avc1", bytes(6), b"\x00\x01", bytes(70), box(b"pasp", U(1, 1)), bytes(4))}, None),   # QuickTime's 0
    ({"entry": box(b"avc1", bytes(6), b"\x00\x01", bytes(70), box(b"pasp", U(1, 1)), U(1))}, "past its parent"),
    ({"entry": box(b"avc1", bytes(6), b"\x00\x01", bytes(70), box(b"abcd"))}, "abcd in avc1 is not a known box"),
    ({"entry": box(b"avc1", bytes(6), b"\x00\x01", bytes(66), struct.pack(">HH", 8, 0))}, "palette"),
    ({"entry": box(b"avc1", bytes(6), b"\x00\x02", bytes(70))}, "names no entry"),
    ({"stbl": {b"stsd": full(b"stsd", 0, 0, U(2), AVC1, AVC1.replace(b"avc1", b"hvc1"))}}, "more than one format"),
    ({"dinf": b""}, "minf without its dinf"), ({"mhd": b""}, "one media header"),
    ({"dinf": box(b"dinf", full(b"dref", 0, 0, U(0)))}, "entry count"),
]


@pytest.mark.parametrize("change,why", KNOWN)
def test_known_boxes_only(change, why):
    data = mp4((change,)) if isinstance(change, dict) else mp4(moov_extra=change)
    if why is None:
        assert H(data)["leaves"] == 1
    else:
        assert why in refused(data)


def test_metadata_text_is_read_as_text():
    assert media("tiny-title-stco.mp4")["leaves"] == 1
    assert "stco outside its place" in refused(mp4(moov_extra=TITLED.replace(b"\xa9nam", b"name", 1)))   # not a text atom


# ── read_after_gen and embed_xmp ────────────────────────────────────────────────

def test_read_the_vector_files():
    rec = derived()[1]
    rid, codes = pregen.message_id("pg.after_gen.v1", rec["body"]), pregen.after_gen_codes(rec)
    got = {r["file"]: r for r in json.loads((DIR / "vectors.json").read_text())["read"]}
    assert got["a-xmp.mp4"] == {"file": "a-xmp.mp4", "c2pa": None, "xmp": rid, "codes": codes, "check": {"xmp": rid}}
    assert codes["Code"].startswith("TOG-AG-LIC-TEST-") and codes["Licence"].startswith("TOG-LIC-TEST-")
    assert got["a-xmp-terms.mp4"]["codes"]["Code"].startswith("TOG-AG-TEST-") and \
        len(got["a-xmp-terms.mp4"]["codes"]) == 1 and len(got["a-xmp-terms.mp4"]["check"]["xmp"]) == 64
    for n in ("a-xmp-code-symbol.mp4", "a-xmp-code-other.mp4", "a-xmp-code-ag.mp4", "a-xmp-licence-is-code.mp4",
              "a-xmp-terms-licence.mp4"):
        assert got[n]["check"] == {"xmp": "the readable code does not match the record"}, n
    for n in ("attack-xmp-code-twice.mp4", "attack-xmp-code-attribute.mp4"):     # the packet carries no record
        assert (got[n]["xmp"], got[n]["codes"], got[n]["check"]) == (None, {}, {}), n
    assert got["a-c2pa-json.mp4"]["c2pa"] == rid and got["a-c2pa-cbor.mp4"]["c2pa"] == rid     # the last manifest wins
    assert got["a-c2pa-earlier.mp4"]["c2pa"] is None
    assert got["a-xmp-foreign.mp4"]["xmp"] is None and got["a-xmp-foreign-pg.mp4"]["xmp"] == rid
    assert got["b-copied-record.mov"]["check"] == {"xmp": "not for this file"}               # vector 6


def test_embed_xmp_round_trip(tmp_path):
    rec = record(media("a.mp4"))
    pregen.embed_xmp(DIR / "a.mp4", tmp_path / "x.mp4", rec)
    data = (tmp_path / "x.mp4").read_bytes()
    assert data.startswith((DIR / "a.mp4").read_bytes()) and media("a.mp4") == pregen.media_hash(tmp_path / "x.mp4")
    assert pregen.read_after_gen(tmp_path / "x.mp4") == {"c2pa": None, "xmp": rec, "codes": {"Licence": LIC_CODE}}
    packet = data[len((DIR / "a.mp4").read_bytes()) + 24:]
    rid = pregen.message_id("pg.after_gen.v1", rec["body"])
    assert b"<pgag:Code>" not in packet                         # this record's code cannot be formed: none is written
    for part in (f"<pgag:Id>{rid}</pgag:Id>", "<pgag:Registry>TEST</pgag:Registry>",
                 'xmlns:pgag="https://pregen.org/ns/after-gen/1/"'):
        assert part.encode() in packet
    assert b"pgag:Status" not in packet          # the record names no status address (The status)
    # again: the last box is rewritten in place, never turned into padding
    pregen.embed_xmp(tmp_path / "x.mp4", tmp_path / "y.mp4", rec)
    assert (tmp_path / "y.mp4").read_bytes() == data
    rec = coded(media("a.mp4"))                                 # a record as a registry signs it: both codes written
    pregen.embed_xmp(DIR / "a.mp4", tmp_path / "x.mp4", rec)
    got = pregen.read_after_gen(tmp_path / "x.mp4")
    assert got == {"c2pa": None, "xmp": rec, "codes": pregen.after_gen_codes(rec)}
    assert check(got["xmp"], media("a.mp4"), codes=got["codes"])["id"] == pregen.message_id("pg.after_gen.v1", rec["body"])
    rec = coded(media("a.mp4"), basis=TERMS)                    # under the person's terms: the approval's code only
    pregen.embed_xmp(DIR / "a.mp4", tmp_path / "x.mp4", rec)
    assert pregen.read_after_gen(tmp_path / "x.mp4")["codes"] == {"Code": pregen.after_gen_codes(rec)["Code"]}
    assert b"pgag:Licence" not in (tmp_path / "x.mp4").read_bytes()


def test_embed_xmp_keeps_existing_properties(tmp_path):
    rec = coded(media("a.mp4"))
    pregen.embed_xmp(DIR / "a-xmp-foreign.mp4", tmp_path / "x.mp4", rec)
    x = (tmp_path / "x.mp4").read_bytes()
    assert x == (DIR / "a-xmp-foreign-pg.mp4").read_bytes()
    assert b"Spring &lt;cut&gt;" in x and b'xml:lang="x-default"' in x and b'xmp:CreatorTool="Studio &amp; Co"' in x
    assert pregen.read_after_gen(tmp_path / "x.mp4")["xmp"] == rec
    a = (DIR / "a.mp4").read_bytes()                                       # the last box in the 64-bit form keeps it
    (tmp_path / "w.mp4").write_bytes(a + struct.pack(">I4sQ", 1, b"uuid", 32 + len(FOREIGN_XMP)) + ag._XMP_UUID + FOREIGN_XMP)
    pregen.embed_xmp(tmp_path / "w.mp4", tmp_path / "x.mp4", rec)
    new = ag._packet(FOREIGN_XMP, rec)
    assert (tmp_path / "x.mp4").read_bytes() == a + struct.pack(">I4sQ", 1, b"uuid", 32 + len(new)) + ag._XMP_UUID + new
    # an XMP box that is not the last: rewritten in place, padded with spaces before its trailer; refused if too small
    room = FOREIGN_XMP.replace(b"<?xpacket end", b" " * 2000 + b"<?xpacket end")
    for packet, fits in ((room, True), (FOREIGN_XMP, False)):
        src, n = insert_after_ftyp(a, xmp_box(packet)), top_boxes(a)[0][2]   # chunk offsets moved, as a tool would
        (tmp_path / "v.mp4").write_bytes(src)
        if not fits:
            with pytest.raises(pregen.PregenError, match="does not fit"):
                pregen.embed_xmp(tmp_path / "v.mp4", tmp_path / "u.mp4", rec)
            continue
        pregen.embed_xmp(tmp_path / "v.mp4", tmp_path / "u.mp4", rec)
        u = (tmp_path / "u.mp4").read_bytes()
        assert len(u) == len(src) and u[:n + 24] == src[:n + 24] and u[n + len(xmp_box(room)):] == src[n + len(xmp_box(room)):]
        assert pregen.read_after_gen(io.BytesIO(u))["xmp"] == rec and H(u) == media("a.mp4") and b"  <?xpacket end" in u


def test_embed_xmp_refusals(tmp_path):
    a = media("a.mp4")
    for packet in (FOREIGN_XMP.replace(b"<rdf:Description", b"<!-- kept? --><rdf:Description"),
                   FOREIGN_XMP.replace(b"Studio &amp; Co", b"pgag:Record=x")):          # it could not be kept under the rule
        (tmp_path / "old.mp4").write_bytes((DIR / "a.mp4").read_bytes() + xmp_box(packet))
        with pytest.raises(pregen.PregenError, match="^xmp: "):
            pregen.embed_xmp(tmp_path / "old.mp4", tmp_path / "x.mp4", record(a))
        assert not (tmp_path / "x.mp4").exists()
    with pytest.raises(pregen.PregenError, match="not for this file"):
        pregen.embed_xmp(DIR / "b.mov", tmp_path / "x.mov", record(a))
    assert not (tmp_path / "x.mov").exists()
    with pytest.raises(pregen.PregenError, match="another file"):
        pregen.embed_xmp(DIR / "a.mp4", DIR / "a.mp4", record(a))
    with pytest.raises(pregen.PregenError, match="envelope"):
        pregen.embed_xmp(DIR / "a.mp4", tmp_path / "x.mp4", {"type": "pg.answer.v1", "body": {}})
    two = tmp_path / "two.mp4"
    two.write_bytes((DIR / "a-xmp-foreign.mp4").read_bytes() + xmp_box(FOREIGN_XMP))
    with pytest.raises(pregen.PregenError, match="more than one XMP"):
        pregen.embed_xmp(two, tmp_path / "x.mp4", record(a))


def test_embed_xmp_writes_the_size_of_a_last_box_that_runs_to_the_end(tmp_path):
    data = bytearray((DIR / "a.mp4").read_bytes())                         # a.mp4 ends with its moov
    struct.pack_into(">I", data, top_boxes(bytes(data))[-1][1], 0)
    (tmp_path / "z.mp4").write_bytes(bytes(data))
    rec = record(media("a.mp4"))
    pregen.embed_xmp(tmp_path / "z.mp4", tmp_path / "x.mp4", rec)
    assert (tmp_path / "x.mp4").read_bytes().startswith((DIR / "a.mp4").read_bytes())
    assert pregen.read_after_gen(tmp_path / "x.mp4")["xmp"] == rec


def read(data):
    return pregen.read_after_gen(io.BytesIO(data))


def test_c2pa_reading():
    rec, a = record(media("a.mp4")), (DIR / "a.mp4").read_bytes()
    assert read(insert_after_ftyp(a, c2pa_box(manifest(1, assertion(rec, "cbor")))))["c2pa"] == rec
    assert read(a + c2pa_box(manifest(1, assertion(rec)), purpose=b"merkle")) == {"c2pa": None, "xmp": None, "codes": {}}
    assert read(a + c2pa_box(manifest(1, assertion(rec, label="org.pregen.after_gen.v2"))))["c2pa"] is None
    assert pregen.c2pa_assertion(rec) == {"label": "org.pregen.after_gen", "data": rec}


MALFORMED_C2PA = [
    ("two stores", lambda r: c2pa_box(manifest(1, assertion(r))) + c2pa_box(manifest(1))),
    ("jumb without jumd", lambda r: c2pa_box(box(b"jumb", box(b"json", b"{}")))),
    ("label without NUL", lambda r: c2pa_box(manifest(1, box(b"jumb", box(b"jumd", bytes(16), b"\x03org.pregen.after_gen"),
                                                         box(b"json", b"{}"))))),
    ("not a store", lambda r: box(b"uuid", ag._C2PA_UUID, bytes(4), b"manifest\x00", bytes(8), jumb("c2pa.x", manifest(1)))),
    ("empty store", lambda r: box(b"uuid", ag._C2PA_UUID, bytes(4), b"manifest\x00", bytes(8), jumb("c2pa"))),
    ("no purpose end", lambda r: box(b"uuid", ag._C2PA_UUID, bytes(4), b"manifest")),
    ("two assertions", lambda r: c2pa_box(manifest(1, assertion(r), assertion(r, label="org.pregen.after_gen__1")))),
    ("two content boxes", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"json", b"{}"), box(b"json", b"{}"))))),
    ("bad JSON", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"json", b"{\"a\":1,\"a\":2}"))))),
    ("JSON array", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"json", b"[]"))))),
    ("CBOR float", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"cbor", b"\xa1\x61a\xf9\x3c\x00"))))),
    ("CBOR tag", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"cbor", b"\xc1\x00"))))),
    ("CBOR bytes", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"cbor", b"\xa1\x61a\x41\x00"))))),
    ("CBOR indefinite", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"cbor", b"\xbf\xff"))))),
    ("CBOR trailing", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"cbor", b"\xa0\x00"))))),
    ("CBOR short", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"cbor", b"\xa1\x61"))))),
    ("CBOR int key", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"cbor", b"\xa1\x01\x01"))))),
    ("CBOR dup key", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"cbor", b"\xa2\x61a\x01\x61a\x02"))))),
    ("CBOR deep", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"cbor", b"\x81" * 100 + b"\xa0"))))),
    ("jumd past parent", lambda r: c2pa_box(box(b"jumb", struct.pack(">I4s", 99, b"jumd")))),
    ("malformed older manifest", lambda r: c2pa_box(jumb("urn:old", box(b"jumb", box(b"free"))), manifest(2, assertion(r)))),
    ("nested superbox", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"json", pregen.canonical_json(r)),
                                                            jumb("x"))))),
    ("JUMBF 70 deep", lambda r: c2pa_box(deep_jumb(70))),
    ("JSON with spaces", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"json", json.dumps(r).encode()))))),
    ("JSON with a BOM", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"json", b"\xef\xbb\xbf" + pregen.canonical_json(r)))))),
    ("JSON in UTF-16", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"json", pregen.canonical_json(r).decode().encode("utf-16")))))),
    ("JSON with NaN", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"json", pregen.canonical_json(r)[:-1] + b',"x":NaN}'))))),
    ("JSON key twice", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"json", b'{"a":1,"a":1}'))))),
    ("CBOR beyond 2^53", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"cbor", cbor({**r, "x": 2**53})))))),
    ("CBOR below -2^53", lambda r: c2pa_box(manifest(1, jumb("org.pregen.after_gen", box(b"cbor", cbor({**r, "x": -2**53})))))),
]


def deep_jumb(n):
    return jumb("c2pa") if n == 0 else box(b"jumb", jumd("x"), deep_jumb(n - 1))


@pytest.mark.parametrize("name,make", MALFORMED_C2PA, ids=[m[0] for m in MALFORMED_C2PA])
def test_malformed_c2pa_is_refused(name, make):
    with pytest.raises(pregen.PregenError, match="^c2pa: "):
        read((DIR / "a.mp4").read_bytes() + make(record(media("a.mp4"))))


def test_xmp_by_the_lexical_rule_only():
    a, rec = (DIR / "a.mp4").read_bytes(), record(media("a.mp4"))
    good = ag._packet(None, rec)
    text = good[good.index(b"<pgag:Record>") + 13:good.index(b"</pgag:Record>")]
    assert read(a + xmp_box(good))["xmp"] == rec
    assert read(a + xmp_box(good.replace(b"<rdf:RDF", b"<rdf:RDF\n")))["xmp"] == rec         # no XML is parsed
    for packet in (good.replace(b"</rdf:RDF>", b"<!-- -->"), good.replace(text, b"<![CDATA[" + text + b"]]>"),
                   b"<!DOCTYPE x>" + good, good.replace(b"<x:", b'<!ENTITY a "b"><x:', 1),
                   good.replace(b"xmlns:pgag=", b'xmlns:pgag="https://x.example/" xmlns:pg2='),     # another pgag binding
                   good.replace(b'xmlns:pgag="', b"xmlns:pgag='").replace(b'/1/"', b"/1/'"),       # the declaration as written
                   good.replace(b"<pgag:Record>", b"<pgag:Record >").replace(b"</pgag:Record>", b"</pgag:Record >"),
                   good.replace(b"</rdf:RDF>", b"<pgag:Record>x</pgag:Record></rdf:RDF>"),         # twice
                   good.replace(b"<pgag:Id>", b'<pgag:Id pgag:Record="x">'),
                   good.replace(b"</pgag:Record>", b"<x/></pgag:Record>"), good.replace(text, text.replace(b'"', b"&#34;", 1)),
                   good.replace(text, b"&amp;" + text), good.replace(b"<pgag:Record>", b"<pgag:Record> "),  # not canonical
                   good.replace(text, b"[1]"), good.replace(b"<pgag:Record>", b"<pg:Record>").replace(b"</pgag:R", b"</pg:R"),
                   good.decode().encode("utf-16"), b"<x:xmpmeta",
                   good.replace(b"<x:xmpmeta", b"<?note <pgag:Record>[1]</pgag:Record> ?><x:xmpmeta", 1),   # another <?
                   good.replace(b'?><x:', b'?><?xpacket begin="" id="x"?><x:', 1),                         # two begins
                   good.replace(b"</rdf:RDF>", b'<rdf:Description xmlns:p2="https://pregen.org/ns/after-gen/1/"/></rdf:RDF>')):
        assert read(a + xmp_box(packet))["xmp"] is None, packet[:60]
    with pytest.raises(pregen.PregenError, match="more than one XMP"):
        read(a + xmp_box(good) + xmp_box(good))


def test_the_codes_in_xmp_by_the_same_rule(tmp_path):
    a, rec = (DIR / "a.mp4").read_bytes(), coded(media("a.mp4"))
    code, lic = pregen.after_gen_codes(rec).values()
    good = ag._packet(None, rec)
    assert read(a + xmp_box(good)) == {"c2pa": None, "xmp": rec, "codes": {"Code": code, "Licence": lic}}
    assert read(a + xmp_box(with_codes(rec, Code=None, Licence=None)))["codes"] == {}            # a copy may be missing
    assert read(a + xmp_box(with_codes(rec, Code="A&amp;B&lt;")))["codes"]["Code"] == "A&B<"    # the five entities
    assert read(a + xmp_box(with_codes(rec, Code="")))["codes"]["Code"] == ""
    tag = f"<pgag:Code>{code}</pgag:Code>".encode()
    for packet in (good.replace(tag, tag * 2),                                                  # twice
                   good.replace(b"</rdf:RDF>", b"<rdf:Description>" + tag + b"</rdf:Description></rdf:RDF>"),
                   good.replace(tag, b"").replace(b"<rdf:Description", f'<rdf:Description pgag:Code="{code}"'.encode()),
                   good.replace(b"<pgag:Id>", b'<pgag:Id pgag:Licence="x">'),                  # an attribute form
                   good.replace(tag, tag.replace(b"</pgag:Code>", b"<x/></pgag:Code>")),       # not text only
                   good.replace(tag, tag.replace(b"<pgag:Code>", b"<pgag:Code>&#84;")),        # another entity
                   good.replace(tag, tag.replace(b"</pgag:Code>", b"")),                       # no end tag
                   good.replace(tag, tag.replace(b"<pgag:Code>", b"<pgag:Code>\xff"))):        # not UTF-8
        assert read(a + xmp_box(packet)) == {"c2pa": None, "xmp": None, "codes": {}}, packet[-300:]
    spells = coded(media("a.mp4"), scope={**SCOPE, "project": "pgag:Code=x"})   # a record that spells the attribute
    with pytest.raises(pregen.PregenError, match="^xmp: "):
        pregen.embed_xmp(DIR / "a.mp4", tmp_path / "x.mp4", spells)


# the ToG code design's printed examples: the TOG check table (I L O U = 32-35), every kind digit, one and two prefixes
TOG_EVENTS = [("403PRAM", "TOG-AG-PRAM-ZZZZ-T8JE-WDJX"), ("444NWRDPRAM", "TOG-AG-LIC-NWRD-PRAM-ZZZZ-ZJGH-HQH3"),
              ("405PRAM", "TOG-LIC-PRAM-ZZZZ-QH28-TDQ8"), ("405OMNI", "TOG-LIC-OMNI-ZZZZ-EKC0-Z18T"),
              ("405KAST", "TOG-LIC-KAST-ZZZZ-FJ4Y-SM2N"), ("401TGOV", "TOG-PG-TGOV-ZZZZ-DHMW-8C2S"),
              ("402VELR", "TOG-PG-LIC-VELR-ZZZZ-Q4VE-P7E4"), ("442NWRDPRAM", "TOG-PG-LIC-NWRD-PRAM-ZZZZ-VGDY-WCWV"),
              ("645KOBEMKPRAM", "TOG-LIC-KOBEMK-PRAM-ZZZZ-BYAV-K2AQ"), ("445NWRDSKAN", "TOG-LIC-NWRD-SKAN-ZZZZ-37NF-0EAS")]
TOG_PERSONS = ["TOG-PRAM-900000037K", "TOG-OMNI-9000000055", "TOG-KINO-900000007B", "TOG-TGOV-9000001014"]


def test_the_tog_check_on_the_design_examples():
    for head, code in TOG_EVENTS:
        tail = code[-14:].replace("-", "")
        assert ag._tog_check(head + tail[:-1]) == tail[-1], code
        assert ag._tog_check(head + tail[:-2] + ("0" if tail[-2] != "0" else "1")) != tail[-1], code
    for code in TOG_PERSONS:
        prefix, serial = code[4:8], code[9:]
        assert ag._tog_check(prefix + serial[:-1]) == serial[-1], code
    assert ag._tog_check("PRAMIL") != ag._tog_check("PRAM11")       # I and L are not 1: their own values


LIC_CODE = "TOG-LIC-TEST-XVQE-XVQE-XVQY"      # basis.licence.id "e" * 64: the tail of 0xeee..., then the check


def test_the_readable_codes():
    rec = coded(a())
    rid = pregen.message_id("pg.after_gen.v1", rec["body"])
    code, lic = pregen.after_gen_codes(rec).values()
    tail = "".join("0123456789ABCDEFGHJKMNPQRSTVWXYZ"[int(f"{int(rid, 16):0256b}"[i:i + 5], 2)] for i in range(0, 55, 5))
    assert code == "TOG-AG-LIC-TEST-" + "-".join(((tail + code[-1])[i:i + 4]) for i in (0, 4, 8)) and lic == LIC_CODE
    assert code[-1] == ag._tog_check("404TEST" + tail) and LIC_CODE[-1] == ag._tog_check("405TEST" + "XVQEXVQEXVQ")
    terms = coded(a(), basis=TERMS)
    assert pregen.after_gen_codes(terms)["Code"].startswith("TOG-AG-TEST-") and pregen.after_gen_codes(terms)["Licence"] is None
    # none where a code does not exist: a check * ~ $ = !, a tail starting ZZZZ, no prefix
    plain = record(a())                                        # issued_at NOW - 100: its check would be a symbol
    pid = pregen.message_id("pg.after_gen.v1", plain["body"])
    ptail = "".join("0123456789ABCDEFGHJKMNPQRSTVWXYZ"[int(f"{int(pid, 16):0256b}"[i:i + 5], 2)] for i in range(0, 55, 5))
    assert ag._tog_check("404TEST" + ptail) in "*~$=!" and pregen.after_gen_codes(plain)["Code"] is None
    assert ag._tog_code("AG", "TEST", "f" * 64) is None and ag._tog_code("LIC", "TEST", "f" * 64) is None   # ZZZZ...
    assert ag._tog_code("AG", "", rid) is None and ag._tog_code("AG", "TEST", "e" * 63) is None
    bare = {**rec, "body": {**rec["body"], "subject_ref": "PG-000042*"}}
    codes = pregen.after_gen_codes(bare)                                       # the bare namespace is PRAMPTA's
    assert codes["Code"].startswith("TOG-AG-LIC-PRAM-") and codes["Licence"].startswith("TOG-LIC-PRAM-")
    for broken in (None, {}, {"body": []}, {"body": {"subject_ref": "x"}}, {**rec, "body": {**rec["body"], "basis": 1}}):
        assert pregen.after_gen_codes(broken)["Licence"] is None
    assert pregen.after_gen_codes({**rec, "body": {**rec["body"], "basis": {"kind": "licence", "licence": "x"}}})[
        "Licence"] is None


def test_the_copies_must_be_the_codes_of_the_record():
    rec, terms = coded(a()), coded(a(), basis=TERMS)
    code, lic = pregen.after_gen_codes(rec).values()
    rid = pregen.message_id("pg.after_gen.v1", rec["body"])
    for codes in ({"Code": code, "Licence": lic}, {"Code": code}, {"Licence": lic}, {}, None):
        assert check(rec, a(), codes=codes)["id"] == rid                                  # a missing copy is fine
    assert check(terms, codes={"Code": pregen.after_gen_codes(terms)["Code"]})["basis"] == TERMS
    other = pregen.after_gen_codes(coded(a(), issued_at=NOW - 50))["Code"]
    changed = code[:-2] + ("0" if code[-2] != "0" else "1") + code[-1]
    plain = record(a())                                                                 # its code cannot be formed
    for env, codes, why in ((rec, {"Code": changed}, "one symbol changed"),
                            (rec, {"Code": other}, "another record's code"),
                            (rec, {"Code": relabel(code, "AG")}, "AG in place of AG-LIC"),
                            (rec, {"Licence": code}, "the approval's code as the licence's"),
                            (rec, {"Licence": relabel(lic, "AG")}, "a licence copy with AG in place of LIC"),
                            (rec, {"Code": code.lower()}, "lower case: one spelling"),
                            (rec, {"Code": code, "Licence": changed}, "one of two copies"),
                            (rec, {"Code": code, "Other": code}, "a copy of nothing"),
                            (terms, {"Licence": lic}, "a licence copy under a terms basis"),
                            (terms, {"Code": relabel(pregen.after_gen_codes(terms)["Code"], "AG-LIC")}, "AG-LIC under terms"),
                            (plain, {"Code": "TOG-AG-LIC-TEST-0000-0000-0000"}, "a copy whose code cannot be formed")):
        assert other != code
        with pytest.raises(pregen.PregenError, match="^the readable code does not match the record$"):
            check(env, codes=codes)


# ── check_after_gen ─────────────────────────────────────────────────────────────

A = None


def a():
    global A
    A = A or media("a.mp4")
    return A


def test_a_valid_record():
    rec = record(a())
    s = check(rec, a())
    assert s == {"id": pregen.message_id("pg.after_gen.v1", rec["body"]), "subject_ref": CODE, "prefix": "TEST",
                 "label": pregen.AFTER_GEN_LABEL, "notice": pregen.AFTER_GEN_NOTICE, "not": pregen.AFTER_GEN_NOT,
                 "holder": "https://studio.example", "basis": BASIS, "scope": SCOPE,
                 "approval": APPROVAL, "approved_by": "approved on the person's own instruction at the registry",
                 "status_url": API + pregen.message_id("pg.after_gen.v1", rec["body"]), "issued_at": NOW - 100,
                 "content": rec["body"]["content"],
                 "file_match": True}
    assert check(rec)["file_match"] is None and check(rec, a()["hash"])["file_match"] is True
    assert check(record(a(), approval={"assent": "self", "decision": "c" * 64}))["approved_by"] == "approved by the person"
    assert check(record(a(), approval={"assent": "registry", "instruction": "c" * 64, "factor": "email"}))["approved_by"] \
        == "approved on the person's own instruction at the registry"
    assert check(record(a(), basis={**BASIS, "use": {"n": 1, "of": None}},
                        scope={**SCOPE, "categories": [], "territories": ["*"], "channels": ["*"]}))
    # the person's own terms: no licence, so not_after is bounded by issued_at only
    assert check(record(a(), basis=TERMS, scope={**SCOPE, "not_after": NOW + 10**9}))["basis"] == TERMS


def nested(member, **extra):
    return {**record(a())["body"][member], **extra}


MUTATIONS = [                                                 # vectors 7, 9, 13 and the approval forms (1-5 in part)
    ("label", {"label": "Approved after generation"}, "constants"),
    ("notice", {"notice": pregen.AFTER_GEN_NOTICE + " "}, "constants"),
    ("not", {"not": ["pre_generation_permission"]}, "constants"),
    ("not order", {"not": ["statement_of_origin", "pre_generation_permission"]}, "constants"),
    ("kind", {"kind": "release"}, "ratification"),
    ("unknown top", {"origin": "ai"}, "exactly the members"),
    ("missing", {"request": DROP}, "exactly the members"),
    ("unknown in scope", {"scope": {**SCOPE, "x": 1}}, "scope: exactly"),
    ("unknown in approval", {"approval": {**APPROVAL, "x": 1}}, "approval \\(registry\\): exactly"),
    ("unknown in content", {"content": "X"}, "content: exactly"),
    ("unknown in use", {"basis": {**BASIS, "use": {"n": 1, "of": 2, "x": 1}}}, "use: exactly"),
    ("unknown in licence", {"basis": {**BASIS, "licence": {**BASIS["licence"], "x": 1}}}, "licence: exactly"),
    ("unknown basis kind", {"basis": {**TERMS, "kind": "grant"}}, "basis.kind"),
    ("basis kind as a list", {"basis": {**TERMS, "kind": ["terms"]}}, "basis.kind"),
    ("basis without kind", {"basis": {k: v for k, v in BASIS.items() if k != "kind"}}, "basis.kind"),
    ("basis a string", {"basis": "f" * 64}, "basis.kind"),
    ("extra member in licence basis", {"basis": {**BASIS, "x": 1}}, "basis \\(licence\\): exactly"),
    ("extra member in terms basis", {"basis": {**TERMS, "x": 1}}, "basis \\(terms\\): exactly"),
    ("licence basis without use", {"basis": {k: v for k, v in BASIS.items() if k != "use"}}, "basis \\(licence\\)"),
    ("licence basis without licence", {"basis": {k: v for k, v in BASIS.items() if k != "licence"}}, "basis \\(licence\\)"),
    ("terms basis without terms", {"basis": {"kind": "terms"}}, "basis \\(terms\\)"),
    ("licence basis with a terms member", {"basis": {**BASIS, "terms": "f" * 64}}, "basis \\(licence\\)"),
    ("terms basis with licence and use", {"basis": {**TERMS, "licence": BASIS["licence"], "use": BASIS["use"]}},
     "basis \\(terms\\)"),
    ("terms not hex", {"basis": {**TERMS, "terms": "F" * 64}}, "basis.terms"),
    ("terms short", {"basis": {**TERMS, "terms": "f" * 63}}, "basis.terms"),
    ("terms an object", {"basis": {**TERMS, "terms": BASIS["licence"]}}, "basis.terms"),
    ("licence and use at the top", {"basis": DROP, "licence": BASIS["licence"], "use": BASIS["use"]},
     "exactly the members"),
    ("unknown in signer", {"signers": [{**signer(KEY)[0], "x": 1}]}, "signer"),
    ("binding", {"content": "sha256"}, "media/1"),
    ("hash", {"content": "upper"}, "media/1"),
    ("licence format", {"basis": {**BASIS, "licence": {"format": "pg.terms.v1", "id": "e" * 64}}}, "pg.grant.v1"),
    ("use n", {"basis": {**BASIS, "use": {"n": 0, "of": 10}}}, "use: n"),
    ("use over", {"basis": {**BASIS, "use": {"n": 11, "of": 10}}}, "use: n"),
    ("intimate", {"scope": {**SCOPE, "categories": ["advertising", "sexual"]}}, "intimate"),
    ("adult", {"scope": {**SCOPE, "categories": ["adult"]}}, "intimate"),
    ("outside vocabulary", {"scope": {**SCOPE, "categories": ["Advertising"]}}, "closed vocabulary"),
    ("unsorted categories", {"scope": {**SCOPE, "categories": ["fashion", "advertising"]}}, "closed vocabulary"),
    ("unsorted territories", {"scope": {**SCOPE, "territories": ["IT", "ES"]}}, "territories"),
    ("repeated channel", {"scope": {**SCOPE, "channels": ["social", "social"]}}, "channels"),
    ("empty purposes", {"scope": {**SCOPE, "purposes": []}}, "purposes"),
    ("unknown purpose", {"scope": {**SCOPE, "purposes": ["promotional"]}}, "purposes"),
    ("bad territory", {"scope": {**SCOPE, "territories": ["es"]}}, "territories"),
    ("territory and star", {"scope": {**SCOPE, "territories": ["*", "ES"]}}, "territories"),
    ("empty channels", {"scope": {**SCOPE, "channels": []}}, "channels"),
    ("long channel", {"scope": {**SCOPE, "channels": ["a" * 33]}}, "channels"),
    ("empty project", {"scope": {**SCOPE, "project": ""}}, "project"),
    ("long project", {"scope": {**SCOPE, "project": "x" * 201}}, "project"),
    ("control in project", {"scope": {**SCOPE, "project": "a‍b"}}, "control"),
    ("not_after", {"scope": {**SCOPE, "not_after": "soon"}}, "not_after"),
    ("self with factor", {"approval": {"assent": "self", "decision": "c" * 64, "factor": "email"}}, "approval \\(self\\)"),
    ("registry without factor", {"approval": {"assent": "registry", "instruction": "c" * 64}}, "approval \\(registry\\)"),
    ("registry factor", {"approval": {"assent": "registry", "instruction": "c" * 64, "factor": "sms"}}, "second factor"),
    ("an approval under a mandate", {"approval": AGENT}, "self or registry"),
    ("agent with registry's members", {"approval": {**APPROVAL, "assent": "agent"}}, "self or registry"),
    ("agent with self's members", {"approval": {"assent": "agent", "decision": "c" * 64}}, "self or registry"),
    ("unknown assent", {"approval": {"assent": "holder", "decision": "c" * 64}}, "self or registry"),
    ("holder", {"holder": "studio.example"}, "provider URL"),
    ("request", {"request": "A" * 64}, "request"),
    ("status_url member", {"status_url": API + "a" * 64}, "member"),
    ("assent as a list", {"approval": {**APPROVAL, "assent": ["registry"]}}, "self or registry"),
    ("territories nested", {"scope": {**SCOPE, "territories": [["ES"]]}}, "territories"),
    ("channels nested", {"scope": {**SCOPE, "channels": [["social"]]}}, "channels"),
    ("251 territories", {"scope": {**SCOPE, "territories": sorted(a + b for a in "ABCDEFGHIJ" for b in "ABCDEFGHIJKLMNOPQRSTUVWXYZ")[:251]}},
     "territories"),
    ("65 channels", {"scope": {**SCOPE, "channels": [f"c{j:02d}" for j in range(65)]}}, "channels"),
    ("not_after at issued_at", {"scope": {**SCOPE, "not_after": NOW - 100}}, "later than issued_at"),
    ("holder with an empty port", {"holder": "https://studio.example:"}, "provider URL"),
    ("holder with port 0", {"holder": "https://studio.example:0"}, "provider URL"),
]


def test_caps_and_ports_that_hold():
    assert check(record(a(), scope={**SCOPE, "territories": sorted(a + b for a in "ABCDEFGHIJ" for b in "ABCDEFGHIJKLMNOPQRSTUVWXYZ")[:250],
                                     "channels": [f"c{j:02d}" for j in range(64)]}, holder="https://studio.example:8443"))


def test_a_malformed_type_anywhere_is_a_pregen_error():
    body = record(a())["body"]
    paths = [(k,) for k in body] + [(k, j) for k in body if isinstance(body[k], dict) for j in body[k]]
    for path in paths:
        for odd in ([], {}, [[]], [{}], ["x"], ["agent"], None, True, "x", 0, 2**60):
            b = json.loads(json.dumps(body))
            (b if len(path) == 1 else b[path[0]])[path[-1]] = odd
            try:
                env = pregen.sign_envelope("pg.after_gen.v1", b, KEY)
            except pregen.PregenError:
                continue
            try:
                check(env, a())
            except pregen.PregenError:
                pass


@pytest.mark.parametrize("name,change,why", MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_each_mutation_is_refused(name, change, why):
    body = record(a())["body"]
    if change.get("content") in ("sha256", "upper", "X"):
        change = {"content": {"sha256": {**body["content"], "binding": "sha256"},
                              "upper": {**body["content"], "hash": body["content"]["hash"].upper()},
                              "X": {**body["content"], "x": 1}}[change["content"]]}
    with pytest.raises(pregen.PregenError, match=why):
        check(record(a(), **change))


def test_signatures_and_the_directory():                     # vector 10
    rec = record(a())
    with pytest.raises(pregen.PregenError, match="bad signature"):
        check({**rec, "body": {**rec["body"], "basis": {**BASIS, "use": {"n": 4, "of": 10}}}})
    with pytest.raises(pregen.PregenError, match="issuer_mismatch"):
        check(record(a(), key=seed("other_registry")))
    with pytest.raises(pregen.PregenError, match="exactly one registry key"):
        check({**rec, "signatures": rec["signatures"] * 2})
    with pytest.raises(pregen.PregenError, match="not a pg.after_gen.v1"):
        check({**rec, "type": "pg.answer.v1"})
    with pytest.raises(pregen.PregenError, match="false claim"):
        check(record(a(), subject_ref="PG-TEST-000002Z"))
    # a revoked registry's records fail
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    steward = seed("after-gen-steward")
    kid = signer(KEY)[0]["key_id"]
    d = {"schema": "pregen.registries.v2", "sequence": 1, "steward_key_id": pregen.fingerprint(pregen.public_key_hex(steward)),
         "registries": [{"name": "Test registry", "prefix": "TEST", "api": "https://registry.test.example",
                         "keys": "https://registry.test.example/keys", "key_fingerprints": [kid],
                         "revoked": {"at": "2026-10-01T00:00:00Z"}}]}
    d["signature"] = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(steward)).sign(pregen.canonical_json(d)).hex()
    revoked = pregen.verify_directory(d, pregen.public_key_hex(steward), successor_public_key_hex=None, now=NOW)
    with pytest.raises(pregen.PregenError, match="revoked"):
        check(rec, directory=revoked)


def test_not_for_this_file():                                # vector 6
    rec = record(a())
    for other in (media("b.mov"), media("b.mov")["hash"], {**a(), "leaves": 57}, {**a(), "binding": "media/2"}):
        with pytest.raises(pregen.PregenError, match="^not for this file$"):
            check(rec, other)


def test_a_record_is_never_an_answer():                       # vector 11
    rec = record(a())
    asked = {"subject_ref": CODE, "provider_id": "https://frame.example", "profile": "likeness/1",
             "use": {"purpose": "commercial"}, "job_id": "job-1", "job_hash": "a" * 64}
    report = {"type": "pg.report.v1", "signatures": [], "body": {
        "answer": pregen.message_id("pg.after_gen.v1", rec["body"]), "outcome": "generated", "output_hash": "d" * 64,
        "job_id": "job-1", "occurred_at": NOW}}
    item = {"request": {"type": "pg.request.v1", "body": asked, "signatures": []}, "answer": rec, "report": report,
            "ack": rec}
    with pytest.raises(pregen.PregenError, match="not a pg.answer.v1 envelope"):
        pregen.check_proof({"format": "pg.proof.v1", "subjects": [item]}, D, get_json, now=NOW)
    with pytest.raises(pregen.PregenError, match="not a pg.answer.v1 envelope"):
        pregen.check_answer(rec, item["request"], D, get_json, now=NOW)
    renamed = {**rec, "type": "pg.answer.v1"}               # the same bytes under the answer's type: not its signature
    with pytest.raises(pregen.PregenError):
        pregen.check_answer(renamed, item["request"], D, get_json, now=NOW)


# ── check_after_gen_status (vector 16) ──────────────────────────────────────────

def check_status(st, rec, now=NOW):
    return pregen.check_after_gen_status(st, rec, D, get_json, now=now)


def test_a_valid_status():
    rec = record(a())
    assert check_status(status(rec), rec) == {"state": "active", "approved_at": NOW - 100, "withdrawn_at": None,
                                              "not_after": NOW + 10**6}
    w = status(rec, state="withdrawn", withdrawn_at=NOW - 50)
    assert check_status(w, rec)["withdrawn_at"] == NOW - 50
    short = record(a(), scope={**SCOPE, "not_after": NOW - 20})
    assert check_status(status(short, state="expired"), short)["state"] == "expired"


STATUS_MUTATIONS = [
    ("other record", {"record": "f" * 64}, "another record"),
    ("expired", {"issued_at": NOW - 400, "expires_at": NOW - 100}, "expired"),
    ("lifetime", {"issued_at": NOW - 10, "expires_at": NOW + 291}, "300 seconds"),
    ("future", {"issued_at": NOW + 61, "expires_at": NOW + 200}, "future"),
    ("withdrawn without withdrawn_at", {"state": "withdrawn"}, "state"),
    ("withdrawn_at while active", {"withdrawn_at": NOW - 50}, "state"),
    ("withdrawn before approval", {"state": "withdrawn", "withdrawn_at": NOW - 101}, "state"),
    ("unknown state", {"state": "paused"}, "state"),
    ("active after not_after", {"not_after": NOW - 20}, "not_after"),
    ("not_after mismatch", {"not_after": NOW + 10**6 + 1}, "not_after"),
    ("approved_at mismatch", {"approved_at": NOW - 99}, "issued_at"),
    ("unknown member", {"reason": "x"}, "exactly the members"),
    ("signer with another member", {"signers": [{**signer(KEY)[0], "x": 1}]}, "signer"),
    ("approved_at not an integer", {"approved_at": True}, "integers"),
]


@pytest.mark.parametrize("name,change,why", STATUS_MUTATIONS, ids=[m[0] for m in STATUS_MUTATIONS])
def test_each_status_mutation_is_refused(name, change, why):
    rec = record(a())
    with pytest.raises(pregen.PregenError, match=why):
        check_status(status(rec, **change), rec)


def test_status_signers():
    rec = record(a())
    with pytest.raises(pregen.PregenError, match="issuer_mismatch"):
        check_status(status(rec, key=seed("other_registry")), rec)
    with pytest.raises(pregen.PregenError, match="bad signature"):
        st = status(rec)
        check_status({**st, "body": {**st["body"], "state": "expired"}}, rec)
    with pytest.raises(pregen.PregenError, match="expired \\(after not_after\\)"):     # active though not_after passed
        short = record(a(), scope={**SCOPE, "not_after": NOW - 20})
        check_status(status(short), short)
    with pytest.raises(pregen.PregenError, match="24 hours"):
        check_status(status(rec), rec, now=NOW + 86_401)


# ── the request and the decision ───────────────────────────────────────────────

def test_request_and_decision():
    key = seed("requester")
    req = pregen.after_gen_request("https://studio.example", key, CODE, "e" * 64, DIR / "a.mp4", SCOPE, now=NOW, nonce="n1")
    assert req["type"] == "pg.after_gen_request.v1" and set(req["body"]) == {
        "signers", "requester", "subject_ref", "licence", "content", "scope", "issued_at", "nonce"}
    assert req["body"]["content"] == a() and req["body"]["signers"] == [
        {"role": "requester", "key_id": pregen.fingerprint(pregen.public_key_hex(key))}]
    assert pregen.verify_bytes(pregen.public_key_hex(key), req["signatures"][0],
                               pregen.signing_input(req["type"], req["body"]))
    assert len(pregen.after_gen_request("https://studio.example", key, CODE, "e" * 64, a(), SCOPE)["body"]["nonce"]) == 32
    rid = pregen.message_id(req["type"], req["body"])
    dec = pregen.after_gen_decision(rid, "approve", SCOPE, key, "subject", now=NOW)
    assert dec["body"] == {"signers": [{"role": "subject", "key_id": req["body"]["signers"][0]["key_id"]}], "request": rid,
                           "outcome": "approve", "scope": SCOPE, "issued_at": NOW}
    assert "scope" not in pregen.after_gen_decision(rid, "refuse", None, key, "subject")["body"]
    assert pregen.after_gen_decision(rid, "refuse", None, key, "agent")["body"]["outcome"] == "refuse"
    for bad in (("approve", None, "subject"), ("refuse", SCOPE, "subject"), ("approve", SCOPE, "registry"),
                ("maybe", SCOPE, "subject"), ("approve", SCOPE, "agent")):
        with pytest.raises(pregen.PregenError):
            pregen.after_gen_decision(rid, bad[0], bad[1], key, bad[2])
    with pytest.raises(pregen.PregenError):
        pregen.after_gen_request("http://studio.example", key, CODE, "e" * 64, a(), SCOPE)


if __name__ == "__main__":
    write_vectors()
