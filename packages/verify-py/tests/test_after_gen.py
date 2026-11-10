"""Draft after-gen (spec/drafts/after-gen.md): media/1, the record in C2PA and XMP, the record and its status, and the
must-reject vectors 6, 7, 9, 10, 11, 13 and 16 at library level. spec/test-vectors/after-gen holds the files and
vectors.json for both libraries; `python tests/test_after_gen.py` rewrites the files derived from the ffmpeg ones."""
import hashlib
import io
import json
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


def trak(tid=1, hdlr=b"vide", samples=(b"abc", b"de"), offset=DATA_AT, tref=b"", stbl=None, entry=None, minf=b""):
    sizes = [len(s) for s in samples]
    tables = {b"stsd": full(b"stsd", 0, 0, U(1), entry or box(b"avc1", bytes(78))),
              b"stts": full(b"stts", 0, 0, U(1, len(sizes), 10)),
              b"stsc": full(b"stsc", 0, 0, U(1, 1, len(sizes), 1)),
              b"stsz": full(b"stsz", 0, 0, U(0, len(sizes), *sizes)),
              b"stco": full(b"stco", 0, 0, U(1, offset))}
    tables.update(stbl or {})
    minf = box(b"minf", full(b"vmhd", 0, 1, bytes(8)), minf, box(b"stbl", *(v for v in tables.values() if v is not None)))
    mdia = box(b"mdia", full(b"mdhd", 0, 0, U(0, 0, 1000, 10 * len(sizes)), bytes(4)),
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
AGENT = {"assent": "agent", "agent": "https://agency.example", "mandate": "b" * 64, "decision": "c" * 64,
         "factor": "signature"}


def signer(key):
    return [{"role": "registry", "key_id": pregen.fingerprint(pregen.public_key_hex(key))}]


def record(media, key=KEY, **change):
    body = {"signers": signer(key), "kind": "ratification", "label": pregen.AFTER_GEN_LABEL,
            "notice": pregen.AFTER_GEN_NOTICE, "not": pregen.AFTER_GEN_NOT, "subject_ref": CODE,
            "content": {k: media[k] for k in ("binding", "hash", "leaves")}, "request": "a" * 64,
            "holder": "https://studio.example", "licence": {"format": "pg.grant.v1", "id": "e" * 64},
            "use": {"n": 3, "of": 10}, "scope": SCOPE, "approval": AGENT, "issued_at": NOW - 100}
    body.update(change)
    return pregen.sign_envelope("pg.after_gen.v1", {k: v for k, v in body.items() if v is not DROP}, key)


def status(rec, key=KEY, **change):
    body = {"signers": signer(key), "record": pregen.message_id("pg.after_gen.v1", rec["body"]), "state": "active",
            "approved_at": rec["body"]["issued_at"], "withdrawn_at": None, "not_after": rec["body"]["scope"]["not_after"],
            "issued_at": NOW - 10, "expires_at": NOW + 290}
    body.update(change)
    return pregen.sign_envelope("pg.after_gen_status.v1", body, key)


def check(env, media=None, directory=D):
    return pregen.check_after_gen(env, directory, get_json, media=media)


# ── the vector files ────────────────────────────────────────────────────────────

# Made once with ffmpeg 9.0.2, B="-fflags +bitexact -map_metadata -1":
#   ffmpeg -f lavfi -i testsrc=size=64x48:rate=10 -f lavfi -i sine=frequency=440 -t 1 -c:v libx264 -preset ultrafast \
#          -pix_fmt yuv420p -c:a aac -b:a 32k $B a.mp4
#   ffmpeg -i a.mp4 -c copy $B a-remux.mp4; ffmpeg -i a-remux.mp4 -c copy -movflags +faststart $B a-remux-faststart.mp4
#   b.mov: the same with testsrc2=size=64x48:rate=12 and sine=frequency=220; b-remux.mov, b-remux-faststart.mov alike
#   ffmpeg -f lavfi -i testsrc=size=32x24:rate=5 -t 1 -c:v libx264 -preset ultrafast -bf 2 -pix_fmt yuv420p $B c.mp4
FFMPEG_FILES = ("a.mp4", "a-remux.mp4", "a-remux-faststart.mp4", "b.mov", "b-remux.mov", "b-remux-faststart.mov",
                "c.mp4")


HUGE = {b"stsz": full(b"stsz", 0, 0, U(1, 2**32 - 1)), b"stts": full(b"stts", 0, 0, U(1, 2**32 - 1, 1)),
        b"stsc": full(b"stsc", 0, 0, U(1, 1, 2**32 - 1, 1))}


CMOV = box(b"cmov", box(b"dcom", b"zlib"), box(b"cmvd", U(0)))
KEPT = ("attack-stray-stco.mp4", "attack-elst-in-udta.mp4", "attack-top-trak.mp4", "attack-top-udta-trak.mp4",
        "attack-top-cmov.mp4", "attack-udta-cmov.mp4", "attack-udta-mvex-moof.mp4", "attack-glbl.mp4", "attack-stss.mp4",
        "attack-st3d-clli.mp4")


GMHD_KEPT = mp4(({"tref": box(b"tapt", b"t") + box(b"edts", box(b"x123", b"e")), "minf": box(b"hdlr", b"h"),
                  "stbl": {b"stss": full(b"stss", 0, 0, U(0))}},)).replace(b"vmhd", b"gmhd")


def derived():
    """Every vector file made here from the ffmpeg ones, by name; deterministic (Ed25519 signs deterministically)."""
    a = (DIR / "a.mp4").read_bytes()
    A = H(a)
    rec, other = record(A), record(H((DIR / "b.mov").read_bytes()))
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
                              {"tid": 5, "hdlr": b"soun", "tref": box(b"tref", box(b"sync", U(1)))})),
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
        "attack-dref-external.mp4": mp4(({"minf": box(b"dinf", full(b"dref", 0, 0, U(1), full(b"url ", 0, 0, b"https://x.example/a\0")))},)),
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
        "attack-dinf-extra.mp4": mp4(({"minf": box(b"dinf", full(b"dref", 0, 0, U(1), full(b"url ", 0, 1)), box(b"udta"))},)),
        "attack-dref-alis.mp4": mp4(({"minf": box(b"dinf", full(b"dref", 0, 0, U(1), full(b"alis", 0, 1)))},)),
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
    }
    out["a-xmp-foreign-pg.mp4"] = out["a-xmp-foreign.mp4"][:-len(xmp_box(FOREIGN_XMP))] \
        + box(b"free", bytes(len(xmp_box(FOREIGN_XMP)) - 8)) + xmp_box(ag._packet(FOREIGN_XMP, rec))
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
            ids = {k: v and pregen.message_id(v["type"], v["body"]) for k, v in got.items()}
            res = {}
            for k, v in got.items():
                if v is not None:
                    try:
                        res[k] = check(v, pregen.media_hash(DIR / n))["id"]
                    except pregen.PregenError as e:
                        res[k] = str(e)
            reads.append({"file": n, **ids, "check": res})
    return {"description": "after-gen/1 (spec/drafts/after-gen.md): media/1 of each file, or its refusal; for files "
                           "carrying a record, the message id read from C2PA and XMP and what check_after_gen says "
                           "against the file's own media/1. The directory and key sets are those of answers.json.",
            "now": NOW, "record": rec, "files": entries, "read": reads}


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


def test_leaves_are_the_movie_each_track_and_each_sample():
    assert media("a.mp4")["leaves"] == 58 and media("b.mov")["leaves"] == 60 and media("c.mp4")["leaves"] == 7
    with open(DIR / "c.mp4", "rb") as f:                   # a file object too; c.mp4 has B-frames (ctts)
        assert pregen.media_hash(f) == media("c.mp4")


def test_moving_the_movie_box_or_metadata_leaves_the_hash():
    assert media("a-remux.mp4") == media("a-remux-faststart.mp4")
    assert media("b-remux.mov") == media("b-remux-faststart.mov")
    for n in ("a-xmp.mp4", "a-xmp-foreign-pg.mp4", "a-c2pa-json.mp4", "a-c2pa-cbor.mp4"):
        assert media(n) == media("a.mp4"), n
    assert media("a-meta.mp4")["hash"] != media("a.mp4")["hash"]           # a top-level meta box: a player may read it
    # ffmpeg's first stream copy of a file it encoded rewrites listed parameters: the movie timescale (mvhd, and so the
    # edit list's durations, which are in it) and the bitrates of the btrt box inside the sample entry. Those decide how
    # the samples play, so the hash changes; a second stream copy keeps them, and the hash (above).
    assert media("a.mp4")["hash"] != media("a-remux.mp4")["hash"]
    assert media("b.mov")["hash"] != media("b-remux.mov")["hash"]


def test_one_coded_byte_changes_it():
    assert media("a-flip.mp4")["hash"] != media("a.mp4")["hash"]
    assert media("a-flip.mp4")["leaves"] == media("a.mp4")["leaves"]


def test_replacing_a_top_level_metadata_box():
    a = (DIR / "a.mp4").read_bytes()
    _, p, size = next(b for b in top_boxes(a) if b[0] == b"free")          # ffmpeg's free box before mdat
    assert H(a[:p] + box(b"skip", bytes(size - 8)) + a[p + size:]) == H(a)


@pytest.mark.skipif(not FFMPEG, reason="ffmpeg not installed")
def test_a_remux_by_ffmpeg_now(tmp_path):
    for src, ext in (("a-remux.mp4", ".mp4"), ("b-remux.mov", ".mov")):
        dst = tmp_path / ("out" + ext)
        subprocess.run([FFMPEG, "-v", "error", "-y", "-i", str(DIR / src), "-c", "copy", "-movflags", "+faststart",
                        "-fflags", "+bitexact", "-map_metadata", "-1", str(dst)], check=True)  # no encoder tag in udta
        assert pregen.media_hash(dst) == media(src)
    dst = tmp_path / "out.mov"               # into another format: MOV writes other sample entries and handlers
    subprocess.run([FFMPEG, "-v", "error", "-y", "-i", str(DIR / "a-remux.mp4"), "-c", "copy", str(dst)], check=True)
    assert pregen.media_hash(dst)["hash"] != media("a-remux.mp4")["hash"]


LEAVES = (b"PREGEN-MEDIA\x00media/1\x00" + el(b"FRMT", b"isobmff") + el(b"tmsc", i64(1000))
          + el(b"rate", i64(0x10000)) + el(b"volu", i64(0x100)) + el(b"mtrx", i64(*MATRIX)),
          el(b"hdlr", b"vide") + el(b"tref", b"") + el(b"vmhd", bytes(8)) + el(b"mdts", i64(1000))
          + el(b"sent", el(b"avc1", bytes(78))) + el(b"tkhd", i64(1, 0, 0, 0, *MATRIX, 64 << 16, 48 << 16)) + el(b"elst", b""),
          [el(b"sdsc", i64(1)) + el(b"dtim", i64(t)) + el(b"ctso", i64(0)) + el(b"sdur", i64(10)) + el(b"data", d)
           for t, d in ((0, b"abc"), (10, b"de"))])


def test_the_leaves_by_hand():
    movie, track, samples = LEAVES
    assert H(mp4()) == {"binding": "media/1", "hash": mth([movie, track, *samples]).hex(), "leaves": 4}
    # gmhd, a media header without version and flags, is hashed whole; other boxes of the track are kept in the order
    # trak, edts, mdia, minf, stbl
    gm = media("tiny-kept.mp4")
    kept = el(b"xbox", el(b"tapt", b"t")) + el(b"xbox", el(b"x123", b"e")) + el(b"xbox", el(b"hdlr", b"h")) \
        + el(b"xbox", el(b"stss", bytes(8)))
    gtrack = track.replace(el(b"vmhd", bytes(8)), el(b"gmhd", b"\x00\x00\x00\x01" + bytes(8))) + kept
    assert gm == {"binding": "media/1", "hash": mth([movie, gtrack, *samples]).hex(), "leaves": 4}
    # tracks by track_ID, every one whatever its handler (meta too), tref by position among them
    a = mp4(({"tid": 5, "hdlr": b"soun", "tref": box(b"tref", box(b"sync", U(2)))}, {"tid": 2, "hdlr": b"meta"}, {}))
    rest = track[len(el(b"hdlr", b"vide") + el(b"tref", b"")):]
    sound = el(b"hdlr", b"soun") + el(b"tref", el(b"sync", i64(1))) + rest
    meta = el(b"hdlr", b"meta") + el(b"tref", b"") + rest
    assert H(a) == {"binding": "media/1", "hash": mth([movie, track, *samples, meta, *samples, sound, *samples]).hex(),
                    "leaves": 10}


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


def test_inserting_a_c2pa_box_before_the_movie_moves_nothing_that_plays():
    a = (DIR / "a-remux-faststart.mp4").read_bytes()                      # moov before mdat: every offset moves
    assert H(insert_after_ftyp(a, c2pa_box(manifest(1)))) == H(a)
    assert H(insert_after_ftyp(a, box(b"free", bytes(3)))) == H(a)


REFUSALS = [
    ("x-no-moov.mp4", "no moov"), ("x-two-moov.mp4", "more than one moov"), ("x-moof.mp4", "fragmented"),
    ("x-mvex.mp4", "fragmented"), ("x-encv.mp4", "encrypted"), ("x-sinf.mp4", "encrypted"), ("x-stz2.mp4", "stz2"),
    ("x-overlap.mp4", "overlap"), ("x-past-eof.mp4", "outside the file"), ("x-box-past-parent.mp4", "past its parent"),
    ("x-tref-unlisted.mp4", "not in the file"), ("x-stts-stsz.mp4", "count different samples"),
    ("attack-short-uuid.mp4", "shorter than its header"), ("attack-dref-external.mp4", "self-contained"),
    ("attack-dos.mp4", "outside the file"), ("attack-cmov.mp4", "compressed movie"), ("attack-two-stco.mp4", "stco"),
    ("attack-two-tkhd.mp4", "tkhd"), ("attack-two-media-headers.mp4", "two media headers"),
    ("attack-dinf-extra.mp4", "one dref"), ("attack-dref-alis.mp4", "self-contained")]


@pytest.mark.parametrize("name,why", REFUSALS)
def test_one_reading_only(name, why):
    msg = refused((DIR / name).read_bytes())
    assert msg.startswith("media/1: ") and why in msg


def test_every_track_whatever_its_handler():
    assert media("attack-meta-red.mp4")["hash"] != media("attack-meta-blue.mp4")["hash"]       # meta plays: it counts
    assert media("attack-hidden-track.mp4")["leaves"] == media("tiny.mp4")["leaves"] + 2
    assert media("tiny-tref.mp4")["leaves"] == 10


def test_every_other_box_kept_as_is():
    plain = H(mp4())
    for name in KEPT:                                       # a player may read any of them: each changes the hash
        assert media(name)["hash"] != plain["hash"], name
    entry = box(b"avc1", bytes(78), box(b"avcC", b"stco"), box(b"colr", b"nclx"))         # inside a hashed entry
    assert H(mp4(({"entry": entry},)))["hash"] != plain["hash"]
    for where in ({"moov_extra": box(b"udta", box(b"\xa9nam", b"Spring"))}, {"top": box(b"udta", b"x")},
                  {"top": box(b"uuid", bytes(16), b"x")}, {"tracks": ({"tref": box(b"udta")},)},
                  {"tracks": ({"minf": full(b"hdlr", 0, 0, b"dhlr", b"url ", bytes(12), b"\x0bDataHandler")},)},
                  {"tracks": ({"stbl": {b"stss": full(b"stss", 0, 0, U(1, 1))}},)}):
        assert H(mp4(**where))["hash"] != plain["hash"], where
    for where in ({"top": box(b"free", b"x") + box(b"skip") + box(b"wide") + box(b"mdat", b"y")},
                  {"top": xmp_box(b"<x/>") + box(b"uuid", ag._C2PA_UUID, bytes(4), b"other\0")},
                  {"tracks": ({"minf": box(b"dinf", full(b"dref", 0, 0, U(2), full(b"url ", 0, 1), full(b"urn ", 0, 1)))},)}):
        assert H(mp4(**where)) == plain, where                # padding, media data, the carriers, a dinf: not kept
    # an xbox by hand: its value is one element of the box's type, the bytes after its size and type
    udta, top = box(b"udta", box(b"\xa9nam", b"x")), struct.pack(">I4sQ", 1, b"PROF", 20) + b"abcd"
    want = mp4(moov_extra=udta, top=top)
    movie, track, samples = LEAVES
    kept = el(b"xbox", el(b"udta", udta[8:])) + el(b"xbox", el(b"PROF", b"abcd"))
    assert H(want) == {"binding": "media/1", "hash": mth([movie + kept, track, *samples]).hex(), "leaves": 4}


def test_short_fixed_layouts_and_values_beyond_64_bits():
    def patched(code, size):
        """mp4() with the box `code` cut to `size` bytes of content, its parents' sizes fixed."""
        data = bytearray(mp4())
        at = data.index(code) - 4
        cut = struct.unpack_from(">I", data, at)[0] - 8 - size
        del data[at + 8 + size:at + 8 + size + cut]
        struct.pack_into(">I", data, at, 8 + size)
        for parent in (b"moov", b"trak", b"mdia", b"minf"):
            p = data.index(parent) - 4
            if p < at:
                struct.pack_into(">I", data, p, struct.unpack_from(">I", data, p)[0] - cut)
        return bytes(data)
    for code, size in ((b"mvhd", 99), (b"mvhd", 72), (b"tkhd", 83), (b"mdhd", 23), (b"vmhd", 11), (b"vmhd", 0)):
        assert "short" in refused(patched(code, size)), code
    assert "shorter than its header" in refused(mp4(moov_extra=box(b"uuid", bytes(8))))
    elst = box(b"edts", full(b"elst", 1, 0, U(1), struct.pack(">Qqhh", 2**63, 0, 1, 0)))
    assert "signed 64-bit" in refused(mp4(({"tref": elst},)))


def test_more_refusals():
    assert "past its parent" in refused(mp4() + b"\x00\x00\x00")                       # a trailing partial header
    assert "past its parent" in refused(FTYP + struct.pack(">I4s", 1 << 20, b"mdat"))
    assert "count different" in refused(mp4(({"stbl": {b"stsc": full(b"stsc", 0, 0, U(1, 1, 1, 1))}},)))
    assert "stsc" in refused(mp4(({"stbl": {b"stsc": full(b"stsc", 0, 0, U(1, 2, 2, 2))}},)))  # no sample entry 2
    assert "ctts" in refused(mp4(({"stbl": {b"ctts": full(b"ctts", 0, 0, U(1, 1, 0))}},)))
    assert "track_ID" in refused(mp4(({}, {"samples": (b"x",)})))
    assert "co64" in refused(mp4(({"stbl": {b"co64": full(b"co64", 0, 0, U(1), struct.pack(">Q", DATA_AT))}},)))
    assert "exactly one stsz" in refused(mp4(({"stbl": {b"stsz": None}},)))
    assert "too short" in refused(mp4(({"stbl": {b"stsd": full(b"stsd", 0, 0)}},)))
    assert "count does not agree" in refused(mp4(({"stbl": {b"stco": full(b"stco", 0, 0, U(2, DATA_AT))}},)))
    # tables that claim billions of samples are refused before they are expanded
    assert "count different" in refused(mp4(({"stbl": {b"stts": full(b"stts", 0, 0, U(2, 2, 10, 2**32 - 1, 10))}},)))
    assert "outside the file" in refused(mp4(({"stbl": {b"stsz": full(b"stsz", 0, 0, U(1, 2**32 - 1))}},)))
    co64 = mp4(({"stbl": {b"stco": None, b"co64": full(b"co64", 0, 0, U(1), struct.pack(">Q", DATA_AT))}},))
    assert H(co64) == H(mp4())                                                       # 32- or 64-bit offsets alike
    big = bytearray(mp4())                                                           # a size-0 last box runs to EOF
    struct.pack_into(">I", big, top_boxes(bytes(big))[-1][1], 0)
    assert H(bytes(big)) == H(mp4())


# ── read_after_gen and embed_xmp ────────────────────────────────────────────────

def test_read_the_vector_files():
    rid = pregen.message_id("pg.after_gen.v1", derived()[1]["body"])
    got = {r["file"]: r for r in json.loads((DIR / "vectors.json").read_text())["read"]}
    assert got["a-xmp.mp4"] == {"file": "a-xmp.mp4", "c2pa": None, "xmp": rid, "check": {"xmp": rid}}
    assert got["a-c2pa-json.mp4"]["c2pa"] == rid and got["a-c2pa-cbor.mp4"]["c2pa"] == rid     # the last manifest wins
    assert got["a-c2pa-earlier.mp4"]["c2pa"] is None
    assert got["a-xmp-foreign.mp4"]["xmp"] is None and got["a-xmp-foreign-pg.mp4"]["xmp"] == rid
    assert got["b-copied-record.mov"]["check"] == {"xmp": "not for this file"}               # vector 6


def test_embed_xmp_round_trip(tmp_path):
    rec = record(media("a.mp4"))
    pregen.embed_xmp(DIR / "a.mp4", tmp_path / "x.mp4", rec)
    data = (tmp_path / "x.mp4").read_bytes()
    assert data.startswith((DIR / "a.mp4").read_bytes()) and media("a.mp4") == pregen.media_hash(tmp_path / "x.mp4")
    assert pregen.read_after_gen(tmp_path / "x.mp4") == {"c2pa": None, "xmp": rec}
    packet = data[len((DIR / "a.mp4").read_bytes()) + 24:]
    rid = pregen.message_id("pg.after_gen.v1", rec["body"])
    for part in (f"<pgag:Id>{rid}</pgag:Id>", "<pgag:Registry>TEST</pgag:Registry>",
                 'xmlns:pgag="https://pregen.org/ns/after-gen/1/"'):
        assert part.encode() in packet
    assert b"pgag:Status" not in packet          # the record names no status address (The status)
    # again: the old box becomes free of the same size, zeroed; still one record
    pregen.embed_xmp(tmp_path / "x.mp4", tmp_path / "y.mp4", rec)
    y = (tmp_path / "y.mp4").read_bytes()
    assert y[:len(data)] == data[:-len(packet) - 24] + struct.pack(">I4s", len(packet) + 24, b"free") + bytes(len(packet) + 16)
    assert pregen.read_after_gen(tmp_path / "y.mp4")["xmp"] == rec and pregen.media_hash(tmp_path / "y.mp4") == media("a.mp4")
    assert y.count(b"<pgag:Record>") == 1


def test_embed_xmp_keeps_existing_properties(tmp_path):
    rec = record(media("a.mp4"))
    pregen.embed_xmp(DIR / "a-xmp-foreign.mp4", tmp_path / "x.mp4", rec)
    x = (tmp_path / "x.mp4").read_bytes()
    assert x == (DIR / "a-xmp-foreign-pg.mp4").read_bytes()
    assert b"Spring &lt;cut&gt;" in x and b'xml:lang="x-default"' in x and b'xmp:CreatorTool="Studio &amp; Co"' in x
    assert pregen.read_after_gen(tmp_path / "x.mp4")["xmp"] == rec
    a = (DIR / "a.mp4").read_bytes()                                       # an old box in the 64-bit form keeps it
    (tmp_path / "w.mp4").write_bytes(a + struct.pack(">I4sQ", 1, b"uuid", 32 + len(FOREIGN_XMP)) + ag._XMP_UUID + FOREIGN_XMP)
    pregen.embed_xmp(tmp_path / "w.mp4", tmp_path / "x.mp4", rec)
    x = (tmp_path / "x.mp4").read_bytes()
    assert x[len(a):len(a) + 32 + len(FOREIGN_XMP)] == struct.pack(">I4sQ", 1, b"free", 32 + len(FOREIGN_XMP)) \
        + bytes(16 + len(FOREIGN_XMP))
    assert pregen.read_after_gen(tmp_path / "x.mp4")["xmp"] == rec


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
    assert read(a + c2pa_box(manifest(1, assertion(rec)), purpose=b"merkle")) == {"c2pa": None, "xmp": None}
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
                 "holder": "https://studio.example", "licence_id": "e" * 64, "use": {"n": 3, "of": 10}, "scope": SCOPE,
                 "approval": AGENT, "approved_by": f"approved by agency.example under mandate {'b' * 64}",
                 "status_url": API + pregen.message_id("pg.after_gen.v1", rec["body"]), "issued_at": NOW - 100,
                 "content": rec["body"]["content"],
                 "file_match": True}
    assert check(rec)["file_match"] is None and check(rec, a()["hash"])["file_match"] is True
    assert check(record(a(), approval={"assent": "self", "decision": "c" * 64}))["approved_by"] == "approved by the person"
    assert check(record(a(), approval={"assent": "registry", "instruction": "c" * 64, "factor": "email"}))["approved_by"] \
        == "approved on the person's instruction at the registry"
    assert check(record(a(), use={"n": 1, "of": None}, scope={**SCOPE, "categories": [], "territories": ["*"],
                                                              "channels": ["*"]}))


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
    ("unknown in approval", {"approval": {**AGENT, "x": 1}}, "approval \\(agent\\): exactly"),
    ("unknown in content", {"content": "X"}, "content: exactly"),
    ("unknown in use", {"use": {"n": 1, "of": 2, "x": 1}}, "use: exactly"),
    ("unknown in licence", {"licence": {"format": "pg.grant.v1", "id": "e" * 64, "x": 1}}, "licence: exactly"),
    ("unknown in signer", {"signers": [{**signer(KEY)[0], "x": 1}]}, "signer"),
    ("binding", {"content": "sha256"}, "media/1"),
    ("hash", {"content": "upper"}, "media/1"),
    ("licence format", {"licence": {"format": "pg.licence.v1", "id": "e" * 64}}, "pg.grant.v1"),
    ("use n", {"use": {"n": 0, "of": 10}}, "use: n"),
    ("use over", {"use": {"n": 11, "of": 10}}, "use: n"),
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
    ("agent without mandate", {"approval": {k: v for k, v in AGENT.items() if k != "mandate"}}, "approval \\(agent\\)"),
    ("agent factor", {"approval": {**AGENT, "factor": "email"}}, "factor signature"),
    ("agent is holder", {"approval": {**AGENT, "agent": "https://studio.example"}}, "never the holder"),
    ("agent url", {"approval": {**AGENT, "agent": "https://Agency.example"}}, "provider URL"),
    ("unknown assent", {"approval": {"assent": "holder", "decision": "c" * 64}}, "self, registry or agent"),
    ("holder", {"holder": "studio.example"}, "provider URL"),
    ("request", {"request": "A" * 64}, "request"),
    ("status_url member", {"status_url": API + "a" * 64}, "member"),
    ("assent as a list", {"approval": {**AGENT, "assent": ["agent"]}}, "self, registry or agent"),
    ("territories nested", {"scope": {**SCOPE, "territories": [["ES"]]}}, "territories"),
    ("channels nested", {"scope": {**SCOPE, "channels": [["social"]]}}, "channels"),
    ("251 territories", {"scope": {**SCOPE, "territories": sorted(a + b for a in "ABCDEFGHIJ" for b in "ABCDEFGHIJKLMNOPQRSTUVWXYZ")[:251]}},
     "territories"),
    ("65 channels", {"scope": {**SCOPE, "channels": [f"c{j:02d}" for j in range(65)]}}, "channels"),
    ("not_after at issued_at", {"scope": {**SCOPE, "not_after": NOW - 100}}, "later than issued_at"),
    ("agent on the holder's host", {"approval": {**AGENT, "agent": "https://studio.example:8443"}}, "never the holder"),
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
        check({**rec, "body": {**rec["body"], "use": {"n": 4, "of": 10}}})
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
    dec = pregen.after_gen_decision(rid, "approve", SCOPE, key, "agent", now=NOW)
    assert dec["body"] == {"signers": [{"role": "agent", "key_id": req["body"]["signers"][0]["key_id"]}], "request": rid,
                           "outcome": "approve", "scope": SCOPE, "issued_at": NOW}
    assert "scope" not in pregen.after_gen_decision(rid, "refuse", None, key, "subject")["body"]
    for bad in (("approve", None, "subject"), ("refuse", SCOPE, "subject"), ("approve", SCOPE, "registry"),
                ("maybe", SCOPE, "subject")):
        with pytest.raises(pregen.PregenError):
            pregen.after_gen_decision(rid, bad[0], bad[1], key, bad[2])
    with pytest.raises(pregen.PregenError):
        pregen.after_gen_request("http://studio.example", key, CODE, "e" * 64, a(), SCOPE)


if __name__ == "__main__":
    write_vectors()
