"""The registry: state in SQLite, the core rules, profile likeness/1 and the extensions
reports, provider-keys, limits, jobs, grants, licensee, observe, sandbox and lookup.

ponytail: one process-wide lock around one SQLite connection serializes every write. That is the
spec's three locks (provider+job, ask, grant counter) collapsed into one: correct, simple, and enough
for a sandbox or a small registry. Per-row locks on Postgres when throughput matters.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field

from pregen import fingerprint

from .protocol import Key, ProtocolError, canonical, check_body, check_envelope, message_id, mint_code, parse_code, seal

PROFILE = "likeness/1"
EXTENSIONS = ["reports", "provider-keys", "limits", "jobs", "grants", "licensee", "observe", "lookup", "identity",
              "proof", "catalog"]
TTL = 300                       # seconds an answer stays valid (≤ 900)
GIVE_BACK_WINDOW = 86400        # likeness/1: 24 hours from issued_at
PURPOSES = {"personal", "educational", "research", "editorial", "commercial"}
USE_MEMBERS = {"purpose", "rights", "territory", "channel", "categories"}
PROHIBITED_FOR_MINORS = {"sexual", "adult", "violence"}
INTIMATE = {"sexual", "adult"}  # likeness/1: only with the person's own signature on the grant
UNAVAILABLE = {"pending", "paused", "disputed", "withdrawn"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS subjects (
  code TEXT PRIMARY KEY, serial INTEGER UNIQUE NOT NULL, name TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active', level TEXT NOT NULL DEFAULT 'self', published INTEGER NOT NULL DEFAULT 1,
  opted_out INTEGER NOT NULL DEFAULT 0, minor INTEGER NOT NULL DEFAULT 0, review INTEGER NOT NULL DEFAULT 0,
  fixed_refusal TEXT, immutable_denials TEXT NOT NULL DEFAULT '[]', no_grant_status TEXT NOT NULL DEFAULT 'deny',
  custody TEXT NOT NULL DEFAULT 'managed', key_public TEXT NOT NULL, key_private TEXT,
  anchor TEXT, proof_url TEXT, offer TEXT);
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY, subject_code TEXT NOT NULL, licensee_id TEXT NOT NULL, purposes TEXT NOT NULL,
  not_before INTEGER NOT NULL, expires_at INTEGER NOT NULL, max_uses INTEGER, uses_offset INTEGER NOT NULL DEFAULT 0,
  envelope TEXT NOT NULL, resale INTEGER NOT NULL DEFAULT 0, categories TEXT NOT NULL DEFAULT '[]');
CREATE TABLE IF NOT EXISTS providers (provider_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS connections (provider_id TEXT NOT NULL, licensee_id TEXT NOT NULL, PRIMARY KEY (provider_id, licensee_id));
CREATE TABLE IF NOT EXISTS keysets (provider_id TEXT NOT NULL, position INTEGER NOT NULL, id TEXT NOT NULL,
  envelope TEXT NOT NULL, PRIMARY KEY (provider_id, position));
CREATE TABLE IF NOT EXISTS jobs (provider_id TEXT NOT NULL, job_id TEXT NOT NULL, job_hash TEXT NOT NULL,
  PRIMARY KEY (provider_id, job_id));
CREATE TABLE IF NOT EXISTS asks (id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, job_id TEXT NOT NULL,
  subject_ref TEXT NOT NULL, request TEXT NOT NULL, closing_ack TEXT, null_report TEXT,
  UNIQUE (provider_id, job_id, subject_ref));
CREATE TABLE IF NOT EXISTS answers (id TEXT PRIMARY KEY, ask_id TEXT NOT NULL, envelope TEXT NOT NULL,
  status TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, grant_id TEXT, use TEXT,
  report_id TEXT);
CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, ask_id TEXT NOT NULL,
  envelope TEXT NOT NULL, ack TEXT NOT NULL);
"""


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class Config:
    prefix: str
    name: str
    api: str
    policy: str = ""
    complaints: str = ""
    sandbox: bool = False
    profiles: list = field(default_factory=lambda: [PROFILE])

    def __post_init__(self):
        if not re.fullmatch(r"[ABCDEFGHJKMNPQRSTVWXYZ]{4}", self.prefix):
            raise ValueError("a registry's prefix is four letters of the PG alphabet (new codes are never bare, PG-CODE.md §9)")


class Registry:
    def __init__(self, config: Config, operator_key: Key, db_path: str = ":memory:", clock=lambda: int(time.time())):
        self.config, self.key, self.clock = config, operator_key, clock
        self.db = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.lock = threading.RLock()  # one sqlite connection: every use of it holds this lock
        self.activated_at = int(self._meta("activated_at") or self._set_meta("activated_at", str(clock())))

    # ── storage helpers ──────────────────────────────────────────────────
    @contextmanager
    def tx(self):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield self.db
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def _row(self, sql, args=()):
        with self.lock:
            return self.db.execute(sql, args).fetchone()

    def _q(self, sql, args=()):
        with self.lock:
            return self.db.execute(sql, args).fetchall()

    def _meta(self, k):
        row = self.db.execute("SELECT v FROM meta WHERE k = ?", (k,)).fetchone()
        return row["v"] if row else None

    def _set_meta(self, k, v):
        self.db.execute("INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)", (k, v))
        return v

    # ── operator actions (CLI) ───────────────────────────────────────────
    def add_subject(self, name: str, *, serial: int | None = None, level: str = "self", holder_public: str | None = None,
                    **flags) -> str:
        """`holder_public`: the person holds their own key (custody self); the registry never sees it."""
        with self.tx() as db:
            if serial is None:
                serial = (db.execute("SELECT COALESCE(MAX(serial), 0) FROM subjects").fetchone()[0] or 0) + 1
            code = mint_code(self.config.prefix, serial)
            key = None if holder_public else Key()
            flags["immutable_denials"] = json.dumps(flags.get("immutable_denials", []))
            if holder_public:
                flags["custody"] = "self"
            cols = ["code", "serial", "name", "level", "key_public", "key_private", *flags]
            db.execute(f"INSERT INTO subjects ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                       (code, serial, name, level, holder_public or key.public_hex, key and key.private_hex,
                        *flags.values()))
            return code

    def add_grant(self, subject_code: str, *, licensee_id: str = "", purposes=("research",), days: int = 365,
                  max_uses: int | None = None, uses_offset: int = 0, resale: bool = False, categories=(),
                  holder_key: Key | None = None) -> str:
        """`resale`: licensee_id is a provider that may sell generations to its own users (catalog.md).
        `categories`: content categories granted explicitly; intimate ones need `holder_key`, the person's own key."""
        with self.tx() as db:
            s = db.execute("SELECT * FROM subjects WHERE code = ?", (subject_code,)).fetchone()
            if not s:
                raise ValueError("unknown subject")
            signer = Key(s["key_private"]) if s["key_private"] else holder_key
            if signer is None or signer.public_hex != s["key_public"]:
                raise ValueError("a grant is signed by the subject's own key: this subject holds it (self custody)")
            now = self.clock()
            use = {"purposes": sorted(purposes)}
            if categories:
                use["categories"] = sorted(categories)
            if resale:
                use["resale"] = True
            env = seal("pg.grant.v1", {"subject_ref": subject_code, "licensee_id": licensee_id, "profile": PROFILE,
                                       "use": use, "not_before": now, "expires_at": now + days * 86400,
                                       "max_uses": max_uses},
                       [("rights_holder", signer), ("registry", self.key)])
            gid = message_id(env["type"], env["body"])
            db.execute("INSERT INTO grants VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (gid, subject_code, licensee_id, json.dumps(sorted(purposes)), now, now + days * 86400,
                        max_uses, uses_offset, json.dumps(env), int(resale), json.dumps(sorted(categories))))
            return gid

    def set_identity(self, code: str, *, anchor: str | None = None, proof_url: str | None = None,
                     offer: dict | None = None):
        """identity.md: the public anchor and the official-channel confirmation; catalog.md: the offer, only with
        the person's consent to be listed."""
        with self.tx() as db:
            db.execute("UPDATE subjects SET anchor = ?, proof_url = ?, offer = ? WHERE code = ?",
                       (anchor, proof_url, json.dumps(offer) if offer is not None else None, code))

    def add_provider(self, provider_id: str | None = None) -> tuple[str, str]:
        provider_id = provider_id or "sbx-" + secrets.token_hex(4)
        token = secrets.token_urlsafe(32)
        with self.tx() as db:
            db.execute("INSERT INTO providers VALUES (?, ?, ?)", (provider_id, _hash_token(token), self.clock()))
        return provider_id, token

    def connect(self, provider_id: str, licensee_id: str):
        with self.tx() as db:
            db.execute("INSERT OR IGNORE INTO connections VALUES (?, ?)", (provider_id, licensee_id))

    def seed_sandbox(self):
        """The standard sandbox subjects (extensions/sandbox.md), serials 1–7; serial 8 stays unregistered."""
        one = self.add_subject("Test subject 1 (allow)", serial=1, level="verified")
        self.add_grant(one, purposes=PURPOSES, days=36500)
        self.add_subject("Test subject 2 (no licence)", serial=2, level="verified")
        self.add_subject("Test subject 3 (opted out)", serial=3, level="verified", opted_out=1)
        four = self.add_subject("Test subject 4 (usage limit)", serial=4, level="verified")
        self.add_grant(four, purposes=PURPOSES, days=36500, max_uses=1, uses_offset=1)
        self.add_subject("Test subject 5 (prohibited)", serial=5, level="verified", fixed_refusal="PG_PROHIBITED_USE")
        self.add_subject("Test subject 6 (review)", serial=6, level="verified", review=1)
        self.add_subject("Test subject 7 (not blocked)", serial=7, level="verified", no_grant_status="not_blocked")

    # ── authentication ───────────────────────────────────────────────────
    def authenticate(self, provider_id: str, authorization: str | None):
        token = (authorization or "").removeprefix("Bearer ").strip()
        row = self._row("SELECT token_hash FROM providers WHERE provider_id = ?", (provider_id or "",))
        if not row or not token or not secrets.compare_digest(row["token_hash"], _hash_token(token)):
            raise ProtocolError("PG_NOT_AUTHENTICATED", "unknown provider or credential", status=401)

    # ── core: requests ───────────────────────────────────────────────────
    def request(self, provider_id: str, authorization: str | None, env) -> dict:
        body = check_envelope(env, "pg.request.v1", (), lambda *_: None)
        check_body("request", body)
        self.authenticate(provider_id, authorization)
        if body["provider_id"] != provider_id:
            raise ProtocolError("PG_NOT_AUTHENTICATED", "provider_id differs from X-Provider-ID", status=401)
        if body["profile"] not in self.config.profiles:
            raise ProtocolError("PG_PROFILE_UNSUPPORTED", f"this registry answers under {self.config.profiles}")
        self._check_use(body["use"])
        licensee = body.get("licensee_id", "")
        if licensee and not self.config.sandbox and not self._row(
                "SELECT 1 FROM connections WHERE provider_id = ? AND licensee_id = ?", (provider_id, licensee)):
            raise ProtocolError("PG_NOT_AUTHENTICATED", "this licensee is not connected to this provider", status=401)
        with self.tx() as db:
            ask = self._bind(db, body)
            if ask["closing_ack"]:
                raise ProtocolError("PG_ASK_CLOSED", "this subject of the job was reported generated", status=409,
                                    ack=json.loads(ask["closing_ack"]))
            now = self.clock()
            open_ = db.execute("SELECT envelope FROM answers WHERE ask_id = ? AND expires_at > ? ORDER BY issued_at DESC",
                               (ask["id"], now)).fetchone()
            if open_:
                return {"answer": json.loads(open_["envelope"]), "attachments": []}
            return {"answer": self._answer(db, ask, body, now), "attachments": []}

    @staticmethod
    def _check_use(use):
        if set(use) - USE_MEMBERS or use.get("purpose") not in PURPOSES \
                or not all(isinstance(use.get(k, []), list) for k in ("rights", "categories")) \
                or not all(isinstance(use.get(k, ""), str) for k in ("territory", "channel")):
            raise ProtocolError("PG_MALFORMED", "use: purpose personal|educational|research|editorial|commercial; "
                                                "optional rights, territory, channel, categories")

    def _bind(self, db, body: dict):
        """extensions/jobs.md: one job_hash per job, one request per subject of the job."""
        row = db.execute("SELECT job_hash FROM jobs WHERE provider_id = ? AND job_id = ?",
                         (body["provider_id"], body["job_id"])).fetchone()
        if row is None:
            db.execute("INSERT INTO jobs VALUES (?, ?, ?)", (body["provider_id"], body["job_id"], body["job_hash"]))
        elif row["job_hash"] != body["job_hash"]:
            raise ProtocolError("PG_JOB_CONFLICT", "this job_id is bound to another job", status=409)
        rid = message_id("pg.request.v1", body)
        ask = db.execute("SELECT * FROM asks WHERE provider_id = ? AND job_id = ? AND subject_ref = ?",
                         (body["provider_id"], body["job_id"], body["subject_ref"])).fetchone()
        if ask is None:
            db.execute("INSERT INTO asks (id, provider_id, job_id, subject_ref, request) VALUES (?, ?, ?, ?, ?)",
                       (rid, body["provider_id"], body["job_id"], body["subject_ref"], json.dumps(body)))
            ask = db.execute("SELECT * FROM asks WHERE id = ?", (rid,)).fetchone()
        elif ask["id"] != rid:
            raise ProtocolError("PG_ASK_CONFLICT", "this subject of the job was asked with another request", status=409)
        return ask

    def _decide(self, db, req: dict, now: int):
        """(status, reason, grant row, level) under likeness/1. Floor first, then grants."""
        parsed = parse_code(req["subject_ref"])
        if parsed is not None and parsed[0] != self.config.prefix:
            return "deny", "PG_OTHER_REGISTRY", None, "self"
        s = db.execute("SELECT * FROM subjects WHERE code = ?", (req["subject_ref"],)).fetchone()
        if s is None:
            return "deny", "PG_UNKNOWN_SUBJECT", None, "self"
        use, level = req["use"], s["level"]
        categories = set(use.get("categories", []))
        if s["status"] in UNAVAILABLE:
            return "deny", "PG_SUBJECT_UNAVAILABLE", None, level
        if s["opted_out"]:
            return "deny", "PG_SUBJECT_OPTED_OUT", None, level
        if s["fixed_refusal"] or (s["minor"] and categories & PROHIBITED_FOR_MINORS):
            return "deny", s["fixed_refusal"] or "PG_PROHIBITED_USE", None, level
        if categories & set(json.loads(s["immutable_denials"])):
            return "deny", "PG_IMMUTABLE_DENIAL", None, level
        intimate = categories & INTIMATE
        if intimate and (s["custody"] != "self" or level != "verified"):
            return "deny", "PG_PERSONAL_SIGNATURE_REQUIRED", None, level
        if s["review"]:
            return "review", "PG_REVIEW_REQUIRED", None, level
        licensee, provider = req.get("licensee_id", ""), req["provider_id"]
        grants = [g for g in db.execute(
            "SELECT * FROM grants WHERE subject_code = ? AND not_before <= ? AND expires_at > ? ORDER BY not_before",
            (s["code"], now, now)).fetchall()
            # catalog.md: an open grant, a grant to this licensee, or the provider's own grant — which covers
            # its users only with the resale right
            if g["licensee_id"] in ("", licensee) or (g["licensee_id"] == provider and (not licensee or g["resale"]))]
        fitting = [g for g in grants if use["purpose"] in json.loads(g["purposes"])
                   and intimate <= set(json.loads(g["categories"]))]
        if not fitting:
            reason = "PG_SCOPE_VIOLATION" if grants else "PG_NO_LICENSE"
            return s["no_grant_status"], reason, None, level
        for g in fitting:                                   # extensions/limits.md: reserve a use if any is left
            if g["max_uses"] is None:
                return "allow", None, g, level
            used = db.execute("SELECT COUNT(*) FROM answers WHERE grant_id = ? AND use IN ('reserved', 'consumed')",
                              (g["id"],)).fetchone()[0] + g["uses_offset"]
            if used < g["max_uses"]:
                return "allow", None, g, level
        return "deny", "PG_USAGE_LIMIT", None, level

    def _answer(self, db, ask, req: dict, now: int) -> dict:
        status, reason, grant, level = self._decide(db, req, now)
        body = {"request_id": ask["id"], "profile": req["profile"], "status": status, "level": level,
                "obligations": [], "issued_at": now, "expires_at": now + TTL}
        if status == "allow":
            body["basis"] = {"kind": "grant", "grant": {"format": "pg.grant.v1", "id": grant["id"]}}
        else:
            body["reason"] = reason
        if self.config.sandbox:
            body["ext"] = {"sandbox": True}
        env = seal("pg.answer.v1", body, [("registry", self.key)])
        use = "reserved" if status == "allow" else None   # catalog.md: every allow is billed unless given back
        db.execute("INSERT INTO answers VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                   (message_id(env["type"], env["body"]), ask["id"], json.dumps(env), status, now, now + TTL,
                    grant["id"] if grant is not None else None, use))
        return env

    # ── extension provider-keys ──────────────────────────────────────────
    def _chain(self, db, provider_id: str) -> list[dict]:
        return [json.loads(r["envelope"]) for r in db.execute(
            "SELECT envelope FROM keysets WHERE provider_id = ? ORDER BY position", (provider_id,))]

    @staticmethod
    def _current(keyset_body: dict) -> dict:
        return next(k for k in keyset_body["keys"] if k["status"] == "current")

    def post_keyset(self, provider_id: str, authorization: str | None, env) -> dict:
        self.authenticate(provider_id, authorization)
        if not isinstance(env, dict) or env.get("type") != "pg.keyset.v1" or not isinstance(env.get("body"), dict):
            raise ProtocolError("PG_MALFORMED", "expected a pg.keyset.v1 envelope")
        body = env["body"]
        check_body("keyset", body)
        if body["provider_id"] != provider_id or [k["status"] for k in body["keys"]].count("current") != 1:
            raise ProtocolError("PG_MALFORMED", "provider_id, and exactly one current key")
        kid = message_id(env["type"], body)
        with self.tx() as db:
            chain = self._chain(db, provider_id)
            if any(message_id(k["type"], k["body"]) == kid for k in chain):
                return {"keyset": env}                                   # the identical keyset again
            new = self._current(body)
            pubs = {"provider": new}
            if body["kind"] == "first":
                if chain:
                    raise ProtocolError("PG_KEYSET_CONFLICT", "this provider already has a key chain", status=409)
                roles = ("provider",)
            elif body["kind"] == "rotation":
                if not chain or body["previous"] != message_id("pg.keyset.v1", chain[-1]["body"]):
                    raise ProtocolError("PG_KEYSET_CONFLICT", "does not chain to the current keyset", status=409)
                if body["recovery_registry"] != chain[-1]["body"]["recovery_registry"]:
                    raise ProtocolError("PG_MALFORMED", "only a recovery keyset may change recovery_registry")
                pubs["provider_previous"], roles = self._current(chain[-1]["body"]), ("provider", "provider_previous")
            else:
                raise ProtocolError("PG_UNSUPPORTED", "recovery is co-signed by the recovery registry; "
                                    "ask the registry operator", status=422)
            check_envelope(env, "pg.keyset.v1", roles,
                           lambda role, key_id: pubs[role]["public_key_hex"] if pubs[role]["key_id"] == key_id else None)
            db.execute("INSERT INTO keysets VALUES (?, ?, ?, ?)", (provider_id, len(chain), kid, json.dumps(env)))
            return {"keyset": env}

    def get_keysets(self, provider_id: str) -> dict:
        with self.lock:
            return {"provider_id": provider_id, "keysets": self._chain(self.db, provider_id)}

    # ── extension reports (+ limits, observe) ────────────────────────────
    def report(self, provider_id: str, authorization: str | None, env) -> dict:
        self.authenticate(provider_id, authorization)
        if not isinstance(env, dict) or env.get("type") != "pg.report.v1" or not isinstance(env.get("body"), dict):
            raise ProtocolError("PG_MALFORMED", "expected a pg.report.v1 envelope")
        body = env["body"]
        check_body("report", body)
        rid = message_id(env["type"], body)
        stored = self._row("SELECT ack FROM reports WHERE id = ? AND provider_id = ?", (rid, provider_id))
        if stored:                                         # identical report: the stored ack, before key status
            return {"ack": json.loads(stored["ack"])}
        with self.lock:
            chain = self._chain(self.db, provider_id)
        if not chain:
            raise ProtocolError("PG_NOT_AUTHENTICATED", "register a provider signing key first (POST /v2/keys)", status=401)
        current = self._current(chain[-1]["body"])
        check_envelope(env, "pg.report.v1", ("provider",),
                       lambda role, key_id: current["public_key_hex"] if key_id == current["key_id"] else None)
        with self.tx() as db:
            stored = db.execute("SELECT ack FROM reports WHERE id = ? AND provider_id = ?", (rid, provider_id)).fetchone()
            if stored:
                return {"ack": json.loads(stored["ack"])}
            if body["answer"] is None:
                req = body["request"]
                if message_id("pg.request.v1", req) != body["request_id"] or req["provider_id"] != provider_id:
                    raise ProtocolError("PG_MALFORMED", "request does not match request_id")
                ask, ans = self._bind(db, req), None
            else:
                ans = db.execute("SELECT * FROM answers WHERE id = ?", (body["answer"],)).fetchone()
                ask = db.execute("SELECT * FROM asks WHERE id = ?", (ans["ask_id"],)).fetchone() if ans else None
                if not ask or ask["id"] != body["request_id"] or ask["provider_id"] != provider_id:
                    raise ProtocolError("PG_MALFORMED", "unknown answer")
            request = json.loads(ask["request"])
            if body.get("mode", "enforce") != request.get("mode", "enforce"):
                raise ProtocolError("PG_MALFORMED", "mode differs from the request's")
            if (ans is not None and ans["report_id"]) or (ans is None and ask["null_report"]) \
                    or (body["outcome"] == "generated" and ask["closing_ack"]):
                raise ProtocolError("PG_REPORT_CONFLICT", "a different report exists for this answer or subject",
                                    status=409)
            now = self.clock()
            counted, released = self._account(db, ask["id"], body, now)
            ack = seal("pg.report_ack.v1", {
                "report": rid, "answer": body["answer"], "answer_status": ans["status"] if ans else "none",
                "counted": counted, "released": released, "provider_key_id": current["key_id"], "received_at": now},
                [("registry", self.key)])
            db.execute("INSERT INTO reports VALUES (?, ?, ?, ?, ?)", (rid, provider_id, ask["id"], json.dumps(env),
                                                                       json.dumps(ack)))
            if ans is not None:
                db.execute("UPDATE answers SET report_id = ? WHERE id = ?", (rid, ans["id"]))
            else:
                db.execute("UPDATE asks SET null_report = ? WHERE id = ?", (rid, ask["id"]))
            if body["outcome"] == "generated":
                db.execute("UPDATE asks SET closing_ack = ? WHERE id = ?", (json.dumps(ack), ask["id"]))
            return {"ack": ack}

    def _account(self, db, ask_id: str, body: dict, now: int):
        """extensions/limits.md."""
        reserved = db.execute("SELECT id, issued_at FROM answers WHERE ask_id = ? AND use = 'reserved' "
                              "ORDER BY issued_at, id", (ask_id,)).fetchall()
        released = []
        give_back = lambda a: now - a["issued_at"] <= GIVE_BACK_WINDOW  # noqa: E731
        if body["outcome"] == "generated":
            named = next((a for a in reserved if a["id"] == body["answer"]), None)
            pick = named or (reserved[0] if reserved else None)
            for a in reserved:
                if pick is not None and a["id"] == pick["id"]:
                    db.execute("UPDATE answers SET use = 'consumed' WHERE id = ?", (a["id"],))
                elif give_back(a):
                    db.execute("UPDATE answers SET use = 'released' WHERE id = ?", (a["id"],))
                    released.append(a["id"])
            return (pick["id"] if pick is not None else None), released
        own = next((a for a in reserved if a["id"] == body["answer"]), None)
        if own is not None and give_back(own):
            db.execute("UPDATE answers SET use = 'released' WHERE id = ?", (own["id"],))
            released.append(own["id"])
        return None, released

    # ── extensions grants, lookup; publication ──────────────────────────
    def grant(self, grant_id: str) -> dict:
        row = self._row("SELECT envelope FROM grants WHERE id = ?", (grant_id,))
        if not row:
            raise ProtocolError("PG_NOT_FOUND", "no such grant", status=404)
        return {"grant": json.loads(row["envelope"])}

    def lookup(self, code: str) -> dict:
        parsed = parse_code(code)
        if parsed is None:
            raise ProtocolError("PG_MALFORMED", "not a PG subject code (or its check character is wrong)")
        if parsed[0] != self.config.prefix:
            return {"code": code, "registry": parsed[0], "status": "other_registry"}
        s = self._row("SELECT * FROM subjects WHERE code = ?", (code,))
        if s is None or not s["published"]:
            return {"code": code, "registry": self.config.prefix, "status": "unknown"}
        return {"code": code, "registry": self.config.prefix, "status": "active", "name": s["name"], "level": s["level"],
                "subject_key": {"key_id": fingerprint(s["key_public"]),
                                "public_key_hex": s["key_public"], "custody": s["custody"]}}

    def anchors(self) -> dict:
        """identity.md: every anchored subject, signed, with its status, so a refusal is visible across registries."""
        rows = self._q("SELECT * FROM subjects WHERE anchor IS NOT NULL ORDER BY serial")
        status = lambda s: "opted_out" if s["opted_out"] else (s["status"] if s["status"] in UNAVAILABLE else "active")  # noqa: E731
        return seal("pg.anchors.v1", {"registry": self.config.prefix, "issued_at": self.clock(), "anchors": [
            {"anchor": s["anchor"], "code": s["code"], "level": s["level"], "proof_url": s["proof_url"] or "",
             "status": status(s)} for s in rows]}, [("registry", self.key)])

    def catalog(self) -> dict:
        """catalog.md: subjects who chose to be offered. A listing is not a permission: every generation still asks."""
        rows = self._q("SELECT * FROM subjects WHERE offer IS NOT NULL AND opted_out = 0 ORDER BY serial")
        return {"registry": self.config.prefix, "offers": [
            {"subject_ref": s["code"], "name": s["name"], "anchor": s["anchor"] or "", "level": s["level"],
             **json.loads(s["offer"])} for s in rows if s["status"] not in UNAVAILABLE]}

    def statement(self, provider_id: str, authorization: str | None) -> dict:
        """catalog.md: what a provider owes, from the allows the registry issued — not from the provider's reports.
        An allow given back within the window (limits.md) is not billed."""
        self.authenticate(provider_id, authorization)
        rows = self._q("SELECT a.grant_id, a.use, COUNT(*) AS n FROM answers a JOIN asks k ON k.id = a.ask_id "
                       "WHERE k.provider_id = ? AND a.status = 'allow' GROUP BY a.grant_id, a.use ORDER BY a.grant_id",
                       (provider_id,))
        out: dict = {}
        for r in rows:
            g = out.setdefault(r["grant_id"], {"grant": r["grant_id"], "billed": 0, "given_back": 0})
            g["given_back" if r["use"] == "released" else "billed"] += r["n"]
        return {"provider_id": provider_id, "grants": list(out.values())}

    def proof(self, short_id: str) -> dict:
        """proof.md: the part of a proof this registry holds, found from the id a watermark carries."""
        if not re.fullmatch(r"[0-9a-f]{16}", short_id):
            raise ProtocolError("PG_MALFORMED", "a proof id is 16 hex characters")
        rows = self._q("SELECT r.envelope AS report, r.ack, k.request, a.envelope AS answer FROM reports r "
                       "JOIN asks k ON k.id = r.ask_id JOIN answers a ON a.report_id = r.id "
                       "WHERE r.id LIKE ? AND k.closing_ack IS NOT NULL", (short_id + "%",))
        if len(rows) != 1:
            raise ProtocolError("PG_NOT_FOUND", "no such proof", status=404)
        r = rows[0]
        return {"format": "pg.proof.v1", "subjects": [{
            "request": {"type": "pg.request.v1", "body": json.loads(r["request"]), "signatures": []},
            "answer": json.loads(r["answer"]), "report": json.loads(r["report"]), "ack": json.loads(r["ack"])}]}

    def document(self) -> dict:
        api = self.config.api.rstrip("/")
        return {"prefix": self.config.prefix, "name": self.config.name, "api": api, "keys": api + "/keys",
                "profiles": self.config.profiles, "extensions": EXTENSIONS + (["sandbox"] if self.config.sandbox else []),
                "policy": self.config.policy, "complaints": self.config.complaints, "sandbox": self.config.sandbox,
                "spec": "PRE-GEN v5"}

    def key_set(self) -> dict:
        """PRE-GEN-SPEC.md §2.3: self-signed; trust comes from the directory, never from this list alone."""
        body = {"current_key_id": self.key.id, "keys": [{
            "key_id": self.key.id, "public_key_hex": self.key.public_hex, "activated_at": self.activated_at,
            "deactivated_at": None, "status": "active", "is_ephemeral": False}]}
        return {**body, "signature": self.key.sign(canonical(body))}
