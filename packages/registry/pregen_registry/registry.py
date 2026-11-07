"""The registry: state in SQLite, the core rules, profile likeness/1 and the extensions
reports, provider-keys, limits, jobs, grants, licensee, observe, sandbox, lookup and provider-identity.

ponytail: one process-wide lock around one SQLite connection serializes every write. That is the
spec's three locks (provider+job, ask, grant counter) collapsed into one: correct, simple, and enough
for a sandbox or a small registry. Per-row locks on Postgres when throughput matters.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import secrets
import socket
import sqlite3
import threading
import time
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field

from pregen import PregenError, check_provider_url, check_public_key, fingerprint, issuer_of
from urllib.parse import urlsplit

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
# provider-identity P-5: a refusal of the person is never masked, whoever asks
FLOOR = {"PG_SUBJECT_OPTED_OUT", "PG_SUBJECT_UNAVAILABLE", "PG_PROHIBITED_USE", "PG_IMMUTABLE_DENIAL",
         "PG_PERSONAL_SIGNATURE_REQUIRED"}
PARTY_REFRESH = 86400           # provider-identity P-3: the party document is read again at least daily
PARTY_MIN_INTERVAL = 60         # P-7: and at most once a minute per provider
PARTY_MAX_BYTES = 65536

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS operator_keys (key_id TEXT PRIMARY KEY, public_key_hex TEXT NOT NULL,
  activated_at INTEGER NOT NULL, deactivated_at INTEGER);
CREATE TABLE IF NOT EXISTS subjects (
  code TEXT PRIMARY KEY, serial INTEGER UNIQUE NOT NULL, name TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active', level TEXT NOT NULL DEFAULT 'self', published INTEGER NOT NULL DEFAULT 0,
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
CREATE TABLE IF NOT EXISTS accepted (provider_id TEXT PRIMARY KEY);
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
    providers: str = "registered"   # "open": providers known by their domain (provider-identity); a sandbox always is

    def __post_init__(self):
        if not re.fullmatch(r"[ABCDEFGHJKMNPQRSTVWXYZ]{4}", self.prefix):
            raise ValueError("a registry's prefix is four letters of the PG alphabet (new codes are never bare, PG-CODE.md §9)")
        if self.providers not in ("open", "registered"):
            raise ValueError("providers is open or registered")
        if self.sandbox:
            self.providers = "open"


def fetch_party(provider_url: str) -> dict:
    """GET {provider URL}/.well-known/pregen-party.json (provider-identity P-2): HTTPS, no redirect, 64 KB, 10 s; a
    host on a private, loopback or link-local address is refused. ponytail: the address is checked before the fetch,
    not on the socket; a production registry closes that gap with a resolver that pins the checked address."""
    host = urlsplit(provider_url).hostname or ""
    for info in socket.getaddrinfo(host, 443):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise ValueError(f"{host} resolves to a private address")

    class Stay(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    req = urllib.request.Request(provider_url + "/.well-known/pregen-party.json",
                                 headers={"Accept": "application/json", "User-Agent": "pregen-registry"})
    with urllib.request.build_opener(Stay).open(req, timeout=10) as res:
        data = res.read(PARTY_MAX_BYTES + 1)
    if len(data) > PARTY_MAX_BYTES:
        raise ValueError("party document over 64 KB")
    return json.loads(data)


class Registry:
    def __init__(self, config: Config, operator_key: Key, db_path: str = ":memory:", clock=lambda: int(time.time()),
                 fetch_party=fetch_party):
        self.config, self.key, self.clock, self.fetch_party = config, operator_key, clock, fetch_party
        self.db = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.lock = threading.RLock()  # one sqlite connection: every use of it holds this lock
        self.activated_at = int(self._meta("activated_at") or self._set_meta("activated_at", str(clock())))
        self._record_key()

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

    def _record_key(self):
        """Every operator key this registry ever signed with stays in /keys (PRE-GEN-SPEC.md §2.3): starting on a new
        key retires the previous one and never forgets it, so earlier answers and proofs stay verifiable (stress
        test C2). A retired key never signs again."""
        with self.tx() as db:
            row = db.execute("SELECT deactivated_at FROM operator_keys WHERE key_id = ?", (self.key.id,)).fetchone()
            if row is not None:
                if row["deactivated_at"] is not None:
                    raise ValueError(f"{self.key.id} is retired: a retired key never signs again")
                return
            now, first = self.clock(), db.execute("SELECT COUNT(*) FROM operator_keys").fetchone()[0] == 0
            db.execute("UPDATE operator_keys SET deactivated_at = ? WHERE deactivated_at IS NULL", (now,))
            db.execute("INSERT INTO operator_keys VALUES (?, ?, ?, NULL)",
                       (self.key.id, self.key.public_hex, self.activated_at if first else now))
            db.execute("DELETE FROM meta WHERE k = 'next_key'")                # the announced key now signs

    def announce_next_key(self, public_key_hex: str):
        """The next operator key, listed in /keys with status `next` until it signs, so the steward can match the
        key id an application names against this registry's own domain."""
        check_public_key(public_key_hex)
        with self.tx() as db:
            db.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('next_key', ?)", (public_key_hex,))

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
        if holder_public:
            check_public_key(holder_public)          # a small-order key would let anyone sign as the person (C1)
        # A real person's name is public at /v2/codes only by their choice; a sandbox holds no real people.
        flags.setdefault("published", int(self.config.sandbox))
        with self.tx() as db:
            if serial is None:
                serial = (db.execute("SELECT COALESCE(MAX(serial), 0) FROM subjects").fetchone()[0] or 0) + 1
                if self.config.sandbox:                     # 1-8 are the standard test codes; 8 stays unregistered
                    serial = max(serial, 9)
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

    def set_published(self, code: str, published: bool):
        """lookup.md: a code's name and level are public only if the rights holder chose to publish them."""
        with self.tx() as db:
            if not db.execute("UPDATE subjects SET published = ? WHERE code = ?", (int(published), code)).rowcount:
                raise ValueError(f"no subject {code} in this registry")

    def set_level(self, code: str, level: str):
        """How far the registry has established who holds the person's rights; answers carry it from now on."""
        if level not in ("self", "asserted", "consented", "verified"):
            raise ValueError(f"unknown level {level}")
        with self.tx() as db:
            if not db.execute("UPDATE subjects SET level = ? WHERE code = ?", (level, code)).rowcount:
                raise ValueError(f"no subject {code} in this registry")

    def opt_out(self, code: str):
        """The person opted out or withdrew: every answer from now on is PG_SUBJECT_OPTED_OUT (core rule 3)."""
        with self.tx() as db:
            if not db.execute("UPDATE subjects SET opted_out = 1 WHERE code = ?", (code,)).rowcount:
                raise ValueError(f"no subject {code} in this registry")

    def revoke_grant(self, grant_id: str):
        """The grant ends now: no answer from now on rests on it. Answers already given stay what they were."""
        with self.tx() as db:
            if not db.execute("UPDATE grants SET expires_at = MIN(expires_at, ?) WHERE id = ?",
                              (self.clock(), grant_id)).rowcount:
                raise ValueError(f"no grant {grant_id} in this registry")

    def remove_provider(self, provider_id: str):
        """Its token stops working at once, and its licensee connections go; its registered keys stay on record."""
        with self.tx() as db:
            if not db.execute("DELETE FROM providers WHERE provider_id = ?", (provider_id,)).rowcount:
                raise ValueError(f"no provider {provider_id} in this registry")
            db.execute("DELETE FROM connections WHERE provider_id = ?", (provider_id,))

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
        if self.is_open(provider_id):
            raise ProtocolError("PG_NOT_AUTHENTICATED", "a provider known by its domain signs its messages; a GET sends "
                                "PG-Access (extensions/provider-identity.md)", status=401)
        token = (authorization or "").removeprefix("Bearer ").strip()
        row = self._row("SELECT token_hash FROM providers WHERE provider_id = ?", (provider_id or "",))
        if not row or not token or not secrets.compare_digest(row["token_hash"], _hash_token(token)):
            raise ProtocolError("PG_NOT_AUTHENTICATED", "unknown provider or credential", status=401)

    # ── core: requests ───────────────────────────────────────────────────
    def request(self, provider_id: str, authorization: str | None, env) -> dict:
        if self.is_open(provider_id):            # provider-identity P-1: signed with the current key of its chain
            self._check_open(provider_id, authorization)
            body = self._signed_by_provider(env, "pg.request.v1", provider_id)
        else:
            body = check_envelope(env, "pg.request.v1", (), lambda *_: None)
        check_body("request", body)
        try:                                     # one code, one string: never a signed answer to another spelling (H5)
            issuer_of(body["subject_ref"])
        except PregenError:
            raise ProtocolError("PG_MALFORMED", "subject_ref is not a canonical PG code (PG-CODE.md §7)") from None
        if not self.is_open(provider_id):
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
            if not grants and not licensee and db.execute(  # licensee.md: only one of this provider's customers would do
                    "SELECT 1 FROM grants WHERE subject_code = ? AND not_before <= ? AND expires_at > ? "
                    "AND instr(licensee_id, ? || ':') = 1", (s["code"], now, now, provider)).fetchone():
                reason = "PG_NOT_CONNECTED"
            return s["no_grant_status"], reason, None, level
        for g in fitting:                                   # extensions/limits.md: reserve a use if any is left
            if g["max_uses"] is None:
                return "allow", None, g, level
            used = db.execute("SELECT COUNT(*) FROM answers WHERE grant_id = ? AND use IN ('reserved', 'consumed')",
                              (g["id"],)).fetchone()[0] + g["uses_offset"]
            if used < g["max_uses"]:
                return "allow", None, g, level
        return "deny", "PG_USAGE_LIMIT", None, level

    def _masked(self, db, req: dict, status: str, reason, grant) -> bool:
        """provider-identity P-5a: a provider this registry has not vetted learns a refusal of the person, a published
        subject, and what its own bound licensee holds; everything else is deny PG_PROVIDER_NOT_ACCEPTED."""
        pid = req["provider_id"]
        if not self.is_open(pid) or self.config.sandbox or reason in FLOOR or reason == "PG_OTHER_REGISTRY" \
                or db.execute("SELECT 1 FROM accepted WHERE provider_id = ?", (pid,)).fetchone():
            return False
        s = db.execute("SELECT published, fixed_refusal FROM subjects WHERE code = ?", (req["subject_ref"],)).fetchone()
        if s is not None and (s["published"] or (s["fixed_refusal"] and reason == s["fixed_refusal"])):
            return False
        licensee = req.get("licensee_id", "")
        return not (status == "allow" and licensee and grant["licensee_id"] == licensee)

    def _answer(self, db, ask, req: dict, now: int) -> dict:
        status, reason, grant, level = self._decide(db, req, now)
        if self._masked(db, req, status, reason, grant):
            status, reason, grant = "deny", "PG_PROVIDER_NOT_ACCEPTED", None
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

    # ── extension provider-identity: providers known by their domain ─────
    @staticmethod
    def is_open(provider_id: str) -> bool:
        return isinstance(provider_id, str) and provider_id.startswith("https://")

    def _check_open(self, provider_id: str, authorization: str | None):
        if self.config.providers != "open":
            raise ProtocolError("PG_NOT_AUTHENTICATED", "this registry issues its own credentials (providers: registered)",
                                status=401)
        if authorization:
            raise ProtocolError("PG_NOT_AUTHENTICATED", "a provider known by its domain sends no credential (P-1)",
                                status=401)
        try:
            check_provider_url(provider_id, allow_port=self.config.sandbox)
        except PregenError as e:
            raise ProtocolError("PG_NOT_AUTHENTICATED", str(e), status=401) from None

    def accept_provider(self, provider_id: str):
        """P-6: vetted under the registry's published procedure; from now on it gets ordinary answers."""
        check_provider_url(provider_id, allow_port=self.config.sandbox)
        with self.tx() as db:
            db.execute("INSERT OR IGNORE INTO accepted VALUES (?)", (provider_id,))

    def pin_party(self, doc, provider_id: str | None = None, posted: bool = False) -> str:
        """A party document's keysets onto the provider's chain (P-2). Fetched from the domain, or posted to a
        sandbox, which holds no real people and takes the document by post because a laptop has no domain."""
        if posted and not self.config.sandbox:
            raise ProtocolError("PG_NOT_FOUND", "this registry is not a sandbox: it reads the party document from your "
                                "domain", status=404)
        check_body("party-document", doc)
        pid = doc["party_id"]
        if provider_id is not None and pid != provider_id:
            raise ProtocolError("PG_MALFORMED", "party_id differs from the provider id")
        try:
            check_provider_url(pid, allow_port=self.config.sandbox)
        except PregenError as e:
            raise ProtocolError("PG_MALFORMED", str(e)) from None
        for env in doc["keysets"]:
            self._keyset_shape(env, pid)
        with self.tx() as db:
            for env in doc["keysets"]:
                try:
                    self._accept_keyset(db, pid, env)
                except ProtocolError as e:
                    if e.code != "PG_KEYSET_CONFLICT":
                        raise
                    raise ProtocolError("PG_NOT_AUTHENTICATED", "the party document does not extend the pinned chain "
                                        "(P-2); whoever takes over a domain does not get its keys", status=401) from None
            db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", ("party:" + pid, "posted" if posted else str(self.clock())))
        return pid

    def _open_chain(self, provider_id: str, key_id: str) -> list[dict]:
        """The pinned chain of a provider known by its domain. Its party document is read when nothing is pinned, when
        a message names a key the chain does not hold, and at least daily (P-2, P-3); at most once a minute (P-7)."""
        with self.lock:
            chain = self._chain(self.db, provider_id)
        last = self._meta("party:" + provider_id) or ""
        stale = chain and last != "posted" and (key_id != self._current(chain[-1]["body"])["key_id"]
                                                or self.clock() - float(last or 0) > PARTY_REFRESH)
        if (not chain or stale) and (not last.replace(".", "").isdigit() or self.clock() - float(last) >= PARTY_MIN_INTERVAL):
            self._set_meta("party:" + provider_id, str(self.clock()))                  # budget the attempt, not the success
            try:
                self.pin_party(self.fetch_party(provider_id), provider_id)
            except ProtocolError as e:
                raise ProtocolError("PG_NOT_AUTHENTICATED", f"party document: {e.detail}", status=401) from None
            except Exception as e:
                raise ProtocolError("PG_NOT_AUTHENTICATED", f"party document not read from {provider_id}: {e}",
                                    status=401) from None
            with self.lock:
                chain = self._chain(self.db, provider_id)
        if not chain:
            raise ProtocolError("PG_NOT_AUTHENTICATED", "no keys known for this provider: serve "
                                "/.well-known/pregen-party.json on its domain", status=401)
        return chain

    @staticmethod
    def _signer_key_id(env) -> str:
        signers = env.get("body", {}).get("signers") if isinstance(env, dict) and isinstance(env.get("body"), dict) else None
        return signers[0].get("key_id", "") if isinstance(signers, list) and signers and isinstance(signers[0], dict) else ""

    def _signed_by_provider(self, env, type_: str, provider_id: str) -> dict:
        chain = self._open_chain(provider_id, self._signer_key_id(env))
        current = self._current(chain[-1]["body"])
        return check_envelope(env, type_, ("provider",),
                              lambda role, key_id: current["public_key_hex"] if key_id == current["key_id"] else None)

    def authenticate_read(self, provider_id: str, authorization: str | None, pg_access: str | None, method: str,
                          path: str) -> str:
        """A GET: the registry's credential, or `PG-Access`, a pg.access.v1 envelope (base64url) signed by a provider
        known by its domain, naming this method and path and issued within 60 seconds. Returns the provider id."""
        if not pg_access:
            self.authenticate(provider_id, authorization)
            return provider_id
        try:
            env = json.loads(base64.urlsafe_b64decode(pg_access + "=" * (-len(pg_access) % 4)))
        except Exception:
            raise ProtocolError("PG_NOT_AUTHENTICATED", "PG-Access is not a base64url pg.access.v1 envelope", status=401) from None
        pid = env.get("body", {}).get("provider_id", "") if isinstance(env, dict) and isinstance(env.get("body"), dict) else ""
        if provider_id and provider_id != pid:
            raise ProtocolError("PG_NOT_AUTHENTICATED", "PG-Access names another provider", status=401)
        self._check_open(pid, authorization)
        body = self._signed_by_provider(env, "pg.access.v1", pid)
        check_body("access", body)
        if body["aud"] != self.config.api.rstrip("/") or body["method"] != method.upper() or body["path"] != path \
                or abs(self.clock() - body["issued_at"]) > 60:
            raise ProtocolError("PG_NOT_AUTHENTICATED", "PG-Access names another registry or request, or is older than "
                                "60 seconds", status=401)
        return pid

    # ── extension provider-keys ──────────────────────────────────────────
    def _chain(self, db, provider_id: str) -> list[dict]:
        return [json.loads(r["envelope"]) for r in db.execute(
            "SELECT envelope FROM keysets WHERE provider_id = ? ORDER BY position", (provider_id,))]

    @staticmethod
    def _current(keyset_body: dict) -> dict:
        return next(k for k in keyset_body["keys"] if k["status"] == "current")

    def _keyset_shape(self, env, provider_id: str) -> dict:
        if not isinstance(env, dict) or env.get("type") != "pg.keyset.v1" or not isinstance(env.get("body"), dict):
            raise ProtocolError("PG_MALFORMED", "expected a pg.keyset.v1 envelope")
        body = env["body"]
        check_body("keyset", body)
        if body["provider_id"] != provider_id or [k["status"] for k in body["keys"]].count("current") != 1:
            raise ProtocolError("PG_MALFORMED", "provider_id, and exactly one current key")
        for k in body["keys"]:                       # stress test C1: a key no one can be held to is never recorded
            try:
                check_public_key(k["public_key_hex"])
            except PregenError as e:
                raise ProtocolError("PG_MALFORMED", f"{k['key_id']}: {e}") from None
        return body

    def _accept_keyset(self, db, provider_id: str, env) -> dict:
        """One keyset onto the provider's chain: the identical one again is a no-op; a first with a chain, or a rotation
        that does not chain, is PG_KEYSET_CONFLICT."""
        body = env["body"]
        kid = message_id(env["type"], body)
        chain = self._chain(db, provider_id)
        if any(message_id(k["type"], k["body"]) == kid for k in chain):
            return env                                                   # the identical keyset again
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
        return env

    def post_keyset(self, provider_id: str, authorization: str | None, env) -> dict:
        if self.is_open(provider_id):
            raise ProtocolError("PG_NOT_AUTHENTICATED", "a provider known by its domain publishes its keys in its party "
                                "document; there is nothing to post", status=401)
        self.authenticate(provider_id, authorization)
        self._keyset_shape(env, provider_id)
        with self.tx() as db:
            return {"keyset": self._accept_keyset(db, provider_id, env)}

    def get_keysets(self, provider_id: str) -> dict:
        with self.lock:
            return {"provider_id": provider_id, "keysets": self._chain(self.db, provider_id)}

    # ── extension reports (+ limits, observe) ────────────────────────────
    def report(self, provider_id: str, authorization: str | None, env) -> dict:
        if self.is_open(provider_id):
            self._check_open(provider_id, authorization)
        else:
            self.authenticate(provider_id, authorization)
        if not isinstance(env, dict) or env.get("type") != "pg.report.v1" or not isinstance(env.get("body"), dict):
            raise ProtocolError("PG_MALFORMED", "expected a pg.report.v1 envelope")
        body = env["body"]
        check_body("report", body)
        rid = message_id(env["type"], body)
        stored = self._row("SELECT ack FROM reports WHERE id = ? AND provider_id = ?", (rid, provider_id))
        if stored:                                         # identical report: the stored ack, before key status
            return {"ack": json.loads(stored["ack"])}
        if self.is_open(provider_id):
            chain = self._open_chain(provider_id, self._signer_key_id(env))
        else:
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

    def statement(self, provider_id: str, authorization: str | None, pg_access: str | None = None,
                  path: str = "/v2/statement") -> dict:
        """catalog.md: what a provider owes, from the allows the registry issued — not from the provider's reports.
        An allow given back within the window (limits.md) is not billed."""
        provider_id = self.authenticate_read(provider_id, authorization, pg_access, "GET", path)
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
                "profiles": self.config.profiles, "extensions": EXTENSIONS + (["sandbox"] if self.config.sandbox else [])
                + (["provider-identity"] if self.config.providers == "open" else []),
                "policy": self.config.policy, "complaints": self.config.complaints, "sandbox": self.config.sandbox,
                "providers": self.config.providers, "spec": "PRE-GEN v5"}

    def key_set(self) -> dict:
        """PRE-GEN-SPEC.md §2.3: every key ever signed with, current and retired, and the announced next key; self-signed,
        so trust comes from the directory, never from this list alone."""
        body = {"current_key_id": self.key.id, "keys": [{
            "key_id": r["key_id"], "public_key_hex": r["public_key_hex"], "activated_at": r["activated_at"],
            "deactivated_at": r["deactivated_at"], "status": "active" if r["deactivated_at"] is None else "retired",
            "is_ephemeral": False} for r in self._q("SELECT * FROM operator_keys ORDER BY rowid")]}
        nxt = self._row("SELECT v FROM meta WHERE k = 'next_key'")
        if nxt:
            body["keys"].append({"key_id": fingerprint(nxt["v"]), "public_key_hex": nxt["v"], "activated_at": None,
                                 "deactivated_at": None, "status": "next", "is_ephemeral": False})
        return {**body, "signature": self.key.sign(canonical(body))}
