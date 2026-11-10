"""The registry: state in SQLite, the core rules, profile likeness/1 and the extensions
reports, provider-keys, limits, jobs, grants, licensee, observe, sandbox, lookup, provider-identity, terms, after-gen
(spec/drafts/after-gen.md) and, in a sandbox, bind.

ponytail: one process-wide lock around one SQLite connection serializes every write. That is the
spec's three locks (provider+job, ask, grant counter) collapsed into one: correct, simple, and enough
for a sandbox or a small registry. Per-row locks on Postgres when throughput matters.
"""
from __future__ import annotations

import base64
from importlib import resources
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import threading
import time
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field

from pregen import (CATEGORIES, INTIMATE, PROHIBITED_FOR_MINORS, PregenError, check_provider_url, check_public_key,
                    fingerprint, forbids, issuer_of, terms_opens)
from urllib.parse import urlsplit

from .protocol import Key, ProtocolError, canonical, check_body, check_envelope, message_id, mint_code, parse_code, seal

PROFILE = "likeness/1"
EXTENSIONS = ["reports", "provider-keys", "limits", "jobs", "grants", "licensee", "observe", "lookup", "identity",
              "proof", "catalog"]
TTL = 300                       # seconds an answer stays valid (≤ 900)
GIVE_BACK_WINDOW = 86400        # likeness/1: 24 hours from issued_at
PURPOSES = {"personal", "educational", "research", "editorial", "commercial"}
USE_MEMBERS = {"purpose", "rights", "territory", "channel", "categories"}
TERMS_LEVELS = {"consented", "verified"}    # terms T-1: the person confirmed, or the registry verified
UNAVAILABLE = {"pending", "paused", "disputed", "withdrawn"}
PARTY_REFRESH = 86400           # provider-identity P-3: the party document is read again at least daily
PARTY_MIN_INTERVAL = 60         # P-7: and at most once a minute per provider
PARTY_MAX_BYTES = 65536
BIND_CODE_TTL = 60              # bind.md step 4: a code lives 60 seconds and is single-use
CONSENT_TTL = 600               # a consent page's one-time nonce: the person has ten minutes to answer it
BINDING_TTL = 365 * 86400       # pg.binding.v1: at most one year, then the person consents again
SANDBOX_HOLDER = "account:holder"   # sandbox.md serial 12: the test creator; an account's grants are reached only by bind
# extensions/sandbox.md, serial 10: a test template; its text governs nothing
SANDBOX_TEMPLATE = {"id": "pregen-sandbox", "version": 1, "jurisdiction": "US"}
AG_REVIEW = 14 * 86400          # after-gen.md step 3: the reference registry's review period; silence approves nothing
AG_SKEW = 300                   # a signed after-gen request, decision or withdrawal is this close to the registry's clock
AG_FACTORS = ("authenticator", "email")
AG_CONSTANTS = {"kind": "ratification", "label": "approved after generation",
                "notice": "Recorded after the content existed. Not a PRE-GEN permission given before generation. Says "
                          "nothing about whether the content is AI-generated.",
                "not": ["pre_generation_permission", "statement_of_origin"]}
AG_REQUEST_MEMBERS = {"signers", "requester", "subject_ref", "licence", "content", "scope", "issued_at", "nonce"}
AG_SCOPE_MEMBERS = {"purposes", "categories", "territories", "channels", "project", "not_after"}
AG_APPROVALS = {"self": {"assent", "decision"}, "registry": {"assent", "instruction", "factor"}}  # a mandate never approves
AG_OPEN = ("pending", "agent_refused")  # undecided by the person: an agency's refusal closes nothing for them
SANDBOX_LEGAL = {"sha256": hashlib.sha256(b"PRE-GEN sandbox template 1: a test record for test subjects. It governs "
                                          b"nothing.\n").hexdigest(),
                 "url": "https://www.pregen.org/test/terms-template-1.txt"}

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
  signatures TEXT NOT NULL DEFAULT '[]', UNIQUE (provider_id, job_id, subject_ref));
CREATE TABLE IF NOT EXISTS terms (id TEXT PRIMARY KEY, subject_code TEXT NOT NULL, version INTEGER NOT NULL,
  envelope TEXT NOT NULL, act TEXT NOT NULL, UNIQUE (subject_code, version));
CREATE TABLE IF NOT EXISTS answers (id TEXT PRIMARY KEY, ask_id TEXT NOT NULL, envelope TEXT NOT NULL,
  status TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, grant_id TEXT, use TEXT,
  report_id TEXT);
CREATE TABLE IF NOT EXISTS bind_consents (nonce_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS bind_codes (code_hash TEXT PRIMARY KEY, provider_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
  challenge TEXT NOT NULL, account TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0,
  binding TEXT);
CREATE TABLE IF NOT EXISTS bindings (licensee_id TEXT PRIMARY KEY, id TEXT NOT NULL, provider_id TEXT NOT NULL,
  account TEXT NOT NULL, grants TEXT NOT NULL, expires_at INTEGER NOT NULL, ended_at INTEGER, envelope TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, ask_id TEXT NOT NULL,
  envelope TEXT NOT NULL, ack TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS after_gen_requests (id TEXT PRIMARY KEY, requester TEXT NOT NULL, subject_ref TEXT NOT NULL,
  licence_id TEXT NOT NULL, media_hash TEXT NOT NULL, leaves INTEGER NOT NULL, scope TEXT NOT NULL, envelope TEXT NOT NULL,
  preview_url TEXT, review_hash TEXT, state TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL,
  decided_at INTEGER, record_id TEXT);
CREATE TABLE IF NOT EXISTS after_gen_records (id TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL, subject_ref TEXT NOT NULL,
  media_hash TEXT NOT NULL, licence_id TEXT NOT NULL, envelope TEXT NOT NULL, issued_at INTEGER NOT NULL,
  not_after INTEGER NOT NULL, withdrawn_at INTEGER, withdrawal TEXT, decision TEXT, UNIQUE (media_hash, licence_id));
CREATE INDEX IF NOT EXISTS after_gen_pending ON after_gen_requests (state, created_at);
CREATE TABLE IF NOT EXISTS mandates (id TEXT PRIMARY KEY, subject_ref TEXT NOT NULL, agent TEXT NOT NULL, powers TEXT NOT NULL,
  limits TEXT NOT NULL, not_after INTEGER NOT NULL, ended_at INTEGER, envelope TEXT NOT NULL);
"""


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _hex64(v) -> bool:
    return isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) is not None


def _int(v, low=0) -> bool:
    return type(v) is int and low <= v <= 2**53 - 1


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
    terms: bool = True              # extension terms: subjects may publish terms, and requests may accept them; open only
    after_gen: bool | None = None   # after-gen (draft): on in a sandbox unless set; off in production unless set

    def __post_init__(self):
        if not re.fullmatch(r"[ABCDEFGHJKMNPQRSTVWXYZ]{4}", self.prefix):
            raise ValueError("a registry's prefix is four letters of the PG alphabet (new codes are never bare, PG-CODE.md §9)")
        if self.providers not in ("open", "registered"):
            raise ValueError("providers is open or registered")
        if self.sandbox:
            self.providers = "open"
        self.terms = self.terms and self.providers == "open"   # terms requires provider-identity: none could accept them
        if self.after_gen is None:
            self.after_gen = self.sandbox
        if self.after_gen and self.providers != "open":
            raise ValueError("after-gen needs providers known by their domain (--open-providers): a record names its "
                             "holder by its party id")


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


REDIRECT_URI = re.compile(json.loads((resources.files("pregen_registry") / "schemas" / "party-document.json")
                                      .read_text())["properties"]["redirect_uris"]["items"]["pattern"])


def _redirect_ok(provider_id: str, uri, sandbox: bool = False) -> bool:
    """bind.md, schemas/party-document.json redirect_uris (the same pattern, so both agree on every edge): HTTPS on the
    provider's own host and port, or a private-use scheme from its reversed domain with one slash after it (RFC 8252
    §7.1), so bind is never an open redirect. A sandbox also takes http on a loopback host, any port (RFC 8252 §7.3)."""
    if not isinstance(uri, str) or not REDIRECT_URI.fullmatch(uri):
        return False
    if uri.startswith("https://"):
        own = "https://" + urlsplit(provider_id).netloc
        return uri == own or uri.startswith(own + "/")
    if uri.startswith("http://"):
        return sandbox
    reverse = ".".join(reversed((urlsplit(provider_id).hostname or "").split(".")))
    scheme = uri.split(":", 1)[0]
    return scheme == reverse or scheme.startswith(reverse + ".")


class Registry:
    def __init__(self, config: Config, operator_key: Key, db_path: str = ":memory:", clock=lambda: int(time.time()),
                 fetch_party=fetch_party):
        self.config, self.key, self.clock, self.fetch_party = config, operator_key, clock, fetch_party
        self.ttl = TTL                 # a sandbox may shorten it, so a test can watch an answer expire
        if config.sandbox and os.environ.get("PREGEN_REGISTRY_ANSWER_TTL"):
            self.ttl = max(1, min(int(os.environ["PREGEN_REGISTRY_ANSWER_TTL"]), TTL))
        self.db = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        if "binding" not in {r["name"] for r in self.db.execute("PRAGMA table_info(bind_codes)")}:   # an early 0.4
            self.db.execute("DROP TABLE bind_codes")                    # codes live 60 seconds: nothing to keep
            self.db.executescript(SCHEMA)
        if "signatures" not in {r["name"] for r in self.db.execute("PRAGMA table_info(asks)")}:   # a 0.3 database
            self.db.execute("ALTER TABLE asks ADD COLUMN signatures TEXT NOT NULL DEFAULT '[]'")
        self.lock = threading.RLock()  # one sqlite connection: every use of it holds this lock
        if not config.sandbox and (self._meta("sandbox") or self.db.execute("SELECT 1 FROM bindings").fetchone()
                                   or self.db.execute("SELECT 1 FROM subjects WHERE serial = 1 AND name = ?",
                                                      (self.SANDBOX_NAMES[1],)).fetchone()):
            raise ValueError("this database is a sandbox's: its test subjects, licences and bindings would give "
                             "answers not marked as sandbox answers. Start it as a sandbox, or make a new registry "
                             "with `init`.")
        self.activated_at = int(self._meta("activated_at") or self._set_meta("activated_at", str(clock())))
        if config.sandbox:
            self._check_sandbox_serials()   # before anything is written: a refused start changes nothing
        self._record_key()
        if config.sandbox:
            self.seed_sandbox()

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
        with self.lock:                # one sqlite connection, shared by the server's threads
            row = self.db.execute("SELECT v FROM meta WHERE k = ?", (k,)).fetchone()
        return row["v"] if row else None

    def _set_meta(self, k, v):
        with self.lock:
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
                if self.config.sandbox:                     # 1-12 are the standard test codes; 8 stays unregistered
                    serial = max(serial, 13)
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
                  holder_key: Key | None = None, ext: dict | None = None) -> str:
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
                                       "max_uses": max_uses, **({"ext": ext} if ext else {})},
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

    def publish_terms(self, code: str, *, purposes, excluded_categories=(), template: dict, legal: dict,
                      factor: str | None = None) -> str:
        """extensions/terms.md: a new version of the subject's terms, made on the subject's own instruction, for a
        published subject that is consented or verified (T-1). One that opens anything (T-3: the first, a purpose added,
        an exclusion removed, another template) needs `factor`, the second factor the operator checked, and names it;
        one that only closes names none. Nothing changed: no new version. Returns the current terms id."""
        rules = {"purposes": sorted(set(purposes)), "excluded_categories": sorted(set(excluded_categories))}
        if not rules["purposes"] or not set(rules["purposes"]) <= PURPOSES or not set(rules["excluded_categories"]) <= CATEGORIES:
            raise ValueError(f"purposes from {sorted(PURPOSES)}, at least one; exclusions from {sorted(CATEGORIES)}")
        with self.tx() as db:
            s = db.execute("SELECT * FROM subjects WHERE code = ?", (code,)).fetchone()
            if not self.config.terms or s is None or not s["published"] or s["level"] not in TERMS_LEVELS:
                raise ValueError("terms are published only for a published subject that is consented or verified (T-1)")
            last = db.execute("SELECT id, envelope FROM terms WHERE subject_code = ? ORDER BY version DESC LIMIT 1",
                              (code,)).fetchone()
            old = json.loads(last["envelope"])["body"] if last else None
            new = {"rules": rules, "minor": bool(s["minor"]), "template": template, "legal": legal}
            if old is not None and all(old[k] == v for k, v in new.items()):
                return last["id"]
            if old is not None and old["template"] == template and old["legal"] != legal:
                raise ValueError("a template's legal text is fixed: another text is another template version")
            opens = terms_opens(old, new)
            if opens and factor not in ("authenticator", "email"):
                raise ValueError("this version opens: it needs the subject's own instruction with a second factor (T-3)")
            now = self.clock()
            act = {"subject": code, **new, "factor": factor if opens else None, "at": now}   # the private record of the act
            body = {"subject_ref": code, "profile": PROFILE, "version": old["version"] + 1 if old else 1,
                    **({"amends": last["id"]} if old else {}), **new, "assent": "registry",
                    "instruction": hashlib.sha256(canonical(act)).hexdigest(), **({"factor": factor} if opens else {}),
                    "issued_at": now}
            env = seal("pg.terms.v1", body, [("registry", self.key)])
            check_body("terms", env["body"])
            tid = message_id(env["type"], env["body"])
            db.execute("INSERT INTO terms VALUES (?, ?, ?, ?, ?)",
                       (tid, code, body["version"], json.dumps(env), canonical(act).decode()))
            return tid

    def _current_terms(self, db, s):
        """(id, body) of the subject's current terms, or None: a subject that is not, or no longer, published and
        consented or verified is answered as if it had no terms (T-1)."""
        if not self.config.terms or not s["published"] or s["level"] not in TERMS_LEVELS:
            return None
        row = db.execute("SELECT id, envelope FROM terms WHERE subject_code = ? ORDER BY version DESC LIMIT 1",
                         (s["code"],)).fetchone()
        return (row["id"], json.loads(row["envelope"])["body"]) if row else None

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

    SANDBOX_NAMES = {1: "Test subject 1 (allow)", 2: "Test subject 2 (no licence)", 3: "Test subject 3 (opted out)",
                     4: "Test subject 4 (usage limit)", 5: "Test subject 5 (prohibited)", 6: "Test subject 6 (review)",
                     7: "Test subject 7 (not blocked)", 9: "Test subject 9 (buy first)",
                     10: "Test subject 10 (the person's terms)", 11: "Test subject 11 (a minor)",
                     12: "Test subject 12 (a creator's licence, through bind)"}

    def _check_sandbox_serials(self) -> dict:
        have = {r["serial"]: r["name"] for r in self._q("SELECT serial, name FROM subjects WHERE serial <= 12")}
        taken = [f"{mint_code(self.config.prefix, n)} ({have[n]!r})" for n, name in self.SANDBOX_NAMES.items()
                 if have.get(n, name) != name]
        if taken:
            raise ValueError(f"this sandbox's {', '.join(taken)} must be the standard test subjects 1-7 and 9-12 "
                             "(extensions/sandbox.md). Make a fresh sandbox with `pregen-registry init --sandbox` and "
                             "add your own test people there again; they get serials from 13.")
        return have

    def seed_sandbox(self):
        """The standard sandbox subjects (extensions/sandbox.md), serials 1–7 and 9–12; serial 8 stays unregistered.
        A sandbox runs this on every start and adds only those missing, so one made by 0.3 (1–7) gains 9–12. A serial
        held by another subject (0.3 numbered the operator's own from 9) is refused: that code would answer wrongly."""
        have = self._check_sandbox_serials()
        with self.lock:
            self._set_meta("sandbox", "1")     # a sandbox's database never starts as a production registry
        self._drop_unbound_localhost_pins()
        name, new = self.SANDBOX_NAMES, lambda n: n not in have
        if new(1):
            self.add_grant(self.add_subject(name[1], serial=1, level="verified"), purposes=PURPOSES, days=36500)
        if new(2):
            self.add_subject(name[2], serial=2, level="verified")
        if new(3):
            self.add_subject(name[3], serial=3, level="verified", opted_out=1)
        if new(4):
            self.add_grant(self.add_subject(name[4], serial=4, level="verified"), purposes=PURPOSES, days=36500,
                           max_uses=1, uses_offset=1)
        if new(5):
            self.add_subject(name[5], serial=5, level="verified", fixed_refusal="PG_PROHIBITED_USE")
        if new(6):
            self.add_subject(name[6], serial=6, level="verified", review=1)
        if new(7):
            self.add_subject(name[7], serial=7, level="verified", no_grant_status="not_blocked")
        if new(9):
            self.set_identity(self.add_subject(name[9], serial=9, level="verified"), offer={
                "purposes": sorted(PURPOSES), "price": {"amount": 100, "currency": "USD", "unit": "generation"}})
        if new(10) and self.config.terms:       # a sandbox built with terms off has no 10 until they are on
            self.publish_terms(self.add_subject(name[10], serial=10, level="verified"), purposes=("editorial", "research"),
                               excluded_categories=("advertising",), template=SANDBOX_TEMPLATE, legal=SANDBOX_LEGAL,
                               factor="authenticator")
        if new(11):
            own = Key()                # the person's own key, so the grant names intimate categories too; then dropped
            eleven = self.add_subject(name[11], serial=11, level="verified", minor=1, holder_public=own.public_hex)
            self.add_grant(eleven, purposes=PURPOSES, days=36500, categories=CATEGORIES, holder_key=own)
        if new(12):                    # the holder's licence is made at each consent (bind_approve): no app shares one
            self.add_subject(name[12], serial=12, level="verified")

    def _drop_unbound_localhost_pins(self):
        """provider-identity, Sandboxes: a localhost id is bound to its key. Pins an earlier version took for a plain
        `https://localhost:8443` (or another key's id) are dropped, so the name is free for whoever owns it now."""
        with self.tx() as db:
            for (pid,) in db.execute("SELECT DISTINCT provider_id FROM keysets").fetchall():
                host = urlsplit(pid).hostname or ""
                if host != "localhost" and not host.endswith(".localhost"):
                    continue
                first = json.loads(db.execute("SELECT envelope FROM keysets WHERE provider_id = ? AND position = 0",
                                              (pid,)).fetchone()["envelope"])
                if host != self._current(first["body"])["key_id"].split(":")[1] + ".localhost":
                    db.execute("DELETE FROM keysets WHERE provider_id = ?", (pid,))
                    db.execute("DELETE FROM meta WHERE k IN (?, ?)", ("party:" + pid, "partydoc:" + pid))

    def purchase(self, provider_id: str, authorization: str | None, env) -> dict:
        """extensions/sandbox.md: a test purchase, no money. The request, authenticated as for /v2/requests, names a
        subject in the catalog; its provider gets a grant of one use on the offer's terms. Buy again: one more."""
        if not self.config.sandbox:
            raise ProtocolError("PG_NOT_FOUND", "this registry is not a sandbox", status=404)
        body = self._checked_request(provider_id, authorization, env)
        offer = next((o for o in self.catalog()["offers"] if o["subject_ref"] == body["subject_ref"]), None)
        if offer is None:
            raise ProtocolError("PG_NOT_FOUND", "this subject is not in the catalog", status=404)
        with self.lock:                # the purchase number keeps two purchases in one second two grants
            n = self._row("SELECT COUNT(*) FROM grants WHERE subject_code = ? AND licensee_id = ?",
                          (body["subject_ref"], provider_id))[0] + 1
            return self.grant(self.add_grant(body["subject_ref"], licensee_id=provider_id, purposes=offer["purposes"],
                                             max_uses=1, resale=bool(offer.get("resale")),
                                             ext={"sandbox": True, "purchase": n}))

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
        body = self._checked_request(provider_id, authorization, env)
        with self.tx() as db:
            now = self.clock()
            ask = db.execute("SELECT * FROM asks WHERE id = ?", (message_id("pg.request.v1", body),)).fetchone()
            if ask is not None:                  # the identical request again (jobs.md)
                if ask["closing_ack"]:
                    raise ProtocolError("PG_ASK_CLOSED", "this subject of the job was reported generated", status=409,
                                        ack=json.loads(ask["closing_ack"]))
                if ask["null_report"]:          # limits.md: given back unseen, the ask is closed; no new answer
                    ack = db.execute("SELECT ack FROM reports WHERE id = ?", (ask["null_report"],)).fetchone()
                    raise ProtocolError("PG_ASK_CLOSED", "this subject of the job was reported not generated with no "
                                        "answer", status=409, ack=json.loads(ack["ack"]))
                open_ = db.execute("SELECT envelope FROM answers WHERE ask_id = ? AND expires_at > ? AND (use IS NULL "
                                   "OR use != 'released') ORDER BY issued_at DESC", (ask["id"], now)).fetchone()
                if open_:
                    return {"answer": json.loads(open_["envelope"]), "attachments": []}
            decision = self._decide(db, body, now)
            # T-7: signed, but binds no job, no ask; a masked answer (P-5a) is kept like any other, so nothing tells apart
            if decision[1] == "PG_TERMS_NOT_ACCEPTED" and not self._masked(db, body, decision[1]):
                return {"answer": self._answer(db, None, body, decision, now), "attachments": []}
            ask = ask or self._bind(db, body, env["signatures"])
            return {"answer": self._answer(db, ask["id"], body, decision, now), "attachments": []}

    def _checked_request(self, provider_id: str, authorization: str | None, env) -> dict:
        """A request's shape and its provider's authentication: signed by an open provider, or a registered one's token."""
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
        if "terms" in body and not self.config.terms:   # terms T-5: sent only to a registry that declares it
            raise ProtocolError("PG_MALFORMED", "this registry does not declare the extension terms")
        if not self.is_open(provider_id):
            self.authenticate(provider_id, authorization)
        if body["provider_id"] != provider_id:
            raise ProtocolError("PG_NOT_AUTHENTICATED", "provider_id differs from X-Provider-ID", status=401)
        if body["profile"] not in self.config.profiles:
            raise ProtocolError("PG_PROFILE_UNSUPPORTED", f"this registry answers under {self.config.profiles}")
        self._check_use(body["use"])
        licensee = body.get("licensee_id", "")
        if licensee and not self._licensee_ok(provider_id, licensee):
            if self.is_open(provider_id):        # bind B-5: "connect your licence", never a refusal
                raise ProtocolError("PG_NOT_BOUND", "this licensee_id has no active binding to this app: ask the person "
                                    "to connect their licence (extensions/bind.md)", status=403)
            raise ProtocolError("PG_NOT_AUTHENTICATED", "this licensee is not connected to this provider", status=401)
        return body

    def _licensee_ok(self, provider_id: str, licensee: str) -> bool:
        """licensee.md: connected by the operator, or bound by the person (bind); a sandbox too, so a made-up id, or
        another provider's, never reaches a grant (sandbox.md serials 9 and 12)."""
        with self.lock:
            return bool(self.db.execute("SELECT 1 FROM connections WHERE provider_id = ? AND licensee_id = ?",
                                        (provider_id, licensee)).fetchone() or self._binding(self.db, provider_id, licensee))

    def _binding(self, db, provider_id: str, licensee: str):
        """The active binding of `licensee` to this provider (bind B-1, B-2), or None. ponytail: the operator key is
        never revoked in this registry, so B-3b (a binding dies with its key) has nothing to check yet."""
        return db.execute("SELECT * FROM bindings WHERE licensee_id = ? AND provider_id = ? AND ended_at IS NULL "
                          "AND expires_at > ?", (licensee, provider_id, self.clock())).fetchone() if licensee else None

    @staticmethod
    def _check_use(use):
        if set(use) - USE_MEMBERS or use.get("purpose") not in PURPOSES \
                or not all(isinstance(use.get(k, []), list) for k in ("rights", "categories")) \
                or not all(isinstance(c, str) for c in use.get("categories", [])) \
                or not all(isinstance(use.get(k, ""), str) for k in ("territory", "channel")):
            raise ProtocolError("PG_MALFORMED", "use: purpose personal|educational|research|editorial|commercial; "
                                                "optional rights, territory, channel, categories")

    def _bind(self, db, body: dict, signatures=()):
        """extensions/jobs.md: one job_hash per job, one request per subject of the job. The request's signatures are
        kept for its proof (a provider's signature is its acceptance of the subject's terms, terms T-5)."""
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
            db.execute("INSERT INTO asks (id, provider_id, job_id, subject_ref, request, signatures) VALUES (?, ?, ?, ?, ?, ?)",
                       (rid, body["provider_id"], body["job_id"], body["subject_ref"], json.dumps(body),
                        json.dumps(list(signatures))))
            ask = db.execute("SELECT * FROM asks WHERE id = ?", (rid,)).fetchone()
        elif ask["id"] != rid:
            if ask["closing_ack"] or not self._stale(db, json.loads(ask["request"])) or db.execute(
                    "SELECT 1 FROM answers WHERE ask_id = ? AND status = 'allow' AND expires_at > ?",
                    (ask["id"], self.clock())).fetchone():
                raise ProtocolError("PG_ASK_CONFLICT", "this subject of the job was asked with another request", status=409)
            # T-7: an ask bound to terms that are no longer current never locks the job. It steps aside under its own
            # id, keeping its answers (still billed, still reportable), and the new request binds.
            db.execute("UPDATE asks SET subject_ref = id WHERE id = ?", (ask["id"],))
            return self._bind(db, body, signatures)
        return ask

    def _stale(self, db, req: dict) -> bool:
        """T-7: the request cites terms that are not the subject's current terms."""
        if "terms" not in req:
            return False
        s = db.execute("SELECT * FROM subjects WHERE code = ?", (req["subject_ref"],)).fetchone()
        terms = self._current_terms(db, s) if s is not None else None
        return terms is None or terms[0] != req["terms"]

    def _decide(self, db, req: dict, now: int):
        """(status, reason, grant row, level) under likeness/1, in the order of extensions/terms.md (The gate): the
        subject step, the floor and the person's refusals, the registry's state, the person's exclusions where no grant
        covers the use, who asks, then grants."""
        parsed = parse_code(req["subject_ref"])
        if parsed is not None and parsed[0] != self.config.prefix:
            return "deny", "PG_OTHER_REGISTRY", None, "self"
        s = db.execute("SELECT * FROM subjects WHERE code = ?", (req["subject_ref"],)).fetchone()
        if s is None:
            return "deny", "PG_UNKNOWN_SUBJECT", None, "self"
        use, level = req["use"], s["level"]
        categories = set(use.get("categories", []))
        if s["status"] in UNAVAILABLE - {"disputed"}:
            return "deny", "PG_SUBJECT_UNAVAILABLE", None, level
        if s["opted_out"]:
            return "deny", "PG_SUBJECT_OPTED_OUT", None, level
        if s["fixed_refusal"] or (s["minor"] and (categories & PROHIBITED_FOR_MINORS or categories - CATEGORIES)):
            return "deny", s["fixed_refusal"] or "PG_PROHIBITED_USE", None, level
        if categories & set(json.loads(s["immutable_denials"])):
            return "deny", "PG_IMMUTABLE_DENIAL", None, level
        intimate = categories & INTIMATE
        if intimate and (s["custody"] != "self" or level != "verified"):
            return "deny", "PG_PERSONAL_SIGNATURE_REQUIRED", None, level
        if s["status"] == "disputed":     # identity.md: a complaint is not a refusal of the person; it holds here only
            return "deny", "PG_SUBJECT_DISPUTED", None, level
        if s["review"]:
            return "review", "PG_REVIEW_REQUIRED", None, level
        licensee, provider = req.get("licensee_id", ""), req["provider_id"]
        binding = self._binding(db, provider, licensee)
        bound = set(json.loads(binding["grants"])) if binding else set()   # bind B-3a: only what the person chose
        grants = [g for g in db.execute(
            "SELECT * FROM grants WHERE subject_code = ? AND not_before <= ? AND expires_at > ? ORDER BY not_before",
            (s["code"], now, now)).fetchall()
            # catalog.md: an open grant, a grant to this licensee, or the provider's own grant — which covers
            # its users only with the resale right. A sandbox purchase is its buyer's alone (sandbox.md): a sandbox
            # connects any licensee, so another provider could otherwise name the buyer as its licensee.
            if g["licensee_id"] == "" or g["id"] in bound
            or (g["licensee_id"] == licensee and not licensee.startswith("account:") and not self._bought_by_another(g, provider))
            or (g["licensee_id"] == provider and (not licensee or g["resale"]))]
        fitting = [g for g in grants if use["purpose"] in json.loads(g["purposes"])
                   and intimate <= set(json.loads(g["categories"]))]
        terms = self._current_terms(db, s)
        if not fitting and terms and forbids(terms[1]["rules"], use):   # a grant decides its own scope; here only
            return "deny", "PG_TERMS_EXCLUDED", None, level
        if "terms" in req and (terms is None or req["terms"] != terms[0] or not self.is_open(provider)):
            return "deny", "PG_TERMS_NOT_ACCEPTED", None, level            # T-7 stale or foreign, T-8 not by its domain
        if not fitting:
            reason = "PG_SCOPE_VIOLATION" if grants else "PG_NO_LICENSE"
            if not grants and not licensee and db.execute(  # licensee.md: only one of this provider's customers would do
                    "SELECT 1 FROM grants WHERE subject_code = ? AND not_before <= ? AND expires_at > ? "
                    "AND instr(licensee_id, ? || ':') = 1", (s["code"], now, now, provider)).fetchone():
                reason = "PG_NOT_CONNECTED"
            return s["no_grant_status"], reason, None, level
        for g in fitting:                                   # extensions/limits.md: reserve a use if any is left
            if g["max_uses"] is None or self._used(db, g) < g["max_uses"]:
                return "allow", None, g, level
        return "deny", "PG_USAGE_LIMIT", None, level

    @staticmethod
    def _used(db, g) -> int:
        """A licence's uses (limits.md): allows reserved or consumed, the uses it started with, and after-gen records
        (after-gen.md step 4), on one counter, so both share `max_uses`. A withdrawn record's use stays counted."""
        return db.execute("SELECT (SELECT COUNT(*) FROM answers WHERE grant_id = ? AND use IN ('reserved', 'consumed')) "
                          "+ (SELECT COUNT(*) FROM after_gen_records WHERE licence_id = ?)",
                          (g["id"], g["id"])).fetchone()[0] + g["uses_offset"]

    def _bought_by_another(self, g, provider: str) -> bool:
        return self.config.sandbox and g["licensee_id"] != provider \
            and "purchase" in json.loads(g["envelope"])["body"].get("ext", {})

    def _masked(self, db, req: dict, reason) -> bool:
        """provider-identity P-5, P-5a: a provider this registry has not vetted learns about a published subject (its
        refusals included) and a subject its own connected licensee holds a grant on; everything else, a floor refusal
        of a subject the registry does not publish included, is deny PG_PROVIDER_NOT_ACCEPTED."""
        pid = req["provider_id"]
        if not self.is_open(pid) or self.config.sandbox or reason == "PG_OTHER_REGISTRY" \
                or db.execute("SELECT 1 FROM accepted WHERE provider_id = ?", (pid,)).fetchone():
            return False
        s = db.execute("SELECT published, offer, anchor FROM subjects WHERE code = ?", (req["subject_ref"],)).fetchone()
        if s is not None and (s["published"] or s["offer"] is not None or s["anchor"] is not None):  # lookup, catalog
            return False                                                         # or the anchor list names it
        licensee, now = req.get("licensee_id", ""), self.clock()      # P-5a: a licensee connected or bound to this
        binding = self._binding(db, pid, licensee)                      # provider that holds a live grant on the
        bound = set(json.loads(binding["grants"])) if binding else set()  # subject learns every answer about it
        if not (binding or licensee and db.execute("SELECT 1 FROM connections WHERE provider_id = ? AND licensee_id = ?",
                                                   (pid, licensee)).fetchone()):
            return True
        return not any(g["licensee_id"] == licensee or g["id"] in bound for g in db.execute(
            "SELECT id, licensee_id FROM grants WHERE subject_code = ? AND not_before <= ? AND expires_at > ?",
            (req["subject_ref"], now, now)))

    def _answer(self, db, ask_id, req: dict, decision, now: int) -> dict:
        """The signed answer to `decision`, kept under `ask_id`; with none (terms T-7) it is kept nowhere."""
        status, reason, grant, level = decision
        if self._masked(db, req, reason):    # P-5a: and the level of an unknown code, so it tells nothing
            status, reason, grant, level = "deny", "PG_PROVIDER_NOT_ACCEPTED", None, "self"
        body = {"request_id": message_id("pg.request.v1", req), "profile": req["profile"], "status": status, "level": level,
                "obligations": [], "issued_at": now, "expires_at": now + self.ttl}
        if status == "allow":
            body["basis"] = {"kind": "grant", "grant": {"format": "pg.grant.v1", "id": grant["id"]}}
        else:
            body["reason"] = reason
        if self.config.sandbox:
            body["ext"] = {"sandbox": True}
        binding = self._binding(db, req["provider_id"], req.get("licensee_id", "")) if status == "allow" else None
        if binding is not None and grant["id"] in json.loads(binding["grants"]):   # B-3c: an allow resting on it
            body["ext"] = {**body.get("ext", {}), "bind": {"binding": binding["id"]}}
        env = seal("pg.answer.v1", body, [("registry", self.key)])
        use = "reserved" if status == "allow" else None   # catalog.md: every allow is billed unless given back
        if ask_id is None:
            return env
        if db.execute("SELECT 1 FROM answers WHERE id = ?", (message_id(env["type"], env["body"]),)).fetchone():
            # the same answer, to the second, was given back: never served again (jobs.md), so ask a second later
            raise ProtocolError("PG_RATE_LIMITED", "ask again in a second", status=429)
        db.execute("INSERT INTO answers VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                   (message_id(env["type"], env["body"]), ask_id, json.dumps(env), status, now, now + self.ttl,
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
        bad = [u for u in doc.get("redirect_uris", []) if not _redirect_ok(pid, u, self.config.sandbox)]
        if bad:
            raise ProtocolError("PG_MALFORMED", f"redirect_uris must be https on {pid}'s own host, or a private-use "
                                f"scheme from its reversed domain (in a sandbox also http on localhost): {bad[0]!r}")
        host = urlsplit(pid).hostname or ""
        if host == "localhost" or host.endswith(".localhost"):    # provider-identity, Sandboxes: bound to the key
            want = self._current(doc["keysets"][0]["body"])["key_id"].split(":")[1] + ".localhost"
            if host != want:
                raise ProtocolError("PG_MALFORMED", f"a sandbox id on localhost is bound to its key: https://{want}"
                                    "[:port] (pregen.sandbox_provider_url)")
        with self.tx() as db:
            for env in doc["keysets"]:
                try:
                    self._accept_keyset(db, pid, env)
                except ProtocolError as e:
                    if e.code != "PG_KEYSET_CONFLICT":
                        raise
                    raise ProtocolError("PG_NOT_AUTHENTICATED", "the party document does not extend the pinned chain "
                                        "(P-2); whoever takes over a domain does not get its keys", status=401) from None
            if posted or (db.execute("SELECT v FROM meta WHERE k = ?", ("party:" + pid,)).fetchone() or {"v": ""})["v"] \
                    != "posted":                   # a read from the domain never unmarks a posted document
                db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)",
                           ("party:" + pid, "posted" if posted else str(self.clock())))
            db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", ("partydoc:" + pid, json.dumps(doc)))
        return pid

    def _open_chain(self, provider_id: str, key_id: str) -> list[dict]:
        """The pinned chain of a provider known by its domain. Its party document is read when nothing is pinned, when
        a message names a key the chain does not hold, and at least daily (P-2, P-3); at most once a minute (P-7)."""
        with self.lock:                # the chain, its marker and the decision to read it again, all at once (P-7)
            chain = self._chain(self.db, provider_id)
            last = self._meta("party:" + provider_id) or ""
            stale = chain and last != "posted" and (key_id != self._current(chain[-1]["body"])["key_id"]
                                                    or self.clock() - float(last or 0) > PARTY_REFRESH)
            fetch = (not chain or stale) and (not last.replace(".", "").isdigit()
                                              or self.clock() - float(last) >= PARTY_MIN_INTERVAL)
            if fetch:
                self._set_meta("party:" + provider_id, str(self.clock()))              # budget the attempt, not the success
        if fetch:
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

    def _signed_by_provider(self, env, type_: str, provider_id: str, role: str = "provider") -> dict:
        chain = self._open_chain(provider_id, self._signer_key_id(env))
        current = self._current(chain[-1]["body"])
        return check_envelope(env, type_, (role,),
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

    # ── extension bind: a person connects their licences to an app ───────
    # ponytail: bind runs only in a sandbox, whose one test creator signs in with no password (sandbox.md serial 12).
    # A production registry needs people's own accounts and sign-in, which this reference registry does not have.
    def bind_client(self, client_id: str, redirect_uri: str) -> dict:
        """bind.md step 1: the app is its party document, and redirect_uri is exactly one of the document's. A bad
        client or redirect URI is answered here and never redirected to."""
        if not self.config.sandbox:
            raise ProtocolError("PG_NOT_FOUND", "this registry offers bind only as a sandbox", status=404)
        if not self.is_open(client_id):
            raise ProtocolError("PG_MALFORMED", "client_id is the app's provider URL", status=400)
        with self.lock:
            doc = self._meta("partydoc:" + client_id)
        if doc is None:
            try:
                self._open_chain(client_id, "")              # reads the party document from the app's domain
            except ProtocolError:
                pass
            with self.lock:
                doc = self._meta("partydoc:" + client_id)
        doc = json.loads(doc) if doc else None
        if doc is None or redirect_uri not in doc.get("redirect_uris", []) \
                or not _redirect_ok(client_id, redirect_uri, self.config.sandbox):
            raise ProtocolError("PG_MALFORMED", "unknown app, or redirect_uri is not one of its party document's "
                                "redirect_uris", status=400)
        with self.lock:                                       # bind.md step 2: what the consent screen may claim
            doc["posted"] = self._meta("party:" + client_id) == "posted"
        return doc

    def bind_offer(self) -> list[dict]:
        """What the sandbox's test creator connects: a new licence on serial 12 for each binding, so no two apps share
        its three uses (sandbox.md)."""
        return [{"subject_ref": mint_code(self.config.prefix, 12), "purposes": ["research"], "max_uses": 3}]

    def bind_consent(self, client_id: str, redirect_uri: str, code_challenge: str) -> str:
        """The consent page's one-time nonce: an approval must come from a page this registry showed."""
        self.bind_client(client_id, redirect_uri)
        nonce, now = secrets.token_urlsafe(32), self.clock()
        with self.tx() as db:
            db.execute("DELETE FROM bind_consents WHERE expires_at <= ?", (now,))
            db.execute("INSERT INTO bind_consents VALUES (?, ?, ?, ?, ?)",
                       (_hash_token(nonce), client_id, redirect_uri, code_challenge, now + CONSENT_TTL))
        return nonce

    def bind_approve(self, client_id: str, redirect_uri: str, code_challenge: str, consent: str) -> str:
        """bind.md steps 2-3: the person approved on a page this registry showed (its nonce is spent); a code for the
        app, single-use, 60 seconds, bound to the client, the redirect URI and the PKCE challenge."""
        self.bind_client(client_id, redirect_uri)
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", code_challenge or ""):
            raise ProtocolError("PG_MALFORMED", "code_challenge is a base64url SHA-256 (S256)", status=400)
        code, now = secrets.token_urlsafe(32), self.clock()
        with self.tx() as db:
            db.execute("DELETE FROM bind_codes WHERE expires_at <= ? AND binding IS NULL", (now,))
            spent = db.execute("DELETE FROM bind_consents WHERE nonce_hash = ? AND client_id = ? AND redirect_uri = ? "
                               "AND challenge = ? AND expires_at > ?", (_hash_token(consent or ""), client_id,
                                                                        redirect_uri, code_challenge, now)).rowcount
            if spent:
                db.execute("INSERT INTO bind_codes VALUES (?, ?, ?, ?, ?, ?, 0, NULL)", (
                    _hash_token(code), client_id, redirect_uri, code_challenge, SANDBOX_HOLDER, now + BIND_CODE_TTL))
        if not spent:
            raise ProtocolError("PG_MALFORMED", "no consent page was shown for this approval, or it was answered "
                                "already or too late", status=400)
        return code

    def bind_exchange(self, provider_id: str, authorization: str | None, env) -> dict:
        """bind.md steps 4-5: the app's signed pg.bind_exchange.v1 for a pg.binding.v1 with a new random licensee_id.
        A new binding replaces the person's earlier one with this app (B-1). A code shown twice by its own client ends
        the binding it gave (RFC 6749 §4.1.2); another client cannot spend it."""
        if not self.config.sandbox:
            raise ProtocolError("PG_NOT_FOUND", "this registry offers bind only as a sandbox", status=404)
        if not self.is_open(provider_id):
            raise ProtocolError("PG_NOT_AUTHENTICATED", "bind is for a provider known by its domain", status=401)
        self._check_open(provider_id, authorization)
        body = self._signed_by_provider(env, "pg.bind_exchange.v1", provider_id)
        fields = {"signers", "provider_id", "code", "code_verifier", "redirect_uri", "issued_at"}
        if set(body) != fields or not all(isinstance(body[k], str) for k in fields - {"signers", "issued_at"}) \
                or type(body["issued_at"]) is not int:
            raise ProtocolError("PG_MALFORMED", "pg.bind_exchange.v1 is {signers, provider_id, code, code_verifier, "
                                "redirect_uri, issued_at}")
        now = self.clock()
        if body["provider_id"] != provider_id or abs(now - body["issued_at"]) > 60:
            raise ProtocolError("PG_NOT_AUTHENTICATED", "provider_id differs from X-Provider-ID, or issued_at is more "
                                "than 60 seconds off", status=401)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(body["code_verifier"].encode()).digest()).rstrip(b"=").decode()
        with self.tx() as db:
            row = db.execute("SELECT * FROM bind_codes WHERE code_hash = ? AND provider_id = ?",
                             (_hash_token(body["code"]), provider_id)).fetchone()
            if row is not None:                         # its own client: spent now, whatever the outcome
                db.execute("UPDATE bind_codes SET used = 1 WHERE code_hash = ?", (row["code_hash"],))
                if row["used"] and row["binding"]:      # a replayed code: the binding it gave ends
                    db.execute("UPDATE bindings SET ended_at = ? WHERE licensee_id = ? AND ended_at IS NULL",
                               (now, row["binding"]))
        ok = row is not None and not row["used"] and row["expires_at"] > now \
            and row["redirect_uri"] == body["redirect_uri"] \
            and re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", body["code_verifier"]) \
            and secrets.compare_digest(row["challenge"], challenge)
        if not ok:
            raise ProtocolError("PG_BIND_CODE", "the code is unknown, used or expired, or not for this client, redirect "
                                "URI or verifier", status=400)
        with self.lock:                # the licence is made now, at the exchange, never for an approval left unused
            n = self._row("SELECT COUNT(*) FROM grants WHERE licensee_id = ?", (SANDBOX_HOLDER,))[0] + 1
            grants = [self.add_grant(o["subject_ref"], licensee_id=row["account"], purposes=o["purposes"],
                                     max_uses=o["max_uses"], ext={"sandbox": True, "consent": n})
                      for o in self.bind_offer()]
        with self.tx() as db:
            db.execute("UPDATE bindings SET ended_at = ? WHERE provider_id = ? AND account = ? AND ended_at IS NULL",
                       (now, provider_id, row["account"]))
            licensee = secrets.token_urlsafe(24)                         # random, new, means nothing elsewhere
            binding = seal("pg.binding.v1", {"authority": self.config.prefix, "provider_id": provider_id,
                                             "licensee_id": licensee, "grants": grants,
                                             "issued_at": now, "expires_at": now + BINDING_TTL}, [("registry", self.key)])
            check_body("binding", binding["body"])
            db.execute("INSERT INTO bindings VALUES (?, ?, ?, ?, ?, ?, NULL, ?)", (
                licensee, message_id(binding["type"], binding["body"]), provider_id, row["account"], json.dumps(grants),
                now + BINDING_TTL, json.dumps(binding)))
            db.execute("UPDATE bind_codes SET binding = ? WHERE code_hash = ?", (licensee, row["code_hash"]))
        return {"binding": binding}

    def bound_grants(self, provider_id: str, authorization: str | None, pg_access: str | None, licensee: str,
                     path: str) -> dict:
        """bind.md "What the person holds": only the provider bound to this licensee, and only the binding's grants.
        status and remaining are unsigned and inform the app; only an allow permits."""
        pid = self.authenticate_read(provider_id, authorization, pg_access, "GET", path)
        now = self.clock()
        with self.lock:
            b = self._binding(self.db, pid, licensee)
            if b is None:
                raise ProtocolError("PG_NOT_BOUND", "this licensee_id has no active binding to this app", status=403)
            out = []
            for gid in json.loads(b["grants"]):
                g = self.db.execute("SELECT * FROM grants WHERE id = ?", (gid,)).fetchone()
                used = self._used(self.db, g)
                out.append({"id": gid, "status": "active" if g["expires_at"] > now else "expired",
                            "remaining": None if g["max_uses"] is None else max(g["max_uses"] - used, 0),
                            "grant": json.loads(g["envelope"])})
        return {"grants": out}

    def bindings(self) -> list[dict]:
        """B-2: each binding, with the number of allows issued through it."""
        rows = self._q("SELECT b.*, (SELECT COUNT(*) FROM answers a JOIN asks k ON k.id = a.ask_id WHERE a.status = "
                       "'allow' AND k.provider_id = b.provider_id AND json_extract(k.request, '$.licensee_id') = "
                       "b.licensee_id) AS allows FROM bindings b ORDER BY rowid")
        return [{"licensee_id": r["licensee_id"], "provider_id": r["provider_id"], "account": r["account"],
                 "allows": r["allows"], "active": r["ended_at"] is None and r["expires_at"] > self.clock()} for r in rows]

    def revoke_binding(self, licensee_id: str):
        """B-2: the person revokes a binding; it takes effect at once."""
        with self.tx() as db:
            if not db.execute("UPDATE bindings SET ended_at = ? WHERE licensee_id = ? AND ended_at IS NULL",
                              (self.clock(), licensee_id)).rowcount:
                raise ValueError(f"no active binding {licensee_id}")

    # ── after-gen (spec/drafts/after-gen.md): the rights holder approves a file that already exists ──
    # A record is never an answer: no allow rests on one, and a report or proof names answers only (vector 11).
    def _ag_on(self):
        if not self.config.after_gen:
            raise ProtocolError("PG_NOT_FOUND", "this registry does not declare after-gen", status=404)

    @staticmethod
    def _ag_scope(scope) -> dict:
        """The record's `scope`: exact members, purposes and categories in the profile's closed vocabulary, at most 250
        territories of two capital letters or ["*"], at most 64 channels of [a-z0-9-]{1,32} or ["*"], lists sorted
        without repeats, a project of 1-200 printable characters. ponytail: a territory is checked by its shape, not
        against the ISO 3166-1 list."""
        def words(v, ok, empty=False, cap=64):
            return isinstance(v, list) and (empty or bool(v)) and len(v) <= cap \
                and all(isinstance(x, str) and ok(x) for x in v) and v == sorted(set(v))

        def star(v, pattern, cap):
            return v == ["*"] or words(v, lambda x: re.fullmatch(pattern, x) is not None, cap=cap)
        p = scope.get("project") if isinstance(scope, dict) else None
        if not isinstance(scope, dict) or set(scope) != AG_SCOPE_MEMBERS or not words(scope["purposes"], PURPOSES.__contains__) \
                or not words(scope["categories"], lambda x: True, empty=True) \
                or not star(scope["territories"], r"[A-Z]{2}", 250) \
                or not star(scope["channels"], r"[a-z0-9-]{1,32}", 64) or not _int(scope["not_after"], 1) \
                or not (isinstance(p, str) and 1 <= len(p) <= 200 and p.isprintable()):
            raise ProtocolError("PG_MALFORMED", "scope is {purposes, categories, territories, channels, project, not_after} "
                                "in the record's vocabulary, lists sorted without repeats (after-gen.md, The record)")
        if set(scope["categories"]) - CATEGORIES:                                       # vector 13
            raise ProtocolError("PG_MALFORMED", "a category outside the profile's closed vocabulary")
        return scope

    @staticmethod
    def _ag_within(n: dict, w: dict) -> bool:
        """A decision approves the request's scope or a narrower one, never a wider one (after-gen.md, The decision)."""
        cover = lambda a, b: b == ["*"] or (a != ["*"] and set(a) <= set(b))  # noqa: E731
        return set(n["purposes"]) <= set(w["purposes"]) and set(n["categories"]) <= set(w["categories"]) \
            and cover(n["territories"], w["territories"]) and cover(n["channels"], w["channels"]) \
            and n["project"] == w["project"] and n["not_after"] <= w["not_after"]

    def _ag_checks(self, db, requester: str, subject_ref: str, licence_id: str, media: str, scope: dict, now: int,
                   mask: bool = False):
        """after-gen.md, The procedure step 2 (and again at signing, step 4): the licence for this subject and this
        holder, valid now, with a use left and at least as wide as the scope; the floor and the subject's refusals; no
        record yet for this file under this licence. Returns (grant row, uses taken). The licence is looked up first,
        so a party that holds none learns nothing about the subject; with `mask`, a provider known by its domain that
        the registry has not vetted gets one refusal about an unpublished subject whatever its state (step 2, P-5a)."""
        g = db.execute("SELECT * FROM grants WHERE id = ? AND subject_code = ? AND licensee_id IN ('', ?)",
                       (licence_id, subject_ref, requester)).fetchone()
        if g is None:
            raise ProtocolError("PG_NO_LICENSE", "no licence with this id for this subject and this holder", status=403)
        if mask and g["licensee_id"] != requester and self._masked(db, {"provider_id": requester,
                                                                        "subject_ref": subject_ref}, None):
            raise ProtocolError("PG_PROVIDER_NOT_ACCEPTED", "this registry has not accepted this provider (P-5)",
                                status=403)

        def refuse(code, detail, status=403):
            raise ProtocolError(code, detail, status=status)
        s = db.execute("SELECT * FROM subjects WHERE code = ?", (subject_ref,)).fetchone()
        categories = set(scope["categories"])
        terms = self._current_terms(db, s)
        if not g["not_before"] <= now < g["expires_at"]:
            refuse("PG_NO_LICENSE", "the licence is not valid now (not yet, expired, or withdrawn from this holder)")
        if s["status"] in UNAVAILABLE:
            refuse("PG_SUBJECT_DISPUTED" if s["status"] == "disputed" else "PG_SUBJECT_UNAVAILABLE", "the subject is "
                   + s["status"])
        if s["opted_out"]:
            refuse("PG_SUBJECT_OPTED_OUT", "the subject opted out")
        if s["minor"] or s["fixed_refusal"] or categories & INTIMATE:                   # vectors 12, 13
            refuse(s["fixed_refusal"] or "PG_PROHIBITED_USE", "no record for a known minor or in an intimate category")
        if categories & set(json.loads(s["immutable_denials"])):
            refuse("PG_IMMUTABLE_DENIAL", "the subject refuses these categories")
        if terms and categories & set(terms[1]["rules"]["excluded_categories"]):        # vector 14
            refuse("PG_TERMS_EXCLUDED", "the subject's terms exclude these categories")
        if not set(scope["purposes"]) <= set(json.loads(g["purposes"])) \
                or not categories <= set(json.loads(g["categories"])) or scope["not_after"] > g["expires_at"]:
            refuse("PG_SCOPE_VIOLATION", "the scope is wider than the licence (purposes, categories, expires_at)")
        if scope["not_after"] <= now:                                                    # step 4: as of now
            refuse("PG_SCOPE_VIOLATION", "scope.not_after has passed")
        used = self._used(db, g)
        if g["max_uses"] is not None and used >= g["max_uses"]:
            refuse("PG_USAGE_LIMIT", "the licence has no use left")
        if db.execute("SELECT 1 FROM after_gen_records WHERE media_hash = ? AND licence_id = ?", (media, g["id"])).fetchone():
            refuse("PG_ALREADY_APPROVED", "this file is already approved under this licence", status=409)   # vector 8
        return g, used

    def _ag_request_body(self, provider_id: str, authorization: str | None, env) -> dict:
        """A pg.after_gen_request.v1 signed by a requester known by its domain (role requester), never a registry
        credential alone (_check_open refuses one): the record names the requester as the holder by its party id. One
        file, by its media/1 hash."""
        self._check_open(provider_id, authorization)
        body = self._signed_by_provider(env, "pg.after_gen_request.v1", provider_id, role="requester")
        lic, content = body.get("licence"), body.get("content")
        if set(body) != AG_REQUEST_MEMBERS or not isinstance(body["requester"], str) \
                or not isinstance(lic, dict) or set(lic) != {"format", "id"} or lic["format"] != "pg.grant.v1" \
                or not _hex64(lic["id"]) or not isinstance(content, dict) or set(content) != {"binding", "hash", "leaves"} \
                or content["binding"] != "media/1" or not _hex64(content["hash"]) or not _int(content["leaves"], 1) \
                or not _int(body["issued_at"]) or not (isinstance(body["nonce"], str)
                                                       and re.fullmatch(r"[A-Za-z0-9_-]{16,128}", body["nonce"])):
            raise ProtocolError("PG_MALFORMED", "pg.after_gen_request.v1 is {signers, requester, subject_ref, licence, "
                                "content, scope, issued_at, nonce}; content is one file, {binding: media/1, hash: 64 "
                                "lowercase hex, leaves >= 1}; nonce 16-128 of [A-Za-z0-9_-]")
        try:
            issuer_of(body["subject_ref"])
        except PregenError:
            raise ProtocolError("PG_MALFORMED", "subject_ref is not a canonical PG code (PG-CODE.md §7)") from None
        self._ag_scope(body["scope"])
        if body["requester"] != provider_id:
            raise ProtocolError("PG_NOT_AUTHENTICATED", "requester differs from X-Provider-ID", status=401)
        if abs(self.clock() - body["issued_at"]) > AG_SKEW or body["scope"]["not_after"] <= self.clock():
            raise ProtocolError("PG_MALFORMED", "issued_at is more than 300 seconds off, or scope.not_after has passed")
        return body

    def _ag_expire(self):
        """Silence approves nothing (step 3): a request undecided within the review period expires, and its viewing
        link goes (vectors 1, 18). Run lazily, in its own transaction (a refusal after it never rolls it back), before
        any after-gen read, the public lookup and status included, or decision; one indexed update. A decision checks
        the period again inside its own transaction."""
        with self.tx() as db:
            db.execute("UPDATE after_gen_requests SET state = 'expired', decided_at = created_at + ?, preview_url = NULL, "
                       "review_hash = NULL WHERE state IN (?, ?) AND created_at <= ?",
                       (AG_REVIEW, *AG_OPEN, self.clock() - AG_REVIEW))

    @staticmethod
    def _ag_open(row, now: int) -> bool:
        """Undecided by the person (pending, or refused by an agency only) and within the review period."""
        return row is not None and row["state"] in AG_OPEN and now < row["created_at"] + AG_REVIEW

    @staticmethod
    def _ag_close(db, rid: str, state: str, now: int, record: str | None = None):
        db.execute("UPDATE after_gen_requests SET state = ?, decided_at = ?, record_id = ?, preview_url = NULL, "
                   "review_hash = NULL WHERE id = ?", (state, now, record, rid))

    @staticmethod
    def _ag_state(row) -> dict:
        return {"request": row["id"], "state": row["state"], "review_until": row["created_at"] + AG_REVIEW,
                **({"record": row["record_id"]} if row["record_id"] else {})}

    def after_gen_request(self, provider_id: str, authorization: str | None, payload) -> dict:
        """POST /v2/after-gen/requests, steps 1-2. A request permits nothing. The private viewing link travels beside the
        signed body and goes only to the approver. A sandbox returns its test approval page to the requester too."""
        self._ag_on()
        preview = payload.get("preview_url") if isinstance(payload, dict) else None
        if not isinstance(payload, dict) or "request" not in payload or set(payload) - {"request", "preview_url"} \
                or ("preview_url" in payload and not (isinstance(preview, str)
                                                      and re.fullmatch(r"https://[!-~]{1,2040}", preview))):
            raise ProtocolError("PG_MALFORMED", 'the body is {"request": <pg.after_gen_request.v1>, "preview_url"?: https}')
        body = self._ag_request_body(provider_id, authorization, payload["request"])
        rid, token = message_id("pg.after_gen_request.v1", body), secrets.token_urlsafe(32)
        self._ag_expire()
        with self.tx() as db:
            now = self.clock()
            row =db.execute("SELECT * FROM after_gen_requests WHERE id = ?", (rid,)).fetchone()
            if row is not None:                                                  # the identical request again
                return self._ag_state(row)
            self._ag_checks(db, body["requester"], body["subject_ref"], body["licence"]["id"], body["content"]["hash"],
                            body["scope"], now, mask=True)
            db.execute("INSERT INTO after_gen_requests (id, requester, subject_ref, licence_id, media_hash, leaves, scope, "
                       "envelope, preview_url, review_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (rid, body["requester"], body["subject_ref"], body["licence"]["id"], body["content"]["hash"],
                        body["content"]["leaves"], json.dumps(body["scope"]), json.dumps(payload["request"]), preview,
                        _hash_token(token) if self.config.sandbox else None, now))
        out = {"request": rid, "state": "pending", "review_until": now + AG_REVIEW}
        if self.config.sandbox:
            out |= {"review_url": f"{self.config.api.rstrip('/')}/v2/after-gen/review/{token}",
                    "note": "Sandbox only: the test creator's approval page. A production registry never gives the "
                            "approval page to the requester; the person approves at their registry."}
        return out

    def after_gen_request_state(self, provider_id: str, authorization: str | None, pg_access: str | None, rid: str,
                                path: str) -> dict:
        """GET /v2/after-gen/requests/{id}: the requester alone sees its request's state, and once approved the record."""
        self._ag_on()
        pid = self.authenticate_read(provider_id, authorization, pg_access, "GET", path)
        self._ag_expire()
        row = self._row("SELECT * FROM after_gen_requests WHERE id = ? AND requester = ?", (rid, pid))
        if row is None:
            raise ProtocolError("PG_NOT_FOUND", "no such request of yours", status=404)
        return self._ag_state(row)

    @staticmethod
    def _ag_mandates(db, subject_ref: str, agent: str, now: int) -> list:
        """The active mandates of this subject to this agent that list after_gen."""
        return [m for m in db.execute("SELECT * FROM mandates WHERE subject_ref = ? AND agent = ? AND ended_at IS NULL "
                                      "AND not_after > ? ORDER BY rowid", (subject_ref, agent, now))
                if "after_gen" in json.loads(m["powers"])]

    @staticmethod
    def _own_key_body(env, type_: str, s):
        """The body if the subject `s` holds their own key (custody self) and signed `env` with it; None otherwise. No
        subject, a key the registry holds and another key look the same, so a caller who may not act learns nothing
        (step 4). A malformed envelope is refused as such: that depends on the envelope alone."""
        pub = s["key_public"] if s is not None and s["custody"] == "self" else None
        try:
            return check_envelope(env, type_, ("subject",), lambda r, k: pub if pub and k == fingerprint(pub) else None)
        except ProtocolError as e:
            if e.code != "PG_NOT_AUTHENTICATED":
                raise
            return None

    @staticmethod
    def _same_host(a: str, b: str) -> bool:
        """A representative is never the holder of the same record: their hosts differ, whatever the port."""
        return urlsplit(a).hostname == urlsplit(b).hostname

    def after_gen_decide(self, agent: str, env) -> dict:
        """POST /v2/after-gen/decisions: a pg.after_gen_decision.v1 {signers, request, outcome, scope (approve only),
        issued_at}, signed by the subject's own key (custody self; role subject) or by a representative's key from its
        own domain (role agent; X-Provider-ID names it) under a mandate listing after_gen (vectors 2, 3, 5). An agent
        learns nothing of a request, not even that it exists, unless it holds a live after_gen mandate of its subject:
        an unknown request and one it may not decide are the same 404 (step 4). A mandate never approves: an agent may
        only refuse a pending request, which becomes agent_refused and stays open for the subject's own decision until
        the review period ends (The mandate; step 3)."""
        self._ag_on()
        body = env.get("body") if isinstance(env, dict) else None
        signers = body.get("signers") if isinstance(body, dict) else None
        role = signers[0].get("role") if isinstance(signers, list) and len(signers) == 1 \
            and isinstance(signers[0], dict) else None
        if role not in ("subject", "agent") or set(body) != {"signers", "request", "outcome", "issued_at"} \
                | ({"scope"} if body.get("outcome") == "approve" else set()) \
                or body["outcome"] not in ("approve", "refuse") or not _hex64(body["request"]) or not _int(body["issued_at"]):
            raise ProtocolError("PG_MALFORMED", "pg.after_gen_decision.v1 is {signers: one, role subject or agent, "
                                "request, outcome: approve|refuse, scope (approve only), issued_at}")
        if role == "agent":
            try:
                check_provider_url(agent, allow_port=self.config.sandbox)
            except PregenError as e:
                raise ProtocolError("PG_NOT_AUTHENTICATED", f"X-Provider-ID names the agent: {e}", status=401) from None
            self._signed_by_provider(env, "pg.after_gen_decision.v1", agent, role="agent")
        with self.lock:
            row = self.db.execute("SELECT * FROM after_gen_requests WHERE id = ?", (body["request"],)).fetchone()
            s = row and self.db.execute("SELECT * FROM subjects WHERE code = ?", (row["subject_ref"],)).fetchone()
            hidden = row is None or role == "agent" and not self._ag_mandates(self.db, row["subject_ref"], agent,
                                                                              self.clock())
        if hidden or role == "subject" and self._own_key_body(env, "pg.after_gen_decision.v1", s) is None:   # vector 4
            raise ProtocolError("PG_NOT_FOUND", "no such request", status=404)
        if role == "agent" and body["outcome"] == "approve":                             # vectors 3, 5
            raise ProtocolError("PG_NO_MANDATE", "a mandate never approves: only the person approves", status=403)
        now, did = self.clock(), message_id("pg.after_gen_decision.v1", body)
        if abs(now - body["issued_at"]) > AG_SKEW:
            raise ProtocolError("PG_MALFORMED", "issued_at is more than 300 seconds off")
        self._ag_expire()
        with self.tx() as db:
            row = db.execute("SELECT * FROM after_gen_requests WHERE id = ?", (row["id"],)).fetchone()
            if not self._ag_open(row, now) or role == "agent" and row["state"] != "pending":   # vector 1
                raise ProtocolError("PG_REQUEST_CLOSED", f"this request is {row['state']}", status=409)
            if role == "agent":                                     # a refusal only; it keeps the request open
                if self._same_host(agent, row["requester"]):                             # vectors 2, 3
                    raise ProtocolError("PG_NO_MANDATE", "a representative is never the holder of the same record",
                                        status=403)
                if not self._ag_mandates(db, row["subject_ref"], agent, now):            # ended since the check above
                    raise ProtocolError("PG_NO_MANDATE", "no active mandate of this subject gives this agent the "
                                        "power after_gen", status=403)
                db.execute("UPDATE after_gen_requests SET state = 'agent_refused' WHERE id = ?", (row["id"],))
                return self._ag_state({**dict(row), "state": "agent_refused"})
            if body["outcome"] == "refuse":
                self._ag_close(db, row["id"], "refused", now)
                return {"request": row["id"], "state": "refused"}
            scope = self._ag_scope(body["scope"])
            if not self._ag_within(scope, json.loads(row["scope"])):
                raise ProtocolError("PG_SCOPE_VIOLATION", "a decision never approves a scope wider than the request's")
            return {"request": row["id"], "state": "approved",
                    "record": self._sign_after_gen(db, row, scope, {"assent": "self", "decision": did}, now,
                                                   decision=env)}

    def _sign_after_gen(self, db, row, scope: dict, approval: dict, now: int, decision=None) -> str:
        """Step 4: every check of step 2 again as of now, one use of the licence counted, the decision envelope kept
        with the record, and pg.after_gen.v1 signed by the registry. `approval` is exactly one of the two forms, the
        person's own act; a mandate never approves (vectors 3, 4). Returns the record id; its status is at
        GET {api}/v2/after-gen/{id}, which the record cannot name (its id is the hash of its body)."""
        a = approval
        if set(a) != AG_APPROVALS.get(a.get("assent"), set()) \
                or a["assent"] == "registry" and (a["factor"] not in AG_FACTORS or not _hex64(a["instruction"])):
            raise ProtocolError("PG_MALFORMED", "approval is self {assent, decision} or registry {assent, instruction, "
                                "factor}: only the person approves, never under a mandate")
        if a["assent"] == "self" and db.execute("SELECT custody FROM subjects WHERE code = ?",
                                                (row["subject_ref"],)).fetchone()["custody"] != "self":
            raise ProtocolError("PG_PERSONAL_SIGNATURE_REQUIRED", "self is the subject's own key", status=403)
        g, used = self._ag_checks(db, row["requester"], row["subject_ref"], row["licence_id"], row["media_hash"], scope, now)
        env = seal("pg.after_gen.v1", {
            **AG_CONSTANTS, "subject_ref": row["subject_ref"],
            "content": {"binding": "media/1", "hash": row["media_hash"], "leaves": row["leaves"]},
            "request": row["id"], "holder": row["requester"],
            "basis": {"kind": "licence", "licence": {"format": "pg.grant.v1", "id": g["id"]},
                      "use": {"n": used + 1, "of": g["max_uses"]}}, "scope": scope, "approval": a, "issued_at": now},
            [("registry", self.key)])
        record = message_id(env["type"], env["body"])
        db.execute("INSERT INTO after_gen_records (id, request_id, subject_ref, media_hash, licence_id, envelope, "
                   "issued_at, not_after, decision) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   (record, row["id"], row["subject_ref"], row["media_hash"], g["id"], json.dumps(env), now,
                    scope["not_after"], json.dumps(decision) if decision else None))
        self._ag_close(db, row["id"], "approved", now, record)
        return record

    def approve_after_gen(self, rid: str, *, instruction: str, factor: str | None, purposes=None) -> str:
        """assent registry: the operator, on the subject's authenticated instruction, with the second factor it confirmed
        (an approval opens). `purposes` narrows the request's. Returns the record id."""
        self._ag_on()
        if factor not in AG_FACTORS or not _hex64(instruction):
            raise ValueError("an approval opens: it needs --instruction-sha256 (64 hex) and the second factor confirmed, "
                             "--factor authenticator|email")
        self._ag_expire()
        with self.tx() as db:
            now = self.clock()
            row = db.execute("SELECT * FROM after_gen_requests WHERE id = ?", (rid,)).fetchone()
            if not self._ag_open(row, now):
                raise ValueError(f"no pending request {rid}" + (f": it is {row['state']}" if row else ""))
            asked = json.loads(row["scope"])
            scope = self._ag_scope({**asked, "purposes": sorted(set(purposes))} if purposes else asked)
            if not self._ag_within(scope, asked):
                raise ValueError("a decision never approves a scope wider than the request's")
            return self._sign_after_gen(db, row, scope, {"assent": "registry", "instruction": instruction,
                                                         "factor": factor}, now)

    def refuse_after_gen(self, rid: str):
        """The subject refused (closing: no factor). Nothing is published."""
        self._ag_on()
        self._ag_expire()
        with self.tx() as db:
            now = self.clock()
            if not self._ag_open(db.execute("SELECT * FROM after_gen_requests WHERE id = ?", (rid,)).fetchone(), now):
                raise ValueError(f"no pending request {rid}")
            self._ag_close(db, rid, "refused", now)

    def after_gen_request_info(self, rid: str | None = None, token: str | None = None):
        """A request the person has not decided (pending, or refused by an agency only) for its approver, with its
        viewing link: by id (the operator), or by a sandbox review token. None when there is none."""
        self._ag_on()
        self._ag_expire()
        row = self._row("SELECT * FROM after_gen_requests WHERE state IN (?, ?) AND (id = ? OR review_hash = ?)",
                        (*AG_OPEN, rid or "", _hash_token(token) if token else ""))
        return dict(row) if row else None

    def after_gen_review(self, token: str, decision: str, evidence: str) -> str | None:
        """The sandbox's approval page answered: the test creator, with a simulated second factor (assent registry,
        factor email; a sandbox holds no real people). The token is spent by the decision. Returns the record id."""
        if not self.config.sandbox:
            raise ProtocolError("PG_NOT_FOUND", "the approval page is a sandbox's", status=404)
        row = self.after_gen_request_info(token=token)
        if row is None or decision not in ("approve", "refuse"):
            raise ProtocolError("PG_NOT_FOUND", "no pending request for this page, or no decision", status=404)
        with self.tx() as db:
            now = self.clock()
            row = db.execute("SELECT * FROM after_gen_requests WHERE id = ? AND review_hash = ?",
                             (row["id"], _hash_token(token))).fetchone()
            if not self._ag_open(row, now):
                raise ProtocolError("PG_NOT_FOUND", "this page was answered already", status=404)
            if decision == "refuse":
                self._ag_close(db, row["id"], "refused", now)
                return None
            proof = {"page": "sandbox after-gen review", "request": row["id"], "form": evidence, "at": now}
            return self._sign_after_gen(db, row, json.loads(row["scope"]), {
                "assent": "registry", "instruction": hashlib.sha256(canonical(proof)).hexdigest(), "factor": "email"}, now)

    def withdraw_after_gen(self, record_id: str, env=None, *, instruction: str | None = None) -> dict:
        """Step 5: the subject withdraws a record with their own key (a pg.after_gen_withdrawal.v1 {signers, record,
        issued_at}, role subject, custody self), or by an authenticated instruction. It closes: no second factor, and
        it keeps working for every record signed when the registry no longer takes new requests (step 5). A signed
        withdrawal not by the subject's own key gets the answer an unknown record gets."""
        row = self._row("SELECT r.*, s.custody, s.key_public FROM after_gen_records r JOIN subjects s ON "
                        "s.code = r.subject_ref WHERE r.id = ?", (record_id,))
        body = None if env is None else self._own_key_body(env, "pg.after_gen_withdrawal.v1", row)
        if row is None or env is not None and body is None:
            raise ProtocolError("PG_NOT_FOUND", "no such record", status=404)
        if env is None:
            if not _hex64(instruction):
                raise ValueError("a withdrawal on instruction names --instruction-sha256 (64 hex)")
            how = {"assent": "registry", "instruction": instruction}
        else:
            if set(body) != {"signers", "record", "issued_at"} or body["record"] != record_id \
                    or not _int(body["issued_at"]) or abs(self.clock() - body["issued_at"]) > AG_SKEW:
                raise ProtocolError("PG_MALFORMED", "pg.after_gen_withdrawal.v1 is {signers, record: this record, "
                                    "issued_at within 300 seconds}")
            how = {"assent": "self", "withdrawal": message_id(env["type"], body)}
        with self.tx() as db:
            db.execute("UPDATE after_gen_records SET withdrawn_at = ?, withdrawal = ? WHERE id = ? AND withdrawn_at IS NULL",
                       (self.clock(), json.dumps(how), record_id))
            at = db.execute("SELECT withdrawn_at FROM after_gen_records WHERE id = ?", (record_id,)).fetchone()[0]
        return {"record": record_id, "state": "withdrawn", "withdrawn_at": at}

    def after_gen_lookup(self, media: str) -> dict:
        """GET /v2/after-gen?media=: approved records only, withdrawn and expired ones included (their status says so);
        never a pending, agency-refused, refused or expired request (vector 17). Answered with after-gen off too (step 5)."""
        if not _hex64(media):
            raise ProtocolError("PG_MALFORMED", "media is a media/1 hash, 64 lowercase hex")
        self._ag_expire()
        return {"records": [r["id"] for r in self._q("SELECT id FROM after_gen_records WHERE media_hash = ? "
                                                    "ORDER BY issued_at, id", (media,))]}

    def after_gen_status(self, rid: str) -> dict:
        """GET /v2/after-gen/{id}: the record, and a pg.after_gen_status.v1 the registry signs now that lives five
        minutes. Withdrawn wins over expired, so a withdrawal is never hidden. Answered with after-gen off too."""
        self._ag_expire()
        row = self._row("SELECT * FROM after_gen_records WHERE id = ?", (rid,))
        if row is None:
            raise ProtocolError("PG_NOT_FOUND", "no such record", status=404)
        now = self.clock()
        state = "withdrawn" if row["withdrawn_at"] is not None else "expired" if now >= row["not_after"] else "active"
        status = seal("pg.after_gen_status.v1", {"record": row["id"], "state": state, "approved_at": row["issued_at"],
                                                 "withdrawn_at": row["withdrawn_at"], "not_after": row["not_after"],
                                                 "issued_at": now, "expires_at": now + TTL}, [("registry", self.key)])
        return {"record": json.loads(row["envelope"]), "status": status}

    def add_mandate(self, subject_ref: str, agent: str, *, powers, purposes, not_after: int, instruction: str,
                    factor: str | None) -> str:
        """pg.mandate.v1 signed by the registry on the subject's instruction, with its second factor. The power
        after_gen lets the agent refuse a request the subject has not decided, and nothing more: a mandate never
        approves. Returns its id."""
        if factor not in AG_FACTORS or not _hex64(instruction):
            raise ValueError("a mandate opens: it needs --instruction-sha256 (64 hex) and --factor authenticator|email")
        return self._store_mandate(seal("pg.mandate.v1", {
            "subject_ref": subject_ref, "agent": agent, "powers": sorted(set(powers)),
            "limits": {"purposes": sorted(set(purposes))}, "not_after": not_after, "assent": "registry",
            "instruction": instruction, "factor": factor, "issued_at": self.clock()}, [("registry", self.key)]))

    def add_mandate_envelope(self, env) -> str:
        """A pg.mandate.v1 the subject signed with their own key (custody self, role subject, assent self)."""
        body = env.get("body") if isinstance(env, dict) else None
        s = self._row("SELECT * FROM subjects WHERE code = ?", (body.get("subject_ref", ""),)) if isinstance(body, dict) else None
        if s is None or s["custody"] != "self":
            raise ValueError("a signed mandate is the subject's own, for a subject who holds their key (custody self)")
        check_envelope(env, "pg.mandate.v1", ("subject",), lambda r, k: s["key_public"] if k == fingerprint(s["key_public"])
                       else None)
        if body.get("assent") != "self":
            raise ValueError("a mandate the subject signed has assent self")
        return self._store_mandate(env)

    def _store_mandate(self, env) -> str:
        b, now = env["body"], self.clock()
        members = {"signers", "subject_ref", "agent", "powers", "limits", "not_after", "assent", "issued_at"} \
            | ({"instruction", "factor"} if b.get("assent") == "registry" else set())
        try:
            check_provider_url(b.get("agent"), allow_port=self.config.sandbox)
        except PregenError as e:
            raise ValueError(f"agent is the representative's party id: {e}") from None
        p, w = b.get("powers"), b.get("limits")
        if set(b) != members or not self._row("SELECT 1 FROM subjects WHERE code = ?", (b["subject_ref"],)) \
                or not (isinstance(p, list) and p and p == sorted(set(p))
                        and all(isinstance(x, str) and re.fullmatch(r"[a-z_]{1,32}", x) for x in p)) \
                or not (isinstance(w, dict) and set(w) == {"purposes"} and isinstance(w["purposes"], list) and w["purposes"]
                        and w["purposes"] == sorted(set(w["purposes"])) and set(w["purposes"]) <= PURPOSES) \
                or not _int(b["not_after"]) or b["not_after"] <= now or not _int(b["issued_at"]) \
                or b["issued_at"] > now + AG_SKEW:
            raise ValueError("pg.mandate.v1 is {signers, subject_ref (here), agent, powers, limits: {purposes}, not_after "
                             "(future), assent, [instruction, factor], issued_at}")
        mid = message_id(env["type"], b)
        with self.tx() as db:
            db.execute("INSERT OR IGNORE INTO mandates VALUES (?, ?, ?, ?, ?, ?, NULL, ?)", (
                mid, b["subject_ref"], b["agent"], json.dumps(p), json.dumps(w), b["not_after"], json.dumps(env)))
        return mid

    def end_mandate(self, mandate_id: str):
        """Ending a mandate closes: no second factor."""
        with self.tx() as db:
            if not db.execute("UPDATE mandates SET ended_at = ? WHERE id = ? AND ended_at IS NULL",
                              (self.clock(), mandate_id)).rowcount:
                raise ValueError(f"no active mandate {mandate_id}")

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
                # the ask by its id first: one that stepped aside under T-7 keeps it, and only it can be given back
                ask = db.execute("SELECT * FROM asks WHERE id = ?", (body["request_id"],)).fetchone() \
                    or self._bind(db, req)
                ans = None
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
                for aid in released:          # given back unseen: never reported again, as generated or otherwise
                    db.execute("UPDATE answers SET report_id = ? WHERE id = ?", (rid, aid))
            if body["outcome"] == "generated":
                db.execute("UPDATE asks SET closing_ack = ? WHERE id = ?", (json.dumps(ack), ask["id"]))
            return {"ack": ack}

    def _account(self, db, ask_id: str, body: dict, now: int):
        """extensions/limits.md."""
        reserved = db.execute("SELECT id, issued_at, expires_at FROM answers WHERE ask_id = ? AND use = 'reserved' "
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
        # A not_generated report releases its own allow; with `answer: null` (an allow the provider never received),
        # every reserved allow of this ask that has expired, so none can still be used (limits.md). Either way,
        # inside the give-back window only.
        for a in reserved:
            if (a["id"] == body["answer"] or (body["answer"] is None and a["expires_at"] <= now)) and give_back(a):
                db.execute("UPDATE answers SET use = 'released' WHERE id = ?", (a["id"],))
                released.append(a["id"])
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
        out = {"code": code, "registry": self.config.prefix, "status": "active", "name": s["name"], "level": s["level"],
               "subject_key": {"key_id": fingerprint(s["key_public"]),
                               "public_key_hex": s["key_public"], "custody": s["custody"]}}
        with self.lock:
            terms = self._current_terms(self.db, s)
        if terms:
            api = self.config.api.rstrip("/")
            out |= {"terms": {"id": terms[0], "url": f"{api}/v2/terms/{terms[0]}"},
                    "status_url": f"{api}/v2/codes/{code}/terms"}
        return out

    def status(self, code: str) -> dict:
        """lookup.md `status_url`: a published subject's current terms and every earlier version, newest first; for
        any other code, nothing (the versions themselves stay fetchable by id, T-2)."""
        s = self._row("SELECT * FROM subjects WHERE code = ?", (code,))
        with self.lock:
            if s is None or self._current_terms(self.db, s) is None:
                raise ProtocolError("PG_NOT_FOUND", "no published terms for this code", status=404)
            rows = self.db.execute("SELECT envelope FROM terms WHERE subject_code = ? ORDER BY version DESC",
                                   (code,)).fetchall()
        return {"code": code, "terms": [json.loads(r["envelope"]) for r in rows]}

    def terms(self, terms_id: str) -> dict:
        """terms T-2: every version ever published, whatever became of the subject since."""
        row = self._row("SELECT envelope FROM terms WHERE id = ?", (terms_id,))
        if not row:
            raise ProtocolError("PG_UNKNOWN_TERMS", "no terms with this id were ever published here", status=404)
        return {"terms": json.loads(row["envelope"])}

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
        """proof.md: the part of a proof this registry holds, found by its report id."""
        if not re.fullmatch(r"[0-9a-f]{16}", short_id):
            raise ProtocolError("PG_MALFORMED", "a proof id is 16 hex characters")
        rows = self._q("SELECT r.envelope AS report, r.ack, k.request, k.signatures, a.envelope AS answer, t.envelope AS "
                       "terms FROM reports r JOIN asks k ON k.id = r.ask_id JOIN answers a ON a.report_id = r.id "
                       "LEFT JOIN terms t ON t.id = json_extract(k.request, '$.terms') "
                       "WHERE r.id LIKE ? AND k.closing_ack IS NOT NULL", (short_id + "%",))
        if len(rows) != 1:
            raise ProtocolError("PG_NOT_FOUND", "no such proof", status=404)
        r = rows[0]
        item = {"request": {"type": "pg.request.v1", "body": json.loads(r["request"]), "signatures": json.loads(r["signatures"])},
                "answer": json.loads(r["answer"]), "report": json.loads(r["report"]), "ack": json.loads(r["ack"])}
        if r["terms"]:                                     # terms: the record the request accepted travels with it
            item["terms"] = json.loads(r["terms"])
        return {"format": "pg.proof.v1", "subjects": [item]}

    def document(self) -> dict:
        api = self.config.api.rstrip("/")
        return {"prefix": self.config.prefix, "name": self.config.name, "api": api, "keys": api + "/keys",
                "profiles": self.config.profiles, "extensions": EXTENSIONS + (["sandbox", "bind"] if self.config.sandbox else [])
                + (["provider-identity"] if self.config.providers == "open" else []) + (["terms"] if self.config.terms else [])
                + (["after-gen"] if self.config.after_gen else []),
                "policy": self.config.policy, "complaints": self.config.complaints, "sandbox": self.config.sandbox,
                "providers": self.config.providers, "spec": "PRE-GEN v5", **({"terms": "optional"} if self.config.terms else {}),
                **({"bind": {"authorize": api + "/v2/bind/authorize", "token": api + "/v2/bind/token"}}
                   if self.config.sandbox else {})}

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
