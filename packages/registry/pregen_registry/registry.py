"""The registry: state in SQLite, the core rules, profile likeness/1 and the extensions
reports, provider-keys, limits, jobs, grants, licensee, observe, sandbox, lookup, provider-identity, terms and, in a
sandbox, bind.

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

from pregen import (CATEGORIES, DIRECTORY_URL, INTIMATE, PROHIBITED_FOR_MINORS, Mistyped, PregenError,
                    check_provider_url, check_public_key, code_for, code_key, fingerprint, forbids, issuer_of, parse_code,
                    terms_opens)
from urllib.parse import urlsplit

from .protocol import Key, ProtocolError, canonical, check_body, check_envelope, message_id, mint_code, mint_serial, seal

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
  envelope TEXT NOT NULL, resale INTEGER NOT NULL DEFAULT 0, categories TEXT NOT NULL DEFAULT '[]', code TEXT);
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
  report_id TEXT, code TEXT);
CREATE TABLE IF NOT EXISTS bind_consents (nonce_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL, challenge TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS bind_codes (code_hash TEXT PRIMARY KEY, provider_id TEXT NOT NULL, redirect_uri TEXT NOT NULL,
  challenge TEXT NOT NULL, account TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0,
  binding TEXT);
CREATE TABLE IF NOT EXISTS bindings (licensee_id TEXT PRIMARY KEY, id TEXT NOT NULL, provider_id TEXT NOT NULL,
  account TEXT NOT NULL, grants TEXT NOT NULL, expires_at INTEGER NOT NULL, ended_at INTEGER, envelope TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, provider_id TEXT NOT NULL, ask_id TEXT NOT NULL,
  envelope TEXT NOT NULL, ack TEXT NOT NULL);
"""


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _reply(answer: dict, code: str | None) -> dict:
    """POST /v2/requests: the signed answer; with an allow, its ToG code beside it, a readable copy (TOG-CODE §14)."""
    return {"answer": answer, "attachments": [], **({"code": code} if code else {})}


def _tog(subject) -> str:
    """A subject row's code in its one written spelling (TOG-CODE §7.3): a row born PG- keeps its stored spelling."""
    return code_key(subject["code"])


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

    def __post_init__(self):
        try:                            # TOG-CODE §9: 4 to 8 letters A-Z, never LIC at either end (the library's grammar)
            parse_code(f"TOG-{self.prefix}-1000000000", check=False)
        except PregenError:
            raise ValueError("a registry's prefix is 4 to 8 letters A-Z that never begin or end with LIC, and no 4-letter "
                             "prefix is LIC with one letter added (TOG-CODE.md §9; new codes are never bare)") from None
        if self.sandbox and not re.fullmatch(r"[ABCDEFGHJKMNPQRSTVWXYZ]{4}", self.prefix):
            raise ValueError("a sandbox's prefix is four letters of the PG alphabet: its fixed test subjects are PG-born "
                             "codes, respelled TOG- (extensions/sandbox.md)")
        if self.providers not in ("open", "registered"):
            raise ValueError("providers is open or registered")
        if self.sandbox:
            self.providers = "open"
        self.terms = self.terms and self.providers == "open"   # terms requires provider-identity: none could accept them


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
        for table in ("grants", "answers"):     # 0.5: the act's ToG code, computed from its signed record (an index)
            if "code" not in {r["name"] for r in self.db.execute(f"PRAGMA table_info({table})")}:
                self.db.execute(f"ALTER TABLE {table} ADD COLUMN code TEXT")
            self.db.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS {table}_code ON {table} (code)")   # issued once
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
        self._backfill_codes()
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

    # ── ToG codes (TOG-CODE.md): one spelling, TOG-; a PG- string is legacy input only ─
    def _subject(self, db, ref: str):
        """The row of the person `ref` names here, or None (another registry's code, or none of ours). Found by number
        (lookup.md, Spellings), so a PG- string is legacy input for the same person and a row keeps the spelling it was
        born with; a record or list writes its TOG spelling (_tog). An over-padded number is PG_MALFORMED with the TOG
        spelling as a hint, never an answer; a string that is not a person's code is PG_MALFORMED."""
        try:
            p, key = parse_code(ref), code_key(ref)
        except Mistyped:
            raise ProtocolError("PG_MALFORMED", "mistyped code: its check character does not match") from None
        except PregenError:
            raise ProtocolError("PG_MALFORMED", "not a person's ToG code (TOG-CODE.md §7)") from None
        if p["kind"] != "subject":
            raise ProtocolError("PG_MALFORMED", "not a person's code: a subject_ref names a person (TOG-CODE.md §2)")
        if p["issuer"] != self.config.prefix:
            return None
        s = db.execute("SELECT * FROM subjects WHERE serial = ?", (int(p["serial"]),)).fetchone()
        if s is not None and _tog(s) != key:
            raise ProtocolError("PG_MALFORMED", f"over-padded number: the code is {_tog(s)}", hint=_tog(s))
        return s

    def _own(self, db, code: str):
        """An operator action's subject: its row, or ValueError."""
        try:
            s = self._subject(db, code)
        except ProtocolError as e:
            raise ValueError(f"{code}: {e.detail}") from None
        if s is None:
            raise ValueError(f"no subject {code} in this registry")
        return s

    def _code(self, env: dict, subject_ref: str, grant_id: str | None = None) -> str | None:
        """The ToG code of an act this registry signed, computed from the record (TOG-CODE §6.1, the flat model: the
        registry signs only for its own people), or None when it gives none (a symbol check, a ZZZZ tail)."""
        try:
            return code_for({"type": env["type"], "id": message_id(env["type"], env["body"]), "signer": self.config.prefix,
                             "subject_ref": subject_ref,
                             "grant": {"id": grant_id, "signer": self.config.prefix} if grant_id else None})
        except PregenError:
            return None

    def _backfill_codes(self):
        """Licences and allows signed before 0.5 get their ToG code by computation, exactly like new ones (TOG-CODE
        §6.2, hard switch): an index beside the record, never a rewritten record. One that gives no code waits for
        its home's countersignature (the home model, not published yet) and stays without one."""
        with self.tx() as db:
            for r in db.execute("SELECT id, envelope FROM grants WHERE code IS NULL").fetchall():
                env = json.loads(r["envelope"])
                db.execute("UPDATE grants SET code = ? WHERE id = ?", (self._code(env, env["body"]["subject_ref"]), r["id"]))
            for r in db.execute("SELECT a.id, a.envelope, a.grant_id, json_extract(k.request, '$.subject_ref') AS ref "
                                "FROM answers a JOIN asks k ON k.id = a.ask_id WHERE a.status = 'allow' "
                                "AND a.code IS NULL").fetchall():
                db.execute("UPDATE answers SET code = ? WHERE id = ?",
                           (self._code(json.loads(r["envelope"]), r["ref"], r["grant_id"]), r["id"]))

    # ── operator actions (CLI) ───────────────────────────────────────────
    def add_subject(self, name: str, *, serial: int | None = None, level: str = "self", holder_public: str | None = None,
                    **flags) -> str:
        """A new person is born TOG-<prefix>-<9 random digits><check> (TOG-CODE §5); `serial` only for a sandbox's
        fixed test subjects. `holder_public`: the person holds their own key (custody self); the registry never sees it."""
        if holder_public:
            check_public_key(holder_public)          # a small-order key would let anyone sign as the person (C1)
        # A real person's name is public at /v2/codes only by their choice; a sandbox holds no real people.
        flags.setdefault("published", int(self.config.sandbox))
        with self.tx() as db:
            if serial is None:
                serial = mint_serial(self.config.prefix)
                while db.execute("SELECT 1 FROM subjects WHERE serial = ?", (serial,)).fetchone():
                    serial = mint_serial(self.config.prefix)
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
            s = self._own(db, subject_code)
            signer = Key(s["key_private"]) if s["key_private"] else holder_key
            if signer is None or signer.public_hex != s["key_public"]:
                raise ValueError("a grant is signed by the subject's own key: this subject holds it (self custody)")
            now = self.clock()
            use = {"purposes": sorted(purposes)}
            if categories:
                use["categories"] = sorted(categories)
            if resale:
                use["resale"] = True
            for second in range(64):  # grants.md: a code ending in a symbol, starting ZZZZ or issued already: sign
                env = seal("pg.grant.v1", {     # again with a changed body, here a licence one second shorter
                    "subject_ref": _tog(s), "licensee_id": licensee_id, "profile": PROFILE, "use": use, "not_before": now,
                    "expires_at": now + days * 86400 - second, "max_uses": max_uses, **({"ext": ext} if ext else {})},
                    [("rights_holder", signer), ("registry", self.key)])
                code = self._code(env, _tog(s))
                if code and not db.execute("SELECT 1 FROM grants WHERE code = ?", (code,)).fetchone():
                    break
            else:
                raise ValueError("no ToG code after 64 signings")
            gid = message_id(env["type"], env["body"])
            db.execute("INSERT INTO grants VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (gid, s["code"], licensee_id, json.dumps(sorted(purposes)), now, env["body"]["expires_at"],
                        max_uses, uses_offset, json.dumps(env), int(resale), json.dumps(sorted(categories)), code))
            return gid

    def set_identity(self, code: str, *, anchor: str | None = None, proof_url: str | None = None,
                     offer: dict | None = None):
        """identity.md: the public anchor and the official-channel confirmation; catalog.md: the offer, only with
        the person's consent to be listed."""
        with self.tx() as db:
            db.execute("UPDATE subjects SET anchor = ?, proof_url = ?, offer = ? WHERE code = ?",
                       (anchor, proof_url, json.dumps(offer) if offer is not None else None, self._own(db, code)["code"]))

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
            db.execute("UPDATE subjects SET published = ? WHERE code = ?", (int(published), self._own(db, code)["code"]))

    def set_level(self, code: str, level: str):
        """How far the registry has established who holds the person's rights; answers carry it from now on."""
        if level not in ("self", "asserted", "consented", "verified"):
            raise ValueError(f"unknown level {level}")
        with self.tx() as db:
            db.execute("UPDATE subjects SET level = ? WHERE code = ?", (level, self._own(db, code)["code"]))

    def opt_out(self, code: str):
        """The person opted out or withdrew: every answer from now on is PG_SUBJECT_OPTED_OUT (core rule 3)."""
        with self.tx() as db:
            db.execute("UPDATE subjects SET opted_out = 1 WHERE code = ?", (self._own(db, code)["code"],))

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
            s = self._own(db, code)
            if not self.config.terms or not s["published"] or s["level"] not in TERMS_LEVELS:
                raise ValueError("terms are published only for a published subject that is consented or verified (T-1)")
            last = db.execute("SELECT id, envelope FROM terms WHERE subject_code = ? ORDER BY version DESC LIMIT 1",
                              (s["code"],)).fetchone()
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
            act = {"subject": _tog(s), **new, "factor": factor if opens else None, "at": now}   # the private record
            body = {"subject_ref": _tog(s), "profile": PROFILE, "version": old["version"] + 1 if old else 1,
                    **({"amends": last["id"]} if old else {}), **new, "assent": "registry",
                    "instruction": hashlib.sha256(canonical(act)).hexdigest(), **({"factor": factor} if opens else {}),
                    "issued_at": now}
            env = seal("pg.terms.v1", body, [("registry", self.key)])
            check_body("terms", env["body"])
            tid = message_id(env["type"], env["body"])
            db.execute("INSERT INTO terms VALUES (?, ?, ?, ?, ?)",
                       (tid, s["code"], body["version"], json.dumps(env), canonical(act).decode()))
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
                             "add your own test people there again; they get new random codes.")
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
        key = code_key(body["subject_ref"])          # either spelling buys the one person
        offer = next((o for o in self.catalog()["offers"] if o["subject_ref"] == key), None)
        if offer is None:
            raise ProtocolError("PG_NOT_FOUND", "this subject is not in the catalog", status=404)
        with self.lock:                # the purchase number keeps two purchases in one second two grants
            s = self._subject(self.db, key)
            n = self._row("SELECT COUNT(*) FROM grants WHERE subject_code = ? AND licensee_id = ?",
                          (s["code"], provider_id))[0] + 1
            return self.grant(self.add_grant(key, licensee_id=provider_id, purposes=offer["purposes"],
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
                open_ = db.execute("SELECT envelope, code FROM answers WHERE ask_id = ? AND expires_at > ? AND (use IS "
                                   "NULL OR use != 'released') ORDER BY issued_at DESC", (ask["id"], now)).fetchone()
                if open_:
                    return _reply(json.loads(open_["envelope"]), open_["code"])
            decision = self._decide(db, body, now)
            # T-7: signed, but binds no job, no ask; a masked answer (P-5a) is kept like any other, so nothing tells apart
            if decision[1] == "PG_TERMS_NOT_ACCEPTED" and not self._masked(db, body, decision[1]):
                return _reply(*self._answer(db, None, body, decision, now))
            ask = ask or self._bind(db, body, env["signatures"])
            return _reply(*self._answer(db, ask["id"], body, decision, now))

    def _checked_request(self, provider_id: str, authorization: str | None, env) -> dict:
        """A request's shape and its provider's authentication: signed by an open provider, or a registered one's token."""
        if self.is_open(provider_id):            # provider-identity P-1: signed with the current key of its chain
            self._check_open(provider_id, authorization)
            body = self._signed_by_provider(env, "pg.request.v1", provider_id)
        else:
            body = check_envelope(env, "pg.request.v1", (), lambda *_: None)
        check_body("request", body)
        with self.lock:                          # never a signed answer to a string that is not a person's code, nor
            self._subject(self.db, body["subject_ref"])  # to an over-padded number (H5, TOG-CODE §7.2)
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
        try:                     # one person, one ask, in either spelling (a 0.4 row keeps the spelling it was asked in)
            rid, key = message_id("pg.request.v1", body), code_key(body["subject_ref"])
        except PregenError:      # a report's request with no answer reaches here unchecked
            raise ProtocolError("PG_MALFORMED", "subject_ref is not a person's ToG code (TOG-CODE.md §7)") from None
        ask = db.execute("SELECT * FROM asks WHERE provider_id = ? AND job_id = ? AND subject_ref IN (?, ?)",
                         (body["provider_id"], body["job_id"], key, "PG" + key[3:])).fetchone()
        if ask is None:
            db.execute("INSERT INTO asks (id, provider_id, job_id, subject_ref, request, signatures) VALUES (?, ?, ?, ?, ?, ?)",
                       (rid, body["provider_id"], body["job_id"], key, json.dumps(body), json.dumps(list(signatures))))
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
        s = self._subject(db, req["subject_ref"])
        terms = self._current_terms(db, s) if s is not None else None
        return terms is None or terms[0] != req["terms"]

    def _decide(self, db, req: dict, now: int):
        """(status, reason, grant row, level) under likeness/1, in the order of extensions/terms.md (The gate): the
        subject step, the floor and the person's refusals, the registry's state, the person's exclusions where no grant
        covers the use, who asks, then grants."""
        if issuer_of(req["subject_ref"]) != self.config.prefix:
            return "deny", "PG_OTHER_REGISTRY", None, "self"
        s = self._subject(db, req["subject_ref"])
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
            if g["max_uses"] is None:
                return "allow", None, g, level
            used = db.execute("SELECT COUNT(*) FROM answers WHERE grant_id = ? AND use IN ('reserved', 'consumed')",
                              (g["id"],)).fetchone()[0] + g["uses_offset"]
            if used < g["max_uses"]:
                return "allow", None, g, level
        return "deny", "PG_USAGE_LIMIT", None, level

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
        s = self._subject(db, req["subject_ref"])
        if s is not None and (s["published"] or s["offer"] is not None or s["anchor"] is not None):  # lookup, catalog
            return False                                                         # or the anchor list names it
        licensee, now = req.get("licensee_id", ""), self.clock()      # P-5a: a licensee connected or bound to this
        binding = self._binding(db, pid, licensee)                      # provider that holds a live grant on the
        bound = set(json.loads(binding["grants"])) if binding else set()  # subject learns every answer about it
        if not (binding or licensee and db.execute("SELECT 1 FROM connections WHERE provider_id = ? AND licensee_id = ?",
                                                   (pid, licensee)).fetchone()):
            return True
        return s is None or not any(g["licensee_id"] == licensee or g["id"] in bound for g in db.execute(
            "SELECT id, licensee_id FROM grants WHERE subject_code = ? AND not_before <= ? AND expires_at > ?",
            (s["code"], now, now)))

    def _answer(self, db, ask_id, req: dict, decision, now: int) -> tuple[dict, str | None]:
        """The signed answer to `decision`, kept under `ask_id`; with none (terms T-7) it is kept nowhere. With an allow,
        its ToG code (proof.md: TOG-PG-LIC-…, computed from the answer, issued once)."""
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
        # proof.md: an allow whose code would end in a symbol, start ZZZZ or was issued already is signed again with a
        # changed body: a second shorter, or longer when a sandbox's answer would not live a second
        code = None
        for second in range(64):
            body["expires_at"] = now + (self.ttl - second if second < self.ttl else self.ttl + second)
            env = seal("pg.answer.v1", body, [("registry", self.key)])
            if ask_id is not None and db.execute("SELECT 1 FROM answers WHERE id = ?",
                                                 (message_id(env["type"], env["body"]),)).fetchone():
                # the same answer, to the second, was given back: never served again (jobs.md), so ask a second later
                raise ProtocolError("PG_RATE_LIMITED", "ask again in a second", status=429)
            if status != "allow":
                break
            code = self._code(env, req["subject_ref"], grant["id"])
            if code and not db.execute("SELECT 1 FROM answers WHERE code = ?", (code,)).fetchone():
                break
        else:
            raise ProtocolError("PG_RATE_LIMITED", "ask again in a second", status=429)
        use = "reserved" if status == "allow" else None   # catalog.md: every allow is billed unless given back
        if ask_id is None:
            return env, code
        db.execute("INSERT INTO answers VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)",
                   (message_id(env["type"], env["body"]), ask_id, json.dumps(env), status, now, body["expires_at"],
                    grant["id"] if grant is not None else None, use, code))
        return env, code

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
                used = self.db.execute("SELECT COUNT(*) FROM answers WHERE grant_id = ? AND use IN ('reserved', "
                                       "'consumed')", (gid,)).fetchone()[0] + g["uses_offset"]
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

    def lookup(self, code: str, media: str | None = None) -> dict:
        """lookup.md: any code, either spelling, answered for its TOG spelling by the registry of its first prefix.
        Nothing is returned that the rights holder did not choose to publish: an unpublished person answers as a code
        never issued, unless they refused (opted out: Do Not Generate). An act answers its record's facts, never
        the person; `media`, the report's output_hash, adds its pg.proof.v1 entry."""
        try:
            p = parse_code(code)
        except Mistyped:
            raise ProtocolError("mistyped", "its check character does not match: a mistyped code", status=400) from None
        except PregenError:
            raise ProtocolError("invalid_format", "not a ToG code (TOG-CODE.md §7)", status=400) from None
        # an old PG licence id has no TOG spelling without its record; this registry never issued one
        head = {**({"code": p["key"]} if p["key"] else {}), "kind": p["kind"]}
        if p["issuer"] != self.config.prefix:
            return {**head, "registry": p["issuer"], "status": "other_registry", "directory": DIRECTORY_URL}
        head["registry"] = self.config.prefix
        with self.lock:
            if p["kind"] == "subject":
                s = self._subject(self.db, code)                # an over-padded number: PG_MALFORMED with a hint
                if s is None or not s["published"]:
                    return {**head, "status": "opted_out" if s is not None and s["opted_out"] else "unknown"}
                out = {**head, "status": "active", "name": s["name"], "level": s["level"],
                       "subject_key": {"key_id": fingerprint(s["key_public"]), "public_key_hex": s["key_public"],
                                       "custody": s["custody"]}}
                terms = self._current_terms(self.db, s)
                if terms:
                    api = self.config.api.rstrip("/")
                    out |= {"terms": {"id": terms[0], "url": f"{api}/v2/terms/{terms[0]}"},
                            "status_url": f"{api}/v2/codes/{p['key']}/terms"}
                return out
            if p["kind"] == "license" and p["key"]:
                g = self.db.execute("SELECT expires_at FROM grants WHERE code = ?", (p["key"],)).fetchone()
                if g is not None:
                    return {**head, "status": "active" if g["expires_at"] > self.clock() else "expired",
                            "issuer": self.config.prefix}
            if p["kind"] == "generated":
                a = self.db.execute("SELECT a.issued_at, a.use, a.report_id, k.request FROM answers a JOIN asks k ON "
                                    "k.id = a.ask_id WHERE a.code = ?", (p["key"],)).fetchone()
                if a is not None:            # an act code has no "withdrawn": the deal stays a contract (rule 3)
                    req = json.loads(a["request"])
                    out = {**head, "status": "valid", "issued_at": a["issued_at"], "purpose": req["use"]["purpose"],
                           **({"terms": req["terms"]} if "terms" in req else {}), "provider": req["provider_id"],
                           "reported": a["use"] == "consumed"}    # false: allowed, no output reported
                    entry = self._proof_entries("r.id = ?", (a["report_id"],)) if media and a["report_id"] else []
                    if entry and entry[0]["report"]["body"]["output_hash"] == media:
                        out["proof"] = entry[0]
                    return out
        return {**head, "status": "unknown"}

    def status(self, code: str) -> dict:
        """lookup.md `status_url`: a published subject's current terms and every earlier version, newest first; for
        any other code, nothing (the versions themselves stay fetchable by id, T-2)."""
        with self.lock:
            try:
                s = self._subject(self.db, code)
            except ProtocolError:
                s = None
            if s is None or self._current_terms(self.db, s) is None:
                raise ProtocolError("PG_NOT_FOUND", "no published terms for this code", status=404)
            rows = self.db.execute("SELECT envelope FROM terms WHERE subject_code = ? ORDER BY version DESC",
                                   (s["code"],)).fetchall()
        return {"code": _tog(s), "terms": [json.loads(r["envelope"]) for r in rows]}

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
            {"anchor": s["anchor"], "code": _tog(s), "level": s["level"], "proof_url": s["proof_url"] or "",
             "status": status(s)} for s in rows]}, [("registry", self.key)])

    def catalog(self) -> dict:
        """catalog.md: subjects who chose to be offered. A listing is not a permission: every generation still asks."""
        rows = self._q("SELECT * FROM subjects WHERE offer IS NOT NULL AND opted_out = 0 ORDER BY serial")
        return {"registry": self.config.prefix, "offers": [
            {"subject_ref": _tog(s), "name": s["name"], "anchor": s["anchor"] or "", "level": s["level"],
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
        items = self._proof_entries("r.id LIKE ?", (short_id + "%",))
        if len(items) != 1:
            raise ProtocolError("PG_NOT_FOUND", "no such proof", status=404)
        return {"format": "pg.proof.v1", "subjects": items}

    def _proof_entries(self, where: str, args) -> list[dict]:
        rows = self._q("SELECT r.envelope AS report, r.ack, k.request, k.signatures, a.envelope AS answer, a.code, "
                       "t.envelope AS terms, g.envelope AS licence_env, g.code AS licence FROM reports r JOIN asks k ON "
                       "k.id = r.ask_id JOIN answers a ON a.report_id = r.id LEFT JOIN terms t ON t.id = "
                       "json_extract(k.request, '$.terms') LEFT JOIN grants g ON g.id = a.grant_id "
                       f"WHERE {where} AND k.closing_ack IS NOT NULL", args)
        items = []
        for r in rows:
            item = {"request": {"type": "pg.request.v1", "body": json.loads(r["request"]),
                                "signatures": json.loads(r["signatures"])},
                    "answer": json.loads(r["answer"]), "report": json.loads(r["report"]), "ack": json.loads(r["ack"])}
            if r["terms"]:                                 # terms: the record the request accepted travels with it
                item["terms"] = json.loads(r["terms"])
            if r["code"]:                                  # proof.md: readable copies, recomputed by every platform
                item["code"] = r["code"]
                if r["licence"]:                           # with the grant, so that the licence copy can be
                    item |= {"licence": r["licence"], "grant": json.loads(r["licence_env"])}   # recomputed
            items.append(item)
        return items

    def document(self) -> dict:
        api = self.config.api.rstrip("/")
        return {"prefix": self.config.prefix, "name": self.config.name, "api": api, "keys": api + "/keys",
                "profiles": self.config.profiles, "extensions": EXTENSIONS + (["sandbox", "bind"] if self.config.sandbox else [])
                + (["provider-identity"] if self.config.providers == "open" else []) + (["terms"] if self.config.terms else []),
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
