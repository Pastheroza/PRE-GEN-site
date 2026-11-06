"""pregen-registry — run and operate a PRE-GEN registry.

  pregen-registry init --dir DATA --prefix TEST --name "My Registry" --api https://registry.example
                       --policy https://registry.example/policy --complaints mailto:… [--sandbox]
  pregen-registry serve --dir DATA [--host 0.0.0.0 --port 8000]
  pregen-registry subject add --dir DATA --name "Maya Cole" [--level verified]
  pregen-registry grant add --dir DATA --subject PG-… [--licensee ID] [--purposes research,commercial] [--days 365] [--max-uses N]
  pregen-registry grant revoke --dir DATA --id GRANT_ID    (the grant ends now)
  pregen-registry provider add --dir DATA [--id frame-ai]     (prints the credential once)
  pregen-registry provider remove --dir DATA --id frame-ai    (its token stops working)
  pregen-registry connect --dir DATA --provider frame-ai --licensee frame-ai:user-1
  pregen-registry info --dir DATA
  pregen-registry key next --dir DATA      (makes the next operator key and lists it in /keys as `next`)
  pregen-registry key rotate --dir DATA    (once the directory lists it: the next key signs, the old one is retired)
  pregen-registry subject list --dir DATA      (every code, with its check character)
  pregen-registry subject anchor --dir DATA --code PG-… --anchor wikidata:Q… [--proof-url https://…]
  pregen-registry subject opt-out --dir DATA --code PG-…  (the person opted out or withdrew: refused from the next answer)
  pregen-registry subject level --dir DATA --code PG-… --level verified   (after you checked identity and authority)
  pregen-registry subject publish --dir DATA --code PG-… [--off]   (name and level public at /v2/codes, by the person's choice)
  pregen-registry check --api https://registry.example [--directory URL --steward HEX] [--provider-id ID --token T --subject PG-… [--purpose P] [--licensee ID]]
"""
from __future__ import annotations

import argparse
import json
import re
import os
import sys
from pathlib import Path

from .protocol import Key
from .registry import Config, Registry


POLICY_TEMPLATE = """# {name}: registry policy

Registry prefix: {prefix}. Operator: <legal name, public address>.
Complaints and disputes: {complaints}, answered within 7 days.
{sandbox}
## How we verify a rights holder
{verify}

## Anchors for public people
{anchors}

## Our refusals
We keep the PRE-GEN core's fixed protections. <any refusals of our own, with their reason codes>

## Answers and opt-outs
An answer lives 300 seconds. An opt-out takes effect at once: from the next answer.
"""


def _paths(d: str):
    p = Path(d)
    return p / "registry.json", p / "operator.key", p / "registry.db"


def _write_key(path: Path, key: Key):
    path.write_text(key.private_hex + "\n")
    os.chmod(path, 0o600)


def load(d: str) -> Registry:
    cfg_path, key_path, db_path = _paths(d)
    if not cfg_path.exists():
        sys.exit(f"no registry in {d}: run `pregen-registry init` first")
    key_hex = os.environ.get("PREGEN_OPERATOR_KEY_HEX") or key_path.read_text().strip()
    return Registry(Config(**json.loads(cfg_path.read_text())), Key(key_hex), str(db_path))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pregen-registry", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("init", "serve", "subject", "grant", "provider", "connect", "info", "key"):
        p = sub.add_parser(name)
        p.add_argument("--dir", required=True)
        if name == "init":
            p.add_argument("--prefix", required=True, help="four letters from the PG alphabet")
            p.add_argument("--name", required=True)
            p.add_argument("--api", required=True, help="the public URL of this registry")
            p.add_argument("--policy", default="")
            p.add_argument("--complaints", default="")
            p.add_argument("--sandbox", action="store_true", help="standard test subjects; credentials without an account")
        elif name == "serve":
            p.add_argument("--host", default="127.0.0.1")
            p.add_argument("--port", type=int, default=8000)
            p.add_argument("--ssl-certfile", help="serve HTTPS directly (a local test); in production, use a TLS proxy")
            p.add_argument("--ssl-keyfile")
        elif name == "subject":
            p.add_argument("action", choices=["add", "anchor", "list", "opt-out", "level", "publish"])
            p.add_argument("--name", help="add: the subject's name")
            p.add_argument("--code", help="anchor, opt-out: the subject's PG code")
            p.add_argument("--anchor", help="anchor: wikidata:Q…, isni:…, or a domain (identity.md)")
            p.add_argument("--proof-url", help="anchor: where the person posted \"PRE-GEN: <code>\" on an official channel")
            p.add_argument("--level", default="self", choices=["self", "asserted", "consented", "verified"])
            p.add_argument("--publish", action="store_true",
                           help="add: show name and level at GET /v2/codes/<code> (only if the person chose to)")
            p.add_argument("--off", action="store_true", help="publish: stop showing them")
        elif name == "grant":
            p.add_argument("action", choices=["add", "revoke"])
            p.add_argument("--subject", help="add: the subject's PG code")
            p.add_argument("--id", help="revoke: the grant id")
            p.add_argument("--licensee", default="")
            p.add_argument("--purposes", default="research")
            p.add_argument("--days", type=int, default=365)
            p.add_argument("--max-uses", type=int)
        elif name == "provider":
            p.add_argument("action", choices=["add", "remove"])
            p.add_argument("--id")
        elif name == "connect":
            p.add_argument("--provider", required=True)
            p.add_argument("--licensee", required=True)
        elif name == "key":
            p.add_argument("action", choices=["next", "rotate"])
    p = sub.add_parser("check", help="the live self-test: document, key set, errors, listing, and one answer")
    p.add_argument("--api", required=True, help="this registry's public https URL")
    p.add_argument("--directory", help="the directory URL to look for this registry in")
    p.add_argument("--steward", help="the steward public key (hex) of that directory; default: the PRE-GEN steward")
    p.add_argument("--provider-id")
    p.add_argument("--token")
    p.add_argument("--subject", help="a PG code this registry holds, to ask about")
    p.add_argument("--purpose", default="commercial", help="the use.purpose of that request (default commercial)")
    p.add_argument("--licensee", default="", help="the licensee_id to ask for (connected to --provider-id)")
    a = ap.parse_args(argv)

    if a.cmd == "check":
        from .check import check
        failed = 0
        for ok, what in check(a.api, a.directory, a.steward, a.provider_id, a.token, a.subject, a.purpose, a.licensee):
            print(("PASS " if ok else "FAIL ") + what)
            failed += not ok
        print("OK: all checks passed" if not failed else f"{failed} check(s) failed")
        sys.exit(1 if failed else 0)

    if a.cmd == "init":
        cfg_path, key_path, db_path = _paths(a.dir)
        if cfg_path.exists():
            sys.exit(f"{a.dir} already holds a registry")
        cfg = {"prefix": a.prefix, "name": a.name, "api": a.api, "policy": a.policy, "complaints": a.complaints,
               "sandbox": a.sandbox}
        try:
            Config(**cfg)
        except ValueError as e:
            sys.exit(str(e))
        Path(a.dir).mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(json.dumps(cfg, indent=2) + "\n")
        key = Key()
        _write_key(key_path, key)
        reg = Registry(Config(**cfg), key, str(db_path))
        policy = Path(a.dir) / "policy.md"
        if not policy.exists():
            policy.write_text(POLICY_TEMPLATE.format(name=a.name, prefix=a.prefix, complaints=a.complaints or "…", **(
                {"verify": "Not applicable: this sandbox holds only test subjects.",
                 "anchors": "Not applicable: this sandbox holds only test subjects."} if a.sandbox else
                {"verify": "<who may register a person, and how we check they are that person or may act for them>",
                 "anchors": "<the anchor we record: a Wikidata item (clients confirm only these today); and how the "
                            "person confirms on their own channel>"}), sandbox=(
                "\nThis is a sandbox: it holds no real people, only the standard test subjects (codes 1-7; code 8 is "
                "deliberately unregistered), and its "
                "answers are marked as sandbox answers.\n" if a.sandbox else "")))
        print(f"Registry created in {a.dir}.\n  prefix: {a.prefix}\n  operator key id: {key.id}\n"
              f"  public key: {key.public_hex}\nGive the key id to the steward (step 9 of docs/registry.md); it reads "
              f"the public key from {a.api.rstrip('/')}/keys.\n"
              f"The private key is in {key_path} (mode 600): back it up offline.\n"
              f"A policy to edit is in {policy}; `serve` publishes it at {a.api.rstrip('/')}/policy.")
        if a.sandbox:
            reg.seed_sandbox()
            print("Sandbox test subjects (copy them; the last character is a check character):")
            for s in reg._q("SELECT code, name FROM subjects ORDER BY serial"):
                print(f"  {s['code']}  {s['name']}")
            from .registry import mint_code
            print(f"  {mint_code(a.prefix, 8)}  Test subject 8 (not registered: PG_UNKNOWN_SUBJECT)")
    elif a.cmd == "serve":
        import uvicorn
        from .app import create_app
        uvicorn.run(create_app(load(a.dir), Path(a.dir) / "policy.md"), host=a.host, port=a.port, ssl_certfile=a.ssl_certfile,
                    ssl_keyfile=a.ssl_keyfile)
    elif a.cmd == "subject" and a.action == "add":
        if not a.name:
            sys.exit("subject add needs --name")
        print(load(a.dir).add_subject(a.name, level=a.level, published=int(a.publish)))
    elif a.cmd == "subject" and a.action == "publish":
        if not a.code:
            sys.exit("subject publish needs --code")
        try:
            load(a.dir).set_published(a.code, not a.off)
        except ValueError as e:
            sys.exit(str(e))
        print(f"{a.code}: name and level " + ("hidden" if a.off else "public") + " at /v2/codes")
    elif a.cmd == "subject" and a.action == "list":
        for s in load(a.dir)._q("SELECT code, name, level FROM subjects ORDER BY serial"):
            print(f"{s['code']}  {s['level']}  {s['name']}")
    elif a.cmd == "subject" and a.action == "level":
        if not a.code:
            sys.exit("subject level needs --code and --level")
        try:
            load(a.dir).set_level(a.code, a.level)
        except ValueError as e:
            sys.exit(str(e))
        print(f"{a.code} is now level {a.level}")
    elif a.cmd == "subject" and a.action == "opt-out":
        if not a.code:
            sys.exit("subject opt-out needs --code")
        try:
            load(a.dir).opt_out(a.code)
        except ValueError as e:
            sys.exit(str(e))
        print(f"{a.code} opted out: every answer from now on is deny PG_SUBJECT_OPTED_OUT")
    elif a.cmd == "subject":
        if not (a.code and a.anchor):
            sys.exit("subject anchor needs --code and --anchor")
        reg = load(a.dir)
        if not reg._row("SELECT code FROM subjects WHERE code = ?", (a.code,)):
            sys.exit(f"no subject {a.code} in this registry")
        reg.set_identity(a.code, anchor=a.anchor, proof_url=a.proof_url)
        print(f"{a.code} anchored to {a.anchor}; GET /v2/anchors lists it")
    elif a.cmd == "grant" and a.action == "revoke":
        try:
            load(a.dir).revoke_grant(a.id or "")
        except ValueError as e:
            sys.exit(str(e))
        print(f"grant {a.id} revoked: no answer from now on rests on it")
    elif a.cmd == "grant":
        if not a.subject:
            sys.exit("grant add needs --subject")
        print(load(a.dir).add_grant(a.subject, licensee_id=a.licensee, purposes=a.purposes.split(","),
                                    days=a.days, max_uses=a.max_uses))
    elif a.cmd == "provider" and a.action == "remove":
        try:
            load(a.dir).remove_provider(a.id or "")
        except ValueError as e:
            sys.exit(str(e))
        print(f"provider {a.id} removed: its token no longer works")
    elif a.cmd == "provider":
        if a.id and not re.fullmatch(r"[A-Za-z0-9-]+", a.id):              # ":" separates provider and customer
            sys.exit("a provider id is letters, digits and -")
        pid, token = load(a.dir).add_provider(a.id)
        print(f"provider_id: {pid}\ntoken: {token}\nShown once. Give it to the provider over a private channel.")
    elif a.cmd == "connect":
        if not a.licensee.startswith(a.provider + ":"):       # a bare id would share grants across providers
            sys.exit(f"a licensee id is <provider id>:<customer id>, for example {a.provider}:{a.licensee}")
        load(a.dir).connect(a.provider, a.licensee)
        print("connected")
    elif a.cmd == "key":
        _, key_path, _ = _paths(a.dir)
        next_path = key_path.with_name("operator.next.key")
        if a.action == "next":
            if not next_path.exists():
                _write_key(next_path, Key())
            nxt = Key(next_path.read_text().strip())
            if not key_path.exists() and not os.environ.get("PREGEN_OPERATOR_KEY_HEX"):   # the current key is lost
                sys.exit(f"{key_path} is missing: run `pregen-registry key rotate` now to make {nxt.id} the current "
                         "key, then apply as a key update; the steward confirms it is you before listing it.")
            reg = load(a.dir)
            reg.announce_next_key(nxt.public_hex)                         # /keys lists it as `next` from now on
            print(f"next operator key id: {nxt.id}\n  public key: {nxt.public_hex}\n{reg.config.api.rstrip('/')}/keys now lists it as "
                  f"`next`. Apply again with this key id added; 24 hours after the directory lists it, stop the "
                  f"server, run `pregen-registry key rotate`, and start it again.")
        else:
            if not next_path.exists():
                sys.exit("no next key: run `pregen-registry key next` and have the steward announce it first")
            if not key_path.exists():                                     # lost: the history in the database stays
                next_path.rename(key_path)
                print(f"operator key is now {load(a.dir).key.id}; the lost key is retired and stays in /keys. Apply "
                      "as a key update with this key id; until the steward lists it, providers refuse what it signs.")
                return
            old = Key(key_path.read_text().strip())
            key_path.rename(key_path.with_name(f"operator.retired.{old.id.split(':')[1]}.key"))
            next_path.rename(key_path)
            new = load(a.dir).key                                          # starting on it retires the old key in /keys
            print(f"operator key is now {new.id}; {old.id} is retired and stays in /keys, so everything it signed "
                  f"still verifies. Move the retired private key file offline.")
    elif a.cmd == "info":
        reg = load(a.dir)
        print(json.dumps({**reg.document(), "operator_key_id": reg.key.id, "public_key": reg.key.public_hex}, indent=2))


if __name__ == "__main__":
    main()
