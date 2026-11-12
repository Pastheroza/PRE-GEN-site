"""pregen-registry — run and operate a PRE-GEN registry.

  pregen-registry init --dir DATA --prefix TEST --name "My Registry" --api https://registry.example
                       --policy https://registry.example/policy --complaints mailto:… [--sandbox] [--open-providers]
  pregen-registry serve --dir DATA [--host 0.0.0.0 --port 8000]
  pregen-registry subject add --dir DATA --name "Maya Cole" [--level verified]
  pregen-registry grant add --dir DATA --subject TOG-… (--licensee ID | --any-provider) [--purposes research,commercial] [--days 365] [--max-uses N]
  pregen-registry grant revoke --dir DATA --id GRANT_ID    (the grant ends now)
  pregen-registry provider add --dir DATA [--id frame-ai]     (prints the credential once)
  pregen-registry provider remove --dir DATA --id frame-ai    (its token stops working)
  pregen-registry provider accept --dir DATA --id https://frame.example   (a provider known by its domain, vetted: ordinary answers)
  pregen-registry connect --dir DATA --provider frame-ai --licensee frame-ai:user-1
  pregen-registry bindings --dir DATA [--revoke LICENSEE_ID]   (bind, in a sandbox: each binding and its allows)
  pregen-registry info --dir DATA
  pregen-registry key next --dir DATA      (makes the next operator key and lists it in /keys as `next`)
  pregen-registry key rotate --dir DATA    (once the directory lists it: the next key signs, the old one is retired)
  pregen-registry subject list --dir DATA      (every code, with its check character)
  pregen-registry subject anchor --dir DATA --code TOG-… --anchor wikidata:Q… [--proof-url https://…]
  pregen-registry subject opt-out --dir DATA --code TOG-…  (the person opted out or withdrew: refused from the next answer)
  pregen-registry subject level --dir DATA --code TOG-… --level verified   (after you checked identity and authority)
  pregen-registry subject publish --dir DATA --code TOG-… [--off]   (name and level public at /v2/codes, by the person's choice)
  pregen-registry subject domain-check --dir DATA --code TOG-… [--gone]   (a company's tog.json shows, or is gone: a lapse at most daily)
  pregen-registry after-gen show --dir DATA REQUEST_ID        (a request the person has not decided and its viewing link)
  pregen-registry after-gen approve --dir DATA REQUEST_ID --instruction-sha256 HEX --factor authenticator|email [--purposes …]
  pregen-registry after-gen refuse --dir DATA REQUEST_ID
  pregen-registry after-gen withdraw --dir DATA RECORD_ID --instruction-sha256 HEX   (closing: no factor)
  pregen-registry mandate add --dir DATA SUBJECT AGENT --powers after_gen --purposes … --not-after T --instruction-sha256 HEX --factor …
                                                              (after_gen: the agent may refuse an undecided request; a mandate never approves)
  pregen-registry mandate add --dir DATA --envelope FILE      (a pg.mandate.v1 the subject signed with their own key)
  pregen-registry mandate end --dir DATA MANDATE_ID
  pregen-registry check --api https://registry.example [--directory URL --steward HEX] [--provider-id ID --token T --subject TOG-… [--purpose P] [--licensee ID]]
"""
from __future__ import annotations

import argparse
import json
import re
import os
import sys
import time
from pathlib import Path

from pregen import code_key

from .protocol import Key, ProtocolError
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
    try:
        return Registry(Config(**json.loads(cfg_path.read_text())), Key(key_hex), str(db_path))
    except ValueError as e:                 # a retired key, or a sandbox whose test serials hold other subjects
        sys.exit(str(e))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pregen-registry", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("init", "serve", "subject", "grant", "provider", "connect", "bindings", "info", "key", "after-gen",
                 "mandate"):
        p = sub.add_parser(name)
        p.add_argument("--dir", required=True)
        if name == "init":
            p.add_argument("--prefix", required=True, help="4 to 8 letters A-Z (TOG-CODE.md §9); a sandbox: four letters of the PG alphabet")
            p.add_argument("--name", required=True)
            p.add_argument("--api", required=True, help="the public URL of this registry")
            p.add_argument("--policy", default="")
            p.add_argument("--complaints", default="")
            p.add_argument("--sandbox", action="store_true", help="standard test subjects; credentials without an account")
            p.add_argument("--open-providers", action="store_true",
                           help="accept providers known by their domain and key, with no credential (provider-identity)")
        elif name == "serve":
            p.add_argument("--host", default="127.0.0.1")
            p.add_argument("--port", type=int, default=8000)
            p.add_argument("--ssl-certfile", help="serve HTTPS directly (a local test); in production, use a TLS proxy")
            p.add_argument("--ssl-keyfile")
        elif name == "subject":
            p.add_argument("action", choices=["add", "anchor", "list", "opt-out", "level", "publish", "prove", "domain-check"])
            p.add_argument("--name", help="add: the subject's name")
            p.add_argument("--code", help="anchor, opt-out, level, publish: the subject's ToG code (a PG- string is not a code)")
            p.add_argument("--anchor", help="anchor: wikidata:Q…, isni:…, or a domain (identity.md)")
            p.add_argument("--proof-url", help="anchor: where the person posted \"ToG: <code>\" on an official channel")
            p.add_argument("--level", default="self", choices=["self", "asserted", "consented", "verified"])
            p.add_argument("--publish", action="store_true",
                           help="add: show name and level at GET /v2/codes/<code> (only if the person chose to)")
            p.add_argument("--off", action="store_true", help="publish: stop showing them")
            p.add_argument("--pending", action="store_true",
                           help="add: a holder registering here, their home: the ToG code is pending until `prove`, "
                                "and deleted after 7 days without it (lookup.md)")
            p.add_argument("--domain", help="add: the holder is a company with this domain (one domain, one code)")
            p.add_argument("--conditions", help="add: the person's conditions in their own words, at most 1,000 "
                                                "characters (ToG 1.0 §6(f)); lookup returns them once the code is active")
            p.add_argument("--gone", action="store_true", help="domain-check: the company's tog.json no longer names "
                                                               "its record (30 days of grace, lookup.md)")
            p.add_argument("--by", default="channel", choices=["channel", "verified"],
                           help="prove: channel (ToG: <code> at an account or domain they control) or verified "
                                "(identity); never an email alone")
        elif name == "grant":
            p.add_argument("action", choices=["add", "revoke"])
            p.add_argument("--subject", help="add: the subject's ToG code")
            p.add_argument("--id", help="revoke: the grant id")
            p.add_argument("--licensee", default="")
            p.add_argument("--purposes", default="research")
            p.add_argument("--days", type=int, default=365)
            p.add_argument("--max-uses", type=int)
            p.add_argument("--any-provider", action="store_true",
                           help="add: no licensee, so the grant covers every provider that asks for this person")
        elif name == "provider":
            p.add_argument("action", choices=["add", "remove", "accept"])
            p.add_argument("--id")
        elif name == "connect":
            p.add_argument("--provider", required=True)
            p.add_argument("--licensee", required=True)
        elif name == "bindings":
            p.add_argument("--revoke", metavar="LICENSEE_ID", help="end this binding now (bind B-2)")
        elif name == "key":
            p.add_argument("action", choices=["next", "rotate"])
        elif name in ("after-gen", "mandate"):          # on the subject's authenticated instruction (after-gen.md)
            p.add_argument("action", choices=["show", "approve", "refuse", "withdraw"] if name == "after-gen"
                           else ["add", "end"])
            p.add_argument("ids", nargs="*")
            p.add_argument("--instruction-sha256", help="SHA-256 of the evidence of the subject's instruction")
            p.add_argument("--factor", choices=["authenticator", "email"], help="the second factor you confirmed")
            p.add_argument("--purposes", help="comma-separated")
            if name == "mandate":
                p.add_argument("--powers", default="after_gen")
                p.add_argument("--not-after", type=int)
                p.add_argument("--envelope", help="a pg.mandate.v1 file the subject signed with their own key")
        if name == "init":
            p.add_argument("--after-gen", action="store_true", help="declare after-gen (a sandbox does unless set)")
    p = sub.add_parser("check", help="the live self-test: document, key set, errors, listing, and one answer")
    p.add_argument("--api", required=True, help="this registry's public https URL")
    p.add_argument("--directory", help="the directory URL to look for this registry in")
    p.add_argument("--steward", help="the steward public key (hex) of that directory; default: the PRE-GEN steward")
    p.add_argument("--provider-id")
    p.add_argument("--token")
    p.add_argument("--subject", help="a ToG code this registry holds, to ask about")
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
               "sandbox": a.sandbox, "providers": "open" if a.open_providers or a.sandbox else "registered",
               **({"after_gen": True} if a.after_gen else {})}
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
                "\nThis is a sandbox: it holds no real people, only the standard test subjects (codes 1-7 and 9-12; code "
                "8 is deliberately unregistered), and its "
                "answers are marked as sandbox answers.\n" if a.sandbox else "")))
        print(f"Registry created in {a.dir}.\n  prefix: {a.prefix}\n  operator key id: {key.id}\n"
              f"  public key: {key.public_hex}\nGive the key id to the steward (step 9 of docs/registry.md); it reads "
              f"the public key from {a.api.rstrip('/')}/keys.\n"
              f"The private key is in {key_path} (mode 600): back it up offline.\n"
              f"A policy to edit is in {policy}; `serve` publishes it at {a.api.rstrip('/')}/policy.")
        if a.sandbox:                       # Registry() seeded the standard test subjects
            print("Sandbox test subjects (copy them; the last character is a check character):")
            for s in reg._q("SELECT code, name FROM subjects ORDER BY serial"):
                print(f"  {code_key(s['code'])}  {s['name']}")
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
        print(load(a.dir).add_subject(a.name, level=a.level, published=int(a.publish), pending=a.pending,
                                      domain=a.domain, conditions=a.conditions))
    elif a.cmd == "subject" and a.action == "prove":
        if not a.code:
            sys.exit("subject prove needs --code")
        try:
            load(a.dir).prove(a.code, a.by)
        except ValueError as e:
            sys.exit(str(e))
        print(f"{a.code} is active ({a.by})")
    elif a.cmd == "subject" and a.action == "domain-check":
        if not a.code:
            sys.exit("subject domain-check needs --code")
        try:
            r = load(a.dir).domain_check(a.code, not a.gone)
        except ValueError as e:
            sys.exit(str(e))
        print(f"{r['domain']} shows its tog.json" if r["shows"] else
              f"notice to {r['domain']}: its tog.json no longer names this record; its answer stays in force until "
              f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(r['grace_until']))}, then the code answers pending")
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
            print(f"{code_key(s['code'])}  {s['level']}  {s['name']}")
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
        try:
            load(a.dir).set_identity(a.code, anchor=a.anchor, proof_url=a.proof_url)
        except ValueError as e:
            sys.exit(str(e))
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
        if bool(a.licensee) == bool(a.any_provider):   # the broadest grant there is: never by leaving a flag out
            sys.exit("grant add needs exactly one of --licensee ID, or --any-provider for a grant every provider may use")
        print(load(a.dir).add_grant(a.subject, licensee_id=a.licensee, purposes=a.purposes.split(","),
                                    days=a.days, max_uses=a.max_uses))
    elif a.cmd == "provider" and a.action == "remove":
        try:
            load(a.dir).remove_provider(a.id or "")
        except ValueError as e:
            sys.exit(str(e))
        print(f"provider {a.id} removed: its token no longer works")
    elif a.cmd == "provider" and a.action == "accept":
        try:
            load(a.dir).accept_provider(a.id or "")
        except ValueError as e:
            sys.exit(str(e))
        print(f"provider {a.id} accepted: it gets ordinary answers from now on (provider-identity P-6)")
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
    elif a.cmd == "bindings":
        reg = load(a.dir)
        if a.revoke:
            try:
                reg.revoke_binding(a.revoke)
            except ValueError as e:
                sys.exit(str(e))
            print("revoked: requests naming this licensee_id get PG_NOT_BOUND from now on")
        else:
            print(json.dumps(reg.bindings(), indent=2))
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
    elif a.cmd in ("after-gen", "mandate"):
        reg, want = load(a.dir), 2 if a.cmd == "mandate" and a.action == "add" and not a.envelope else 1
        if len(a.ids) != want:
            sys.exit(f"{a.cmd} {a.action} needs " + ("SUBJECT AGENT" if want == 2 else "one id"))
        purposes = a.purposes.split(",") if a.purposes else None
        try:
            if a.cmd == "after-gen" and a.action == "show":
                row = reg.after_gen_request_info(rid=a.ids[0])
                if row is None:
                    sys.exit(f"no pending request {a.ids[0]}")
                print(json.dumps({**row, "subject_ref": code_key(row["subject_ref"]), "scope": json.loads(row["scope"]),
                                  "envelope": json.loads(row["envelope"])}, indent=2))
            elif a.cmd == "after-gen" and a.action == "approve":
                print(reg.approve_after_gen(a.ids[0], instruction=a.instruction_sha256 or "", factor=a.factor,
                                            purposes=purposes))
            elif a.cmd == "after-gen" and a.action == "refuse":
                reg.refuse_after_gen(a.ids[0])
                print(f"request {a.ids[0]} refused: nothing is published")
            elif a.cmd == "after-gen":
                print(json.dumps(reg.withdraw_after_gen(a.ids[0], instruction=a.instruction_sha256 or "")))
            elif a.action == "end":
                reg.end_mandate(a.ids[0])
                print(f"mandate {a.ids[0]} ended")
            elif a.envelope:
                print(reg.add_mandate_envelope(json.loads(Path(a.envelope).read_text())))
            else:
                if not (purposes and a.not_after):
                    sys.exit("mandate add needs --purposes and --not-after")
                print(reg.add_mandate(a.ids[0], a.ids[1], powers=a.powers.split(","), purposes=purposes,
                                      not_after=a.not_after, instruction=a.instruction_sha256 or "", factor=a.factor))
        except (ValueError, ProtocolError) as e:
            sys.exit(str(e))
    elif a.cmd == "info":
        reg = load(a.dir)
        print(json.dumps({**reg.document(), "operator_key_id": reg.key.id, "public_key": reg.key.public_hex}, indent=2))


if __name__ == "__main__":
    main()
