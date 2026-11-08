#!/usr/bin/env python3
"""The PRE-GEN steward's tool: create the steward key, change and sign the
registry directory, check a signed directory (PG-CODE.md §9.1).

The steward key never leaves the steward's computer. It is written once,
encrypted with a passphrase, and used a few times a year: when a registry is
added or changes its keys.

  python3 steward.py init ~/PRE-GEN-steward.pem
  python3 steward.py review --prefix ABCD --api https://registry.example KEY_ID...    # admission check, signs nothing
  python3 steward.py add ~/PRE-GEN-steward.pem registries.json --name "Example" --prefix ABCD --api https://registry.example KEY_ID...
  python3 steward.py revoke-key ~/PRE-GEN-steward.pem registries.json KEY_ID --reason "..."
  python3 steward.py revoke-registry ~/PRE-GEN-steward.pem registries.json ABCD --reason "..."
  python3 steward.py false-claim ~/PRE-GEN-steward.pem registries.json --anchor wikidata:Q42 --code PG-ABCD-... --reason "..."
  python3 steward.py reverse-false-claim ~/PRE-GEN-steward.pem registries.json --anchor wikidata:Q42 --code PG-ABCD-... --reason "..."
  python3 steward.py freeze ~/PRE-GEN-steward.pem registries.json --anchor wikidata:Q42 --days 7 --reason "..."
  python3 steward.py sign ~/PRE-GEN-steward.pem registries.json          # after a hand edit; checked against the published one
  python3 steward.py sign --handover ~/PRE-GEN-steward-successor.pem registries.json   # only if the steward key is lost or stolen
  python3 steward.py verify registries.json [--steward <public key hex>]

Every command that signs refuses a directory that verifiers would refuse: one
that drops a listing, a key, a revocation, a false claim, a reversal or a freeze
of the directory it replaces. The runbook is spec/tools/STEWARD.md.

Needs the `cryptography` package, and the `pregen` library (this repository's
packages/verify-py is used when present, else `pip install "pregen>=0.13.0"`).
"""

import argparse
import getpass
import json
import os
import subprocess
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, Encoding, PrivateFormat, load_pem_private_key)

sys.path.insert(0, str(Path(__file__).resolve().parent))
_LIB = Path(__file__).resolve().parents[2] / "packages" / "verify-py"
if _LIB.is_dir():
    sys.path.insert(0, str(_LIB))
import pregen  # noqa: E402
from pregen_directory import (  # noqa: E402
    DirectoryError, fingerprint, public_hex, sign_directory, verify_directory)

# The published steward key (PG-CODE.md §9.1).
STEWARD_PUBLIC_KEY_HEX = "5cb949aab04186e3e216ec541b847c912fc3f78138c0ec3cb2560b2dad0d1f1b"


def _passphrase(confirm: bool) -> bytes:
    # PREGEN_STEWARD_PASSPHRASE: for a test steward run by a script. Never put the real steward's passphrase in it.
    p = os.environ.get("PREGEN_STEWARD_PASSPHRASE") or getpass.getpass("Passphrase for the steward key: ")
    if os.environ.get("PREGEN_STEWARD_PASSPHRASE"):
        return p.encode()
    if confirm:
        if len(p) < 12:
            sys.exit("Use at least 12 characters.")
        if getpass.getpass("Repeat it: ") != p:
            sys.exit("The two passphrases differ.")
    return p.encode()


def cmd_init(args) -> None:
    path = Path(args.keyfile).expanduser()
    if path.exists():
        sys.exit(f"{path} already exists — refusing to overwrite a steward key.")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(_passphrase(True)))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    pub = public_hex(key)
    # The public half, next to it: safe to share, and what gets published.
    Path(str(path) + ".pub").write_text(pub + "\n")
    print(f"Steward key written to {path} (encrypted, readable only by you).")
    print(f"Public key written to {path}.pub (safe to share).")
    print(f"  public key:  {pub}")
    print(f"  fingerprint: {fingerprint(pub)}")
    print("Make a backup copy now (password manager or a USB stick kept apart).")
    print("Lose both the file and the backup and the directory can never be signed again.")


def _load(path: str) -> Ed25519PrivateKey:
    data = Path(path).expanduser().read_bytes()
    try:
        key = load_pem_private_key(data, password=_passphrase(False))
    except ValueError:
        sys.exit("Wrong passphrase, or not a steward key file.")
    if os.environ.get("PREGEN_STEWARD_PASSPHRASE") and \
            public_hex(key) in (STEWARD_PUBLIC_KEY_HEX, pregen.STEWARD_SUCCESSOR_PUBLIC_KEY_HEX):
        sys.exit("PREGEN_STEWARD_PASSPHRASE is for a test steward key only: unset it and type the passphrase.")
    return key


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _false_claim(d: dict, code: str, anchor: str) -> bool:
    """Whether verifiers drop this claim now: the library's own rule, on the unsigned directory being edited."""
    return pregen.Directory(d, pregen._TOKEN).is_false_claim(code, anchor)


def _signed_by(d: dict, pub: str) -> bool:
    try:
        verify_directory(d, pub)
        return True
    except DirectoryError:
        return False


def _published(path: Path, pub: str):
    """The directory verifiers already hold: the signed copy on origin/main (main deploys pregen.org), else HEAD."""
    for ref in ("origin/main", "HEAD"):
        r = subprocess.run(["git", "-C", str(path.resolve().parent), "show", f"{ref}:./{path.name}"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            d = json.loads(r.stdout)
            if _signed_by(d, pub):
                return d, f"git {ref}"
    return None, None


def _sign_and_write(key, path: Path, d: dict, previous, old_pub: str, handover=False) -> None:
    me = public_hex(key)
    if previous is not None and previous.get("steward_key_id") != fingerprint(me) and not handover:
        sys.exit(f"This directory was signed by {previous['steward_key_id']}, not by this key ({fingerprint(me)}). "
                 "Use --handover only to take over with the successor key.")
    # Verifiers know the successor only as the one published next to the steward key (PG-CODE.md §9.1).
    successor = pregen.STEWARD_SUCCESSOR_PUBLIC_KEY_HEX if old_pub == STEWARD_PUBLIC_KEY_HEX else me
    if handover and me != successor:
        sys.exit(f"This is not the published successor key ({fingerprint(successor)}): every verifier would refuse "
                 "what it signs.")
    if handover:
        print(f"HANDOVER: from now on verifiers refuse directories signed by {(previous or d).get('steward_key_id')}.")
    d = {k: v for k, v in d.items() if k != "signature"}
    d["sequence"] = int((previous or d).get("sequence") or 0) + 1
    d["issued_at"] = _now()
    try:
        signed = sign_directory(d, key)
        # What every verifier does with it: shape, signature, and nothing dropped from the one it replaces.
        pregen.verify_directory(signed, old_pub if handover else me, previous=previous,
                                successor_public_key_hex=successor if handover else None)
    except (DirectoryError, pregen.PregenError) as e:
        sys.exit(f"Not signed: {e}")
    path.write_text(json.dumps(signed, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Signed {path}: sequence {signed['sequence']}, steward {fingerprint(me)}")
    _print_listing(signed)


def _print_listing(d: dict) -> None:
    for r in d["registries"]:
        print(f"  {r.get('name')}: {('PG-' + r['prefix'] + '-…') if r['prefix'] else 'bare PG-… codes'}"
              f" — {len(r['key_fingerprints'])} key(s){'  REVOKED ' + r['revoked']['at'] if r.get('revoked') else ''}")
    for k in d.get("revoked_keys") or []:
        print(f"  revoked key {k['key_id']} at {k['at']}")
    for f in d.get("false_claims") or []:
        print(f"  false claim {f['code']} ({f.get('anchor')}) at {f['at']}")
    for f in d.get("false_claim_reversals") or []:
        print(f"  reversed false claim {f['code']} ({f['anchor']}) at {f['at']}")
    for f in d.get("freezes") or []:
        print(f"  freeze of {f['anchor']} from {f['at']} until {f['until']}")


def cmd_sign(args) -> None:
    key = _load(args.keyfile)
    path = Path(args.directory)
    d = json.loads(path.read_text(encoding="utf-8"))
    old_pub = args.old_steward or STEWARD_PUBLIC_KEY_HEX
    pub = old_pub if args.handover else public_hex(key)
    if args.previous:
        previous, source = json.loads(Path(args.previous).read_text(encoding="utf-8")), args.previous
        if not _signed_by(previous, pub):
            sys.exit(f"{args.previous} is not a directory signed by {fingerprint(pub)}.")
    elif args.first:
        previous, source = None, None
    else:
        previous, source = _published(path, pub)
        if previous is None:
            sys.exit("No signed earlier directory found in git (origin/main or HEAD). Pass --previous <the published "
                     "registries.json>, or --first for a directory that has never been published.")
    if source:
        print(f"Checked against the directory verifiers hold: {source}, sequence {previous['sequence']}")
    _sign_and_write(key, path, d, previous, old_pub, args.handover)


def _edit(args, change) -> None:
    """Load the signed directory, make one change, sign: the file as loaded is the one the new one replaces, and it
    must not be behind the published one."""
    key = _load(args.keyfile)
    path = Path(args.directory)
    published, source = _published(path, public_hex(key))
    if path.exists():
        d = json.loads(path.read_text(encoding="utf-8"))
        if not _signed_by(d, public_hex(key)):
            sys.exit(f"{path} is not a directory signed by this key as it stands. Restore the signed copy, "
                     "or after a hand edit use `sign`.")
        if published is not None:
            try:
                pregen.verify_directory(d, public_hex(key), previous=published, successor_public_key_hex=None)
            except pregen.PregenError as e:
                sys.exit(f"{path} is behind or differs from the published directory ({source}, sequence "
                         f"{published['sequence']}): {e}. Start from the published copy.")
        previous = json.loads(json.dumps(d))
    elif args.first and published is None:
        d = {"schema": "pregen.registries.v2", "sequence": 0, "providers": [], "registries": []}
        previous = None
        print(f"{path} does not exist: starting a new directory.")
    else:
        sys.exit(f"{path} does not exist. Check the path; --first starts a directory only where none was published.")
    change(d)
    _sign_and_write(key, path, d, previous, public_hex(key))


def _get_json(url: str):
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "pregen-steward"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def _review(prefix: str, api: str, key_ids: list, directory: dict, notes=None) -> list:
    """Admission rule 4 and the entry's shape (PG-CODE.md §9.1): reasons to refuse, empty when it may be listed.
    Rules 1–3 (operator, policy, the core) are read by the steward in the application itself. No announced next
    key goes into `notes`, for the steward to weigh: the registry guide makes it optional until a rotation."""
    reasons = []
    api = api.rstrip("/")
    listed = {r["prefix"]: r for r in directory.get("registries", [])}
    # One namespace, one registry, one set of keys: a key another registry lists is that registry's (only the
    # closed bare namespace shares its keys with its own registry's prefix, at the same api).
    elsewhere = {f: r for r in directory.get("registries", []) for f in r["key_fingerprints"]
                 if r["api"].rstrip("/") != api}
    reasons += [f"{k} is listed for {elsewhere[k]['name']} (prefix {elsewhere[k]['prefix'] or 'bare'})"
                for k in key_ids if k in elsewhere]
    if prefix in listed and listed[prefix]["api"].rstrip("/") != api:
        reasons.append(f"prefix {prefix} is listed for {listed[prefix]['api']}")
    if prefix in listed and listed[prefix].get("revoked"):
        reasons.append(f"prefix {prefix} is revoked and never reassigned")
    if not api.startswith("https://"):
        reasons.append("api must be https")
    try:
        doc = _get_json(api + "/.well-known/pregen-registry.json")
        if doc.get("prefix") != prefix:
            reasons.append(f"{api}/.well-known/pregen-registry.json names prefix {doc.get('prefix')!r}, not {prefix}")
    except Exception as e:  # noqa: BLE001 — any failure to reach it is a reason
        reasons.append(f"GET {api}/.well-known/pregen-registry.json failed: {e}")
    try:
        ks = _get_json(api + "/keys")
    except Exception as e:  # noqa: BLE001
        return reasons + [f"GET {api}/keys failed: {e}"]
    keys = {k.get("key_id"): k for k in ks.get("keys") or [] if isinstance(k, dict)}
    current = keys.get(ks.get("current_key_id"))
    if not current or not pregen.verify_signed(ks, current.get("public_key_hex", ""), "signature"):
        reasons.append("the live key set is not signed by its current key")
    if ks.get("current_key_id") not in key_ids:
        reasons.append(f"the current key {ks.get('current_key_id')} is not among the fingerprints given")
    if not key_ids:
        reasons.append("no fingerprints given")
    for kid in key_ids:
        k = keys.get(kid)
        if k is None:
            reasons.append(f"{kid} is not in the live key set at {api}/keys")
            continue
        try:
            pregen.check_public_key(k.get("public_key_hex", ""))   # the steward takes each public key itself
            if fingerprint(k["public_key_hex"]) != kid:
                reasons.append(f"{kid} does not match its public key")
        except (pregen.PregenError, DirectoryError) as e:
            reasons.append(f"{kid}: {e}")
    if notes is not None and not any(k.get("status") == "next" for k in keys.values()):
        notes.append(f"no next key announced at {api}/keys (rule 4 asks for one)")
    return reasons


def cmd_review(args) -> None:
    notes = []
    reasons = _review(args.prefix, args.api, args.key_ids, json.loads(Path(args.directory).read_text(encoding="utf-8")),
                      notes)
    for n in notes:
        print(f"Note: {n}")
    if reasons:
        sys.exit("REFUSE\n" + "\n".join(f"  - {r}" for r in reasons))
    print("OK: the keys and the endpoints pass. Rules 1–3 (operator, policy, the core) are yours to read in the application.")


def cmd_add(args) -> None:
    def change(d):
        notes = []
        reasons = _review(args.prefix, args.api, args.key_ids, d, notes)
        for n in notes:
            print(f"Note: {n}")
        if reasons:
            sys.exit("Not listed:\n" + "\n".join(f"  - {r}" for r in reasons))
        api = args.api.rstrip("/")
        entry = next((r for r in d["registries"] if r["prefix"] == args.prefix), None)
        if entry is None:
            if not args.name:
                sys.exit("A new registry needs --name.")
            entry = {"name": args.name, "prefix": args.prefix, "api": api, "keys": api + "/keys",
                     "key_fingerprints": []}
            d["registries"].append(entry)
        new = [k for k in args.key_ids if k not in entry["key_fingerprints"]]
        if not new:
            sys.exit(f"{args.prefix}: every key given is already listed; nothing to sign.")
        entry["key_fingerprints"] += new                                     # never removes a key
    _edit(args, change)


def cmd_revoke_key(args) -> None:
    def change(d):
        if not any(args.key_id in r["key_fingerprints"] for r in d["registries"]):
            sys.exit(f"{args.key_id} is not listed for any registry.")
        if any(k["key_id"] == args.key_id for k in d.get("revoked_keys") or []):
            sys.exit(f"{args.key_id} is already revoked.")
        d.setdefault("revoked_keys", []).append({"key_id": args.key_id, "at": _now(), "reason": args.reason})
    _edit(args, change)


def cmd_revoke_registry(args) -> None:
    def change(d):
        entry = next((r for r in d["registries"] if r["prefix"] == args.prefix), None)
        if entry is None:
            sys.exit(f"No registry holds prefix {args.prefix!r}.")
        if entry.get("revoked"):
            sys.exit(f"{entry['name']} is already revoked.")
        entry["revoked"] = {"at": _now(), "reason": args.reason}
    _edit(args, change)


def cmd_false_claim(args) -> None:
    def change(d):
        try:
            issuer = pregen.issuer_of(args.code)
        except pregen.PregenError as e:
            sys.exit(f"{args.code!r}: {e}")
        if not any(r["prefix"] == issuer for r in d["registries"]):
            sys.exit(f"No listed registry holds the namespace of {args.code}.")
        if _false_claim(d, args.code, args.anchor):
            sys.exit(f"{args.code} is already a false claim under {args.anchor}.")
        d.setdefault("false_claims", []).append(
            {"anchor": args.anchor, "code": args.code, "at": _now(), "reason": args.reason})
    _edit(args, change)


def cmd_reverse_false_claim(args) -> None:
    def change(d):
        if not _false_claim(d, args.code, args.anchor):
            sys.exit(f"{args.code} is not a false claim under {args.anchor}: nothing to reverse.")
        d.setdefault("false_claim_reversals", []).append(
            {"anchor": args.anchor, "code": args.code, "at": _now(), "reason": args.reason})
        if _false_claim(d, args.code, args.anchor):          # a tie by `at` stays false
            sys.exit("The false claim was recorded this very second: run it again.")
    _edit(args, change)


def cmd_freeze(args) -> None:
    def change(d):
        at = _now()
        until = (datetime.fromisoformat(at.replace("Z", "+00:00")) + timedelta(days=args.days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        d.setdefault("freezes", []).append({"anchor": args.anchor, "at": at, "until": until, "reason": args.reason})
    _edit(args, change)


def cmd_verify(args) -> None:
    pub = args.steward or STEWARD_PUBLIC_KEY_HEX
    if not pub:
        sys.exit("No steward public key: pass --steward <hex>.")
    d = json.loads(Path(args.directory).read_text(encoding="utf-8"))
    try:
        pregen.verify_directory(d, pub)              # as a verifier: the published successor counts too
    except pregen.PregenError as e:
        sys.exit(f"INVALID: {e}")
    print(f"OK: sequence {d['sequence']}, signed by {d['steward_key_id']}, {len(d['registries'])} registries")
    _print_listing(d)


def main() -> None:
    p = argparse.ArgumentParser(description="PRE-GEN steward tool (PG-CODE.md §9.1)")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("init", help="create the steward key (once)")
    s.add_argument("keyfile")
    s.set_defaults(fn=cmd_init)

    s = sub.add_parser("review", help="check a registry's endpoints and keys before listing it; signs nothing")
    s.add_argument("--prefix", required=True)
    s.add_argument("--api", required=True)
    s.add_argument("--directory", required=True, help="the current directory: the prefix and keys must be free")
    s.add_argument("key_ids", nargs="*")
    s.set_defaults(fn=cmd_review)

    s = sub.add_parser("add", help="list a registry, or add keys to a listed one, and sign")
    s.add_argument("--first", action="store_true", help="start a directory that was never published")
    s.add_argument("keyfile")
    s.add_argument("directory")
    s.add_argument("--name", help="the operator's name (new registries)")
    s.add_argument("--prefix", required=True)
    s.add_argument("--api", required=True)
    s.add_argument("key_ids", nargs="+")
    s.set_defaults(fn=cmd_add)

    s = sub.add_parser("revoke-key", help="revoke one stolen operator key, and sign")
    s.add_argument("--first", action="store_true", help="start a directory that was never published")
    s.add_argument("keyfile")
    s.add_argument("directory")
    s.add_argument("key_id")
    s.add_argument("--reason", required=True)
    s.set_defaults(fn=cmd_revoke_key)

    s = sub.add_parser("revoke-registry", help="revoke a registry (its prefix is never reassigned), and sign")
    s.add_argument("--first", action="store_true", help="start a directory that was never published")
    s.add_argument("keyfile")
    s.add_argument("directory")
    s.add_argument("prefix")
    s.add_argument("--reason", required=True)
    s.set_defaults(fn=cmd_revoke_registry)

    s = sub.add_parser("false-claim", help="record a false identity claim (never removed), and sign")
    s.add_argument("--first", action="store_true", help="start a directory that was never published")
    s.add_argument("keyfile")
    s.add_argument("directory")
    s.add_argument("--anchor", required=True)
    s.add_argument("--code", required=True)
    s.add_argument("--reason", required=True)
    s.set_defaults(fn=cmd_false_claim)

    s = sub.add_parser("reverse-false-claim", help="reverse a false claim the steward found wrong, and sign")
    s.add_argument("--first", action="store_true", help="start a directory that was never published")
    s.add_argument("keyfile")
    s.add_argument("directory")
    s.add_argument("--anchor", required=True)
    s.add_argument("--code", required=True)
    s.add_argument("--reason", required=True)
    s.set_defaults(fn=cmd_reverse_false_claim)

    s = sub.add_parser("freeze", help="refuse a person everywhere from now for up to 7 days (never lifted early), and sign")
    s.add_argument("--first", action="store_true", help="start a directory that was never published")
    s.add_argument("keyfile")
    s.add_argument("directory")
    s.add_argument("--anchor", required=True)
    s.add_argument("--days", type=int, choices=range(1, 8), default=7)
    s.add_argument("--reason", required=True)
    s.set_defaults(fn=cmd_freeze)

    s = sub.add_parser("sign", help="sign the registry directory after a hand edit")
    s.add_argument("--handover", action="store_true",
                   help="sign with the successor key, replacing the current steward key for good")
    s.add_argument("--old-steward", help="with --handover: the replaced steward public key, hex (default: the published one)")
    s.add_argument("--previous", help="the directory verifiers hold now (default: the signed copy in git)")
    s.add_argument("--first", action="store_true", help="a directory that has never been published")
    s.add_argument("keyfile")
    s.add_argument("directory")
    s.set_defaults(fn=cmd_sign)

    s = sub.add_parser("verify", help="check a signed directory")
    s.add_argument("directory")
    s.add_argument("--steward", help="steward public key, hex (default: the published one)")
    s.set_defaults(fn=cmd_verify)
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
