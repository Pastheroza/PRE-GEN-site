#!/usr/bin/env python3
"""The PRE-GEN steward's tool: create the steward key, sign the registry
directory, check a signed directory (PG-CODE.md §9.1).

The steward key never leaves the steward's computer. It is written once,
encrypted with a passphrase, and used a few times a year: when a registry is
added or changes its keys.

  python3 steward.py init ~/PRE-GEN-steward.pem
  python3 steward.py sign ~/PRE-GEN-steward.pem registries.json
  python3 steward.py sign --handover ~/PRE-GEN-steward-successor.pem registries.json   # only if the steward key is lost or stolen
  python3 steward.py verify registries.json [--steward <public key hex>]

Needs the `cryptography` package (pip install cryptography).
"""

import argparse
import getpass
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, Encoding, PrivateFormat, load_pem_private_key)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pregen_directory import (  # noqa: E402
    DirectoryError, fingerprint, public_hex, sign_directory, verify_directory)

# The published steward key (PG-CODE.md §9.1).
STEWARD_PUBLIC_KEY_HEX = "5cb949aab04186e3e216ec541b847c912fc3f78138c0ec3cb2560b2dad0d1f1b"


def _passphrase(confirm: bool) -> bytes:
    p = getpass.getpass("Passphrase for the steward key: ")
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
        return load_pem_private_key(data, password=_passphrase(False))
    except ValueError:
        sys.exit("Wrong passphrase, or not a steward key file.")


def cmd_sign(args) -> None:
    key = _load(args.keyfile)
    path = Path(args.directory)
    d = json.loads(path.read_text(encoding="utf-8"))
    me = fingerprint(public_hex(key))
    if d.get("steward_key_id") and d["steward_key_id"] != me and not args.handover:
        sys.exit(f"This directory was signed by {d['steward_key_id']}, not by this key ({me}). "
                 "Use --handover only to take over with the successor key.")
    if args.handover:
        print(f"HANDOVER: from now on verifiers refuse directories signed by {d.get('steward_key_id')}.")
    d["sequence"] = int(d.get("sequence") or 0) + 1
    d["issued_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        signed = sign_directory(d, key)
    except DirectoryError as e:
        sys.exit(f"Not signed: {e}")
    path.write_text(json.dumps(signed, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Signed {path}: sequence {signed['sequence']}, steward {me}")
    for r in signed["registries"]:
        print(f"  {r.get('name')}: {('PG-' + r['prefix'] + '-…') if r['prefix'] else 'bare PG-… codes'}"
              f" — {len(r['key_fingerprints'])} key(s)")


def cmd_verify(args) -> None:
    pub = args.steward or STEWARD_PUBLIC_KEY_HEX
    if not pub:
        sys.exit("No steward public key: pass --steward <hex>.")
    d = json.loads(Path(args.directory).read_text(encoding="utf-8"))
    try:
        verify_directory(d, pub)
    except DirectoryError as e:
        sys.exit(f"INVALID: {e}")
    print(f"OK: sequence {d['sequence']}, signed by {d['steward_key_id']}, {len(d['registries'])} registries")


def main() -> None:
    p = argparse.ArgumentParser(description="PRE-GEN steward tool (PG-CODE.md §9.1)")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("init", help="create the steward key (once)")
    s.add_argument("keyfile")
    s.set_defaults(fn=cmd_init)
    s = sub.add_parser("sign", help="sign the registry directory")
    s.add_argument("--handover", action="store_true",
                   help="sign with the successor key, replacing the current steward key for good")
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
