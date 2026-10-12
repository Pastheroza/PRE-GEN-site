"""pregen-registry — run and operate a PRE-GEN registry.

  pregen-registry init --dir DATA --prefix TEST --name "My Registry" --api https://registry.example [--sandbox]
  pregen-registry serve --dir DATA [--host 0.0.0.0 --port 8000]
  pregen-registry subject add --dir DATA --name "Maya Cole" [--level verified]
  pregen-registry grant add --dir DATA --subject PG-… [--licensee ID] [--purposes research,commercial] [--days 365] [--max-uses N]
  pregen-registry provider add --dir DATA [--id frame-ai]     (prints the credential once)
  pregen-registry connect --dir DATA --provider frame-ai --licensee user-1
  pregen-registry info --dir DATA
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .protocol import Key
from .registry import Config, Registry


def _paths(d: str):
    p = Path(d)
    return p / "registry.json", p / "operator.key", p / "registry.db"


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
    for name in ("init", "serve", "subject", "grant", "provider", "connect", "info"):
        p = sub.add_parser(name)
        p.add_argument("--dir", required=True)
        if name == "init":
            p.add_argument("--prefix", required=True, help="four letters from the PG alphabet, or '' for an origin registry")
            p.add_argument("--name", required=True)
            p.add_argument("--api", required=True, help="the public URL of this registry")
            p.add_argument("--policy", default="")
            p.add_argument("--complaints", default="")
            p.add_argument("--sandbox", action="store_true", help="standard test subjects; credentials without an account")
        elif name == "serve":
            p.add_argument("--host", default="127.0.0.1")
            p.add_argument("--port", type=int, default=8000)
        elif name == "subject":
            p.add_argument("action", choices=["add"])
            p.add_argument("--name", required=True)
            p.add_argument("--level", default="self", choices=["self", "asserted", "consented", "verified"])
        elif name == "grant":
            p.add_argument("action", choices=["add"])
            p.add_argument("--subject", required=True)
            p.add_argument("--licensee", default="")
            p.add_argument("--purposes", default="research")
            p.add_argument("--days", type=int, default=365)
            p.add_argument("--max-uses", type=int)
        elif name == "provider":
            p.add_argument("action", choices=["add"])
            p.add_argument("--id")
        elif name == "connect":
            p.add_argument("--provider", required=True)
            p.add_argument("--licensee", required=True)
    a = ap.parse_args(argv)

    if a.cmd == "init":
        cfg_path, key_path, db_path = _paths(a.dir)
        if cfg_path.exists():
            sys.exit(f"{a.dir} already holds a registry")
        Path(a.dir).mkdir(parents=True, exist_ok=True)
        cfg = {"prefix": a.prefix, "name": a.name, "api": a.api, "policy": a.policy, "complaints": a.complaints,
               "sandbox": a.sandbox}
        cfg_path.write_text(json.dumps(cfg, indent=2) + "\n")
        key = Key()
        key_path.write_text(key.private_hex + "\n")
        os.chmod(key_path, 0o600)
        reg = Registry(Config(**cfg), key, str(db_path))
        if a.sandbox:
            reg.seed_sandbox()
        print(f"Registry created in {a.dir}.\n  prefix: {a.prefix or '(origin)'}\n  operator key id: {key.id}\n"
              f"  public key: {key.public_hex}\nGive the key id and public key to the steward for the directory.\n"
              f"The private key is in {key_path} (mode 600): back it up offline.")
    elif a.cmd == "serve":
        import uvicorn
        from .app import create_app
        uvicorn.run(create_app(load(a.dir)), host=a.host, port=a.port)
    elif a.cmd == "subject":
        print(load(a.dir).add_subject(a.name, level=a.level))
    elif a.cmd == "grant":
        print(load(a.dir).add_grant(a.subject, licensee_id=a.licensee, purposes=a.purposes.split(","),
                                    days=a.days, max_uses=a.max_uses))
    elif a.cmd == "provider":
        pid, token = load(a.dir).add_provider(a.id)
        print(f"provider_id: {pid}\ntoken: {token}\nShown once. Give it to the provider over a private channel.")
    elif a.cmd == "connect":
        load(a.dir).connect(a.provider, a.licensee)
        print("connected")
    elif a.cmd == "info":
        reg = load(a.dir)
        print(json.dumps({**reg.document(), "operator_key_id": reg.key.id, "public_key": reg.key.public_hex}, indent=2))


if __name__ == "__main__":
    main()
