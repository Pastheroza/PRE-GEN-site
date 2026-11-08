"""HTTP interface (PRE-GEN-CORE.md and extensions/*.md)."""
from __future__ import annotations

import time

from fastapi import Body, FastAPI, Header, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from . import __version__
from .protocol import ProtocolError
from .registry import Registry

SANDBOX_ACCESS_PER_HOUR = 10


def _path(request: Request) -> str:
    return request.url.path + ("?" + request.url.query if request.url.query else "")


def create_app(registry: Registry, policy_file=None) -> FastAPI:
    """`policy_file`: a published policy page, served at GET /policy (text/markdown) when it exists."""
    app = FastAPI(title=f"PRE-GEN registry — {registry.config.name}", version=__version__,
                  docs_url="/docs", redoc_url=None)
    issued: dict[str, list[float]] = {}            # sandbox credentials per client address, last hour

    @app.exception_handler(ProtocolError)
    def protocol_error(_: Request, e: ProtocolError):
        return JSONResponse({"error": e.code, "error_description": e.detail, **e.extra}, status_code=e.status)

    @app.get("/.well-known/pregen-registry.json")
    def document():
        return registry.document()

    @app.get("/keys")
    def keys():
        return registry.key_set()

    @app.get("/policy")
    def policy():
        if not (policy_file and policy_file.exists()):
            raise ProtocolError("PG_NOT_FOUND", "no policy.md in this registry's data folder", status=404)
        return PlainTextResponse(policy_file.read_text(encoding="utf-8"), media_type="text/markdown; charset=utf-8")

    @app.post("/v2/requests")
    def requests(env=Body(...), x_provider_id: str = Header(""), authorization: str | None = Header(None)):
        return registry.request(x_provider_id, authorization, env)

    @app.post("/v2/reports")
    def reports(env=Body(...), x_provider_id: str = Header(""), authorization: str | None = Header(None)):
        return registry.report(x_provider_id, authorization, env)

    @app.post("/v2/keys")
    def post_keys(env=Body(...), x_provider_id: str = Header(""), authorization: str | None = Header(None)):
        return registry.post_keyset(x_provider_id, authorization, env)

    @app.get("/v2/keys/{provider_id:path}")
    def get_keys(provider_id: str):                     # a provider URL (provider-identity) has slashes in it
        return registry.get_keysets(provider_id)

    @app.get("/v2/grants/{grant_id}")
    def grant(grant_id: str, request: Request, x_provider_id: str = Header(""), authorization: str | None = Header(None),
              pg_access: str | None = Header(None)):
        if not registry.config.sandbox:
            registry.authenticate_read(x_provider_id, authorization, pg_access, "GET", _path(request))
        return registry.grant(grant_id)

    @app.get("/v2/codes/{code}")
    def lookup(code: str):
        return registry.lookup(code)

    @app.get("/v2/codes/{code}/terms")
    def status(code: str):
        return registry.status(code)

    @app.get("/v2/terms/{terms_id}")
    def terms(terms_id: str):
        return registry.terms(terms_id)

    @app.get("/v2/anchors")
    def anchors():
        return registry.anchors()

    @app.get("/v2/catalog")
    def catalog():
        return registry.catalog()

    @app.get("/v2/statement")
    def statement(request: Request, x_provider_id: str = Header(""), authorization: str | None = Header(None),
                  pg_access: str | None = Header(None)):
        return registry.statement(x_provider_id, authorization, pg_access, _path(request))

    @app.post("/v2/sandbox/party")
    def sandbox_party(doc=Body(...)):
        """provider-identity, in a sandbox: the party document by post, since a laptop has no domain to serve it on.
        ponytail: no rate limit; a sandbox holds no real people and a pin is one row."""
        if not registry.config.sandbox:
            raise ProtocolError("PG_NOT_FOUND", "this registry is not a sandbox: it reads the party document from your "
                                "domain", status=404)
        pid = registry.pin_party(doc, posted=True)
        return {"party_id": pid, "note": "Pinned: requests and reports signed by this chain's current key are accepted "
                "here with X-Provider-ID: " + pid + " and no Authorization header. A production registry reads the "
                "same document from your domain."}

    @app.post("/v2/sandbox/purchases")
    def sandbox_purchase(env=Body(...), x_provider_id: str = Header(""), authorization: str | None = Header(None)):
        """extensions/sandbox.md: a test purchase, no money — one more use of a catalog subject for this provider."""
        return registry.purchase(x_provider_id, authorization, env)

    @app.get("/v2/proofs/{short_id}")
    def proof(short_id: str):
        return registry.proof(short_id)

    @app.post("/v2/sandbox/access")
    def sandbox_access(request: Request):
        """extensions/sandbox.md: credentials without an account — only in a sandbox, which holds no real people."""
        if not registry.config.sandbox:
            raise ProtocolError("PG_NOT_FOUND", "this registry is not a sandbox", status=404)
        who, now = request.client.host if request.client else "?", time.time()
        recent = [t for t in issued.get(who, []) if now - t < 3600]
        if len(recent) >= SANDBOX_ACCESS_PER_HOUR:
            raise ProtocolError("PG_RATE_LIMITED", "too many sandbox credentials from this address; try later",
                                status=429)
        issued[who] = [*recent, now]
        provider_id, token = registry.add_provider()
        return {"provider_id": provider_id, "token": token, "registry": registry.document()["api"],
                "note": "Sandbox only: test subjects, no real people. Keep the token secret; it is shown once."}

    return app
