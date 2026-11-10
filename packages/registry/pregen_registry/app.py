"""HTTP interface (PRE-GEN-CORE.md and extensions/*.md)."""
from __future__ import annotations

import json
import threading
from html import escape
from urllib.parse import parse_qs, urlencode, urlsplit

from fastapi import Body, FastAPI, Header, Request
from starlette.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

from . import __version__
from .protocol import ProtocolError
from .registry import Registry

SANDBOX_ACCESS_PER_HOUR = 10
BIND_APPROVALS_PER_HOUR = 20
BIND_PAGES_PER_HOUR = 60
AFTER_GEN_REQUESTS_PER_HOUR = 60
PUBLIC_READ = {"Access-Control-Allow-Origin": "*"}   # after-gen's two public reads, fetched by a browser check page
PAGE_HEADERS = {"X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors 'none'", "Cache-Control": "no-store"}


def _path(request: Request) -> str:
    return request.url.path + ("?" + request.url.query if request.url.query else "")


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def _authorize_params(registry: Registry, q: dict) -> dict:
    """bind.md step 1: OAuth 2.0 code with PKCE S256 and state. The app and its redirect URI are checked first, so a
    bad one is never redirected to. `hint` only pre-selects among the person's own licences: here it changes nothing."""
    doc = registry.bind_client(q.get("client_id", ""), q.get("redirect_uri", ""))
    if q.get("response_type") != "code" or q.get("code_challenge_method") != "S256" or not q.get("state") \
            or not q.get("code_challenge"):
        raise ProtocolError("PG_MALFORMED", "response_type=code, state, code_challenge and code_challenge_method=S256 "
                            "are required", status=400)
    return doc


def create_app(registry: Registry, policy_file=None) -> FastAPI:
    """`policy_file`: a published policy page, served at GET /policy (text/markdown) when it exists."""
    app = FastAPI(title=f"PRE-GEN registry — {registry.config.name}", version=__version__,
                  docs_url="/docs", redoc_url=None)
    issued: dict[str, list[float]] = {}            # sandbox credentials per client address, last hour
    approvals: dict[str, list[float]] = {}         # bind consents per client address, last hour
    pages: dict[str, list[float]] = {}             # consent pages shown per client address, last hour
    ag_requests: dict[str, list[float]] = {}       # after-gen requests taken per client address, last hour

    limits = threading.Lock()

    def take(seen: dict, request: Request, limit: int, what: str):
        """One slot of an hourly per-address limit, checked and taken at once (so concurrent requests cannot share a
        count), on the registry's clock. Returns the call that gives the slot back if the request turns out invalid.
        ponytail: per process, in memory; behind a proxy that hides client addresses, every client is one address."""
        who, now = request.client.host if request.client else "?", registry.clock()
        with limits:
            recent = [t for t in seen.get(who, []) if now - t < 3600]
            if len(recent) >= limit:
                raise ProtocolError("PG_RATE_LIMITED", f"too many {what} from this address; try later", status=429)
            seen[who] = [*recent, now]

        def give_back():
            with limits:
                if now in seen.get(who, []):
                    seen[who].remove(now)
        return give_back

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

    @app.get("/v2/bind/authorize")
    def bind_authorize(request: Request):
        """bind.md step 2: the consent screen. The sandbox's test creator is signed in; it holds no real people."""
        q = {k: v for k, v in request.query_params.items() if k != "consent"}
        give_back = take(pages, request, BIND_PAGES_PER_HOUR, "consent pages")
        try:
            doc = _authorize_params(registry, q)
            q["consent"] = registry.bind_consent(q["client_id"], q["redirect_uri"], q["code_challenge"])
        except ProtocolError:
            give_back()                           # an invalid request shows no page and takes no slot
            raise
        unchecked = ("<p>Not checked: this app's party document was posted to this sandbox, not read from its domain."
                     "</p>" if doc["posted"] else "")
        offer = "".join(f"<li>{escape(o['subject_ref'])}: {', '.join(o['purposes'])}, {o['max_uses']} uses</li>"
                        for o in registry.bind_offer())
        name, domain = escape(str(doc.get("name", ""))), escape(doc["party_id"])
        fields = "".join(f'<input type="hidden" name="{escape(k)}" value="{escape(v)}">' for k, v in q.items())
        page = (f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>"
                f"<title>Connect your licences</title><h1>Connect your licences from {escape(registry.config.name)} "
                f"to {name}?</h1><p>App: {name} at <b>{domain}</b></p>{unchecked}<p>Licences that become usable there:</p>"
                f"<ul>{offer}</ul><p>{name} will learn the terms of these licences and a random id for this app. It "
                f"will not learn your account, your email, your other licences or the other apps you use.</p>"
                f"<p>Signed in as the sandbox's test creator, with no password: a sandbox holds no real people.</p>"
                f"<form method=post>{fields}<button name=decision value=approve>Connect</button> "
                f"<button name=decision value=deny>Cancel</button></form>")
        return HTMLResponse(page, headers={"X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors 'none'",
                                           "Cache-Control": "no-store"})

    @app.post("/v2/bind/authorize")
    async def bind_decide(request: Request):
        """bind.md step 3: back to the app with a code, or with access_denied."""
        origin = request.headers.get("origin")
        if origin and origin != _origin(registry.config.api):
            raise ProtocolError("PG_MALFORMED", "the consent form is answered only from this registry's own page",
                                status=403)
        try:                                      # before the limit: a form that is not UTF-8 takes no slot
            q = {k: v[-1] for k, v in parse_qs((await request.body()).decode(), keep_blank_values=True,
                                               errors="strict").items()}
        except UnicodeDecodeError:
            raise ProtocolError("PG_MALFORMED", "the consent form is not UTF-8", status=400) from None
        give_back = take(approvals, request, BIND_APPROVALS_PER_HOUR, "consents")

        def decide():                             # blocking (it may read the app's party document): off the event loop
            _authorize_params(registry, q)
            return registry.bind_approve(q["client_id"], q["redirect_uri"], q["code_challenge"],
                                         q.get("consent", "")) if q.get("decision") == "approve" else None
        try:                                      # only an approval that passed every check keeps its slot
            code = await run_in_threadpool(decide)
        except ProtocolError:
            give_back()
            raise
        if code is None:
            give_back()
        back = {"code": code} if code else {"error": "access_denied"}
        sep = "&" if "?" in q["redirect_uri"] else "?"
        back |= {"state": q["state"], "iss": registry.config.prefix}
        return RedirectResponse(q["redirect_uri"] + sep + urlencode(back), status_code=303)

    @app.post("/v2/bind/token")
    def bind_token(env=Body(...), x_provider_id: str = Header(""), authorization: str | None = Header(None)):
        return registry.bind_exchange(x_provider_id, authorization, env)

    @app.get("/v2/grants")
    def bound_grants(request: Request, licensee_id: str = "", x_provider_id: str = Header(""),
                     authorization: str | None = Header(None), pg_access: str | None = Header(None)):
        return registry.bound_grants(x_provider_id, authorization, pg_access, licensee_id, _path(request))

    # ── after-gen (spec/drafts/after-gen.md) ──
    @app.post("/v2/after-gen/requests")
    def after_gen_request(request: Request, payload=Body(...), x_provider_id: str = Header(""),
                          authorization: str | None = Header(None)):
        give_back = take(ag_requests, request, AFTER_GEN_REQUESTS_PER_HOUR, "after-gen requests")
        try:                                      # only a request that was taken keeps its slot
            return registry.after_gen_request(x_provider_id, authorization, payload)
        except ProtocolError:
            give_back()
            raise

    @app.get("/v2/after-gen/requests/{rid}")
    def after_gen_request_state(rid: str, request: Request, x_provider_id: str = Header(""),
                                authorization: str | None = Header(None), pg_access: str | None = Header(None)):
        return registry.after_gen_request_state(x_provider_id, authorization, pg_access, rid, _path(request))

    @app.post("/v2/after-gen/decisions")
    def after_gen_decision(env=Body(...), x_provider_id: str = Header("")):
        """X-Provider-ID names the agent for a decision signed with role agent; a subject's own key needs nothing."""
        return registry.after_gen_decide(x_provider_id, env)

    def review_page(body: str) -> HTMLResponse:
        return HTMLResponse("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>"
                            "<title>Approve a file</title>" + body, headers=PAGE_HEADERS)

    @app.get("/v2/after-gen/review/{token}")
    def after_gen_review(token: str):
        """Sandbox only: the approval page of the sandbox's test creator. It alone shows the viewing link."""
        row = registry.after_gen_request_info(token=token) if registry.config.sandbox else None
        if row is None:
            raise ProtocolError("PG_NOT_FOUND", "no pending request for this page", status=404)
        scope = json.loads(row["scope"])
        items = "".join(f"<li>{escape(k)}: {escape(', '.join(v) if isinstance(v, list) else str(v))}</li>"
                        for k, v in scope.items())
        link = (f'<p>Preview: <a href="{escape(row["preview_url"])}" rel="noreferrer noopener" target=_blank>'
                f'{escape(row["preview_url"])}</a></p>' if row["preview_url"] else "<p>No preview link was sent.</p>")
        return review_page(
            f"<h1>Approve this file for {escape(row['requester'])}?</h1>"
            f"<p>Subject: {escape(row['subject_ref'])}. Licence: {escape(row['licence_id'])}.</p>"
            f"<p>File (media/1): {escape(row['media_hash'])}, {row['leaves']} leaves.</p>{link}"
            f"<p>Scope asked for:</p><ul>{items}</ul>"
            "<p>An approval is recorded after the content existed. It is not a PRE-GEN permission given before "
            "generation, and it says nothing about whether the content is AI-generated.</p>"
            "<p>Signed in as the sandbox's test creator, acting for the test subject, with a simulated second factor "
            "(email): a sandbox holds no real people.</p>"
            "<form method=post><button name=decision value=approve>Approve</button> "
            "<button name=decision value=refuse>Refuse</button></form>")

    @app.post("/v2/after-gen/review/{token}")
    async def after_gen_review_decide(token: str, request: Request):
        origin = request.headers.get("origin")
        if origin and origin != _origin(registry.config.api):
            raise ProtocolError("PG_MALFORMED", "the approval form is answered only from this registry's own page",
                                status=403)
        try:
            form = (await request.body()).decode()
            decision = parse_qs(form, keep_blank_values=True, errors="strict").get("decision", [""])[-1]
        except UnicodeDecodeError:
            raise ProtocolError("PG_MALFORMED", "the approval form is not UTF-8", status=400) from None
        record = await run_in_threadpool(registry.after_gen_review, token, decision, form)
        return review_page(f"<h1>Approved</h1><p>Record {escape(record)}.</p>" if record else
                           "<h1>Refused</h1><p>Nothing is published.</p>")

    @app.post("/v2/after-gen/{rid}/withdraw")
    def after_gen_withdraw(rid: str, env=Body(...)):
        if not isinstance(env, dict):           # a withdrawal on instruction is the operator's, never over HTTP
            raise ProtocolError("PG_MALFORMED", "expected a pg.after_gen_withdrawal.v1 envelope")
        return registry.withdraw_after_gen(rid, env)

    def public(read, *args):
        try:
            return JSONResponse(read(*args), headers=PUBLIC_READ)
        except ProtocolError as e:
            return JSONResponse({"error": e.code, "error_description": e.detail, **e.extra}, status_code=e.status,
                                headers=PUBLIC_READ)

    @app.get("/v2/after-gen")
    def after_gen_lookup(media: str = ""):
        return public(registry.after_gen_lookup, media)

    @app.get("/v2/after-gen/{rid}")
    def after_gen_status(rid: str):
        return public(registry.after_gen_status, rid)

    @app.get("/v2/proofs/{short_id}")
    def proof(short_id: str):
        return registry.proof(short_id)

    @app.post("/v2/sandbox/access")
    def sandbox_access(request: Request):
        """extensions/sandbox.md: credentials without an account — only in a sandbox, which holds no real people."""
        if not registry.config.sandbox:
            raise ProtocolError("PG_NOT_FOUND", "this registry is not a sandbox", status=404)
        take(issued, request, SANDBOX_ACCESS_PER_HOUR, "sandbox credentials")
        provider_id, token = registry.add_provider()
        return {"provider_id": provider_id, "token": token, "registry": registry.document()["api"],
                "note": "Sandbox only: test subjects, no real people. Keep the token secret; it is shown once."}

    return app
