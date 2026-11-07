# Extension `bind` — a person connects their licences to an app

**Solves:** a person who holds a licence at a registry wants to use it in an
AI app. **Nothing a person can copy and paste authorizes anything:** a licence id, a subject
code or a link only tells the app where to ask. The authorization is the signature of the
app's own key on a request about a licensee bound to that app, and the binding exists only
because the person approved it while signed in at their registry. Builds on
`provider-identity` (the app is its domain) and `licensee`.

## Who binds

The **authority** is the registry that holds the person's account. Its endpoints are
`bind.authorize` and `bind.token`, in its registry document (`"bind": {"authorize", "token"}`).
A registry that implements this extension declares `bind`.

## The flow

OAuth 2.0 authorization code with PKCE (RFC 6749, RFC 7636) and the issuer parameter
(RFC 9207). The client id is the provider URL; its `redirect_uris` come from its party
document, as in OAuth's client-id metadata documents.

1. **Start.** The app sends the person to `bind.authorize` with `response_type=code`,
   `client_id={provider URL}`, `redirect_uri` (exactly one of the document's), `state`,
   `code_challenge`, `code_challenge_method=S256`, and optionally `hint` (a licence id or
   subject code). `hint` only pre-selects among the person's own licences; one they do not hold
   is ignored silently, so it cannot be used to test what exists.
   - A registry's "Use at <app>" button opens the app's `bind_initiate_uri?iss=<authority>&hint=…`.
     The app then starts here. **On an initiated start the app asks the person first**
     ("Connect your licences from <authority name>?") before redirecting, and `iss` must be a
     prefix in the directory. An app never reads a document from an `iss` it did not choose.
     These two rules stop a hostile registry from binding its own licensee to a victim's account.
2. **Consent.** The person signs in at the authority. The screen shows the app's `name` and
   **domain** from its party document, the licences that would become usable there, and one
   sentence: what the app will learn (the terms of these licences and a random id for this
   app) and what it will not (the account, email, other licences, other apps).
3. **Return.** The authority redirects to `redirect_uri?code=…&state=…&iss=<authority>`. The
   app checks `state` and that `iss` is the authority it started with.
4. **Exchange.** The app posts `pg.bind_exchange.v1`, signed with its current key, to
   `bind.token`: `{signers, provider_id, code, code_verifier, redirect_uri, issued_at}`. The code
   is single-use, lives 60 seconds, and is bound to the client, the redirect URI and the
   challenge.
5. **Binding.** The answer is `{"binding": <pg.binding.v1>}`, which the app stores on the
   person's account in the app.

## `pg.binding.v1`, signed by the authority

`schemas/binding.json`:

| Member | Rule |
|---|---|
| `signers` | `[{role: "registry", key_id}]` |
| `authority` | the registry's prefix (`""` for the origin's bare namespace) |
| `provider_id` | the provider URL, or a registry-issued id |
| `licensee_id` | what the app puts in requests: **random and new for every binding**, so it differs for every app and means nothing anywhere else |
| `grants` | the grant and licence ids the person chose on the consent screen |
| `issued_at`, `expires_at` | integer times, at most one year apart; then the person consents again |

## Rules

- **B-1 One per app.** A licensee has at most one active binding per provider (its
  registrable domain). A new binding replaces the old one, whose `licensee_id` is refused from
  then on.
- **B-2 Revocable and visible.** At the authority the person sees each binding with the number
  of allows issued through it, and revokes it; an issuer's revocation takes effect at once.
- **B-3 Bound to the app's key, and its word.** A request with a bound `licensee_id` is
  honoured only when it is signed by that provider (`provider-identity` P-1) or carries that
  provider's own registered credential. A leaked `licensee_id` is useless to anyone else.
  Inside the app, the signed `licensee_id` is the provider's signed statement that the output
  is for that person; generating another customer's output under it is a provable false
  statement. A registry may cap the rate per binding.
- **B-3a Only what was shown.** A binding reaches only its `grants`. A licence bought later
  joins only by the person's choice: at checkout ("Also use it at <app>?") or through a new
  consent. A phished binding cannot reach licences the person never saw.
- **B-3b Dies with its key.** A binding is valid only while the key that signed it is current,
  or retired but not revoked, in the authority's chain. Revoking a key voids every binding it
  signed.
- **B-3c The answer names the binding.** An `allow` on a request with a bound `licensee_id`
  carries `ext.bind = {"binding": <the binding's message id>}`. `basis` stays `{kind, grant}`,
  which every current client checks; a proof verifier reads `ext.bind`.
- **B-4 Grant scope still applies.** A grant that names `providers` is reached only through a
  binding to one of them (`PG_SCOPE_VIOLATION` otherwise); a grant without `providers` is
  usable through any bound provider.
- **B-5 Not connected is not refused.** A request naming a licensee with no active binding to
  this provider gets HTTP 403 **`PG_NOT_BOUND`**. The app shows it as "connect your licence",
  never as a refusal. `PG_NOT_AUTHENTICATED` (401) keeps one meaning: the provider itself was
  not recognised.

## What the person holds

`GET {api}/v2/grants?licensee_id=…` (with `PG-Access` or the provider's credential): only a
provider bound to that licensee may call it, and it sees only the binding's `grants`:
`{"grants": [{"id", "grant", "status", "remaining"}]}`. `grant` is the signed `pg.grant.v1`;
`status` (`active`, `paused`, `revoked`, `expired`) and `remaining` are unsigned and inform the
app's interface. Only an `allow` permits.

## Status

Specified for interoperability; the open reference registry (`packages/registry`) does not
implement `bind` yet and lists it under its limits.
