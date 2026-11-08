# Extension `provider-identity` — a provider known by its domain

**Solves:** without this extension a provider needs a credential from every registry it
asks, so "integrate PRE-GEN once" really means "integrate once and open an account at every
registry". With it, the provider's identity is its own domain and its own key: it publishes
one document on its domain, signs every message, and asks any registry that declares this
extension with no account anywhere. A registry's commerce (selling licences) stays a
separate, optional relationship.

## The provider URL

A provider that uses this extension is identified by its **provider URL**: `https://` and
the app's own domain, and nothing else. `https://frame.example`.

- Lower case, ASCII (an internationalised domain in its `xn--` form), no path, query,
  fragment, credentials, port or trailing dot. `https://www.frame.example`,
  `https://Frame.example` and `https://frame.example/` are not ids.
- **One app, one id.** The domain is the app's registrable domain (eTLD+1 under the Public
  Suffix List, private section included): `alice.github.io` and `mallory.github.io` are two
  apps; `github.io` itself is never an id. Proving control of `www.frame.example` or
  `tenant.frame.example` does not attach `https://frame.example`.
- Registry-issued ids (`frame-ai`) keep working. They never contain `://`, so the two kinds of
  id cannot collide. A registry that issues its own credentials matches a rights holder's
  block list against every name it knows for an app, so a veto of either name holds for both.
  An allow list, signed licence terms included, matches only an app's exact one id.
- **A sandbox** (`sandbox` extension) also accepts a port, and on `localhost` only an id bound to
  the key: `https://<k>.localhost[:port]`, where `<k>` is the 32 hex characters of the key id
  (`pg-ed25519:<k>`) of the chain's first key. So a provider can test from a laptop, and two
  people's tests never take the same id (Sandboxes, below).

## The party document

The provider serves it at `{provider URL}/.well-known/pregen-party.json`
(`schemas/party-document.json`):

```json
{"party_id": "https://frame.example",
 "name": "Frame",
 "roles": ["provider"],
 "keysets": [{"type": "pg.keyset.v1", "body": {"kind": "first", "...": "..."}, "signatures": ["…"]}],
 "redirect_uris": ["https://frame.example/pregen/callback"],
 "policy": "https://frame.example/legal/pregen",
 "contact": "pregen@frame.example"}
```

| Member | Rule |
|---|---|
| `party_id` | the provider URL |
| `name` | what a consent screen shows beside the domain (`bind`) |
| `roles` | `["provider"]` |
| `keysets` | the provider's `pg.keyset.v1` chain (`provider-keys`), oldest first; `provider_id` in each is the provider URL. The same chain `provider-keys` already asks a provider to publish on its domain; `/.well-known/pregen-keys.json` stays valid for a provider that publishes keys only |
| `redirect_uris`, `bind_initiate_uri` | for `bind`; optional |
| `policy`, `contact` | optional |

The libraries build it: `pregen.party_document(url, name, key)` /
`await partyDocument(url, name, key)`. The same key gives the same document every time.

## Rules

- **P-1 Signed or nothing.** A message whose `provider_id` is a provider URL carries no
  credential: no `Authorization` header. It MUST be signed with the current key of the
  provider's chain: a request gets `signers: [{"role": "provider", "key_id"}]` in its body and
  one signature (`schemas/request.json`); reports are signed already. `X-Provider-ID` carries
  the provider URL. A registry refuses an unsigned message from a provider URL, and a signed
  one that also carries a credential.
- **P-2 Domain, then pin.** A registry reads the party document over HTTPS (no redirects, at
  most 64 KB, private, loopback and link-local addresses refused) and verifies the chain. It
  **pins the chain** with the first message signed by that chain that it accepts. A later
  document MUST extend the pinned chain through a `rotation` signed by the previous key (or a
  `recovery`, `provider-keys`). A document that does not extend it is refused with
  `PG_NOT_AUTHENTICATED`, and the pinned key keeps working: **whoever takes over the domain
  does not get the keys.** Recovery of a lost key is per registry, as `provider-keys` says;
  proving control of the domain is never enough.
- **P-3 Refresh.** A registry reads the document again when a message names a key id the
  pinned chain does not hold, and at least once every 24 hours while the provider is active.
- **P-4 Declared.** A registry that accepts providers known by their domain declares
  `provider-identity` in its `extensions` and `"providers": "open"` in its registry document.
  `"providers": "registered"` (or no member) means it issues its own credentials. Both kinds of
  provider may ask the same registry; a registry that declares `open` keeps answering its
  registered providers.
- **P-5 A published person's refusal is never masked.** For a subject the registry publishes
  (P-5a), a floor refusal (`likeness/1`: opt-out, unavailable, prohibited use, immutable denial,
  personal signature required) comes back with its real reason to any provider. A person's "no"
  must hold everywhere (`identity` rule 2), and that rule works through anchors, which only
  published subjects have.
- **P-5a Everything else is private until the registry vets the provider.** Subject serials
  are sequential, so without a rule anyone with a domain could enumerate codes and learn who
  registered privately. To a provider it has not vetted, a registry answers about: a subject it
  publishes (`lookup` returns a name, its anchor list names it, or it has an offer (`catalog`),
  including while the catalog hides it because the subject is unavailable or opted out: whoever
  chose to be offered is already public, and a later refusal must be seen), refusals included
  (P-5); and a subject on which the request's `licensee_id`, connected or bound to that
  provider, holds a live grant, whatever the answer, refusals included. Every other request
  gets **`deny` with reason `PG_PROVIDER_NOT_ACCEPTED`**, whether the code is unknown, private or unlicensed for this use,
  and a floor refusal of a subject the registry does not publish too, whatever the categories
  (`adult`, `sexual`, `intimate`, `violence` or any other). Otherwise a provider could try
  categories one by one and learn that a private registration exists, and that it is a minor's.
  It is a refusal either way: nobody generates on it. A masked answer carries the level and
  obligations of an unknown code (`level` `self`, no obligations), so nothing in it tells the codes
  apart. A sandbox masks nothing.
- **P-6 Vetting** is the registry's own published procedure (a form, a company domain, a
  contract). It turns `PG_PROVIDER_NOT_ACCEPTED` into ordinary answers. It is not needed to
  honour a licence the person connected to the provider (`bind`).
- **P-7 Budget.** A registry rate-limits, and budgets first contacts and document reads, per
  registrable domain, so a wildcard of subdomains is one provider, not thousands. It may refuse
  a domain under its published policy.

## Reads: `PG-Access`

A provider known by its domain authenticates a `GET` (`/v2/grants/{id}`, `/v2/statement`)
with the header `PG-Access`: the base64url of a `pg.access.v1` envelope
(`schemas/access.json`), signed with its current key, over
`{signers, provider_id, aud, method, path, issued_at}`. `aud` is the registry's `api` from the
directory, so a header signed for one registry is refused by every other; `path` includes the
query string. A registry accepts it within 60 seconds of `issued_at`, for itself and that method
and path only. Replaying it inside that minute only repeats a read the provider was allowed to
make. The libraries build it: `pregen.pg_access(url, key, api, "GET", path)` /
`await pgAccess(url, key, api, "GET", path)`.

## Sandboxes

A laptop has no domain to serve a document on, so a sandbox MAY take the party document by
post: `POST {sandbox api}/v2/sandbox/party` with the document as the body → HTTP 200
`{"party_id", "note"}`, pinned under the same rules (a document that does not extend a pinned
chain is refused). A production registry reads the document from the domain, never by post.

An id on `localhost` is bound to its key: `https://<k>.localhost[:port]`, with `<k>` the hex of
the first key's id. A sandbox refuses a posted document whose `localhost` id is not its own
key's, a plain `https://localhost:8443` included, so the first test never takes the name from the
next. The libraries build it: `pregen.sandbox_provider_url(KEY, port)` /
`await sandboxProviderUrl(KEY, port)`.

## Errors

| Code | HTTP | Meaning |
|---|---|---|
| `PG_NOT_AUTHENTICATED` | 401 | no document on the domain, a chain that does not extend the pin, a signature by a key that is not current, a credential sent beside a provider URL, or a `PG-Access` for another request |

`PG_PROVIDER_NOT_ACCEPTED` is an answer reason (P-5a), not an HTTP error.
