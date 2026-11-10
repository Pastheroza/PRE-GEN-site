# PRE-GEN protocol changelog

Protocol-only, from 2026-08-24 onward: the specification, schemas, vectors, and the `pregen`,
`@pregen/verify` and `pregen-registry` packages. Earlier history: the Zenodo versions listed in
[`VERSIONS.md`](VERSIONS.md). What triggers an entry: any change to a normative text, schema, vector or
library behaviour in this repository.

## Collected for the next version (not yet published)

Text only: no message format, required schema member or vector changes.
- **No watermark** (decided 2026-10-29). The `proof` bundle travels in the C2PA manifest and is found by the report
  id (`GET {api}/v2/proofs/{16 hex}`); PRE-GEN defines no watermark. A legacy `watermark` obligation id and the legacy
  fields `watermark_payload` and `watermark_embedded` are recognised, not used (`PRE-GEN-CORE.md`,
  `extensions/proof.md`, `profiles/likeness-1.md`, `PRE-GEN-SPEC.md`, `PRE-GEN-EXTENSIONS.md`).
- **`bind`:** the exchange carries `X-Provider-ID` and an `issued_at` within 60 seconds; an Errors table
  (`PG_BIND_CODE`, 400); `GET /v2/grants?licensee_id=…` returns `grant` where the registry declares `grants`,
  otherwise the licence's `terms`, unsigned.
- **`licensee`:** a licensee not bound to a provider URL gets 403 `PG_NOT_BOUND` (`bind` B-5), not 401.
- **Conformance:** two profiles for the message interface (`PRE-GEN-SPEC.md` §8.1).

## pregen-registry 0.5.0 (unreleased): the registry writes ToG codes

Needs `pregen` 0.14.
- **Persons:** a new person is born `TOG-<prefix>-<9 random digits><check>`. PG code is incompatible: a `PG-`
  string is not a code in requests, lookups, commands or schemas (`PG_MALFORMED`, `400 invalid_format`, no
  hint). At start the registry migrates its own rows once: every column naming one of its persons is rewritten
  `TOG-` with the same number and check; signed envelopes keep their bytes. An over-padded number gets
  `PG_MALFORMED` with the code as a hint.
- **Licences and allows:** every licence has a `TOG-LIC` code and every allow a `TOG-PG-LIC` code, computed from
  the signed record (flat model) and issued once; one that would give no code, or a code issued already, is signed
  again a second shorter. Records signed before 0.5 get their codes by the same computation at start, under the
  person's migrated TOG code (never from the old signed bytes). One whose
  code would end in a symbol or start `ZZZZ` (about 1 in 7) is not signed again: it has no code and no
  `/v2/codes` answer until the home model exists.
- **`POST /v2/requests`** returns an allow's code beside the answer (`extensions/proof.md`); proof entries carry
  `code`, `licence` and `grant`.
- **Lookup** answers any ToG code with its kind (`extensions/lookup.md`); a `PG-` string is `400 invalid_format`.
- **Anchor lists, catalog, terms and grants** write `TOG-`. Prefixes are 4 to 8 letters; a sandbox keeps 4 PG
  letters (old-shape test codes).
- **A grant signed before 0.5 whose bytes hold a PG id is not served:** `GET /v2/grants/{id}` answers 404
  `PG_NOT_FOUND`, and `GET /v2/grants?licensee_id=…` leaves it out. Its ToG code answers at `/v2/codes`.

## pregen 0.14.0, @pregen/verify 0.14.0 (unreleased): the ToG code

A core change (ToG code design, all decisions approved; decision 4 replaced by the hard switch, then PG code made
incompatible).
Both libraries implement it: `parse_code`, `kind_of`, `describe`, `issuer_of`, `code_key`, `normalize_typed`,
`find_codes`, `code_for`, `metadata_ok`, `code_verdict`, `check_parties`, `admission_refusal`, directory v3
(`parseCode`, `kindOf`, `describe`, `codeKey`, … in `@pregen/verify`).
- **`TOG-CODE.md` (new):** the ToG code, formerly PG code. Every code is written `TOG-`. Persons
  `TOG-<PREFIX>-<9 random digits><check>`; licences and acts `TOG-<KIND>-<ISSUER>[-<HOME>]-XXXX-XXXX-XXXX`
  with the kinds `PG`, `PG-LIC`, `AG`, `AG-LIC` and `LIC`. The tail is 55 bits of the message id
  of the object the home signed for the act (the act itself in the flat model); no counter. The
  check covers two prefix-length digits and a kind digit; I, L, O, U take 32–35 in a TOG-only
  value table. Prefixes are 4–8 letters A–Z, never with `LIC` at either end, admitted under
  §9.1. Readable copies of a file's codes are recomputed and refused on any mismatch (§14).
- **PG code is incompatible:** a `PG-` string is not a code anywhere: not as input, not folded,
  not converted, not suggested. `parse_code`, `code_key` (no folding: the code itself),
  `issuer_of`, `describe`, `find_codes`, anchor lists, false claims, channel lines and a request's
  `subject_ref` refuse it like any other non-code. Typed, it gets one message, `RETIRED`: "PG codes
  are retired. Use the ToG code your registry shows you.", with no TOG suggestion; only a PG start
  counts, so a wrapped or mistyped ToG code (`(TOG-PG-…)`, `TO-PG-…`, `TPG-…`) or an event code without
  its `TOG-` is "not a code", never retired (`TOG-CODE.md` §7.4). Each registry
  migrates its own rows once (persons and release works by the marker, same number and check; old
  licences get the `TOG-LIC` code of their signed object). An object whose signed bytes hold a PG id
  (a `pg.license.v2`, an act with a PG `subject_ref`) gives no code and is not accepted; there is no
  legacy verifier mode. `AskRegistry` / `ask_registry` and the `licences` arguments are gone.
- **Directory v3** at `https://www.pregen.org/registries.v3.json`: entity, group, dated roles,
  government, provider domains, `void_from`, `closed`, `resolver`, `min_library`. v2 stays
  frozen at its URL for 0.10–0.13 clients.
- **`PRE-GEN-CORE.md`** rules 1 and 2; **`identity`:** ToG codes only, compared by `code_key`;
  `verify_anchors` / `verifyAnchors` keep `TOG-` lines; an entry that is not a person code (a `PG-`
  line, not a code, mistyped, a licence or event code) fails the whole list; **`lookup`:** `kind`, `moved`, `alias`, a `PG-` string `400 invalid_format`, an over-padded number
  gets `PG_MALFORMED` with a hint, `/v1/pg` retired at a registry's switch, the pregen.org proxy's
  transition shim; **`grants`:** a licence's `TOG-LIC` code, old licences by their registry's migration;
  **`proof`:** each subject's `PG` or `PG-LIC` code, readable copies `code`, `licence` and the
  `grant` they are recomputed from.
- **Schemas:** `subject_ref` accepts `TOG-` only (request, grant, terms); prefixes 4–8 letters
  (anchors, registry document, key set); `proof.json` entries may carry `code`, `licence`,
  `grant`. The registry's vendored copies follow.
- **`PG-CODE.md`** marked "Retired, not supported", kept as history, with a pointer to `TOG-CODE.md`; its errata
  are in `TOG-CODE.md` §18.
- **Vectors:** `test-vectors/tog-code.json` (with `describe`, `migrate` and `proxy`; every published `PG-` string
  `malformed`; typed `PG-` input with the retired `message`), generated from the reference model
  `tools/tog_code.py` by `tools/tog_vectors.py`; `test-vectors/anchors.json` revised (a `PG-` line fails the
  list); `answers.json`, `messages.json` and `terms.json` regenerated with `TOG-TEST-…` subjects, and
  `answers.json` gains a request naming a `PG-` string (refused); `vectors.json`'s namespace cases name ToG codes
  of the same namespaces (codes are not signed; the directories are unchanged).
- **Simulator:** an allow names the example licence `TOG-LIC-TEST-ZZZZ-0000-001K` (a reserved `ZZZZ` tail, never
  issued), and the simulator's throwaway directory lists it under the `TEST` prefix instead of the bare namespace.
- **Steward tool:** `false-claim` and `reverse-false-claim` write ToG codes into the signed directory; a mistyped
  code or a `PG-` string is refused.
- **`verify_license` / `verifyLicense` are retired:** every `pg.license.v2` holds a PG id in its signed bytes, so no
  verifier accepts one (`TOG-CODE.md` §6.11). An old licence answers by its `TOG-LIC` code at its registry's lookup.
  An answer whose `basis.grant` carries a `license_id` is refused; an old licence is referenced as
  `{"format": "pg.license.v2", "id"}` (`grants.md`, `schemas/answer.json`).
- **Vectors v3:** `vectors.json` drops the `license_countersignature` and `pg_code` sections; Level 1 has no
  `verify_license` and no `pg_*` operations, and requiring `verify_license` fails the run. Vectors v2, as published
  with 0.13, stay frozen at `test-vectors/vectors.v2.json`.
- **Typed input:** a PG string typed in any form (wrapped in brackets or quotes, a leading dash or letter, no dash,
  `:` `_` `.` `/` as the separator, `P G`, a Cyrillic `РГ`) gets the retired message, never a TOG suggestion. The
  pregen.org lookup proxy gives the same message on its own route.
- **Old clients:** 0.13 refuses every TOG code (fails closed); 0.13.1 refuses an anchor list
  with a TOG line instead of dropping it. 0.14 reads it, and refuses a list with a `PG-` line the same way.

## pregen 0.13.1, @pregen/verify 0.13.1 (unreleased)

A patch that changes published behaviour (ToG code design, decision 14, approved):
- **`identity`:** an anchor-list entry of unknown shape fails the whole list. 0.13.0 dropped it silently, so a
  refusal written in a code shape it cannot read (a `TOG-` code) was lost. Now `verify_anchors` / `verifyAnchors`
  refuse the list, and that registry's people get no decision until a list verifies. Another registry's code of a
  known shape is still dropped. Vectors: `test-vectors/anchors.json`. This patch ships before any registry writes
  `TOG-` codes.

## pregen 0.13.0, @pregen/verify 0.13.0, pregen-registry 0.4.0 (unreleased)

Four clarifications of existing extensions (approved 2026-11-07), no new extension:
- **`licensee`, `catalog`:** a provider sends a person's `licensee_id` only when the request rests on that person's
  licence (under `bind`, the subject is among the binding's grants; under a registry's own connect, the subjects that
  registry said the licence covers); otherwise `""`, on its own grant, which covers
  its users only with resale. **`bind` B-3c:** `ext.bind` only on an allow whose basis is one of the binding's grants.
- **`limits`, `jobs`:** a `not_generated` report with `answer: null` releases every reserved allow of the ask (by
  `request_id`) that has expired, inside the give-back window, and those allows cannot be reported again; the ask is
  then closed (`PG_ASK_CLOSED`). Send it instead of the request again, and only once any answer would have expired.
  An answer is open until its `expires_at`, unless it was given back: a given-back answer is never served again. X-7: a job may have started generating from the moment core rule 5
  passed; store that moment first.
- **`provider-identity`, Sandboxes:** a `localhost` id is bound to its key, `https://<32 hex>.localhost[:port]`; a
  sandbox refuses any other. `sandbox_provider_url` / `sandboxProviderUrl` build it.
- **`bind`:** a `redirect_uri` is HTTPS on the provider's own host or a private-use scheme from its reversed domain;
  `http` only on a loopback host and only in a sandbox (RFC 8252 §7.3). `schemas/party-document.json` gives the
  pattern; a registry refuses a party document that lists anything else.

A person's terms of generation, as one more extension: additive to v5. The answer does not change, so apps on 0.12
keep working.
- **`terms`** (`extensions/terms.md`, `schemas/terms.json`): a subject's terms are a public, signed `pg.terms.v1`
  that keeps every version (`version`, `amends`): the purposes they allow and the categories they exclude, a template
  with a pinned legal text, `minor`. Signed by the registry alone; `assent` is `registry` (`self` and `agent` are
  reserved and refused). A version that opens (the first one, a purpose added, an exclusion removed, another template,
  `minor` cleared) takes the subject's own instruction with a second factor and names it (`factor`); one that only
  closes names none. `GET {api}/v2/terms/{id}` serves every version ever published, otherwise 404 `PG_UNKNOWN_TERMS`.
- **Accepting:** a signed request may carry `terms`, the current version's message id (`schemas/request.json`; it
  requires `signers`, and then `use.categories` only in the closed vocabulary). The answer's `request_id` covers it.
  New answer reasons `PG_TERMS_NOT_ACCEPTED` (a stale or foreign id, or a provider that cannot accept; it binds no
  ask, so the provider asks again under the same `job_id`) and `PG_TERMS_EXCLUDED` (no grant covers the use and the
  terms exclude it, personal use included). The gate reads the floor and the subject's own refusals before anything
  about who asks. An allow about a subject with terms lives at most 300 seconds.
- **`likeness/1`:** a closed vocabulary of 16 category codes, `advertising` among them; prohibited for minors
  `sexual`, `adult`, `violence`; intimate `sexual`, `adult`. A request without `terms` may still use other words.
- **`lookup`:** `terms: {id, url}` and `status_url` for a subject that has terms. **`proof`:** a subject's entry may
  carry its `pg.terms.v1`; a platform reports `terms` (`absent`, `ok`, `outside`, `unverified`) and `terms_assent`,
  without changing whether the bundle is accepted.
- **Registry document:** `terms` in `extensions`, and `"terms": "optional"`.
- **Libraries:** `CATEGORIES`, `PROHIBITED_FOR_MINORS`, `INTIMATE`, `floor`, `forbids`, `terms_opens` / `termsOpens`,
  `check_terms` / `checkTerms`; `check_proof` / `checkProof` report `terms` per subject. `check_channel_proof` no longer
  takes a `withdraw` line as a confirmation.
- **`identity`, additive v5 clarifications** (identity stress round, 2026-11-07; no message format or schema
  change). Official channels come only from current Wikidata statements (not deprecated, not ended, started), with a
  value of the property's own form. A confirmation stands only at a fixed place: `https://<host>/.well-known/pregen`
  on the official website, or a post or the profile of the official account that the platform itself says the
  account wrote; no other page on the host counts, and a `proof_url` is taken exactly as written (at most 512
  characters, no user part, port, query, fragment, percent-escape or dot segment). An unreadable place means
  unconfirmed; no decision only for a claim the client saw confirmed at its previous check. A channel permits only
  once it has stood on Wikidata for 7 days, and for 7 days a refusal survives the loss of its channel or line. A
  failed anchor list blocks only the people who confirmed a claim at that registry, and a revoked registry's last
  verified `opted_out` or `paused` entries keep refusing the person while the person confirms them. A dispute is not a refusal of the person:
  `likeness/1` answers it `PG_SUBJECT_DISPUTED` at that registry only, no longer `PG_SUBJECT_UNAVAILABLE`; only the
  person, or a steward `freezes` entry of at most 7 days, refuses a person everywhere. `false_claims` match on
  anchor and code together and are corrected by `false_claim_reversals` (`PG-CODE.md` §9.1). A written complaint
  procedure: who files, what evidence counts, deadlines, outcomes, correction.
- **Reference registry 0.4.0:** declares `terms`; publishes terms, serves `GET /v2/terms/{id}`, and answers a request
  that carries `terms` in the gate order above.
- **`sandbox`:** standard serials 9–11 (1–8 unchanged): 9 buy first, with a test purchase
  (`POST {api}/v2/sandbox/purchases`, one use per purchase, sandbox only); 10 the person's terms; 11 a minor. For a
  known minor, a category outside the closed vocabulary is `PG_PROHIBITED_USE` (`likeness/1`, the floor).
  A test purchase is its buyer's alone: another provider naming the buyer as its `licensee_id` is refused (403
  `PG_NOT_BOUND`, or 401 with a registered credential).
  **Upgrading a 0.3 sandbox:** 0.4.0 adds the missing standard subjects each time a sandbox starts, so an existing
  one gains 9–11 by restarting on 0.4.0. 0.3 numbered the operator's own test people from 9; a sandbox whose 9, 10
  or 11 is such a subject refuses to start and says so: make a fresh one (`init --sandbox`) and add those people
  again (from 0.4.0 they are numbered from 13).
- **`sandbox` serial 12** (1–11 unchanged): a creator's licence reached only through `bind`. Without a binding
  `PG_NO_LICENSE`; through one, `research` is `allow` with `ext.bind`, `commercial` is `PG_SCOPE_VIOLATION`, a fourth
  use `PG_USAGE_LIMIT`; a `licensee_id` with no active binding to the asking provider is HTTP 403 `PG_NOT_BOUND`.
  Each consent gives the sandbox's test creator a new licence (research, three uses), so apps never share one.
- **Reference registry 0.4.0 implements `bind` in a sandbox** (`/v2/bind/authorize`, `/v2/bind/token`,
  `GET /v2/grants?licensee_id=…`, `pregen-registry bindings`). A production registry built from it does not list
  `bind`: it has no accounts or sign-in for people. A sandbox now checks every `licensee_id` as production does:
  only a binding or an operator connection passes; anything else, the buyer's provider id included (serial 9), is
  403 `PG_NOT_BOUND` from a provider known by its domain and 401 `PG_NOT_AUTHENTICATED` with a registered credential.
  The consent page's one-time nonce must come back with the approval and a foreign `Origin` is refused, which stops
  a cross-site form, not an app approving its own request in a sandbox, where the creator has no password; pages and
  valid approvals are limited per address. A sandbox drops pins of a `localhost` id not bound to its key. A code is
  spent only by its own client, and shown twice by it ends the binding it gave (RFC 6749 §4.1.2); the licence is
  made at the exchange. A sandbox's database never starts as a production registry. A masked answer (P-5a) carries
  the level of an unknown code, so the level no longer tells a private code from an unknown one. `grant add` needs
  `--licensee` or `--any-provider`.
- **`provider-identity` P-5, P-5a** (decided 2026-11-08): a floor refusal is unmasked only for a subject the registry
  publishes (lookup, an offer, or its anchor list) or one the request's connected licensee holds a live grant on; for
  any other subject an unvetted provider gets the masked answer of an unknown code, whatever the categories, so trying categories tells neither that a private registration exists nor
  that it is a minor's. `identity` rule 2 is unchanged: it works through anchors, which only published subjects have.
- **`terms` T-7, `provider-identity` P-5a:** a request whose answer is masked is kept and bound like any other
  answer, terms included; T-7's "keeps no ask" applies only to an answer that is not masked, so a repeat, a report or
  a conflict never tells a private code from an unknown one.
- **Reference provider** (`examples/reference-provider`): an app that signs creators in, connects their licence
  through `bind`, journals each job before asking, renders only what it asked about, reports and attaches the proof,
  and recovers after a crash; with a self-check over sandbox codes 1–12.

## pregen 0.12.0, @pregen/verify 0.12.0, pregen-registry 0.3.0 (2026-11-06)

Two extensions, so that PRE-GEN is integrated once, with no account at any registry, and a registry's commerce
is a separate, optional layer.
- **`provider-identity`** (`extensions/provider-identity.md`): a provider is its domain and its key. It serves
  `/.well-known/pregen-party.json` (`schemas/party-document.json`: name, roles, its `pg.keyset.v1` chain), signs
  every request (`signers` in `schemas/request.json`) and report, and sends no credential. A registry declares
  `"providers": "open"` and `provider-identity`; it pins the chain with the first accepted message, and a later document
  must extend it (P-2). Until the registry vets the provider, everything but a floor refusal, a published subject and
  the provider's own bound licensee's grant is `deny PG_PROVIDER_NOT_ACCEPTED` (P-5a). `GET`s carry `PG-Access`
  (`schemas/access.json`, with `aud` = the registry's `api`). A sandbox accepts a port and `localhost` in the provider URL and takes the document by
  post (`POST /v2/sandbox/party`).
- **`bind`** (`extensions/bind.md`, `schemas/binding.json`): a person connects their licences to an app through
  OAuth 2.0 code + PKCE at the authority that holds their account; the binding (`pg.binding.v1`) names a random
  per-app `licensee_id`; `PG_NOT_BOUND` (403) is "connect your licence", never a refusal. Specified; implemented by
  PRAMPTA (api2.prampta.com); not in the reference registry yet.
- **Listing condition (`PG-CODE.md` §9.1, item 5):** a listed registry answers any AI service known by its domain, with
  no account, on the same terms; it may also issue credentials and may vet a service first. Registries listed earlier
  have 90 days from publication. `pregen-registry check` reports it.
- **Registry document:** `providers` (`open` | `registered`), `bind` endpoints; `extensions` may name both, and `commerce`
  (a registry's own optional layer, no shared page yet).
- **Libraries:** `check_provider_url` / `checkProviderUrl`, `party_document` / `partyDocument`, `pg_access` / `pgAccess`.
- **Reference registry 0.3.0:** `init --open-providers` (a sandbox always is), `provider accept --id https://…`,
  `POST /v2/sandbox/party`, `PG-Access` on `GET /v2/grants/{id}` and `/v2/statement`; `GET /v2/keys/{provider URL}`.

## pregen 0.11.0, @pregen/verify 0.11.0, pregen-registry 0.2.0 (2026-11-05)

Security fixes from an internal review (2026-10-28), and what the two new guides need (`docs/provider.md`,
`docs/registry.md`). No message format changes; one behaviour change in `decide_identity`.
- **C1 — keys no one can be held to are refused.** Under a small-order Ed25519 key a fixed signature verifies for any
  message. Such keys (in either sign-bit encoding) and every non-canonical encoding (y ≥ p) are refused wherever a key
  is recorded, and nothing verifies under them. Core, Messages, Signature; `PG-CODE.md` §9.1 item 4 (the steward
  takes the key itself); vectors in `test-vectors/small-order-keys.json`.
- **C2 — the reference registry keeps every key in `/keys`** (as `PRE-GEN-SPEC.md` §2.3 already said); `key next` and
  `key rotate`.
- **H1 — a proof's time is bounded by the registry.** `occurred_at` is the provider's word, so a proof also needs the
  acknowledgement's `received_at` within 24 hours of the answer's expiry (`extensions/proof.md` item 3). A late report is
  recorded but proves nothing.
- **H2 — `occurred_at` is when generation began**, when core rule 5 checked the allow (`extensions/reports.md`).
- **H5 — one code, one string.** A full-match ASCII grammar for codes in messages; no trimming, case change or folding
  except where a person types a code; a registry answers a non-canonical `subject_ref` with `PG_MALFORMED` (422), never
  a signed answer (`PG-CODE.md` §7).
- **`decide_identity` (behaviour change).** With no confirmed claim the result is `not_blocked`,
  `PG_IDENTITY_UNCONFIRMED`: an unconfirmed claim neither permits nor refuses, so an impostor's listing can no longer
  freeze a person who never confirmed anything, and `allow_unconfirmed` no longer permits. With no allow among confirmed
  claims, the strongest refusal wins, never the first in the list (`extensions/identity.md` rules 3–4).
  `check_channel_proof` matches the whole code, not its start.
- **Conformance Level 1 tests v5.** New operations `message_id`, `signing_input`, `verify_envelope` (with the C1
  forgeries) and `check_answer` (`test-vectors/answers.json`, 20 cases), required by default; a run where nothing ran
  fails. Before, an implementation with every v5 message id wrong passed Level 1.
- **Libraries:** `sign_envelope` / `signEnvelope`, `signing_input` / `signingInput`, `new_private_key_hex` /
  `newPrivateKeyHex`, `public_key_hex` / `publicKeyHex`; `load_directory` / `loadDirectory` take a test steward key;
  `check_proof` / `checkProof` take `testing`.
- **Reference registry:** `serve --ssl-certfile/--ssl-keyfile`, `subject anchor`. **Steward tool:** a scripted test
  steward reads `PREGEN_STEWARD_PASSPHRASE`.

## v5 — 2026-10-12

- **Honest security wording** (2026-10-13, external review; editorial, no rule changes).
  `extensions/identity.md` and the paper: a confirmation proves control of the channel, not a
  right to license every use; an impostor cannot post there *without taking over the account*;
  a confirmation lapses when the line is removed. Paper §10: "None" residual risks state their
  condition (registry key not stolen; provider keeps its job rules), and a row for a hijacked
  official channel. Paper §12: the first registry's codes move to `PRAM` from its listing, not
  "now".
- **One list of normative parts** (2026-10-12, external review). `PRE-GEN-SPEC.md` §0.2 no longer
  calls itself the core: it lists the same normative parts as `README.md`, with `PRE-GEN-CORE.md` first,
  and says the core governs the v5 interface where both describe it. Editorial; no rule changes.
- **Core and extensions** (2026-10-12, founder: «все гениальное просто… ядро отличное даже идеальное для
  индустрии»). The message interface of v5 is now a one-page core plus optional extensions.
  - `PRE-GEN-CORE.md`: codes, directory, ask, signed answer, the generation rule.
  - `extensions/`: `reports`, `provider-keys`, `limits`, `jobs`, `grants`, `licensee`, `observe`,
    `sandbox`, `lookup` — one page each, each only adds.
  - `profiles/likeness-1.md`.
  - JSON Schemas in `schemas/`.
  - Byte vectors in `test-vectors/messages.json`, generated by `tools/message_vectors.py` and checked
    by both the Python reference registry and the JavaScript SDK.
  - Draft until v5 is published; the earlier `/v1` interface stays valid.
  - The core is self-contained (2026-10-12, founder: «Да, делай 1, 2, 4»): canonical JSON, key id,
    key set and the directory checks are written in it, so an implementer needs no other document.
    The `/v1` interface is marked legacy: valid forever, no new features.
  - **No new bare codes** (founder: «По пункту 3 закрываем»). Every registry, the origin one
    included, issues new codes under its own prefix (`PG-CODE.md` §9 rule 3). Existing bare codes keep
    their meaning. A directory needs at most one bare entry, so a test directory has none.
  - The directory proven end to end: `check_answer` / `checkAnswer` in the verification libraries
    (0.9.0) accept an answer only through the signed directory; tests show an unlisted registry, a copy
    of a listed registry with its own key and a revoked registry are refused. The sandbox extension
    defines the test directory.
  - **A directory is used for at most 24 hours** (founder: «Да, добавляй»). A verifier loads it again at
    least daily, preferably from pregen.org, and accepts no answer on a copy it loaded earlier (core rule 2,
    `PG-CODE.md` §9.1); `checkAnswer` / `check_answer` enforce it (`DIRECTORY_MAX_AGE`). This bounds how
    long a verifier keeps a copy, not how old a copy's content is: a stale copy can still hide a newer
    revocation (corrected after external review; a signed freshness statement is future work).
  - **An allow must name its basis** (external review). The libraries now refuse a signed answer that breaks
    core rule 4: an `allow` without a policy or grant basis, an `allow` with a reason, or a refusal without a
    reason (`@pregen/verify` and `pregen` 0.9.1).
  - **No registry has special rights** (founder and co-founder, 2026-10-12: «прампте нужен тоже префикс…
    чтобы мы были как все»). PRAMPTA is the *first* registry, not an "origin" one: it issues new codes under
    `PRAM` like every registry; the bare codes it issued before v5 are a closed legacy namespace with no
    special right; its own refusal codes defined before v5 keep their meaning, new ones carry its prefix;
    `PRE-GEN-EXTENSIONS.md` is marked as one registry's informative extensions. The verification libraries
    (0.10.0) no longer pin PRAMPTA's keys: no registry is pinned by default, and a verifier may pin any
    registry itself (`pinnedKeys` / `pinned_keys`; `originKeyFingerprints` stays as a deprecated alias).
  - **Identity, proof, catalog** (founder: «N1–N8 да, делай»; scenarios in PRAMPTA `nmp/pregen-identity-proof-market.md`).
    The core is unchanged; three extensions and one profile rule:
    - `identity`: anchors (Wikidata/ISNI/domain) for public persons, confirmation on the person's own channel,
      the rule "who proved it, not who came first" (a refusal of the person holds in all their registries; no
      proof and several claims freeze), 7-day disputes, `false_claims` in the directory.
    - `proof`: the `pg.proof.v1` bundle carried in C2PA and found from a watermark; checked as of the moment
      of generation; `bindings` (soft bindings) in reports.
    - `catalog`: opt-in catalog, resale only with `use.resale`, billing by issued allows minus give-backs.
    - `likeness/1`: intimate categories need the person's own key, level `verified` and a grant naming them
      (`PG_PERSONAL_SIGNATURE_REQUIRED`).
    - Libraries: `verifyAnswer`, `decideIdentity`, `verifyAnchors`, `checkChannelProof`, `wikidataOfficialUrls`,
      `checkProof` (JS and Python); reference registry: `/v2/anchors`, `/v2/catalog`, `/v2/statement`,
      `/v2/proofs/{id}`.

- **The principle** (2026-10-12, founder: "защитить и зафиксировать принцип
  пред генерационный механизм"). A short section before §0 states the five
  commitments every version keeps:
  1. permission is checked before generation;
  2. those entitled to decide, decide;
  3. every answer is signed and checkable by anyone;
  4. open to every registry on the same terms;
  5. floors only go up.

  It adds no new requirement, because the numbered rules in §8 already
  implement it, and it records the first publication date (Zenodo v1, 2026-05-12).
- **P-10 without a self-declared tie-break; annulling a thief's revocations**
  (2026-10-04, founder; after the second package re-check). P-10: when two
  registries disagree about what may be the same subject, neither answer
  decides by itself — `subject_authority` is a registry's own statement; the
  provider keeps both, tells both, decides under its own policy and does not
  call the output licensed while a refusal is unresolved. `PG-CODE.md` §9.1:
  the successor's first directory may annul, by name and with a reason,
  revocations the old key signed after `steward_compromised_since`; earlier
  ones cannot be annulled. Libraries 0.7.0 enforce it.
- **Fixes after the re-check of the published packages** (2026-10-04). R-10:
  the identical receipt again gets the original answer, a different one is
  refused, so a provider can tell its own receipt from someone else's.
  `PG-CODE.md` §9.1: a steward handover may restart the sequence but keeps
  every listing and revocation. Libraries 0.6.0 enforce `schema_version`,
  required `issued_at`, the 900-second lifetime and the handover rule.
- **P-10 and R-15 replaced** (2026-10-04, founder; after an external
  review: "why is that registry entitled to answer for this subject? A
  matching name is not enough"). The earlier text let any listed registry
  stop another's subject by claiming a duplicate. Now another registry's
  refusal binds a provider only when its `subject_authority` is `verified`
  and the allowing decision's is not; both `verified` means hold until the
  registries resolve it; otherwise the refusal is a recorded signal. R-15:
  a duplicate claim needs evidence and is examined between the registries;
  a forwarded opt-out applies once its filer's authority is verified.
- **Trust in registries** (2026-10-04, founder; NMP P21, after the question
  "what stops a fake registry from selling licences for a celebrity?").
  `PG-CODE.md` §9.1: admission conditions for a listing; revocation of a
  registry (`revoked` in its entry) or of one key (`revoked_keys`), never
  undone, the entry and prefix kept forever. Core: V-14 (nothing signed by a
  revoked registry or key authorizes a generation), P-10 (several registries
  holding the same subject: every one asked must allow; a hard refusal
  prevails), R-15 (a registry that finds a duplicate SHOULD freeze new
  licences with `PG_SUBJECT_DISPUTED`; an opt-out at either applies at
  both), `subject_authority` moved from the origin extension into the core
  decision (a provider MAY require `verified` for commercial use). Vectors:
  `namespace.revocation_cases` (additive). Libraries 0.5.0 check revocation,
  `critical` (E-3) and, on request, verified authority.
- **Core and extensions** (2026-10-04, founder; NMP P20). `PRE-GEN-SPEC.md`
  is now the core; what the origin registry adds moved, unchanged in
  meaning, to the new `PRE-GEN-EXTENSIONS.md`: origin decision and request
  members (X.2), decision reuse with R-9 and the cache form of P-7 (X.3),
  end-user binding with V-13 (X.4), how the origin registry builds a licence
  body (X.5), evidence bundles (X.6, was §1.4), C2PA assertions (X.7, was
  §1.5), observations (X.8, was §1.6), lifecycle events (X.9). New in the
  core: §0.5 with E-1 (floors only go up; a later version may decide on
  relaxing them), E-2 extra members, E-3 `critical`, E-4 own codes with the
  issuer prefix, E-5 published policy, E-6 shared extensions; the licence
  envelope (§1.2: verified from `signed_body`, without knowing the
  registry's fields; the steward decides which registries are trusted); 17
  core refusal codes (§3; `REFUSAL-CODES.md` is the origin registry's
  table with core rows marked); P-7 is now "one generation, reuse only as an
  extension permits"; P-9 several subjects in one output; a decision lives
  at most 900 seconds. Roles: authorization registry and registry operator.
  Requirement identifiers are unchanged. Nothing on the wire changes for the
  origin registry or its clients.
- Vectors for the 36-character limit (2026-10-04, after an external review
  noted the published vectors had not changed): `pg_code.length_accepts`
  (a 36-character body verifies) and `pg_code.length_rejects` (two
  37-character bodies with the formula's check character must fail). The
  reference registry now rejects them too. Additive; no existing vector
  changed.
- `PG_NO_SUBJECT` is not a prohibition (2026-10-04, §5.4 P-5, after an
  external review): it says only that this registry holds no such subject; the
  provider may proceed under its own policy, as for `not_blocked`, without
  presenting the output as licensed. Before, P-5 forbade generating on any
  `deny`, which turned "unknown here" into "forbidden".
- Maximum code body 36 characters (2026-10-03, `PG-CODE.md` §4.2, after an
  external review): at position 37 the weight is 0 mod 37, so the
  single-substitution guarantee did not hold for longer bodies. No issued
  code is affected; the longest body is 19 characters.
- Successor steward key (2026-10-03, `PG-CODE.md` §9.1): published and
  pinned in `@pregen/verify` / `pregen` 0.3.0; a directory it signs replaces
  the steward key's line whatever its sequence. Replaces "a change of
  steward is announced by the outgoing key", which a thief holding that key
  could also do.
- Known limits stated exactly (2026-10-03, §10, after an external review):
  self custody prevents a forged license but not a false allow (provable
  afterwards only); an opt-out or pause stops new decisions, not issued
  ones; who may file an opt-out versus pause; legal overrides have no
  format; personal-use observations cannot name their decision. No rule
  changed.
- Next key announced in advance (2026-10-03, `PG-CODE.md` §9.1): a
  registry SHOULD list its next operator key's fingerprint before using it,
  so verifiers that pin its keys survive a rotation without an update.
- Erratum in the reference code (2026-10-03): the bare namespace includes
  licenses of every three-letter class, retired ones too (`PG-EDT-…`,
  `PG-EST-…`, `PG-ENT-…`, `PG-PER-…`, `PG-OWN-…`); `pregen_directory.py`
  recognised only STD, SUB, PRM and RND and would have refused a genuine old
  license as `unknown_issuer`. New vector `retired_class_bare_by_origin`.
- Directory continuity (2026-10-03, `PG-CODE.md` §9.1): a verifier that keeps
  the last accepted directory SHOULD refuse a newer one that removes a
  namespace or fingerprint, or a different one with the same `sequence`; it
  MAY pin the origin registry's fingerprints. No wire change.
- New verifier rules (2026-10-03): directory `api`/`keys` MUST use HTTPS
  without credentials, query or fragment (`PG-CODE.md` §9.1); V-3 requires
  positive integer expiry and issued-before-expiry; new V-13 requires verified,
  non-empty user binding for an `allow` when the provider supplied a user or
  identity-link id. §8 requires a claimed profile's operations to run rather
  than skip. These tighten acceptance without changing signed bytes or existing
  vectors; client-behaviour coverage remains explicitly separate from Level 1/2.
- Client/reference hardening (2026-10-02, no wire change): exact request
  binding including empty values, generation and intended-use context;
  safe validity checks; boolean/disposition/schema validation; TypeScript
  code-point key ordering and integer-only signed JSON. Two additive vectors
  cover Unicode key ordering and safe-integer limits; existing vectors are
  unchanged. TypeScript source supports an opt-in pinned signed directory
  with symmetric issuer and endpoint checks, persisted snapshot comparison
  for rollback and same-sequence equivocation, offline license countersignature
  verification, and strict `assertLicensed` separate from reporting-only
  `not_blocked`. Directory root publication, freshness/revocation and
  rights-authority verification are NOT supplied by these client fixes.
- Conformance runner now separately counts passes/failures/skips, tests
  tampered signature bodies and supports `--require-op` so a verifier cannot
  silently skip mandatory operations. Future trust architecture is a proposal
  in `drafts/TRUST-ARCHITECTURE.md`, not a new normative schema or release.

PRE-GEN version numbers now match Zenodo (`VERSIONS.md`): v1–v4 are the four
published Zenodo versions, this is v5. The dated entries below, from
2026-08-24 on, are the drafts that became v5; "Spec-Version" in them was the
earlier, date-based label. What a v4 implementation must change is listed in
`VERSIONS.md`.


- Review fixes before publication (text only, no wire change):
  managed custody is described as proof of key use, not of consent
  (§1.2 "Custody and consent"); `pg.observation.v1`, already live, is now
  specified (§1.6); §8 states that a decision is not single-use and that
  several registries can disagree about rights; C2PA reference corrected.
  Second review: opt-out cooling and anchoring limits stated (§8); paper
  compares RSL and the Human Consent Standard, adds the cycle overview,
  drops PRE-LEARN. v5 is marked draft until published on Zenodo.
- Who may issue which PG codes (2026-09-30): the registry directory
  (`registries.json`) is signed by a steward key held by the editor, not by
  any registry, and binds each namespace — bare for the origin registry, a
  prefix for every other — to the operator keys allowed to sign in it
  (`PG-CODE.md` §9.1). New R-14, V-10 to V-12; new `namespace` vectors and
  `verify_directory` / `check_namespace` conformance ops. Additive: every
  existing vector is byte-identical.
- Written as a standard (2026-09-29): BCP 14 requirement language and
  numbered requirements (§0, §5, §8); the text is normative and a vector
  that disagrees with it is an erratum (§0.3), replacing "the vectors win";
  references to PRAMPTA's code are informative. New normative content that
  was previously only in code: the verification request and evaluation
  rules (§5.2–§5.3), how a provider checks a decision (§5.4), receipts and
  lifecycle events (§5.5), the license countersignature bytes
  (`body || subject signature || license id`, §1.2), exact canonical-JSON
  escaping and integer rules (§2), audit event bytes and per-chain
  `prev_hash` (§2.2), the key set format at `GET /keys` and why it must be
  pinned (§2.3), and what "stays valid" means (§6.3). Conformance profiles
  Verifier / Provider / Registry with a table of what the checks cover
  (§8); reference implementation status (§9).
- Vectors: new `license_countersignature` case and `verify_license`
  conformance op. Additive: every existing vector is byte-identical.
- Evidence bundle (`pg.evidence.v1`): the `license` member now carries
  `signed_body` and `subject_public_key_hex`, so both license signatures
  verify offline, as §1.4 always promised. Additive.
- PRE-GEN is published as a public standard at https://www.pregen.org,
  copyright Valerii Egorov, Apache-2.0.
- Issuer prefix (`PG-CODE.md` §9): other registries prefix every code they
  issue with exactly four letters — `PG-NWRD-000042=`,
  `PG-NWRD-RND-000042-ZZZZZZJ`. The prefix is part of the checked body.
  Additive: bare codes keep meaning the origin registry forever, and every
  existing vector is byte-identical; new `issuer_*` vectors added.

## 2026-09-23

- Added opt-in `pg.receipt.v3`, which signs the lifecycle `event_type` along
  with the existing receipt fields. v2 stays the default and is not
  deprecated. The API reports whether a provider signature actually bound
  the event type; this is not a royalty settlement or completeness guarantee.
  `Spec-Version` advanced to `2026-09-23.1` for the new signed object shape.

## 2026-08-29

- **Known-limitations section added to the spec** (`spec/PRE-GEN-SPEC.md`
  §8). **Not a protocol change**, and `Spec-Version` is deliberately not
  bumped — §8 documents what the five signed objects cannot currently
  express (one subject per decision; `output_hash` not surviving re-encode;
  no commercial terms in a license; no signed settlement artifact) and
  points at a draft proposal. No object, field, or vector changed;
  `spec/conformance/` is unaffected.
- **Revenue-extension design drafted**
  (`docs/PRE-GEN-Revenue-Extensions-DRAFT.md`) — proposes `pg.revenue.v1`
  and `pg.settlement.v1`, plus additions to License, Decision, Receipt, and
  Assertion, each analyzed against §5.1's per-object versioning rule.
  **Nothing is implemented.** Recorded here because the analysis makes one
  thing concrete: Receipt is the only one of the four that breaks, so the
  dual-accept window built dormant on 2026-08-24 now has a named first use
  if this ever ships.

## 2026-08-24

- **Spec published.** `spec/PRE-GEN-SPEC.md` — normative spec for the 5
  signed protocol objects (Decision, License, Receipt, Evidence bundle,
  Assertion), the canonicalization rule, a generated refusal-code table
  (`spec/REFUSAL-CODES.md`), and a PG-code ABNF grammar + canonical regex.
  Not a protocol change itself — this is the first time the existing
  protocol was written down completely enough for an outside implementer
  to build against it without reading PRAMPTA's source. `Spec-Version:
  2026-08-24`.
- **Governance policy adopted.** `docs/PROTOCOL-GOVERNANCE.md` +
  `SECURITY.md` — deprecation-window policy (License: permanent per-row;
  Receipt: 90-day dual-accept, proposed) and a security-advisory contact.
  Not a protocol change either — a policy for how future ones get
  announced.
- **Dual-accept mechanism added for Receipt** (`backend/app/core/
  receipt_body.py`) — the server can now verify a provider's signature
  against either the current receipt-body shape or a recent prior one, for
  a bounded window, and marks a fallback match with `Deprecation`/`Sunset`
  headers. **No format change**: `pg.receipt.v2` remains the only shape
  that has ever actually existed; this entry records that the mechanism
  now exists, ready for the day a real second shape is added, not that one
  has been.
- **Conformance suite published.** `spec/conformance/` — Level 1 (offline,
  a CLI adapter protocol replaying `vectors.json` against all four named
  implementations) and Level 2 (HTTP scenarios against a live server, a
  representative subset of refusal codes, not all 36). Not a protocol
  change — the first standalone artifact a fifth, unknown implementation
  could point at itself.
- **Publishing pipeline built** (`.github/workflows/release-sdk.yml`) —
  `@prampta/sdk` (npm) and `prampta` (PyPI), OIDC trusted publishing, no
  stored tokens. Not shipped yet — needs a one-time account-side Trusted
  Publisher registration on each registry before the first tag-push
  succeeds (`docs/PROTOCOL-GOVERNANCE.md` "Publishing"). Also fixed:
  `spec/README.md`/`PG-CODE.md`/`PRE-GEN-SPEC.md`/`conformance/README.md`
  all linked their Apache-2.0 claim at the repo-root `/LICENSE`, which is
  actually proprietary (it covers the PRAMPTA service, not the spec) —
  added `spec/LICENSE` with the real Apache-2.0 text `sdk/typescript/
  LICENSE` already had, and fixed the four links. Not a normative change
  either way (a citation fix, not a spec change) — no `Spec-Version` bump.
- **SDK publish pipeline unblocked.** `@prampta/sdk` (npm) and `prampta`
  (PyPI) trusted publishers registered on npmjs.com/pypi.org (founder);
  GitHub Environments `npm-publish`/`pypi-publish` created to match
  `release-sdk.yml` exactly. Still no release tag pushed — that remains a
  separate, deliberate action.
- **PG-code ergonomics (Phase 5).** `spec/PG-CODE.md` §§11–13: a reserved
  subject-serial range (`RESERVED_SUBJECT_SERIAL_FLOOR = 900,000,000`,
  founder-confirmed as a numeric block) so documentation/example/test
  codes can never collide with a real subject or license; a public,
  unauthenticated resolver (`GET /v1/pg/{code}`) that finally implements
  §7's mistyped-vs-not-found distinction, which no running code did
  before this; `GET /.well-known/pg-policy` (RFC 8615); a QR/display
  convention (full resolver URL, not a bare code); homoglyph folding at
  the resolver's input boundary, explicitly non-exhaustive. **`Spec-
  Version` bump (`.1`)**: this is a normative addition — the reserved
  range and the mistyped/not-found split are new, checkable facts about
  the protocol, not just documentation. 5.5 (standalone zero-dependency
  `pg-code` packages) explicitly deferred, stated in `spec/PRE-GEN-
  SPEC.md`'s own intro rather than silently dropped.
- **Fixed a stale §7.** `spec/PRE-GEN-SPEC.md` §7 still called the
  conformance suite "not yet built — Phase 3" a full phase after Phase 3
  actually shipped it — found while touching this file for the Phase 5
  entry above, not a new problem introduced today. Rewritten to describe
  the real suite and link `spec/conformance/README.md`.
- **Property-based and fuzz testing (Phase 6, the last of the six
  originally-scoped phases).** hypothesis (Python,
  `backend/tests/test_property_based.py`) and fast-check (TypeScript,
  `sdk/typescript/tests/property.test.ts`) property-test canonicalization
  (determinism, insertion-order independence, round-tripping) and the
  check-character algorithm (single-substitution/adjacent-transposition
  detection), on both sides of the language boundary, alongside the
  pre-existing exhaustive brute-force tests. Not a protocol change — no
  `Spec-Version` bump.

  Fuzzing (`backend/tests/test_fuzz_no_unhandled_exceptions.py`, a plain
  random-garbage generator against the two public unauthenticated
  surfaces) found and fixed three real robustness bugs, two of them
  Postgres-only — invisible to every prior SQLite-only CI run:
  1. `verify_check_char` raised an unhandled `KeyError` on a body
     containing a Unicode "digit" `str.isdigit()` accepts but the
     Crockford alphabet doesn't (e.g. superscript `²`) — reachable from
     the Phase 5 public resolver with a crafted code string.
  2. A NUL byte in any `POST /v1/verify` string field crashed with
     `asyncpg.CharacterNotInRepertoireError` (Postgres rejects it at the
     driver level; SQLite silently accepts it) — now rejected with a
     clean `422`, not stripped, matching `/verify`'s own fail-closed
     design.
  3. Fixing #2 surfaced a third, more general, pre-existing bug: a
     validator raising a bare `ValueError` can leave a non-JSON-
     serializable object in Pydantic v2's `errors()[].ctx`, which used to
     crash `main.py`'s validation handler outright — turning an intended
     `422` into an unhandled `500`. No validator had ever raised
     `ValueError` in this codebase before #2, so this was invisible until
     now. Fixed with `jsonable_encoder`, the standard fix for this
     Pydantic v2 shape, protecting every future validator, not just #2's.

  None of these are protocol/format changes (§1–§4 of this spec are
  unaffected) — implementation robustness fixes, logged here because
  fuzzing found them during this phase, not because the wire format
  moved. Full detail: `PRAMPTA_STRATEGIC_TRUST_PLAN.md` §17.
