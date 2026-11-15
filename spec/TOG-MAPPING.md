# ToG-L 1.0 and PRE-GEN: what maps to what

**Status:** informative. It explains how the terms of the Terms of Generation Licence, Version 1.0
(`ToG-L-1.0`, sha256 `bfff2e4620d2786f150d0582434b7b9741a12d21637a365a246c7bd203243939`,
[pregen.org/tog/1.0](https://www.pregen.org/tog/1.0)) meet the messages of the PRE-GEN core
([`PRE-GEN-CORE.md`](PRE-GEN-CORE.md)) and its extensions. Where they differ, the licence decides
what is permitted and the core decides what a valid message is. This page changes neither.

**Two layers.** ToG-L is the legal layer: who may permit what, and what a provider promises. PRE-GEN
is the technical layer: how a provider asks before it generates and how anyone checks the signed
answer. The message names stay `pg.*` because they belong to the PRE-GEN Protocol; ToG names the
codes, the licence and the Holder's statement.

## Terms and messages

| ToG-L 1.0 | PRE-GEN | Notes |
|---|---|---|
| Holder's code | `subject_ref`, a ToG code ([`TOG-CODE.md`](TOG-CODE.md)) | the first prefix names the home Registry |
| Registry | a registry in the steward's directory (core rule 2) | it signs only for its own prefix |
| Steward | the steward key and the signed directory | admission and removal: [`PG-CODE.md`](PG-CODE.md) §9.1 |
| Statement, its Rules and Conditions | `pg.terms.v1` ([`extensions/terms.md`](extensions/terms.md)) | `legal` carries the licence hash; every version is kept |
| Stop (incl. the token `tog:no`) | `pg.terms.v1` with no `purposes`, or a closed subject; the answer is `deny` | a Stop never comes back as `allow` |
| Request | `pg.request.v1`, signed by the provider (`provider-identity`), naming the terms by message id | signing it is how a provider accepts the licence for that request |
| Undertaking | the provider's party document at `/.well-known/pregen-party.json` and its keys | a member that states the Undertaking is not yet defined (see Gaps) |
| Lookup | `GET {api}/v2/codes/{code}` ([`extensions/lookup.md`](extensions/lookup.md)) plus the sources the steward lists | no face or voice recognition, in either layer |
| Permission (Section 3 and a Deal) | answer `status: allow` | **only `allow` permits** |
| Deal | `pg.grant.v1` ([`extensions/grants.md`](extensions/grants.md)); the answer's `basis` is `{"kind": "grant"}` | the Deal's own terms live in the agreement, not in the message |
| Record | the registry's signed `allow` for the request and, with `reports`, its signed acknowledgement of what was made | together they are the `request`/`answer`/`report`/`ack` parts of `pg.proof.v1` |
| ToG Proof (Section 9(h)) | `pg.proof.v1` in the output's C2PA manifest with the file's SHA-256 ([`extensions/proof.md`](extensions/proof.md)) | never a watermark |
| Approval (Section 8(e)) | answer `status: review` until the Holder answers | the Holder's confirmation is a registry record; see Gaps |
| No Statement (Section 4(f)) | answer `status: not_blocked`, or the reason `PG_UNKNOWN_SUBJECT` | silence permits nothing |
| Several Holders in one Output (2(f)) | [`extensions/jobs.md`](extensions/jobs.md): every subject needs a valid `allow` | one refusal stops the job |
| Withdrawal and change (Section 7) | a new `pg.terms.v1` version; later requests get the new answer | what an earlier `allow` covered is judged by its time and version |

## Time

A PRE-GEN answer may live 1 to 900 seconds (core rule 4). ToG-L lets a provider rely on a
Registry's answer for the period it states and **at most 5 minutes**, and on a Statement read where
the Holder publishes it for 24 hours. A provider under ToG-L therefore treats an answer as expired
after 5 minutes, whatever its `expires_at` says. PRAMPTA signs its answers for 300 seconds.

## Gaps: named by the licence, not yet defined in the spec

- **Profiles** `likeness/2`, `marks/1` and `proof/1`. The licence names them with their hash still
  `[hash]`; the spec publishes `likeness/1` only.
- **Check Record** and its code: a ToG Proof for content that is not an Output. Drafted, not
  published.
- **Undertaking and Platform Undertaking** as a member of the party document.
- **Approval** of one Output by its SHA-256, and **Authorised Person** appointments (2(i)), as
  signed messages. Today they are records inside a registry.
- **Authorisations** for Restricted Capabilities (9(i)).

Each of these is added as a profile or an extension. The core does not change.
