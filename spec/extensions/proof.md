# Extension `proof` — the record travels with the output

**Solves:** a code printed on a video proves nothing. A platform needs the signed record
of *this* output, even after re-encoding.

**Requires:** [`reports`](reports.md).

## The bundle — `pg.proof.v1`

`{"format": "pg.proof.v1", "subjects": [{request, answer, report, ack}, …]}` — one entry per
subject of the job, each part exactly as signed. Schema: `schemas/proof.json`. The bundle
itself is unsigned: every part is. Under [`terms`](terms.md), a subject's entry may also carry
`terms`: the `pg.terms.v1` whose message id its request carries, so the bundle can be checked
without the registry.

The report names the output by its SHA-256 (`output_hash`) and may add `bindings`:
`[{alg, value}]`, fingerprints that survive re-encoding (C2PA *soft bindings*; `alg` is a
C2PA soft-binding algorithm name). A binding fingerprints the output file, never a person.
Its `value` is opaque to PRE-GEN: registries store it, and the libraries neither compute nor
compare it.

## The code under the output

Each subject's entry has one act code (`TOG-CODE.md` §6.1), computed from its answer, never read
off a caption:

- **`TOG-PG-…`** when the answer was made under the person's terms; **`TOG-PG-LIC-…`** when its
  `basis` names a licence (a `pg.grant.v1` or an old `pg.license.v2`).
- **Issuer:** the registry that signed the answer. **Tail:** from the message id of the object
  the home signed for it: its countersignature in the home model, the answer itself in the flat
  model. In the flat model the answer's signer must be the registry the person's code was born
  at; otherwise the entry has no code.
- **One allow, one code.** Every output reported under one allow shows the same code.
- A registry does not issue an `allow` whose code would end in a symbol or whose tail would start
  `ZZZZ`: it signs it again with a changed body. It refuses a code it has already issued.

A file approved after it was made gets an `AG` or `AG-LIC` code the same way, from its AFTER-GEN
record. A caption shows the code; a verifier checks the caption against the record, never the
other way round (`TOG-CODE.md` §15). Vectors: `test-vectors/tog-code.json`, `code_for`,
`verdict`.

## Readable copies

A subject's entry may carry two readable copies (`TOG-CODE.md` §14):

| Member | Value |
|---|---|
| `code` | the entry's act code, `TOG-PG-…` or `TOG-PG-LIC-…` |
| `licence` | the licence's `TOG-LIC` code, only when the answer's `basis` names one |
| `grant` | the `pg.grant.v1` envelope the `basis` names, so that `licence` can be recomputed |

**Copies, never authority.** A platform recomputes both copies from the signed parts and refuses
the bundle on any mismatch. A `licence` copy on an answer whose basis is not a licence is a
mismatch; so is one that cannot be recomputed because the licence is not in the entry. A missing
copy is not an error. Vectors: `metadata`.

## Carrying it

- **C2PA manifest:** the bundle as an assertion labelled `org.pregen.proof`.
- **By id:** if the manifest is stripped, the holder presents the bundle, or a platform that
  knows the report id fetches that registry's part:
  `GET {api}/v2/proofs/{first 16 hex of the report id}` → a `pg.proof.v1` bundle with that
  subject.

For a job with several subjects the full bundle travels in the C2PA manifest; by id a
platform recovers the subject that report names. PRE-GEN defines no watermark.

## Checking it

A platform accepts the bundle when, for every subject:

1. the answer verifies through a directory loaded in the last 24 hours (core rules 2 and 5)
   and was a valid `allow` **at the report's `occurred_at`**, the moment generation began —
   it is checked as of then, not today;
2. the acknowledgement is signed by a key the directory lists for the subject's prefix, and
   names this report and this answer; the report's outcome is `generated`;
3. any readable copy (`code`, `licence`) equals the code recomputed from the signed parts;
4. the acknowledgement's `received_at` is **no later than 24 hours after the answer's
   `expires_at`**. `occurred_at` is the provider's word; the registry's `received_at` is not.
   A report that arrives later is still recorded (`reports` has no deadline), but it proves
   nothing: one old allow must not buy a "permitted" output at any later time;

and all reports name one `output_hash` and one `job_id`. Given the file, its SHA-256 must
equal `output_hash`. After re-encoding, a platform may match a soft binding with that
algorithm's own tooling, outside this specification; `check_proof` does not.

A revoked registry's bundles fail, including old ones (`PRE-GEN-SPEC.md` V-14). A bundle
shows what was permitted and by whom; it does not decide whether a use is lawful.

The libraries implement the check as `checkProof` / `check_proof`.

## The terms

For each subject a platform also reports `terms`, which never changes whether the bundle is
accepted:

| `terms` | When |
|---|---|
| `absent` | the request carries no `terms`. Neither a pass nor a failure: a bundle made without terms keeps its meaning |
| `unverified` | the request carries `terms`, and the entry has no `pg.terms.v1` with that message id, or the record does not follow `schemas/terms.json`, is about another code, has `amends` wrong for its `version`, or is not signed by its one registry signer with a key the directory lists for the code's prefix |
| `outside` | the record checks out, and the request's `use` fails the profile's floor (with the record's `minor`), names an intimate category (terms never cover one, whatever the basis), names a category outside the profile's closed vocabulary or categories that are not a list of words, or, where the answer's `basis` is a policy, falls outside the record's `rules` (a grant decides its own scope) |
| `ok` | the record checks out, and the use keeps to it |

Beside it, `terms_assent` is the record's `assent`, which is always `registry`: the registry's
word, never the subject's own key. The bundle shows **what was signed**, not that the terms
still stand: a later version is the registry's live state (`lookup`'s `status_url`).
