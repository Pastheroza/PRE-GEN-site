# Extension `lookup` — what a code is

**Solves:** a person, a lawyer or a platform holds a code and wants to know whom it names.

## Endpoint

`GET {api}/v2/codes/{code}` (public), at the registry named by the code's **first** prefix
(`TOG-CODE.md` §8). The response:
- `{"code", "kind", "registry": "<prefix>", "status": "active" | "pending" | "expired" | "opted_out" | "unknown" |
  "other_registry"}`;
- `code` is always the TOG spelling (`TOG-CODE.md` §7.3), whatever spelling was asked;
- `kind` is `subject`, `license`, `generated` (`PG`, `PG-LIC`) or `approved_after` (`AG`,
  `AG-LIC`);
- **for a subject that answers `active`, also:** `"holder": "person" | "company"`, so no verifier reads a
  company's code as a person's; a company also `"domain"`, the domain it proved (below); a person who gave
  conditions in their own words also `"conditions"` (below);
- **for a subject the registry publishes, also:** `"name"`, `"level"` and `"subject_key":
  {"key_id", "public_key_hex", "custody"}`;
- **under a registry that declares [`terms`](terms.md), for a subject that has terms, also:**
  `"terms": {"id", "url"}`, the current version's message id and its `GET {api}/v2/terms/{id}`
  address, and `"status_url"`, the registry's public page for the subject, which shows the
  current terms and every earlier version.

**Nothing is returned that the rights holder did not choose to publish.** A ToG code's status, holder
and level are public by its nature (below), never with a name the holder did not publish.

## Which registry answers

- A registry asked for a code whose first prefix it does not hold answers `other_registry`, with
  a link to the directory.
- **A closed or revoked issuer.** When the directory marks the first prefix `closed` or sets its
  `void_from`, ask the home: the second prefix, or the home named in the record. The home answers
  for every object it countersigned. If the home is hidden and no record is at hand, nobody can
  answer; the file's own bundle still verifies offline.

## Spellings

- **A `PG-` string is not a code.** `PG-ZYXW-1234567R` asked is answered `400 invalid_format`,
  like any other non-code, with no hint, and never as `TOG-ZYXW-1234567R`. An old licence answers
  only by its `TOG-LIC` code. `GET /v1/pg/{code}` is retired at a registry's switch.
- **A registry finds a person by number:** prefix, legacy class (`STD`, `SUB`) and the serial's
  value. An over-padded number (`TOG-STD-0000123` for `TOG-STD-000123`) is answered
  `PG_MALFORMED` (422) with the code as a hint, never with a signed answer or a record.
- A string that is not a code is answered `400 invalid_format`, one whose check fails
  `400 mistyped`, both apart from `unknown`.

Vectors: `test-vectors/tog-code.json`, section `lookup`.

## ToG codes: pending, active, expired

A holder, a person or a company, has **one home registry**, which alone registers them
([`identity`](identity.md)). The home issues the holder's ToG code at once, **pending**. A person's
code and a company's code have the same form (`TOG-CODE.md` §5).

- **Pending:** the answer is exactly `{"code", "kind": "subject", "registry", "status": "pending"}`:
  no name, no level, no terms. A pending code permits nothing and forbids nothing. The registry
  signs nothing for it (no terms, no licence, no allow), and answers a request about it
  `not_blocked`, `PG_SUBJECT_PENDING` ([`likeness/1`](../profiles/likeness-1.md)): the holder's
  "no" counts only once the code is verified, and a "yes" only once their identity is.
- **Verified:** the holder proved control of a public account or a domain by placing the line
  `ToG: <code>` at its confirmation place ([`identity`](identity.md), Confirmation; a company:
  its `https://<domain>/.well-known/tog.json` names the home's record for the code, read without
  redirects), or the registry verified their identity. **An email address alone never verifies a
  code.** From then on the code answers `active` with `holder`, `level` and, when in force, `terms`
  and `status_url`, whether the holder is published or not; `name` and `subject_key` only if the
  holder chose to publish them. A verified code never returns to pending by itself; a company whose
  domain stops naming the record answers `pending` until it does again.
- **Conditions** (ToG 1.0 public draft 1, Section 6(f)): a person's own words, in any language, at most 1,000
  characters, that only narrow their rules. An `active` code's answer carries them as `"conditions": "<text>"`,
  the exact string the holder gave (the form of `spec/drafts/tog-funnel.md`: non-empty NFC, at most 1,000 code
  points, LF the only control), and a verifier shows them first, as plain text. **A pending or expired code never
  carries them**, nor does a company's. Adding conditions takes effect at once; changing or removing them may open a
  use, so the home registry takes them only with the holder's second factor.
- **Seven days.** A code not verified within 7 days of its issue is deleted; the registry reminds the
  holder on day 3. A deleted code answers `"status": "expired"` (no other member but `code`, `kind`
  and `registry`): it permits nothing and forbids nothing. **Its serial is never issued again**
  (`TOG-CODE.md` §5). The holder may register again and gets a new code.
- **After verification the holder's yes or no is global:** every registry and AI service that
  integrated PRE-GEN reads it at the home, by this code.

`level` of a ToG holder: `channel` (control of an account or domain proved) or `verified` (identity
verified). Only `verified` may open a use.

## Persons

- **Published:** as above, plus `"moved": "<prefix>"` when the person moved to another home, and
  `"alias": "<code>"` when two codes were joined. Both codes of a joined pair resolve forever.
- **Unpublished:** exactly the answer for a code never issued (`unknown`), in the same time, at
  every registry, **except a code that carries a Do Not Generate refusal, which answers its
  refusal (`opted_out`), and a ToG code (above), which answers `pending`, `active` or
  `expired`, never a name.** A v5 licence id of an unpublished person (`PG-PRAM-PRM-…`, which holds the serial)
  also answers like a licence never issued.

## Acts and licences

- `generated`: the status of the record (valid; `void_from` if any), its issued date, purpose,
  terms id and the provider's domain. With `?media=<hash>` equal to the report's `output_hash`,
  also the `pg.proof.v1` entry. A `PG` code has no "withdrawn": a withdrawal stops new
  generation, and the deal stays a contract. Until a report arrives the answer says "allowed; no
  output reported".
- `approved_after`: its AFTER-GEN status.
- `license`: its status and its issuer, and **the ToG code it is tied to:** `"subject": "<the holder's
  code>"` and `"subject_level"`, that code's `level` (`verified` when the holder's identity is
  verified). `generated` and `approved_after` carry the same two members. Every licence and record
  is tied to one ToG code; its own code never contains it (`TOG-CODE.md` §1.5).

## Level

`level` is the registry's own statement of how well it established who may decide for the
subject. **It is a claim, not evidence.**

| Level | Meaning |
|---|---|
| `self` | the person registered themselves |
| `asserted` | a representative asserts authority |
| `consented` | the person confirmed the representative |
| `verified` | the registry verified identity and authority |
| `channel` | a ToG holder proved control of a public account or domain, not identity |
