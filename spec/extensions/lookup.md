# Extension `lookup` — what a code is

**Solves:** a person, a lawyer or a platform holds a code and wants to know whom it names.

## Endpoint

`GET {api}/v2/codes/{code}` (public), at the registry named by the code's **first** prefix
(`TOG-CODE.md` §8). The response:
- `{"code", "kind", "registry": "<prefix>", "status": "active" | "unknown" | "other_registry"}`;
- `code` is always the TOG spelling (`TOG-CODE.md` §7.3), whatever spelling was asked;
- `kind` is `subject`, `license`, `generated` (`PG`, `PG-LIC`) or `approved_after` (`AG`,
  `AG-LIC`);
- **for a subject the registry publishes, also:** `"name"`, `"level"` and `"subject_key":
  {"key_id", "public_key_hex", "custody"}`;
- **under a registry that declares [`terms`](terms.md), for a subject that has terms, also:**
  `"terms": {"id", "url"}`, the current version's message id and its `GET {api}/v2/terms/{id}`
  address, and `"status_url"`, the registry's public page for the subject, which shows the
  current terms and every earlier version.

**Nothing is returned that the rights holder did not choose to publish.**

## Which registry answers

- A registry asked for a code whose first prefix it does not hold answers `other_registry`, with
  a link to the directory.
- **A closed or revoked issuer.** When the directory marks the first prefix `closed` or sets its
  `void_from`, ask the home: the second prefix, or the home named in the record. The home answers
  for every object it countersigned. If the home is hidden and no record is at hand, nobody can
  answer; the file's own bundle still verifies offline.

## Spellings

- **The TOG spelling and its `PG-` legacy input are one code.** `PG-ZYXW-1234567R` asked is
  answered as `TOG-ZYXW-1234567R`. An old PG licence id is answered through the registry's
  record, as its `TOG-LIC` code.
- **A registry finds a person by number:** prefix, legacy class (`STD`, `SUB`) and the serial's
  value. An over-padded number (`PG-STD-0000123` for `TOG-STD-000123`) is answered
  `PG_MALFORMED` (422) with the TOG spelling as a hint, never with a signed answer or a record.
- A string that is not a code is answered `400 invalid_format`, one whose check fails
  `400 mistyped`, both apart from `unknown`.

Vectors: `test-vectors/tog-code.json`, section `lookup`.

## Persons

- **Published:** as above, plus `"moved": "<prefix>"` when the person moved to another home, and
  `"alias": "<code>"` when two codes were joined. Both codes of a joined pair resolve forever.
- **Unpublished:** exactly the answer for a code never issued (`unknown`), in the same time, at
  every registry, **except a code that carries a Do Not Generate refusal, which answers its
  refusal.** A v5 licence id of an unpublished person (`PG-PRAM-PRM-…`, which holds the serial)
  also answers like a licence never issued.

## Acts and licences

- `generated`: the status of the record (valid; `void_from` if any), its issued date, purpose,
  terms id and the provider's domain. With `?media=<hash>` equal to the report's `output_hash`,
  also the `pg.proof.v1` entry. A `PG` code has no "withdrawn": a withdrawal stops new
  generation, and the deal stays a contract. Until a report arrives the answer says "allowed; no
  output reported".
- `approved_after`: its AFTER-GEN status.
- `license`: its status and its issuer.

## Level

`level` is the registry's own statement of how well it established who may decide for the
subject. **It is a claim, not evidence.**

| Level | Meaning |
|---|---|
| `self` | the person registered themselves |
| `asserted` | a representative asserts authority |
| `consented` | the person confirmed the representative |
| `verified` | the registry verified identity and authority |
