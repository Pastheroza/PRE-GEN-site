# Steward runbook

What the steward does, step by step, with `spec/tools/steward.py` (PG-CODE.md §9.1). Every
command that signs refuses a directory verifiers would refuse: one that drops a listing, a key,
a revocation, a false claim, a reversal or a freeze of the directory it replaces. Never edit `registries.json` by
hand when a command exists for the change.

Run from the repository root with `cryptography` installed (`pip install cryptography`); the
tool uses `packages/verify-py` from the same checkout. `S=spec/tools/steward.py`,
`K=~/PRE-GEN-steward.pem`.

## Before anything

- `PREGEN_STEWARD_PASSPHRASE` must not be set: the tool refuses it for the real keys.
- The steward key and the successor key are kept apart: the successor key on separate offline
  media, never on the computer that signs. Each passphrase is stored apart from its key file.
- Work on a branch that changes only `registries.json`. `main` deploys pregen.org, so a merge
  publishes everything on it.

## List a registry

1. Read the application (GitHub issue, `registry-application` label) against admission rules
   1–3 yourself: a named operator with a public address and a complaints contact; a published
   policy page with the items the template asks for; "yes" to the core. Check the operator is
   who they say (company register, the domain's owner).
2. Check the pasted `pregen-registry check` output ends `OK: all checks passed`.
3. `python3 $S review --prefix ABCD --api https://… --directory registries.json KEY_ID…`
   fetches the registry's live `/keys` and `/.well-known/pregen-registry.json` on its own
   domain and refuses: a fingerprint not in the live key set, a current key not given, a key set
   not signed by its current key, a small-order or non-canonical key, a key another registry
   lists, a prefix the registry does not claim or that is taken or revoked. It notes, without
   refusing, a registry that has announced no next key: rule 4 asks for one; decide.
4. `python3 $S add $K registries.json --name "Operator" --prefix ABCD --api https://… KEY_ID…`
   runs the same review, adds the entry and signs. Every command that changes the directory
   refuses a `registries.json` that is behind the published one (`origin/main`) and a path that
   does not exist (`--first` only for a directory never published).
5. Commit `registries.json`, merge, and check the live copy:
   `curl -s https://www.pregen.org/registries.json > /tmp/live.json && python3 $S verify /tmp/live.json`.
6. Answer the issue with the new sequence, and close it.

## A listed registry adds a key

Its key-update issue gives the new fingerprint, already in its live `/keys` (as `next` or
current). If it lost its key (no `next` was announced and the old key is now retired in its
`/keys`), confirm through its listed operator contact that the request is really theirs before
adding the key. Run the same `add` with `--prefix` and `--api` as listed and every key id it now
has: only new ones are added, none is ever removed.

## A stolen operator key

Reports come only through the private security advisory form, never a public issue.

1. Confirm with the operator on its listed complaints contact, not on the reporter's word alone.
2. `python3 $S revoke-key $K registries.json KEY_ID --reason "…"`, commit, merge, verify live.
3. Announce it on pregen.org with the reason (PG-CODE.md §9.1). The registry keeps its other
   keys and lists a new one with `add`.

## Revoke a registry

Grounds are only those of PG-CODE.md §9.1. Ask the operator to answer first unless there is
ongoing harm, and keep the exchange.
`python3 $S revoke-registry $K registries.json ABCD --reason "…"`. The prefix is never
reassigned. Announce it with the reason.

## A false identity claim

After the dispute is decided (extensions/identity.md):
`python3 $S false-claim $K registries.json --anchor wikidata:Q… --code TOG-ABCD-… --reason "…"`.
The entry is never removed. Repeated false claims are a ground to revoke the registry.
If the finding was wrong:
`python3 $S reverse-false-claim $K registries.json --anchor wikidata:Q… --code TOG-ABCD-… --reason "…"`.
For one anchor and code the latest entry of the two decides; record the claim again with `false-claim`.

## Freeze a person

Ongoing harm while a complaint is examined (extensions/identity.md):
`python3 $S freeze $K registries.json --anchor wikidata:Q… --days 7 --reason "…"`.
Every verifier refuses the person from now for 1–7 days; a freeze is never lifted early.
A longer one is a new freeze with its own reason.

## After a hand edit

Only for a change no command makes (for example `steward_compromised_since` and `annulled`
in a handover): edit, then `python3 $S sign $K registries.json`. It finds the published
directory in git (`origin/main`, else `HEAD`) and refuses to sign if anything was dropped;
`--previous FILE` names it explicitly.

## Handover (the steward key is lost or stolen)

1. Take the successor key out of its offline place.
2. In `registries.json` add `steward_compromised_since` (the earliest time the old key may have
   been in other hands). For each revocation the thief signed after that time, delete it (the
   key's line in `revoked_keys`, or the entry's `revoked` member) and list it in `annulled`
   (`{"key_id"}` or `{"prefix"}`, each with a `reason`): a revocation left in place stays in
   force. Revocations dated before that time cannot be annulled.
3. `python3 $S sign --handover ~/PRE-GEN-steward-successor.pem registries.json`. It refuses any
   key but the published successor.
4. Publish the successor's public key as the new steward key everywhere the old one is
   (PG-CODE.md §9.1, README, the paper, the DNS TXT record, `STEWARD_PUBLIC_KEY_HEX` in this
   tool and in both libraries), create a new successor key with `init`, and store it apart.
   The libraries need a release that pins the new pair. Until this tool carries the new key,
   check the live copy with `verify --steward <the successor's public key hex>`.

## The test directory

`test/registries.json`, served at `https://www.pregen.org/test/registries.json` (`test.pregen.org` redirects there:
a host rewrite would lose to the real `registries.json`, which Vercel serves first). Test steward key `~/PRE-GEN-test-steward.pem`, public key in its `.pub`, its
passphrase in `~/PRE-GEN-test-steward.passphrase`. It lists sandbox registries only (the
application's Status: sandbox). Same commands, with `--steward <the test key hex>` for `verify`;
the test steward key signs nothing production accepts. Only
for that key a script may pass the passphrase in `PREGEN_STEWARD_PASSPHRASE`; never the real
steward's.
