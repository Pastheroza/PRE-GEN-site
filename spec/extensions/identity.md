# Extension `identity` — one person, several registries

**Solves:** the same public person can be claimed by several registries — by right (they
registered twice), or by an impostor. A name never decides; a refusal by the person must hold
everywhere; **who came first never wins — who proved it does.**

## Anchors

An **anchor** is the person's identifier in an independent public source:
`wikidata:Q11571`, `isni:0000000123456789`, or `domain:example.com`.

- A registry MUST give an anchor for every public person it registers. Registering a public
  person without one is ground for revocation (`PG-CODE.md` §9.1).
- Private persons have no anchor and are never listed.

`GET {api}/v2/anchors` → `pg.anchors.v1`, signed by `registry`:

| Member | Rule |
|---|---|
| `registry` | the registry's prefix |
| `issued_at` | integer time; a client refuses a list more than 24 hours old, so an old copy cannot hide a new opt-out |
| `anchors` | `[{anchor, code, level, proof_url, status}]`; `status` is `active`, `opted_out`, or the subject's unavailable status |

Schema: `schemas/anchors.json`. A client collects every listed registry's list, at least
daily, and for a public person asks **every** code its anchor names.

A client drops a list entry that names another registry's code (the rest of the list stands),
and refuses a list that names one code twice.

**A list that fails blocks only that registry's people.** While a registry's list has not
verified within the last 24 hours, a client generates none of that registry's own codes, and
keeps the entries of its last verified list as claims with no answer: a person whose claim
there they confirmed has no decision, unless another confirmed claim refuses them (rule 2).
Every other person, one that list also named included, is decided without that registry. A
client keeps the entries it verified, not the signed list, which stops verifying after a day.

**A revoked registry's refusals keep counting.** A revoked registry is never asked, but a
client keeps the entries of its last verified list. An entry whose `status` is `opted_out` or
`paused` is a claim whose answer is `deny` with `PG_SUBJECT_OPTED_OUT` or
`PG_SUBJECT_UNAVAILABLE`; it counts like any other claim, so it refuses the person only while
the person confirms it (or under "A recent refusal survives" below). Its other entries are
dropped: they neither permit nor leave anyone without a decision. Revoking a registry cannot
turn a person's opt-out held there into a permission elsewhere; the person lifts it by removing
their line.

## Confirmation on the person's own channel

A claim is **confirmed** when the line `PRE-GEN: <code>` stands at the confirmation place of
one of the person's official channels, and `proof_url` is that place. Anyone can check it. An
impostor cannot put it there without taking over the account or misusing someone's access to
it, so a confirmation proves control of the channel, not a right to license every use.
Registries re-check confirmations at least daily; once the line is gone, the claim is no
longer confirmed.

**Official channels.** Only a `wikidata:` anchor has them in this version; any other anchor
confirms nothing. They are the values, on the anchor's Wikidata item, of these properties, and
only of **current** statements: rank not deprecated; no end time (P582) that is unknown,
unreadable, or on or before today, compared by day at the qualifier's own precision (an end
time given only as this year has ended); no start time (P580) after today. A deprecated or
ended statement names no channel, so a former website whose domain anyone can buy confirms
nothing. A value not of its property's form names no channel; it is never repaired.

| Property | Form of the value | Channel |
|---|---|---|
| official website (P856) | `http://` or `https://` URL, any path, whose host in lower case is a plain ASCII domain name, with no user part or port | `https://<host>`, lower case, `www.` kept |
| X username (P2002) | `[A-Za-z0-9_]{1,15}` | `https://x.com/<value>` |
| Instagram username (P2003) | `[A-Za-z0-9_][A-Za-z0-9._]{0,29}` | `https://www.instagram.com/<value>` |
| YouTube channel ID (P2397) | `UC[0-9A-Za-z_-]{22}` | `https://www.youtube.com/channel/<value>` |
| TikTok username (P7085) | `[A-Za-z0-9_][A-Za-z0-9._]{0,23}` | `https://www.tiktok.com/@<value>` |

**The confirmation place** is fixed, and nothing else on the host or platform confirms:
- **Official website:** exactly `https://<host>/.well-known/pregen`, the website's own host.
  Its text has a line `PRE-GEN: <code>`.
- **Official account:** a post or the profile at or under the account's own URL, where the
  platform's own record names the account (letter case aside) as the one who wrote the line.
  A comment, a reply or another account's post, a search page or any other page confirms
  nothing.

The line is `PRE-GEN: <code>`, the whole code, alone on its line or followed by a space and
more words, spaces around it ignored; inside HTML or a sentence it is not a line, and
`PRE-GEN: <code> withdraw …` confirms nothing. A `proof_url` is compared exactly as written:
`https://`, a lower-case ASCII host, no user part, port, query, fragment or percent-escape, no
empty, `.` or `..` path segment, path characters only letters, digits and `._~@-`, at most 512
characters. It is fetched without following a redirect. The Python and JavaScript libraries
apply the same checks over one shared set of cases.

**Reading the place.**
- The line is there: confirmed.
- The page is read without it, or answers 404, 410 or a redirect: not confirmed.
- **Unreadable** (a timeout, a connection error, any other 4xx such as 403 or 429, a 5xx):
  not confirmed, so an impostor's broken link freezes nobody. Only if the client saw this
  claim confirmed at its previous check, within the last 7 days, does it have no decision for
  this person, and it generates nothing for them until the place reads again.

**A new channel waits 7 days before it permits.** A channel is **settled** when it was also a
current official channel in the item as it stood 7 days earlier (Wikidata's revision
history). A claim confirmed only on a channel that is not settled counts for rules 1 and 2
below, but its `allow` permits nothing. A fresh edit to Wikidata can refuse at once; it can
permit only if it stands for a week.

**A recent refusal survives a channel change.** A claim still counts, for rule 2 only, when
its line stands at the place of a channel that was current in the item as it stood 7 days
earlier and is no longer (removed, replaced or ended), or when the client saw it confirmed
within the last 7 days and its line can no longer be found. So replacing a person's channels
on Wikidata, or deleting their line from a taken-over account, does not silence their opt-out.
A client keeps, for 7 days, which claims it saw confirmed.

## The rule

For one anchor, over the claims that remain after the steward's false claims are removed:

0. **A steward freeze decides first.** While the directory freezes the anchor (below), the
   result is `deny`, `PG_SUBJECT_UNAVAILABLE`.
1. **Confirmed claims silence unconfirmed ones.** Only confirmed claims, and claims that count
   for rule 2 under "A recent refusal survives", count. Codes confirmed by the same person are
   one person in several registries.
2. **A refusal of the person holds everywhere.** If any counted answer refuses with a floor
   reason (`PG_SUBJECT_OPTED_OUT`, `PG_SUBJECT_UNAVAILABLE`, `PG_PROHIBITED_USE`,
   `PG_IMMUTABLE_DENIAL`, `PG_PERSONAL_SIGNATURE_REQUIRED`), the result is that refusal. "No
   licence here" is not a refusal of the person, and neither is a dispute
   (`PG_SUBJECT_DISPUTED`).
3. **No proof: PRE-GEN says nothing.** With no confirmed claim the result is `not_blocked`,
   `PG_IDENTITY_UNCONFIRMED`: it permits nothing and forbids nothing. No provider policy
   turns an unconfirmed claim into a permission.
4. A confirmed claim with no valid answer (its registry failed, or its list did) leaves no
   decision: generate nothing for this person.
5. Otherwise an `allow` from a confirmed claim on a settled channel permits; with none, the
   strongest refusal among the confirmed claims (`deny`, then `review`), whatever the order of
   the claims; if they only allowed, and none is settled, `not_blocked`,
   `PG_IDENTITY_UNCONFIRMED`.

An impostor can neither permit nor freeze a person who never confirmed anything; an edit to
the person's Wikidata item refuses only while it stands, and permits only after a week.
The libraries implement the rule as `decideIdentity` / `decide_identity`.

## Disputes, freezes and false claims

**A complaint is not a refusal of the person.** While a registry examines a complaint about one
of its codes, the code is `disputed`: that registry answers `deny`, `PG_SUBJECT_DISPUTED`,
before any grant. It holds at that registry only; the person's other confirmed claims decide
as before (rule 2).

**Only the person or the steward freezes a person everywhere.**
- The person, through a claim they confirmed: an opt-out or a pause (`PG_SUBJECT_OPTED_OUT`,
  `PG_SUBJECT_UNAVAILABLE`), for as long as they keep it.
- The steward, in the directory: `freezes: [{anchor, at, until, reason}]`, each at most 7 days
  from `at` to `until`. A longer freeze is a new entry with its own reason. A freeze is in
  effect while `at` ≤ now < `until`.

**False claims.** The steward records the outcome of a complaint in the directory:
`false_claims: [{anchor, code, at, reason}]`, every member required. A client drops a claim
only when both its anchor and its code match an entry, so an entry under the wrong anchor
cannot silence the person's real claim. Asked as a private person, outside the rule above, a
code an entry names is never generated. The steward does not record a code whose claim
currently confirms unless the evidence shows that the confirmation came from a taken-over
channel. An entry is never removed; a mistake is corrected by `false_claim_reversals: [{anchor, code, at, reason}]`. For
one anchor and code, the latest of its entries in the two lists, by `at`, decides. Repeated
false claims are ground for revoking the registry.

### Complaints

The steward decides disputes under this procedure until an independent panel takes over.

1. **Where.** First to the registry that holds the code, at its complaints contact
   (`PG-CODE.md` §9.1, admission 1). To the steward (pregen.org) when the registry has not
   answered within 7 days, when the complaint is about the registry itself, or when ongoing
   harm needs a freeze.
2. **Who.** Anyone may complain to a registry. The steward acts on a complaint from the
   person, someone with the person's written authority, a listed registry, or a complainant
   the registry did not answer within 7 days. A registry need not reopen a dispute on the same
   code from the same complainant without new evidence.
3. **Evidence.** The code, the anchor, and what is false: the claim is not the person's, the
   registry has no authority from them, or the confirmation came from a taken-over channel.
   Only what a third party can check counts: a line at the person's confirmation place, a
   signed statement from the person or their representative, the registry's records. A name,
   a resemblance, news or a fan page is not evidence.
4. **Deadlines.** The registry decides within 7 days. The steward asks the registry and the
   holder of any confirmed claim on the anchor to answer within 7 days, and decides within
   30 days of the complaint. A freeze may be set at once.
5. **Outcomes.** Dismissed; the code `disputed` at its registry while it examines, then
   cleared, corrected or withdrawn there; a steward freeze; a false claim; revocation of the
   registry (`PG-CODE.md` §9.1). The steward publishes every outcome of its own on pregen.org
   with its reason.
6. **Correction.** Either side may ask the steward once, with new evidence, within 30 days of
   a published outcome, to reconsider it. A false claim found wrong is reversed, never deleted.
