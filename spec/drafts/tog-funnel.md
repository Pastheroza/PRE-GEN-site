# The registration process — one process for pregen.org and every registry

**Status: Part A is required (founder decision, 2026-11-12); the file stays in `drafts/` until it moves into the
specification.** It has two layers, so that the process is one standard without freezing anyone's design:

- **Part A, required:** what pregen.org and every registry that takes ToG statements MUST follow, word for word in
  meaning: the roles, the intake, the closed answers, the age rule, the order of decisions, the outcomes, what a
  registry does with the answers, pending and proof, the ToG statement, the fragment and the return, with their
  vectors. Every rule written as "does" in Part A is a MUST.
- **Part B, reference presentation:** the screens and wording of `pregen.org/tog/create`, recommended and free to restyle
  or translate, as long as Part A holds.

# Part A — required

## A.1 Roles

- **pregen.org is not a registry.** It keeps the protocol, the signed list of registries and this process. It
  registers no person or company and holds no code.
- **A registry registers.** The person or company chooses one home registry from the signed list. It records the
  answers, issues the ToG code, confirms identity and rights (a company: control of its domain), and from then the code
  takes effect for every registry and AI service on PRE-GEN Protocol. One home per holder.
- **An AI service and a registry operator never register** in this process: they get no code (A.2).

## A.2 Intake and outcomes

The first question is what the person needs ToG for, from exactly these four, and it decides the outcome:

| Answer | Who answers next | Outcome |
|---|---|---|
| My likeness | a natural person, for themself (or, under 18, their parent or legal guardian: A.3) | a person's ToG code and their ToG statement |
| My company's brand or products | a company, for the marks, products and characters it owns | a company's ToG code (same form, `TOG-CODE.md` §5), its `/.well-known/tog.json`, and its statement |
| My AI service | nobody: no question is asked and nothing is sent | no code; `/connect` (ask before generating, read codes, act on the signed answer) |
| A registry | nobody | no code; `/create-registry` (get listed in the signed list) |

The second question, **where the ToG will be used** (website · public profile or account · only the code), chooses
which form of the one statement is shown first (A.7); it never changes the answers, the code or what is sent.

## A.3 The age rule

A person gives their date of birth before any decision. It decides only 18 or over, stays on the device, and is never
sent, encoded, stored or shown to the registry. **Under 18:** the person cannot make a statement alone; only a parent
or legal guardian (other legal representative) files for them, and only a No: the answers are exactly
`{"who": "child", "decision": "no"}`. No screen offers "my child" before the date. Sexual or adult content showing a
person under 18 is never permitted, under any statement.

## A.4 The order of decisions

need → use → (a person: date of birth → under 18 ends at the representative's No) → decision → on a Yes: purposes
(at least one; none means No) → excluded categories → (a person: voice → commercial fees when commercial work is
allowed → own conditions) → check of every answer → choice of one home registry → the registry issues the code → the
statement. The closed answer sets are those of the fragment (A.9). Political content and sexual or adult content are
always excluded on every Yes. A Yes is recorded at once and takes effect only after identity verification; a No takes
effect once the code is confirmed.

## A.5 What the home registry does with the answers

The registry's `tog_start` receives the answers in the fragment (A.9) and takes the person **straight from the answers
to an account, a code and the statement**, without asking the questions again:

1. Decode strictly (`decodeFragment`); remove the fragment from the address at once. `ok`: go on. `minor`,
   `malformed` or `unknown_version`: never repair; send the person to the process's start (`pregen.org/tog/create` or the
   registry's own copy of Parts A and B).
2. Show the statement the answers make (the card, conditions first, as plain text) and ask the person to confirm it.
   The person may change answers only through the same closed choices; the registry never adds or widens one.
3. Ask only what the registry itself needs: the account (email, second factor), for a company its domain, for a
   representative a declaration of their authority over the minor. Never the date of birth, never a new question that
   changes the outcome.
4. Issue the code at once, **pending** (A.6), one per holder, and keep the answers it recorded with it.
5. Send the person to the return (A.8): pregen.org shows their statement with the code, in its three forms (website, profile, code only).

## A.6 Pending, proof, one home

A new code is pending for 7 days: it permits and forbids nothing; the registry reminds the holder on day 3; on day 7
an unconfirmed code is deleted and its number is never issued again (`extensions/lookup.md`). A person confirms it by
the line `ToG: <code>`, alone on its line, at a public account or website they control, or by identity verification;
a company by its domain's `/.well-known/tog.json` (A.7). Once confirmed the holder's Yes or No is global for every
registry and AI service on PRE-GEN Protocol. One home registry per holder.

## A.7 The ToG statement

One text, the same for a website, a profile and a record, built from the answers and the code alone. It cites the
common legal text, never copies it:

```
ToG: TOG-PRAM-900000037K

Terms of Generation
[Made for a person under 18 by their parent or legal guardian.]
[My own conditions, which only narrow the terms below:
<the conditions, exactly as written>]

<the card's lines>

Licence: ToG-L 1.0, https://www.pregen.org/tog/1.0        (a person only)
SHA-256 c608c6cb477918d040a432417ba2101f1731aee906ce15024933efcb907ba2ac
Record: https://www.pregen.org/lookup?code=TOG-PRAM-900000037K, home registry PRAMPTA
```

- **Website:** the same text as an HTML `<section id="tog">` for a page such as `/tog`. The line `ToG: <code>` stands
  alone on its own source line inside a `<p>`, so a registry that reads the raw page or its rendered text finds it
  (`extensions/identity.md`, Confirmation). The person gives the registry the page's address.
- **Profile:** the plain text above, for a profile or a post in the person's own name; its first line is the proof.
- **Only the code:** the code to cite in contracts, credits, packaging or metadata, and the line to put on a public
  page (a person) or the company's `/.well-known/tog.json`.
- **A company's `/.well-known/tog.json`**, in the form its home registry checks:
  `{"tog": 1, "registered": [{"notary": "<prefix>", "record": "<the code's record page>", "claim": "<claim>"}]}`.
  `record` and `claim` come from the registry (in its return, or on its own page); pregen.org never invents them.

Publishing the statement where the person controls the page is the proof that moves the code from pending to active.
A company's code is proved by its domain's `tog.json`.

## A.8 The return: the registry sends the person back

Once it has issued the code, the home registry sends the person, by a top-level navigation, to:

```
https://www.pregen.org/tog/document#code=<code>&tog=v1.<answers>[&record=<record>&claim=<claim>]
```

- `code`: the code it issued, exactly, a person's or a company's (`TOG-CODE.md`; never a PG- string, an event code or
  a code without a check character).
- `tog=v1.…`: the answers it recorded for the code, encoded as below. When the person changed nothing at the registry
  it is byte for byte the fragment the registry received.
- `record` and `claim`: both or neither, and only on a company's answers: the two members of its `tog.json` entry.
  `record` is percent-encoded as `encodeURIComponent` does (upper-case escapes), an `https:` URL of printable ASCII
  without credentials or fragment, at most 512 characters (`return.record_max`), on the registry's own website (the
  page checks the origin against the signed list). `claim` is 16 to 64 characters of `0-9a-f`.
- In this order only, at most 8,192 characters (`return.max_length`). Decode is strict: the whole re-encodes to
  exactly the input, or it is refused. Results: `ok` with `code`, `answers` and, for a company, `record` and `claim`;
  `unknown_version`, `minor` or `malformed` as for the fragment.
- The page reads the fragment in the browser; only the code is sent, to `/api/lookup`, for its public status. The page
  is `noindex` and sends no referrer. The link is the person's own permanent copy of the statement.
- Vectors: `return.encode` and `return.decode` in `test-vectors/tog-generator.json`; ports: `encodeReturn` and
  `decodeReturn` in `@pregen/verify` (`tog.js`). Until a registry returns, the person types the code on `/tog/create`, which
  builds the same link.

## A.9 The fragment, the legal text and the registry step
Vectors: `test-vectors/tog-generator.json` (generated by `tools/tog_generator_vectors.py` from the approved reference
`tools/tog_generator.py`).

**One common text** (founder, 2026-11-11). Like Apache 2.0: one licence text, identical for everyone, fixed by its
hash: ToG-L 1.0 (identifier `ToG-L-1.0`, 2026-11-13) at `https://www.pregen.org/tog/1.0` (the deed at
`/tog/1.0/deed`; the hashed bytes at `/tog/1.0/legal-code.txt`, SHA-256
`c608c6cb477918d040a432417ba2101f1731aee906ce15024933efcb907ba2ac`, 73,492 bytes; `meta.legal` in the vectors; the PDFs
at `/downloads`). Every page and card that cites it says "ToG-L 1.0" (`meta.legal.label`).
The page's output is a short card (the answers, later the code) that links that text. It never builds a personal copy
of the licence.

**The registry step is mandatory**, for a company too. The home registry issues the code at once, pending: it
permits nothing until verified, and is deleted after 7 days without it (`extensions/lookup.md`). After verification
the holder's yes or no is global for every registry on PRE-GEN Protocol ("Once verified, your YES or NO is global for
every registry on PRE-GEN Protocol."). A yes is recorded as the holder's wish;
it opens only after identity verification.

### The fragment `tog=v1`

```
{tog_start}#tog=v1.<base64url, no padding, of the UTF-8 bytes of the canonical JSON of the answers>
```

- Canonical JSON: keys sorted, no spaces; arrays in the generator's own order, never sorted; a string's non-ASCII
  characters as raw UTF-8, never `\u` escapes (the only escapes are `\"`, `\\` and `\n`). Every value but
  `conditions` is ASCII, so a fragment without conditions is byte for byte what it was before conditions existed.
- A person answering for themself — members: `age` (`"18+"`, always; `"13-17"` decodes as `minor`), `decision` (`"no"` | `"approve_all"` | `"rules"`, always);
  if the decision is not no: `for` (non-empty, ⊆ `fun, news, paid` in that order), `never` (⊆ `vice, weapons,
  violence, gambling, money, health, religion, ads, endorse, fashion` in that order), `voice` (boolean); `floor`
  (`"each"` | `"project"` | `"video"`, the kind of lowest price, never an amount) iff `paid` is in `for`;
  optionally `conditions` (below).
- **`conditions`** (ToG-L 1.0, Section 6(f)): the person's own words, in any language, which only
  narrow what they allow. Optional, and only on a person's yes: never on a no (a no has nothing to narrow), a
  company's answer or a representative's. When present it is a JSON string that is:
  - non-empty, and at most **1,000 Unicode code points** (`CONDITIONS_MAX`; a code point is a character, so an
    emoji counts 1 although JavaScript's `length` says 2); a longer text is refused, never cut;
  - in Unicode NFC (`s.normalize("NFC") === s`), never normalised for the person: the page normalises before encoding;
  - free of every C0 and C1 control but LF (U+0000–U+0009, U+000B–U+001F, U+007F–U+009F), of U+2028 and U+2029,
    of the bidi controls (U+202A–U+202E, U+2066–U+2069), and of lone surrogates. LF is the
    one line break. These would let the card show other text than the bytes that were signed.
  The page trims the text and omits the member when nothing is left. The card shows the conditions **first**, as
  plain text exactly as written (never parsed for markup), under the line "They can only narrow what you allow."
  They do not enter the machine-read rules (`rules_from_answers` ignores them), but they are part of what the
  person agreed (ToG 1.0 §1(m)): a registry that signs a version carries them in its body as `conditions`, and any
  change makes a new version. Vectors: `fragment.encode` and `fragment.decode`
  entries named `conditions…`; `meta.fragment.conditions_max`.
- A company: exactly `{"who": "company", "decision"}` for a no, `{"who": "company", "decision", "for", "never"}` for
  a yes, the same closed sets. Never an age, a voice, a floor, a domain or a name: the domain is typed at the registry.
- A minor's parent, guardian or other legal representative: exactly `{"who": "child", "decision": "no"}`. A minor
  is registered only by them, and only with a no for now.
- Under 18 is never encoded for a person themself.
- Decode is strict and never repairs: at most 6,144 characters (`meta.fragment.max_length`; the longest possible
  fragment, 1,000 four-byte characters of conditions, is 5,629); `tog=` then `v1.`; base64url alphabet only, no `=`;
  UTF-8 JSON; the exact member set; every value in its closed set; and re-encoding the answers gives back exactly
  the input (this rejects padding, non-canonical bits, key order, spaces, duplicate keys and escapes).
- Results: `ok` with the answers; `unknown_version` (anything after `tog=` but `v1.`); `minor` (any `age` 13-17);
  `malformed` (everything else). The person sees every answer and the card again at the registry before anything
  is signed, so a corrupted link costs nothing.

**Privacy.** The answers are closed codes, not personal data, except `conditions`, the person's own words. All of it
rides only in the fragment, which browsers never send in a request or a Referer. The year of birth, a name and an email never enter it; the query string is never
used. The registry reads the fragment and removes it from the address at once.

### The registry chooser

The page reads the signed directory (`/registries.json`) and offers an entry only if its `prefix` is non-empty, it
is not revoked, and its `tog_start` is `https:` with the same origin as its `website` (default port and letter case
do not matter), without credentials, query or fragment. The button is a top-level navigation, in a new tab (`noopener noreferrer`), to
`tog_start + "#" + fragment`. Until a steward lists a `tog_start`, the page says "No registry takes ToG statements yet."

On `localhost` only, the page reads `/test/tog-local/registries.json`, signed by the ephemeral key in
`/test/tog-local/steward.json` (`node test/tog-local.mjs [origin]`), and then also allows `http://localhost`.

### A company

A company answers the same questions without voice and goes to a registry like a person. It gets a code of the same
form (`TOG-CODE.md` §5), pending until it proves its domain: the registry gives it the `/.well-known/tog.json` to
place at `https://<domain>`, naming the registry's record for the code, read without redirects. Lookup says
`holder: "company"`. A company's card cites ToG-L 1.0 like a person's (founder decision 2026-11-13). When the file later
stops naming the record, the company gets a notice and 30 days of grace, then
its code answers `pending` until the file is back; the home re-checks at most daily (`extensions/lookup.md`;
`DOMAIN_GRACE` and `DOMAIN_RECHECK` in the reference registry, founder decision 2026-11-12).

# Part B — reference presentation (recommended, free to restyle)

The screens of `pregen.org/tog/create` (`tog.js`, styled by `styles.css`): one question per screen, each with a Back, a step
count and an error message that says what to do; real radio buttons and checkboxes; the statement shown as it will
stand on the holder's own page. A registry may translate, restyle or merge screens, as long as Part A holds.

1. **What do you need ToG for?** My likeness (a person) · My company's brand or products · My AI service · A registry.
   An AI service needs no code and goes to `/connect`; a registry is listed, not registered, and goes to
   `/create-registry`. Nothing is asked of either.
2. **Where will you use your ToG?** On my website · On a public profile or account · Only the code. This chooses only
   which form of the result is shown first (below); every form stays available.
3. **Date of birth** (a person): day, month, year. It only decides 18 or over; it stays in the browser and is never
   sent, encoded or stored. **Under 18:** the person cannot make a statement alone; their parent or legal guardian may
   make one for them, and the only statement is No (`{"who": "child", "decision": "no"}`). There is no "my child"
   choice before the date.
4. **May AI generate your likeness?** (a company: its marks, products or characters) No · Yes, with my approval of
   each output · Yes, within terms I set. A Yes is recorded now and takes effect only after identity verification.
5. On a Yes: **purposes** (at least one), **excluded categories** (the usual ones preselected; political content and
   sexual or adult content always excluded), and for a person **voice**, **commercial fees** (when commercial work is
   allowed) and **additional conditions** in their own words.
6. **Check your statement:** every answer with a Change link, the statement as it will read (without the code), and
   the home registry step (below).
7. **The registry issues the code.** It opens in a new tab with the answers in the fragment. The person comes back
   with the code: typed into `/tog/create` today, or by the registry's return (below).
8. **The ToG statement**, in three forms of one text, with the code's live status from `/api/lookup`.

The list of registries is headed "Available registries", one row per registry: its name, its website, its prefix and
an example code of its form (an example serial, 900000000 and up, never issued), and a button "Register with <name>".
