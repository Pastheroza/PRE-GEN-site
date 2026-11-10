# Draft: AFTER-GEN — the rights holder approves a file that already exists

**Working draft, not part of PRE-GEN.** Nothing here changes what an implementation of the
standard must do. Version `after-gen/1`.

## The problem it solves

Most AI video for advertising is made today without asking anyone first, and the rights in
it are sold on paper. The paper stays in an inbox. The video travels without it, and whoever
publishes the video, who is the one the law asks, cannot see who approved what.

AFTER-GEN fixes that without any change at the AI provider:
1. a production makes the video with any tool;
2. it asks the rights holder's registry to approve **that exact file**, under a licence the
   registry already holds;
3. the rights holder, or a representative whose power to do this is written in the mandate
   the person signed, looks at the file and approves it;
4. the registry signs a record that names the file by its hash, and the record goes into the
   file's metadata;
5. anyone holding the file checks it in a browser: whose likeness, which licence, which terms,
   who approved and on what basis, and whether it still stands today.

## What a record never says

Every record carries these three statements as fixed constants, and every verifier shows them
wherever it shows the record:
- **it was made after the content existed;**
- **it is not a PRE-GEN permission given before generation,** and no registry, gate or
  verifier accepts it where an answer is required;
- **it says nothing about whether the content is AI-generated or real.** No record has a
  member that states origin.

A record permits the publication of one existing file within its scope. It never permits a
new generation.

## The record — `pg.after_gen.v1`

Signed by the registry alone. Its id is its message id (`PRE-GEN-CORE.md`, Messages).

```json
{"type": "pg.after_gen.v1",
 "body": {"signers": [{"role": "registry", "key_id": "pg-ed25519:…"}],
          "kind": "ratification",
          "label": "approved after generation",
          "notice": "Recorded after the content existed. Not a PRE-GEN permission given before generation. Says nothing about whether the content is AI-generated.",
          "not": ["pre_generation_permission", "statement_of_origin"],
          "subject_ref": "PG-TEST-000001N",
          "content": {"binding": "media/1", "hash": "<64 hex>", "leaves": 1843},
          "request": "<message id of the pg.after_gen_request.v1>",
          "holder": "https://studio.example",
          "licence": {"format": "pg.grant.v1", "id": "<message id of the grant>"},
          "use": {"n": 3, "of": 10},
          "scope": {"purposes": ["commercial"], "categories": ["advertising"],
                    "territories": ["ES", "IT"], "channels": ["online-video", "social"],
                    "project": "Spring campaign 2027", "not_after": 1830000000},
          "approval": {"assent": "agent", "agent": "https://agency.example",
                       "mandate": "<message id of the pg.mandate.v1>",
                       "decision": "<message id of the pg.after_gen_decision.v1>",
                       "factor": "signature"},
          "issued_at": 1794200000},
 "signatures": ["<ed25519 hex>"]}
```

| Member | Rule |
|---|---|
| `kind` | `ratification`: an output a generative system produced. Other kinds are not in `after-gen/1` |
| `label`, `notice`, `not` | the exact constants above. Any other value, case or spacing is refused |
| `subject_ref` | the subject's PG code |
| `content` | the file, by its hash under a binding (below). `after-gen/1` knows `media/1` only, with `leaves` the number of leaves of its tree. One record names one file, never a class of files or future files |
| `request` | the message id of the request this record answers |
| `holder` | who may publish the file: the requester's party id. It equals the licence's `licensee_id`, unless the licence is for any licensee (`""`) |
| `licence` | the `pg.grant.v1` the use is counted against |
| `use` | the licence's count of uses when this record was signed, this one included: `n` from 1; `of` the licence's `max_uses`, or `null` for no limit. A use given back by an allow that was not generated lowers the count, so two records may show the same `n` |
| `scope` | what the approver approved. `purposes` and `categories` in the profile's closed vocabulary (`categories` may be empty); `territories` at most 250 ISO 3166-1 alpha-2 codes or `["*"]`; `channels` at most 64 words of `[a-z0-9-]{1,32}` or `["*"]`; `project` printable text of 1–200 characters; `not_after` an integer time later than `issued_at` and no later than the licence's `expires_at`. Lists are sorted, without repeats; `purposes`, `territories` and `channels` are never empty |
| `approval` | who approved, and on what basis (below) |
| `issued_at` | the registry's time when it signed |

No other member is allowed, in the body or in any object of it.

### Who approved: `approval`

The approval is an act that opens: after it, a publication is permitted that was not
permitted before. So it is the subject's own act, in one of three forms, and nobody else's:

| `assent` | Who | Members, exactly these |
|---|---|---|
| `self` | the subject, with their own key (`custody: self` in the subject record) | `assent`, `decision`: the message id of the `pg.after_gen_decision.v1` the subject signed |
| `registry` | the subject, by an authenticated instruction at their registry | `assent`, `instruction`: the SHA-256 of the instruction's evidence, `factor`: `authenticator` or `email`, the second factor the registry confirmed before signing |
| `agent` | a representative under a mandate the subject signed that lists the power `after_gen` | `assent`, `agent`: the representative's party id, `mandate`: the mandate's message id, `decision`: the message id of the decision the representative signed with a key from its own domain, `factor`: `signature` |

Never the holder, the requester, a provider, a platform, another registry, or a
representative whose mandate does not list the power. `self` never names a factor;
`registry` always does. A representative is never the holder of the same record: their hosts
differ, whatever the port. `assent` is one of the three words, never a list or any other type.

A verifier shows the approval as it is: "approved by the person", "approved on the person's
instruction at the registry" or "approved by `agency.example` under mandate `…`".

### The decision — `pg.after_gen_decision.v1`

Signed by the subject's own key (`role: subject`) or by the representative's key from its own
domain (`role: agent`): `{signers, request, outcome, scope, issued_at}`, where `outcome` is
`approve` or `refuse` and `scope` (for `approve` only) is the scope approved, never wider than
the request's: the same `project`; purposes, categories, territories and channels a subset
(`["*"]` covers any list); `not_after` no later. A decision names exactly one request, and is
refused more than five minutes off the registry's clock.

### The mandate — `pg.mandate.v1`

Signed by the subject's key, or by the registry on the subject's instruction with a second
factor (`assent`, `instruction`, `factor` as above): `{signers, subject_ref, agent, powers,
limits, not_after, assent, …, issued_at}`. `powers` lists `after_gen` for this use;
`limits.purposes` bounds what the representative may approve. Ending a mandate closes, and needs
no second factor. A mandate that does not list `after_gen` gives no power to approve a file.

## Which bytes the hash covers: `media/1`

Putting a record into a file changes the file's bytes, so a plain hash of the file could not
both be in the record and stay true. `media/1` hashes **every byte of the file a player could
read**, and leaves out only the record's two carriers. Two files with one `media/1` hash
therefore hold the same boxes with the same contents everywhere but in those two boxes (a box's
size field may be written in its short or long form, and chunk offsets may shift with a
carrier), and the rules below make sure no player reads media from the carriers or reads the
file as anything but MP4; they play the same. (A player may show the XMP box's other
properties, such as a title, as metadata: those are not covered, and a verifier shows only the
record.) `after-gen/1`
defines `media/1` for ISO base media files (MP4, MOV, M4V).

An earlier design hashed only the coded samples and the parameters thought to matter, so that
remuxing would keep the hash. Review showed that players act on many more fields than any such
list names (durations, the file type, the order of tracks, a track's language, how uncompressed
audio is chunked), so a file could play differently under the same hash. `media/1` gives up
that convenience for that guarantee.

**Elements.** An element is written as a four-byte ASCII code, its value's length as an
unsigned 64-bit big-endian integer, then its value. An integer value is eight bytes,
big-endian, two's complement. A value made of elements is those elements joined.

**The stream.** The ASCII bytes `PREGEN-MEDIA`, `0x00`, `media/1`, `0x00`, then one element
for each top-level box in file order, leaving out only the two carrier boxes (the C2PA and
XMP `uuid` boxes of "Carrying the record"); padding (`free`, `skip`, `wide`) is hashed like
any other box. A box's element has the box's
type as its code. Its value is the box's bytes after its size and type fields (after the
64-bit size too, where it has one; a `uuid` box's value begins with its 16-byte user type),
except for `moov`, `trak`, `mdia`, `minf` and `stbl` on the path `moov`/`trak`/`mdia`/`minf`/
`stbl`, whose value is the elements of their children, built by the same rule; and except for
`stco` and `co64` inside such an `stbl`, whose value is version and flags (4 bytes), the entry
count as an integer, and, for each chunk offset, two integers: the position (from 0) of the
top-level `mdat` box whose data holds the offset, and the offset counted from the first byte
of that box's data. Everything else, `mdat` data included, is hashed as the file holds it.

**The tree.** The stream is cut into pieces of 1 048 576 bytes, the last one shorter (at least
one piece). The hash is the root of an RFC 6962 Merkle tree over the pieces (leaf hash
`SHA-256(0x00 ‖ piece)`, node `SHA-256(0x01 ‖ left ‖ right)`, split at the largest power of
two smaller than the count), as 64 lowercase hex characters; `leaves` is the number of pieces.
A verifier never needs the whole file in memory.

**What keeps the hash, and what changes it.** Appending, removing or rewriting the XMP box,
inserting or removing the C2PA box (a C2PA tool rewrites the chunk offsets when it inserts its
box before the movie, and the offsets are hashed by position within `mdat`) keep the hash. An
existing XMP box is rewritten in place when it is the last box or the new packet fits in it,
padded with spaces as XMP allows; otherwise embedding is refused, since turning it into padding
would change the hash. Any other change changes it: a remux, moving the movie box, a new title or chapters,
a tool's own tag in `udta`, new creation times. So a production asks for approval of the file
it will publish, after its last remux and metadata edit, and adds only the record afterwards.

**One reading only.** Every byte is hashed, so two files with one hash differ only inside the
carriers. What remains is to make sure that every player finds its samples where `media/1`
does, so that no player reads media from a carrier. A verifier therefore refuses `media/1`, and
says why, for:
- a file whose first box is not `ftyp`, or whose `ftyp` major brand is `jp2 `, `jpx ` or `jxl `
  (a player's MP4 probe then scores the file low and may read it as another format), with no
  `moov` or more than one; a box whose size runs
  past its parent, or that is shorter than its own header (a `uuid` box under 24 bytes); a value
  that does not fit a signed 64-bit integer;
- **carriers that are not what they claim:** an XMP box whose packet is not UTF-8 text free of
  NUL bytes, a C2PA box that does not parse as a JUMBF manifest store, more than one of either,
  or a carrier larger than 64 MiB;
- a fragmented file (`mvex` in `moov`, or a `moof` at the top level); encrypted samples (an
  `encv`, `enca` or `encs` entry, or a `sinf` in any entry); a data reference that is not in the same file (a `dref` entry that is not a
  self-contained `url ` or `urn `);
- **a second movie anywhere:** the code `cmov` or `hoov` at any byte position of the file
  outside `mdat` data, carriers included (a player decompresses or adopts such a movie wherever
  it finds one); the sixteen-byte pattern `hdlr`, any four bytes, `mhlr`, `MPEG` anywhere in the
  file (it makes a player give up reading the file as MP4 and scan it as another format); and
  the eight bytes of NUT's main startcode `4E 4D 7A 56 1F 5F 04 AD` anywhere in the file (a
  player's NUT probe then ties with its MP4 probe and the file opens as neither);
- **tables outside their place:** any of the codes `stco`, `co64`, `stsc`, `stsz`, `stz2`,
  `stts`, `ctts`, `iloc`, `saio`, `saiz`, `sidx`, `ssix`, `tfra`, `mfra`, `trun`, `tfhd` found
  at any byte position of a top-level box other than `mdat` and the carriers, except as a
  direct child of an `stbl` on the path `moov`/`trak`/`mdia`/`minf`/`stbl` (the payloads of the
  boxes there are not searched; a text in metadata that spells such a code makes the file
  refused);
- **tables that read two ways:** an `stbl` without exactly one `stsd`, one `stts`, one `stsc`,
  one of `stsz` and `stz2` and one of `stco` and `co64`, or with more than one `ctts`; an
  `stsc` whose first entry's first chunk is not 1, whose first chunks do not strictly increase
  or exceed the number of chunks, with a count of 0, or with a sample description index that
  names no entry; a sample count from `stsc` over all chunks, or from `stts`, that differs from
  the count of `stsz`/`stz2`; a table whose length is not exactly what its count gives;
- **chunks outside `mdat`:** a chunk offset that does not fall inside the data of a top-level
  `mdat`, or a chunk whose samples run past the end of that data;
- **sound read by chunk:** a track whose `stts` durations are all 1, unless its `trak` has at least
  one `hdlr` (in `mdia` or in `minf`) and every one has the handler type `vide`: a player may take any
  other track's sample entry as audio, whatever its first handler says, and then reads its
  chunks by the sample entry, not by `stsz`. Such a track is refused unless its `stsz` gives one fixed size
  equal to the frame size players take from the entry: for a version 1 entry, its bytes per frame
  (with samples per packet 1); for a version 2 entry, its bytes per packet (with frames per
  packet 1); for a version 0 entry, the entry's channel count times the codec's bytes per
  sample: `raw `, `ulaw`, `alaw` 1, `twos` and `sowt` the entry's sample size ÷ 8, `in24` 3,
  `in32` and `fl32` 4, `fl64` 8; for `ipcm` and `fpcm`, the sample size its `pcmC` box states ÷ 8.
  Any other entry in chunk mode is refused, and so is a version 1 or 2 entry whose fields
  disagree with that codec width where the codec has one.

**Re-encoded copies.** A transcoded copy has other coded samples and does not match. A later
version may carry soft bindings (C2PA soft-binding algorithm names with opaque values) for a
registry to look up; `after-gen/1` computes and compares none, and a match by a fingerprint is
never proof that two files are the same.

## Carrying the record

The record is the same whatever carries it, and a verifier checks it the same way.
- **In a C2PA manifest:** an assertion labelled `org.pregen.after_gen` whose data is the
  envelope, stored as JSON (its bytes exactly the canonical JSON of the envelope) or CBOR
  (integers within ±2^53−1; no floats, tags, byte strings or indefinite lengths). The production adds it with its own C2PA tool and its own
  signing certificate, as it adds any assertion; the libraries return the assertion to add.
  PRE-GEN issues no C2PA certificate. A reader takes the assertion from the active (last)
  manifest of the store. Every superbox of the store must be well-formed; the active manifest
  holds at most one such assertion, and the assertion holds exactly one content box and no
  nested superbox.
- **In XMP:** in an MP4 file, a top-level `uuid` box with the XMP identifier
  `BE7ACFCB-97A9-42E8-9C71-999491E3AFAC`, appended at the end of the file so that no offset
  moves. Namespace `https://pregen.org/ns/after-gen/1/`, prefix `pgag`: `pgag:Record` holds the
  envelope as canonical JSON text; `pgag:Id`, `pgag:Registry` (the prefix) and `pgag:Status`
  (the status address) are copies for people and tools, never read as the record. An existing XMP
  box keeps its properties and is rewritten in place: when it is the last box of the file it
  may grow; elsewhere the new packet must fit in it, padded with spaces, or embedding is
  refused (see "What keeps the hash"). So that every reader finds the same record, the packet
  is read by a fixed lexical rule, not by an XML library: it holds no `<!--`, `<![CDATA[`,
  `<!DOCTYPE` or `<!ENTITY`, and no `<?` other than the packet's opening `<?xpacket begin=`
  and closing `<?xpacket end=`; the namespace `https://pregen.org/ns/after-gen/1/` appears
  exactly once in the packet, in the declaration
  `xmlns:pgag="https://pregen.org/ns/after-gen/1/"`, and no other `xmlns:pgag=` appears; `<pgag:Record>` appears exactly once and
  `pgag:Record=` never; its text runs to the first `</pgag:Record>`, holds no `<`, and uses no
  `&` other than `&amp;`, `&lt;`, `&gt;`, `&quot;` and `&apos;`. Unescaped, it is the canonical
  JSON of the envelope. A packet that breaks the rule carries no record; one that cannot keep
  its existing properties under it is refused when embedding.
- **Held apart:** the registry keeps every record it signed and answers by hash, so a file
  whose metadata was stripped still leads to its record:
  `GET {api}/v2/after-gen?media=<hash>` → `{"records": ["<id>", …]}`.

A record found in a file proves nothing by being there: it is checked like any other, and a
record copied into another file names a hash that file does not have.

## The procedure

1. **The request — `pg.after_gen_request.v1`,** signed by the requester's key from its own
   domain (`role: requester`). The requester is a party known by its domain, because the
   record names it as the holder:
   `{signers, requester, subject_ref, licence, content, scope, issued_at, nonce}`. One file per
   request. `scope` is what is asked for, in the record's vocabulary. A private viewing link
   may travel **beside** the signed body (`preview_url`, `https` only): the registry gives it
   only to the approver and deletes it when the request is decided or expires, and never
   receives the file itself. A request permits nothing.
2. **Checks before the approver sees it.** The registry refuses a request whose licence is
   not for this subject or this holder, not valid now, or already used up; whose scope is wider
   than the licence (`purposes`; `categories` outside the licence's own `use.categories`, so a
   licence that names none allows only `[]`; `not_after` after `expires_at` or already past); whose categories
   name an intimate category, a word outside the closed vocabulary, or one the subject's terms
   exclude; about a subject who is a known minor, opted out, withdrawn from this holder or
   unavailable; or about a file already approved under this licence. Where the registry masks
   an unpublished subject from a party it has not vetted (`provider-identity`, P-5a), it gives
   that party the same refusal whatever the subject's state, so a request learns nothing.
3. **The approver decides,** after viewing the file: approve as asked, approve a narrower
   scope, or refuse. Silence approves nothing: a request undecided within the review period
   (the registry's policy; 14 days in the reference registry) expires.
4. **The record.** On approval the registry checks everything in step 2 again, as of now
   (a `not_after` already past is refused), counts one use of the licence, keeps the decision
   it received, and signs the record. A party that may not decide on a request learns
   nothing about it: whether it exists, its state or its scope. A refusal, a pending request and an
   expired one are never published: a lookup by hash shows only approved records, so asking
   before publishing costs the asker nothing.
5. **Withdrawal.** The subject withdraws a record with their own key, in a
   `pg.after_gen_withdrawal.v1` `{signers, record, issued_at}` (`role: subject`), or by an
   authenticated instruction at the registry, with no second factor: it closes. From then on the status says "approved at
   T, withdrawn at W". New uses stop. What was already published stays a matter of the licence
   between the parties. A registry that stops taking new requests keeps answering status,
   lookup and withdrawal for every record it signed.

## The status — `pg.after_gen_status.v1`

The record does not carry its own status address: its id is the hash of its body, so the
body cannot contain it. A verifier asks the registry the directory lists for the subject's
prefix, at `{api}/v2/after-gen/{id}`, and nowhere else.

`GET {api}/v2/after-gen/{id}` returns `{"record": <envelope>, "status": <envelope>}`. The
status is signed by the registry and lives five minutes:
`{signers, record, state, approved_at, withdrawn_at, not_after, issued_at, expires_at}` where
`state` is `active`, `withdrawn` (the subject withdrew it) or `expired` (`not_after` has
passed). `withdrawn_at` is `null` unless the state is `withdrawn`. A verifier refuses a status
for another record, one that has expired, or one not signed by a key the directory lists for
the subject's prefix.

## How a verifier checks a file

1. Compute `media/1` of the file it holds.
2. Find the record: in the file's C2PA assertion or XMP, or by asking the registry by the
   hash.
3. Check the record: its shape and constants, its signature by a registry key the directory
   lists for the subject's prefix at `issued_at` (a revoked registry's records fail), the
   approval form, and that no category is intimate or outside the closed vocabulary.
4. Compare: the record's `content.hash` must equal the file's `media/1` hash. Otherwise the
   record is not for this file.
5. Fetch and check the status.
6. Show the subject, the licence, the scope, who approved and on what basis, the status, and
   the three statements of "What a record never says".

The libraries implement step 1 as `media_hash` / `mediaHash`, step 2 as `read_after_gen` /
`readAfterGen`, steps 3–4 as `check_after_gen` / `checkAfterGen`, and step 5 as
`check_after_gen_status` / `checkAfterGenStatus`.

## Whose word stands behind each member

| Member | Who chooses | Who vouches | Who gains if it is wrong | Why that is acceptable |
|---|---|---|---|---|
| `kind`, `label`, `notice`, `not` | fixed by the type | the verifier's check of the constants | anyone wanting it read as PRE-GEN or as real | a distinct type, never accepted as an answer; constants checked |
| `content` | the requester computes it; the approver approves that file | the hash: a record moved to another file does not match | a holder wanting cover for other files | one file per record; the verifier recomputes the hash itself |
| `subject_ref` | the requester | the registry's signature | a holder naming the wrong person | the registry holds the subject and the licence for that subject |
| `holder` | the registry, from the requester's authentication | the registry | someone using another's licence | must be the licence's licensee |
| `licence`, `use` | the requester names the licence; the registry counts | the registry's signature and its count | a holder exceeding the number of uses | counted once per record, at signing, against the licence |
| `scope` | the requester asks; the approver approves | the approver's act; the registry checks it against the licence and the floor | a holder wanting a wider scope | only within the licence; never wider than asked |
| `scope.categories` | the requester declares | no one, until a finding | a holder hiding an intimate category | the approver sees the file; an intimate category is refused even if declared; a false declaration stays the requester's statement on record |
| `approval` | the subject, or a representative within its mandate | the subject's key; the registry with a second factor; the representative's key and the mandate | someone acting in the subject's name | three named forms only, and the record says which |
| `issued_at` | the registry | the registry | a holder wanting the record to look earlier | the record is after the content by definition; an earlier date gains nothing it does not already state |
| status `state` | the registry | the registry's signature, five-minute life | a holder hiding a withdrawal | a status is fetched live; an old one expires |

## Must-reject vectors

A registry refuses to sign, and a verifier refuses to accept, each of these. Each has a test in
the reference registry or in both libraries.

**Laundering**
1. A record without an approval: from silence, an expired review period, or the request itself.
2. An approval by the holder, the requester, a provider, a platform or another registry.
3. An approval by a representative whose mandate does not list `after_gen`, has ended or
   expired, is for another subject, or whose limits the scope exceeds.
4. An approval on instruction that names no second factor; `self` that names one; `self` for a
   subject whose key the registry holds.
5. A decision signed by a key that is not the subject's (for `self`) or the representative's
   (for `agent`), or that names another request.

**The file**

6. A record checked against a file whose `media/1` hash differs: "not for this file".
7. A request or record naming its file by anything but a `media/1` hash, or naming more than one.
8. A second record for a file already approved under the same licence.

**The record**

9. A record whose `label`, `notice` or `not` differ from the constants, or with any unknown
   member.
10. A record not signed by a key the directory lists for the subject's prefix, or from a
    revoked registry.
11. A record presented where an answer is required: as the basis of an allow, inside a proof
    bundle, or cited by a report.

**Floors**

12. Any record for a subject the registry knows to be a minor.
13. Any record whose categories name an intimate category (`sexual`, `adult`), or a word
    outside the closed vocabulary.
14. A record for a subject who opted out, is unavailable, or withdrew from the holder; or
    whose categories the subject's terms exclude.

**The licence**

15. A licence for another subject or another holder, not yet valid or expired, with no uses
    left, or narrower than the scope (`purposes`, `categories`, `not_after`).

**Status and privacy**

16. A status for another record, expired, or not signed by the subject's registry.
17. A lookup by hash that discloses a pending, refused or expired request.
18. A viewing link kept after the decision.

## What `after-gen/1` leaves out

- Witnessed logs and anchors: `issued_at` is the registry's word.
- Captured footage (a `release` kind) and a request to remove (`remove`).
- A fee or a share in the record: the money is in the licence.
- Several files in one request.
- `media/1` for formats other than ISO base media files. A JPEG, PNG or WebM file gets no
  record in this version.
- Computing soft bindings for transcoded copies.
- Players beyond those tested. The guarantee that one `media/1` hash means one playback was
  tested against FFmpeg 9 and Apple AVFoundation. A player that reads media from a place the
  rules above do not foresee, such as one that scans a whole file for another format's start
  codes, is outside it.
