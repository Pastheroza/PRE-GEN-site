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
3. the person looks at the file and approves it themself; an agency acting for them may only
   turn it down, and the person's own later decision overrides that;
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
          "basis": {"kind": "licence",
                    "licence": {"format": "pg.grant.v1", "id": "<message id of the grant>"},
                    "use": {"n": 3, "of": 10}},
          "scope": {"purposes": ["commercial"], "categories": ["advertising"],
                    "territories": ["ES", "IT"], "channels": ["online-video", "social"],
                    "project": "Spring campaign 2027", "not_after": 1830000000},
          "approval": {"assent": "registry", "instruction": "<sha-256 of the instruction's evidence>",
                       "factor": "authenticator"},
          "issued_at": 1794200000,
          "nonce": "<32 lowercase hex>"},
 "signatures": ["<ed25519 hex>"]}
```

| Member | Rule |
|---|---|
| `kind` | `ratification`: an output a generative system produced. Other kinds are not in `after-gen/1` |
| `label`, `notice`, `not` | the exact constants above. Any other value, case or spacing is refused |
| `subject_ref` | the subject's PG code |
| `content` | the file, by its hash under a binding (below). `after-gen/1` knows `media/1` only, with `leaves` the number of leaves of its tree. One record names one file, never a class of files or future files |
| `request` | the message id of the request this record answers |
| `holder` | who may publish the file: the requester's party id. Under a licence it equals the licence's `licensee_id`, unless the licence is for any licensee (`""`) |
| `basis` | on what the approval rests, one of two kinds. `{"kind": "licence", "licence", "use"}`: a deal. `licence` is the `pg.grant.v1` the use is counted against; `use` is the licence's count of uses when this record was signed, this one included: `n` from 1, `of` the licence's `max_uses` or `null` for no limit (a use given back by an allow that was not generated lowers the count, so two records may show the same `n`). `{"kind": "terms", "terms"}`: no deal, the person's own standing terms, which allow approval after generation for this purpose; `terms` is the message id of the `pg.terms.v1` version in force. The reference registry issues only the licence kind in `after-gen/1`; verifiers accept both |
| `scope` | what the approver approved. `purposes` and `categories` in the profile's closed vocabulary (`categories` may be empty); `territories` at most 250 ISO 3166-1 alpha-2 codes or `["*"]`; `channels` at most 64 words of `[a-z0-9-]{1,32}` or `["*"]`; `project` printable text of 1–200 characters; `not_after` an integer time later than `issued_at` and, under a licence, no later than its `expires_at`. Lists are sorted, without repeats; `purposes`, `territories` and `channels` are never empty |
| `approval` | who approved, and on what basis (below) |
| `issued_at` | the registry's time when it signed |
| `nonce` | 32 lowercase hex characters (16 random bytes), chosen by the registry only so that the approval's readable code exists (see "The readable codes") |

No other member is allowed, in the body or in any object of it.

### Who approved: `approval`

The approval is an act that opens: after it, a publication is permitted that was not
permitted before. So it is only ever the subject's own act, in one of two forms:

| `assent` | Who | Members, exactly these |
|---|---|---|
| `self` | the subject, with their own key (`custody: self` in the subject record) | `assent`, `decision`: the message id of the `pg.after_gen_decision.v1` the subject signed |
| `registry` | the subject, by an authenticated instruction at their registry | `assent`, `instruction`: the SHA-256 of the instruction's evidence, `factor`: `authenticator` or `email`, the second factor the registry confirmed before signing |

The instruction is the person's own, given at their registry and confirmed with their second
factor, never an agency's. Never the holder, the requester, a provider, a platform, another
registry, or a representative under any mandate: a mandate never carries the power to approve.
`self` never names a factor; `registry` always does. `assent` is one of the two words, never a
list or any other type. A record that names any other form is refused.

A verifier shows the approval as it is: "approved by the person" or "approved on the person's
own instruction at the registry".

### The decision — `pg.after_gen_decision.v1`

Signed by the subject's own key (`role: subject`), or by a representative's key from its own
domain (`role: agent`) for a refusal only: `{signers, request, outcome, scope, issued_at}`,
where `outcome` is `approve` (the subject only) or `refuse`, and `scope` (for `approve` only) is the scope approved, never wider than
the request's: the same `project`; purposes, categories, territories and channels a subset
(`["*"]` covers any list); `not_after` no later. A decision names exactly one request, and is
refused more than five minutes off the registry's clock.

### The mandate — `pg.mandate.v1`

Signed by the subject's key, or by the registry on the subject's instruction with a second
factor (`assent`, `instruction`, `factor` as above): `{signers, subject_ref, agent, powers,
limits, not_after, assent, …, issued_at}`. The power `after_gen` lets the representative
**refuse** a request the subject has not yet decided, and nothing more: no mandate carries the
power to approve a file. A refusal by a representative is labelled as the agency's, closes
nothing for the subject, and is overridden by the subject's own later decision within the
review period. Ending a mandate closes, and needs no second factor.

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

**What keeps the hash, and what changes it.** Inserting, removing or rewriting a carrier
keeps the hash: the XMP box is appended at the end of the file, and a C2PA tool that inserts its
box before the movie rewrites the chunk offsets, which are hashed by position within `mdat`. An
existing XMP box is rewritten in place when it is the last box or the new packet fits in it,
padded with spaces as XMP allows; otherwise embedding is refused. Any other change changes it: a remux, moving the movie box, a new title or chapters,
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
- **a box that is not known, or not whole** (see "Known boxes only" below);
- **carriers that are not what they claim:** an XMP box whose packet is not UTF-8 text free of
  NUL bytes, a C2PA box that does not parse as a JUMBF manifest store, more than one of either,
  or a carrier larger than 64 MiB;
- a fragmented file (`mvex` in `moov`, or a `moof` at the top level); encrypted samples (an
  `encv`, `enca` or `encs` entry, or a `sinf` in any entry); a data reference that is not in the
  same file (a `dref` entry that is not a self-contained `url ` or `urn `, or a self-contained
  `alis` with nothing after its version and flags, as Apple's writers make it); a `dinf` that
  holds anything but one `dref`; a `dref` whose entry count is not the number of entries it
  holds, or is 0; a sample entry whose data reference index names no entry;
- **a second movie anywhere:** the code `cmov` or `hoov` at any byte position of the file
  outside `mdat` data, carriers included (a player decompresses or adopts such a movie wherever
  it finds one); the sixteen-byte pattern `hdlr`, any four bytes, `mhlr`, `MPEG` anywhere in the
  file (it makes a player give up reading the file as MP4 and scan it as another format); and
  the eight bytes of NUT's main startcode `4E 4D 7A 56 1F 5F 04 AD` anywhere in the file (a
  player's NUT probe then ties with its MP4 probe and the file opens as neither);
- **tables outside their place:** any of the codes `stco`, `co64`, `stsc`, `stsz`, `stz2`,
  `stts`, `ctts`, `iloc`, `saio`, `saiz`, `sidx`, `ssix`, `tfra`, `mfra`, `trun`, `tfhd` found
  at any byte position of a top-level box other than `mdat` and the carriers, except as a
  sample table (`stts`, `ctts`, `stsc`, `stsz`, `stz2`, `stco`, `co64`) that is a direct child
  of an `stbl` on the path `moov`/`trak`/`mdia`/`minf`/`stbl`, whose payload is not searched,
  and metadata text that players read as text, not as boxes: the payload of a `data` box inside
  an `ilst`, of a `udta` child whose type begins with the byte `A9` (©), and of a `udta` `XMP_`
  box. Everything else is searched, the sample descriptions in `stsd` included, since a player
  reads boxes appended to a sample entry;
- **tables that read two ways:** an `stbl` without exactly one `stsd`, one `stts`, one `stsc`,
  one of `stsz` and `stz2` and one of `stco` and `co64`, or with more than one `ctts`; an
  `stsc` whose first entry's first chunk is not 1, whose first chunks do not strictly increase
  or exceed the number of chunks, with a count of 0, or with a sample description index that
  names no entry; a sample count from `stsc` over all chunks, or from `stts`, that differs from
  the count of `stsz`/`stz2`; a table whose length is not exactly what its count gives;
- **chunks outside `mdat`:** a chunk offset that does not fall inside the data of a top-level
  `mdat`, or a chunk whose samples run past the end of that data;
- **sound read by chunk:** a track whose `stts` durations are all 1, unless the handler types found
  wherever the code `hdlr` occurs in its `trak` (a player acts on a `hdlr` anywhere in a track;
  the handler type is the four bytes twelve bytes after the code), leaving out data and
  metadata handlers (`url `, `urn `, `alis`, `mdir`, `mdta`, `ID32`, `mp7t`, `mp7b`), are at
  least one and all `vide`: a player may take any
  other track's sample entry as audio, whatever its first handler says, and then reads its
  chunks by the sample entry, not by `stsz`. Such a track is refused unless its `stsz` gives one fixed size
  equal to the frame size players take from the entry: for a version 1 entry, its bytes per frame
  (with samples per packet 1); for a version 2 entry, its bytes per packet (with frames per
  packet 1); for a version 0 entry, the entry's channel count times the codec's bytes per
  sample: `raw `, `ulaw`, `alaw` 1, `twos` and `sowt` the entry's sample size ÷ 8, `in24` 3,
  `in32` and `fl32` 4, `fl64` 8; for `ipcm` and `fpcm`, the sample size its `pcmC` box states ÷ 8.
  Any other entry in chunk mode is refused, and so is a version 1 or 2 entry whose fields
  disagree with that codec width where the codec has one.

**Known boxes only.** A player reads a box by its type wherever it meets one, and reads the
fields of a box even past the box's end when the box is shorter than they are or its count
says more entries than it holds; the bytes it then reads may be a carrier's. So inside `moov`
a verifier accepts only the boxes below, only where they are listed, and only whole: each one
exactly as long as its fields, its version and its counts make it, and each container exactly
filled by its children. Anything else inside `moov` refuses the file. `free` and `skip` are
accepted in every container below.
- `moov`: `mvhd`, `trak`, `udta`, `meta`, `iods`.
- `trak`: `tkhd`, `edts`, `tref`, `mdia`, `udta`, `meta`, `tapt`. `edts`: `elst`. `tref`:
  reference types from a closed list (such as `chap`, `tmcd`, `hint`, `cdsc`, `auxl`, `sync`),
  each holding a whole number of track ids. `tapt`: `clef`, `prof`, `enof`.
- `mdia`: `mdhd`, `hdlr` (exactly one, before `minf`, since a player reads the sample entries
  by the handler it has seen), `minf`, `elng`, `udta`. `minf`: one media header (`vmhd`,
  `smhd`, `sthd`, `hmhd`, `nmhd`, `gmhd`), `hdlr` (a data handler: `url `, `urn ` or `alis`),
  `dinf`, `stbl`. `gmhd`: `gmin`, `text`, `tmcd` (holding `tcmi`).
- `stbl`: `stsd`, `stts`, `ctts`, `stsc`, `stsz` or `stz2`, `stco` or `co64`, `stss`, `stps`,
  `sdtp`, `sgpd` (version 1 or 2), `sbgp`, `cslg`, `subs`. `stsd` is version 0 and holds one
  kind of entry. An entry's kind follows the track's handler (`vide` visual, `soun` sound),
  otherwise its code from closed lists of visual, sound, timecode and text codes; an entry of
  no known kind refuses the file, since a player may read it as video and read its fixed
  fields past a short entry. A visual entry whose palette a player would read from the file is
  refused. Each sample entry is its fixed fields (visual 78 bytes, sound 28, 44 or 64 by
  version, `tmcd` 26, `tx3g` and `text` 38) followed by whole boxes of these types: `avcC`,
  `hvcC`, `av1C`, `vpcC`, `esds` (its descriptors inside it, as players read them), `dOps`,
  `dfLa`, `alac`, `dac3`, `dec3`, `pcmC`, `colr` (`nclx`, `nclc` or `prof`), `pasp`, `clap`,
  `btrt`, `fiel`, `gama`, `chrm`, `chan`, `wave` (holding `frma`, `enda`, `mp4a`, `esds`,
  `alac`, `chan`, `dac3`, `dec3` and a terminator), `mdcv`, `clli`, `st3d`, `sv3d` (holding `svhd` and
  `proj`), `dvcC`, `dvvC`, `glbl`, `tcmi`, `ftab`, `name`, and the 20-byte iPod `uuid`; then,
  as Apple's writers end it, optionally four zero bytes (`tmcd`: two).
- `udta` (in any of the places above): `meta`, `XMP_`, `chpl`, `name`, `loci`, `Xtra`, and
  text atoms whose type begins with the byte `A9` (©), each made of (length, language, text)
  records that fill it exactly. `meta` (in its ISO or QuickTime form): `hdlr` whose handler
  type is `mdir`, `mdta` or `ID32`, `keys`, `ilst`, `xml `. `ilst`: items whose type is an
  `mdta` key index, begins with the byte `A9` (©), is `----` or comes from a closed list of
  iTunes atoms, each holding only `data`, `mean` and `name` boxes; a `data` box holds at least
  the value a player reads from it (4 bytes for `trkn`, `disk`, `tves`, `tvsn`; 2 for `gnre`; 1
  for `stik`, `rtng`, `cpil`, `pgap`, `hdvd`, `pcst`, `akID`, `egid`).
- At most one box of a type in a container, except `trak`, `ilst` items and their children,
  one `sgpd` and one `sbgp` per grouping type, `free` and `skip`. Required: `mvhd`; `tkhd`
  and `mdia`; `mdhd`, `hdlr` and `minf`; `dinf` and `stbl`; `elst` in `edts`.

The libraries list the exact layout of each box beside their code.
A file that holds a box outside this list, such as one a newer tool writes, is remuxed by a
tool that keeps only these before it is approved; a later version of `media/1` may list more.

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
  (the status address) are copies for people and tools, never read as the record. `pgag:Code`
  and `pgag:Licence` are the readable codes (see "The readable codes" below); unlike the other
  copies they are checked. An existing XMP
  box keeps its properties and is rewritten in place (see "What keeps the hash"). So that every reader finds the same record, the packet
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

### The readable codes

Beside the record a file may carry two ToG codes a person can read and type: the code of this
approval and, when its basis is a licence, the licence's code. They follow the ToG code design
(its grammar, the TOG check table in which I, L, O and U take 32 to 35, and the five event
kinds). In `after-gen/1` a record is signed by the person's own registry alone (no home
countersignature), so each code has one prefix:
- **The approval:** `TOG-AG-<prefix>-XXXX-XXXX-XXXX` under the person's terms,
  `TOG-AG-LIC-<prefix>-XXXX-XXXX-XXXX` under a licence. `<prefix>` is the registry prefix of
  `subject_ref` (`PRAM` for a code of the bare namespace, which is PRAMPTA's). The eleven tail symbols are the first 55 bits of the record's message id in
  Crockford base32, most significant first. The last symbol is the check over the body: the
  prefix's length, `0`, the kind digit (`AG` 3, `AG-LIC` 4), the prefix, the tail.
- **The licence:** `TOG-LIC-<prefix>-XXXX-XXXX-XXXX`, the same construction over the message id
  of the `pg.grant.v1` that `basis.licence` names, with kind digit 5.

A registry never signs a record whose code would not exist: when the check would be one of
`* ~ $ = !`, or the tail would begin `ZZZZ` (kept for examples), it signs again with a new nonce.

**Copies, never authority.** In XMP they are `pgag:Code` and `pgag:Licence`, each at most once,
read by the same lexical rule as `pgag:Record`. A verifier recomputes both from the signed
record and refuses the file when a copy differs from what it computes, when `pgag:Licence` is
present under a terms basis, or when a copy is present whose code cannot be formed. A missing copy is not
a refusal: the record is enough. Like the record, the copies lie outside `media/1`.

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
3. **The person decides,** after viewing the file: approve as asked, approve a narrower
   scope, or refuse. An agency with the person's mandate may refuse a request the person has
   not decided; the refusal is labelled as the agency's, and the person may still approve it
   within the review period. Silence approves nothing: a request undecided within the review period
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
   T, withdrawn at W". An approval is final for what it covered; a withdrawal only stops what
   comes next. Under a licence, new uses stop, and what was already published stays a matter of
   the licence between the parties. Under the person's terms, the file is no longer approved for
   anyone new. A registry that stops taking new requests keeps answering status,
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
| `basis` | the requester names the licence, or the registry the terms version in force | the registry's signature and its count; the terms record's own signature | a holder exceeding the number of uses, or claiming terms that do not allow it | counted once per record, at signing, against the licence; the terms version is checked as of signing |
| `scope` | the requester asks; the approver approves | the approver's act; the registry checks it against the licence and the floor | a holder wanting a wider scope | only within the licence; never wider than asked |
| `scope.categories` | the requester declares | no one, until a finding | a holder hiding an intimate category | the approver sees the file; an intimate category is refused even if declared; a false declaration stays the requester's statement on record |
| `approval` | the subject alone | the subject's key; or the registry, on the subject's own instruction, with a second factor | someone acting in the subject's name, an agency included | two named forms only, and the record says which; no mandate approves |
| `nonce` | the registry, at random | no one: it carries no meaning | — | it only makes the approval's readable code exist; `issued_at` stays the registry's clock |
| `issued_at` | the registry | the registry | a holder wanting the record to look earlier | the record is after the content by definition; an earlier date gains nothing it does not already state |
| status `state` | the registry | the registry's signature, five-minute life | a holder hiding a withdrawal | a status is fetched live; an old one expires |

## Must-reject vectors

A registry refuses to sign, and a verifier refuses to accept, each of these. Each has a test in
the reference registry or in both libraries.

**Laundering**
1. A record without an approval: from silence, an expired review period, or the request itself.
2. An approval by the holder, the requester, a provider, a platform or another registry.
3. An approval by a representative, under any mandate; and a refusal by a representative
   whose mandate does not list `after_gen`, has ended or expired, or is for another subject.
4. An approval on instruction that names no second factor; `self` that names one; `self` for a
   subject whose key the registry holds.
5. A decision signed by a key that is not the subject's (to approve) or a mandated
   representative's (to refuse), or that names another request.

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
