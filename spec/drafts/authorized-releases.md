# Proposed: Authorized Releases

**Draft for discussion — informative, not part of PRE-GEN v5.** Nothing here changes what an
implementation must do. Feedback: https://github.com/Pastheroza/PRE-GEN-site/issues

## The idea

A person may permit their voice or likeness not only in one generation but in a work that is
published and earns money: an AI-made track released on a streaming service, a film, a game.
The order stays the order of the core: **permission first, then generation, then publication
with proof.** A share of income is never assigned one-sidedly to someone who did not agree; it
exists only where the person or their agency set those terms in advance. Platforms already
refuse recognisable voice clones published without the artist's permission, even without the
artist's name ([Spotify](https://support.spotify.com/us/artists/article/music-that-impersonates-another-artists-voice/)).

## Most of it exists in v5

| Step | Already in PRE-GEN |
|---|---|
| The artist permits their voice for released music | A signed grant (`grants`): purposes, territory, time, limits |
| A creator makes a track, possibly with several voices | The core request and answer, one per subject (`jobs`), for a connected creator (`licensee`) |
| The track carries its stamp | The proof bundle (`proof`) in a C2PA manifest or a watermark, with soft bindings for re-encoded audio |
| A distributor or platform checks it | `checkProof` / `check_proof` in both libraries |
| Use is recorded and billed | Signed reports and acknowledgements (`reports`); the registry's statement (`catalog`) |

## What a release would add

Three small additions that only add:

1. **A shared vocabulary of media in `use`** — for example advertising, film, television, social
   media, video games, audio — so a grant for released music means the same in every registry.
2. **`terms_ref` in a grant** — the hash of the terms the parties agreed (shares, what they are
   counted from, accounting). PRE-GEN carries the reference; it never computes or sends payments.
3. **A publication link in a report** — where the output was released (an ISRC for a recording,
   a URL), signed by the provider, so a release can be traced to the permission behind it.

## Boundaries

PRE-GEN answers one question: did the person permit this use of their likeness or voice. The
composition, the lyrics, the sound recording and any samples are separate rights; a future
profile for works may cover them. A release card that brings them together, and the flow of
money through distributors, belong to registries and distributors, not to the protocol.
Registering a release does not create copyright in AI-generated material. A proof helps a
platform decide; it does not guarantee that a release is accepted.

## Stamping content that already exists

A creator may bring an AI-made track or video made earlier, with no other person in it — their
own voice, their own generator — and stamp it with a PG code.

- **The code.** The work receives an ordinary subject code. It stays the same for the work;
  each version of the file is registered under it. The PG code format does not change: what
  kind of subject a code names lives in the registry's record and the profile, never in the
  code (`PG-CODE.md` §1, §8).
- **What is registered.** Only the file's SHA-256 and size; the audio can stay on the creator's
  device. Each version records the fingerprint, the time of registration (set by the registry),
  the creator's own statement of how it was made, and, if given, the creation date the creator
  states, marked as theirs.
- **Versions.** A registered version never changes. A corrected statement or a new file becomes
  the next version, linked to the one before. Later evidence — a connected generator confirming
  the generation, documents checked — is added as separate events, never by rewriting the
  statement. Each fact is shown with its source: *claimed by the creator*, *confirmed by the
  generator*, or *documents checked*.
- **The signed record.** The registry signs the record of each version: work, version,
  fingerprint, statement and time of registration. A verifier takes the registry's key from its
  published key set and the directory, never from the record itself, and compares a file with
  the fingerprint of one named version. A re-encoded file has a different fingerprint: a
  mismatch, not evidence of forgery.
- **Not a PRE-GEN proof.** The record shows a claim and when it was made, not that a generation
  was permitted in advance. No flag marks a stamp as "after creation": a late registration is
  compatible with a permission given earlier, so the record shows its dates and their sources.
- **Not ownership.** Registering first fixes the claim first and never decides ownership —
  otherwise whoever downloaded an unreleased track could register it. A registration never makes
  the registrant the author, and never confirms that a work infringes no one's rights.
- **Privacy.** The record is private until its owner opens it; a withdrawn page cannot recall
  copies already downloaded.
- **Dates that hold against the registry.** The record's audit event is anchored outside the
  registry. A verifier sees which state applies: signed by the registry, submitted for external
  timestamping, or external confirmation verified.

## Next step

First a creator's own release, with no other party; then a pilot on v5 as it stands — one
consenting artist, one original track, one distributor — with the release use recorded as a
registry's own value in the grant. The three additions are proposed for a later version only if
the pilot shows that registries and distributors need them.
