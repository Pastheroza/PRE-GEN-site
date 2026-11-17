# ToG-L 1.1 and ToG-RS 1.1: changes against 1.0

Version 1.0 texts are unchanged, byte for byte. Statements that cite 1.0 stay valid (Licence 16(b), 2(e)).

## Size

| Text | 1.0 words | 1.1 words |
|---|---|---|
| ToG-L legal code | 12,752 | 13,003 |
| ToG-L deed | 6,100 | 5,614 |
| ToG-RS | 5,075 | 5,074 |

The Licence is 2% longer, not shorter. Three general mechanisms (Levels, Delegations, functions) cost about 900 words; compressing Section 16(g) (Appendices), 7(g), and the Authorised Person text recovered about 650. The remaining weight is three role blocks that are not about a Holder's likeness: Platforms (9(j), about 740 words), Restricted Capabilities (definitions, 9(i), Appendix F, about 800) and Registry criteria (16(f)). Moving them into their own modules would cut ToG-L by about 2,000 words. That is a founder choice (see 00-RU.md), not done here.

## The three mechanisms

1. **Level** (Section 1, 2(b), 8(j)). Ordered scale: Level 1 `channel` (control of a named account, site or domain, the Holder's own press and second factor, a Person's declared age), Level 2 `verified` (identity document or public register), Level 3 `qualified` (qualified signature or seal). A Statement may require a higher Level per purpose. A Provider relies on an answer only at or above the required Level, and has the safe harbour of 12(d)(3). The Licence fixes Levels only at the floors: 5(a) sexual or adult (Person personally, Level 2 or 3 by an official identity document), 5(d) minors (representative at Level 2). A no needs no Level (2(c)). A Level never widens Section 3.
2. **Delegation** (2(i), RS 15). Any party, written, Authenticated at a stated Level, scoped, with an end date. Scope: prepare, give Approvals, permit a class, sign Deals with named or described licensees. Revocable at any time, free, visible to the Holder first. Never reaches Section 5, the second factor, the Holder's Stop or its lifting, or another Delegation. A Provider or Platform Delegate cannot approve or permit for its own use.
3. **Function** (Licence 13(a), 13(e), 16(f); RS 1, 2, 6, 13, 15). Stop function (every Registry), Level function, Deal function. Duties are in proportion to the functions the Listing states. A Service on top of a home Registry is not a Registry and signs nothing. No Registry, Listing, policy, code, signature or Service grants, enlarges or overrides a Permission except through the Holder's own act; a Delegation is the Holder's act (Licence 2(a), 13(a); RS 2(e)).

Commercial use: Section 3 is not widened. Free advertising is `commercial` and needs a Deal with each party (6(a)(5), 8(j)). What a Holder can do: say yes to non-commercial use for everyone, and yes to commercial use only by a Deal, including a Deal at no price, with each party or each class member who accepts it under a Delegation.

## Keep / move / cut, by 1.0 section (numbering unchanged)

| 1.0 | 1.1 |
|---|---|
| 1 Definitions | Keep. Cut "Authorised Person". Add "Level", "Delegation", "Delegate", "Registry Standard". Rewritten: "Authenticated" (now by Level), "Registry" (by function), "Deal", "Statement", "Appendices" (shorter), "Authorisation" (Level 2). |
| 2(a)-(d) | Keep. 2(a) allows a Delegation and states the no-authority rule. 2(b) now by Level. 2(c) a Stop needs no Level. 2(d) says Delegation. |
| 2(e)-(h) | Keep. |
| 2(i) Authorised Persons | Move to 2(i) Delegations. Authorised Person is the case "prepare only". Its ban on Approvals and signing is now a scope the Holder chooses, still barred for Section 5 and the second factor. |
| 3, 4 | Keep. |
| 5 | Keep. 5(a) names Level 2 or 3, 5(d) names Level 2. |
| 6 | Keep. 6(a)(5) states that free advertising needs a Deal. 6(f) lets a Condition require a Level. |
| 7 | Keep. 7(g) shortened to three items, Level 3 wording. |
| 8 | Keep. 8(a), 8(e) name Delegations. New 8(j) Level. |
| 9 | Keep. |
| 10 | Keep. 10(a) a Deal opens only once held at the home Registry. |
| 11 | Keep. |
| 12 | Keep. 12(c), 12(d) name Delegations and Levels. |
| 13 | Keep. 13(a) no authority and Services, new 13(e) functions. 13(d) reports the Level. |
| 14, 15 | Keep. |
| 16 | 16(a) identifier `ToG-L-1.1`. 16(f) criteria by function. 16(g) Appendix contents moved to the profile (A to F letters unchanged, D and E share one item). |

ToG-RS: 1 adds Function, Service; 2 adds no authority, Services, any business model, pinning rule for the specifications; 3(b) Published Policy states Functions and Levels; 6 is now Levels and Verification (old 6(b) to (f) became Levels 1 to 3, per purpose); 7(b) answers show the Level; 12(a) free or paid; 13(b) light log for Stop-only; 15 is now Delegations (old 15 Authorised Persons, about 1,300 words, now about 700); 16 adds transition from 1.0. The `[version and hash]` placeholders in 2(c) are replaced by a pinning rule: the Steward pins each specification by SHA-256 in the signed Directory, and a Registry conforms to the version pinned when its Listing is signed or renewed. (The Steward's tool must publish that list; nothing else about the Steward or Directory changed.)

## Level mapping

| Level | PRAMPTA | Generator reference (`may_sign`) |
|---|---|---|
| none (no code proved) | `claimed` (pending, permits nothing) | pending |
| 1 | `channel` | `channel-official` |
| 2 | `verified` | `verified` |
| 3 | not issued | not issued |

PRAMPTA's `YES_LEVELS = ("channel", "verified")` is exactly the 1.1 default: a yes opens from Level 1. The generator reference `may_sign` (channel-official or verified) already agrees for a Person.

## Cases, and the clause that handles each

| Case | Clause |
|---|---|
| A yes at a confirmed channel | Level 1 definition, 2(b), 8(j); RS 6(b)(1) |
| An ad yes that needs an identity document | The Statement requires Level 2 for the purpose (2(b)); a Deal is the only commercial route (6(a)(5)); Provider relies only at that Level (8(j), 12(d)(3)) |
| A fan club with a Delegation | 2(i) item 3; 8(e)(2); RS 15(a), 15(b) |
| A registry that gives everything free for fun | RS 2(g), 12(a): Stop and Level functions, no Deal function; price and ads free; no sale of a Level |
| A state registry on a national eID | RS 6(b)(2) (eID scheme at eIDAS substantial or high, NIST IAL2 or higher) or Level 3; public operator allowed, RS 2(g) |
| A no-only hobby registry | RS 1 (Stop function), 6(a), 6(h), 13(b) light log |
| A minor | 5(d); 2(i) (representative, Stops only); RS 6(g) (a Registry with no Level 2 takes no minor's Stop) |
| Sexual content | 5(a); 2(i) never reaches Section 5; RS 6(g) |
| A Holder revokes a Delegation mid-Deal | 2(i) revocation paragraph; 10(d); RS 15(g): the Deal stays, the Holder may withdraw, no new Generation under the Delegate's permission |
| A registry that closes | 13(c); RS 11(c), 11(e); a Delegation ends on a Move (RS 15(g)) |

## Cold-review findings

Provider's counsel, fixed: Delegate that is a Provider or Platform approving for itself, or a class permission lifting a category or Condition (2(i), 8(e)(2)); a Deal not held at the home Registry (10(a)); garbled "Authenticated" item 1.
Fan-registry operator, fixed or noted: 2(i) last sentence reworded; RS 4(e) says "Statements or Stops". Noted, not changed: a Stop-only registry cannot take a minor's Stop (RS 6(g)); the permanent Prefix and hand-over duties are heavy for a hobby site.
Carried from 1.0, not changed (for 1.2): Providers that never accept the Licence owe nothing; name-only requests; a Pending code forbids nothing and a no filed at a Registry waits for proof; `editorial` has no business limit; 24 hours reliance on a Statement read off the Holder's page against 5 minutes at a Registry; tog:no needs a named channel.
Accepted risk: Level 1 proves control of an account, not identity. An impostor who controls a fan account can open non-commercial use for a celebrity. Limits: the real Holder's Stop always wins (2(f)), a Level 1 answer shows no verified name (RS 7(b)), nothing commercial opens, and 12(d) covers deception. The alternative is Level 2 for any Likeness yes; it contradicts the founder's policy.

## Stale mentions found (pages not edited)

- `get-started.md` lines 129, 138, 396; `create-registry.html`, `connect.html`: profile `likeness/1`; the current profiles are `likeness/2`, `marks/1`, `proof/1`.
- `spec/profiles/` holds only `likeness-1.md`; the three current profiles have no published file.
- `spec/extensions/lookup.md`: "Only `verified` may open a use" contradicts Level 1. It is the reason the RS pins no hash for it.
- `llms.txt` line 11 and `spec/TOG-MAPPING.md` name `likeness/1`.
- The create flow (`tog.js`), `packages/verify-js/tog.js`, `spec/test-vectors/tog-generator.json` and `spec/tools/tog_generator_vectors.py` still cite ToG-L 1.0 on purpose: changing the pinned hash changes the vectors. They move together with PRAMPTA.
- Downloads example PDFs (six) are 1.0 examples. "Someone the holder appoints" in the frame-deal example is the 1.0 Authorised Person.

## PRAMPTA must change to cite 1.1 (not done)

1. `backend/app/core/pg_terms.py`: `LEGAL2` sha256 `b010104acec8f3b63eea04580ba378159066282334dc8db54d6318fdf998b6ef`, url `https://www.pregen.org/tog/1.1`; `LEGAL2_LABEL = "ToG-L 1.1"`; `LEGAL_LABELS` keeps every 1.0 hash labelled "ToG-L 1.0" and adds the 1.1 hash; `TEMPLATE2 id = "ToG-L-1.1"`; update the header comment.
2. `frontend/public/pregen/ToG-L-1.1.txt`: byte-identical copy; `tests/test_pg_terms.py` pins (hash, length 1.1, label).
3. `backend/tests/data/tog-generator.json` `meta.legal` (id, label, sha256, url) from the regenerated shared vectors.
4. Relicense flow (`publish_tog(relicense=True)`, `/tog/relicense`): works unchanged: it re-signs the same rules when the cited sha differs from `LEGAL2`; same rules open nothing, so no second factor. Offer it to every Statement that cites 1.0.
5. Answers (`lookup`) must state the Level (`channel` or `verified`) per Licence 8(j); they already carry `level`. A per-purpose Level needs a profile change (likeness/3) or a Condition; until then the default is Level 1.
6. `authz.py` and Authorised Person tables become Delegations: scopes prepare, approve, class permission, sign Deals; an end date; Level of the Delegation; revocation logged; a Delegation ends on a Move.
7. PRAMPTA's Listing and Published Policy state its Functions (Stop, Level 1 and 2, Deal) and map `claimed`, `channel`, `verified`.
8. `terms.py` (`_TOG_*`, "Section 8(e)/(f)/(g)") and `pg_commerce.py` ("Section 10(a)") cite 1.0 section numbers; numbering is unchanged in 1.1, so only the text "ToG-L 1.0" changes.
