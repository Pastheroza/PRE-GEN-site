# Extension `sandbox` — the same test subjects everywhere

**Solves:** every provider needs to test refusals, not only success. Every registry's
sandbox should answer alike.

## Standard subjects

A registry whose document says `"sandbox": true` publishes these subjects on its own
prefix, with fixed serials:

| Serial | Answer (`likeness/1`, `purpose: "research"`) |
|---|---|
| 1 | `allow` — basis a grant with no usage limit |
| 2 | `deny`, `PG_NO_LICENSE` |
| 3 | `deny`, `PG_SUBJECT_OPTED_OUT` |
| 4 | `deny`, `PG_USAGE_LIMIT` |
| 5 | `deny`, `PG_PROHIBITED_USE` |
| 6 | `review`, `PG_REVIEW_REQUIRED` |
| 7 | `not_blocked`, `PG_NO_LICENSE` |
| 8 | not registered — `deny`, `PG_UNKNOWN_SUBJECT` |
| 9 | `deny`, `PG_NO_LICENSE` until a test purchase, then `allow` — buy first (below) |
| 10 | `deny`, `PG_NO_LICENSE` — the person's terms (below) |
| 11 | `allow` — a minor (below) |
| 12 | `deny`, `PG_NO_LICENSE` without a binding; `allow` through one — a creator's licence ([`bind`](bind.md), below) |

Serials 9–11 let a provider test payment, the person's terms and the floor:

| Serial | Request | Answer |
|---|---|---|
| 9 | no test purchase by this provider | `deny`, `PG_NO_LICENSE` |
| 9 | after one test purchase | `allow`, basis the purchased grant; billed in `/v2/statement` |
| 9 | again, while that use is reserved or consumed | `deny`, `PG_USAGE_LIMIT` |
| 9 | after a `not_generated` report within the give-back window ([`limits`](limits.md)) | `allow`: the use is back; the statement shows it `given_back` |
| 9 | two jobs at once for the last use | one `allow`, the other `deny`, `PG_USAGE_LIMIT` |
| 9 | another provider, which bought nothing | `deny`, `PG_NO_LICENSE` |
| 9 | another provider, naming the buyer as its `licensee_id` | `deny`, `PG_NO_LICENSE` |
| 10 | no `terms` | `deny`, `PG_NO_LICENSE` |
| 10 | `terms`: the current id, signed by a provider known by its domain | `deny`, `PG_NO_LICENSE`: the terms grant nothing |
| 10 | `terms`: any other id | `deny`, `PG_TERMS_NOT_ACCEPTED`; it binds no ask (T-7) |
| 10 | `terms`: the current id, from a provider with a registry credential | `deny`, `PG_TERMS_NOT_ACCEPTED` (T-8) |
| 10 | `purpose: "commercial"`, with or without `terms` | `deny`, `PG_TERMS_EXCLUDED` |
| 10 | `categories: ["advertising"]`, with or without `terms` | `deny`, `PG_TERMS_EXCLUDED` |
| 11 | no `categories`, or `["fashion"]` | `allow` |
| 11 | `["violence"]` | `deny`, `PG_PROHIBITED_USE` |
| 11 | a word outside the closed vocabulary, without `terms` | `deny`, `PG_PROHIBITED_USE` |
| 11 | `["sexual"]` or `["adult"]` | `deny`, `PG_PROHIBITED_USE`: the minor's protection comes first, though the grant names them |
| 12 | no `licensee_id` | `deny`, `PG_NO_LICENSE` |
| 12 | the `licensee_id` of this provider's binding, `purpose: "research"` | `allow`, with `ext.bind` naming the binding (B-3c) |
| 12 | the same, `purpose: "commercial"` | `deny`, `PG_SCOPE_VIOLATION`: outside the licence |
| 12 | the same, a fourth time | `deny`, `PG_USAGE_LIMIT` |
| 12 | a `licensee_id` with no active binding to this provider: another app's, replaced, revoked or made up | HTTP 403 `PG_NOT_BOUND` (B-5) |

- **9** is in the catalog ([`catalog`](catalog.md)) with a test price and no grant.
- **10** has published terms ([`terms`](terms.md)): purposes `editorial` and `research`, `advertising`
  excluded, `minor: false`; a sandbox declares `terms`. Its lookup names the current id.
- **11** is a minor holding their own key, with a grant signed by it for every purpose and every category
  ([`likeness/1`](../profiles/likeness-1.md), the floor).
- **12** has no grant of its own. A sandbox declares `bind` and has one test creator, who signs in on its consent page
  with no password. Each consent gives that creator a new licence on 12, `purpose` `research` and `max_uses` 3, and
  the binding reaches only it, so no two apps share its uses.

A request already answered gets the same answer while it is open ([`jobs`](jobs.md)): after a purchase or a
give-back, ask under a new `job_id`.

## Test purchase

`POST {api}/v2/sandbox/purchases`, only in a sandbox (404 elsewhere): a `pg.request.v1` envelope naming a
subject in the catalog, authenticated as for `/v2/requests` (a provider known by its domain signs it; a
registered one sends its credential). No money moves. HTTP 200 `{"grant": <pg.grant.v1>}`: one use
(`max_uses: 1`) for that provider (`licensee_id`), on the offer's purposes, with
`ext: {"sandbox": true, "purchase": n}`. Each purchase adds one such grant, and it is that provider's
alone. A subject not in the catalog: 404 `PG_NOT_FOUND`.

## Rules

- **Every sandbox answer carries `ext: {"sandbox": true}`.**
- **Never accepted in production.** A client MUST NOT accept a sandbox answer unless it is
  explicitly configured for testing.
- **Test directory.** Sandbox registries are listed in a test directory: the same format as
  the real one (core rule 2), at `https://www.pregen.org/test/registries.json`, signed by a
  separate **test steward key** that never signs the real directory. It holds no bare
  namespace. A client uses it only when configured for testing, so a sandbox registry can
  never sign anything accepted in production.
- **Credentials.** A sandbox MAY issue credentials without an account, because it holds no
  real people.

## Example

The **PRE-GEN Test Registry** (prefix `TEST`): serial 1 is `PG-TEST-000001` plus its check
character. Serials 9, 10 and 11 are `PG-TEST-000009V`, `PG-TEST-000010M` and `PG-TEST-000011Y`. Serial 12 is
`PG-TEST-0000123`.
