# Extension `catalog` — providers sell what registries offer

**Solves:** a provider wants to offer people from many registries to its own users, and the
people must be paid for each use without trusting the provider's own count.

## The catalog

`GET {api}/v2/catalog` → `{"registry", "offers": [{subject_ref, name, anchor, level, …terms}]}`.

- **Only subjects who chose to be offered are listed.** A private person is never listed
  without consent; an opted-out or unavailable subject disappears from the catalog.
- Terms come from the rights holder: purposes, territory, channels, price per unit
  (`{amount, currency, unit}`), whether resale is offered, exclusivity.
- **A listing is not a permission.** Every generation still asks and needs an `allow`.

## Resale

A grant ([`grants`](grants.md)) whose `licensee_id` is a provider covers that provider's own
use. It covers generations **for the provider's users** (`licensee_id` in the request, see
[`licensee`](licensee.md)) only when its `use` carries `"resale": true`. Without it the
registry answers `PG_NO_LICENSE`. Purpose, territory, channels and limits still apply to every
generation.

## What is owed

`GET {api}/v2/statement` (authenticated provider) →
`{"provider_id", "grants": [{grant, billed, given_back}]}`.

- **Billed = every `allow` the registry issued** to that provider under the grant, minus the
  ones given back within the profile's window ([`limits`](limits.md)).
- The count is the registry's, not the provider's: without an `allow` there is no permitted
  generation to bill or to prove. Reports refine the record; they never reduce the bill
  outside the give-back window.

Price changes apply to grants issued after them; an issued grant keeps its terms.
