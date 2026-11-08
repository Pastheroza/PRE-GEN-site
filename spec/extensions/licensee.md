# Extension `licensee` — answers for a connected end user

**Solves:** a grant belongs to a person or company who uses the provider, not to the
provider itself.

## Request member

`licensee_id` — the end user's id at this registry (under [`bind`](bind.md), the binding's
random per-app id), or `""` for a provider-level request.

## How the user is connected

Each registry connects end users to providers in its own way, for example with an OAuth
sign-in. The registry then accepts requests for that user from that provider.

## Rules

- A request for a licensee that is not connected to this provider is refused with
  `PG_NOT_AUTHENTICATED` (401) for a registry-issued provider id; for a provider URL under
  [`bind`](bind.md) it is HTTP 403 `PG_NOT_BOUND` ("connect your licence"), never a refusal.
- A use that needs a connected user, asked without one, gets an answer with reason
  `PG_NOT_CONNECTED`. A provider shows this as "connect your account", not as a refusal.
- **When to send it.** A provider sends a person's `licensee_id` only when the request rests on
  that person's licence: under [`bind`](bind.md), when the subject is among the binding's grants
  (`GET {api}/v2/grants?licensee_id=…`); under the registry's own connect, for the subjects the
  registry told it that person's licence covers. Otherwise it sends `""` and rests on its own grant. Its own
  grant covers generations for its users only with the resale right ([`catalog`](catalog.md)), so a
  `licensee_id` sent where the person holds nothing can only turn an allow into a refusal.
