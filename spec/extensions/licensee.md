# Extension `licensee` — answers for a connected end user

**Solves:** a grant belongs to a person or company who uses the provider, not to the
provider itself.

## Request member

`licensee_id` — the end user's id at this registry, or `""` for a provider-level request.

## How the user is connected

Each registry connects end users to providers in its own way, for example with an OAuth
sign-in. The registry then accepts requests for that user from that provider.

## Rules

- A request for a licensee that is not connected to this provider is refused with
  `PG_NOT_AUTHENTICATED`.
- A use that needs a connected user, asked without one, gets an answer with reason
  `PG_NOT_CONNECTED`. A provider shows this as "connect your account", not as a refusal.
