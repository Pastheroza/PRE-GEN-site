# Extension `lookup` — what a code is

**Solves:** a person, a lawyer or a platform holds a code and wants to know whom it names.

## Endpoint

`GET {api}/v2/codes/{code}` (public). The response:
- `{"code", "registry": "<prefix>", "status": "active" | "unknown" | "other_registry"}`;
- **for a subject the registry publishes, also:** `"name"`, `"level"` and `"subject_key":
  {"key_id", "public_key_hex", "custody"}`.

**Nothing is returned that the rights holder did not choose to publish.**

## Level

`level` is the registry's own statement of how well it established who may decide for the
subject. **It is a claim, not evidence.**

| Level | Meaning |
|---|---|
| `self` | the person registered themselves |
| `asserted` | a representative asserts authority |
| `consented` | the person confirmed the representative |
| `verified` | the registry verified identity and authority |
