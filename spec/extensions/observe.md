# Extension `observe` — trial without blocking

**Solves:** a provider wants to try PRE-GEN on real traffic before it starts blocking.

## Member

`mode` in the request and in the report:
- `enforce` (the core behaviour);
- `observe`.

**The report's `mode` must equal the request's.**

## Rules

- **In `observe`, the provider generates whatever the answers are** — including when an
  answer is missing or unusable — **and reports every generation** ([`reports`](reports.md)).
- **Permission comes only from the answer and its basis, never from the mode.** An output
  made without a valid `allow` is never presented as permitted.
- **Switching to `enforce` is a configuration change, not a new integration.**
