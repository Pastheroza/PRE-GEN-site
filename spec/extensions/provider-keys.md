# Extension `provider-keys` — the provider's signing keys

**Solves:** reports must be signed by the provider. Its keys need a history that survives
rotation and theft.

## Keyset — `pg.keyset.v1`

- `POST {api}/v2/keys` (authenticated as the provider) → `{"keyset": <envelope>}`.
- `GET {api}/v2/keys/{provider_id}` (public) → `{"provider_id", "keysets": [ … ]}`,
  oldest first.

| Member | Rule |
|---|---|
| `kind` | `first`, `rotation` or `recovery` |
| `provider_id` | the provider |
| `previous` | `null` for `first`; otherwise the message id of the keyset it replaces |
| `recovery_registry` | the prefix of the registry allowed to co-sign a recovery (`""` = origin). Fixed by `first`; only `recovery` may change it |
| `keys` | `[{key_id, public_key_hex, status}]`; exactly one `current`, others `previous` or `revoked` |

| Kind | Signers, in order | Accepted when |
|---|---|---|
| `first` | `provider` (the new current key) | the provider has no keyset at this registry |
| `rotation` | `provider`, `provider_previous` (the old current key) | it chains to the accepted keyset and keeps `recovery_registry` |
| `recovery` | `provider`, `recovery_registry` | co-signed by the named registry after it re-verified the provider |

## Rules

- **Status applies to new actions.** A new report must be signed by the current key.
- **Old reports stay checkable.** A report already acknowledged keeps its acknowledgement.
  A verifier checks it against the keyset that was current when it was acknowledged, from
  the public history.
- **Rotation is idempotent.** Posting the identical keyset again returns it. Posting
  `first` again with the same current key is accepted.
- **Publish on your domain.** A provider SHOULD also publish its chain at
  `https://<its domain>/.well-known/pregen-keys.json`.
