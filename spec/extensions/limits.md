# Extension `limits` — grants with a number of uses

**Solves:** a grant allows N uses. Two jobs must not both take the last use, and a use that
never happened must be given back.

**Requires:** [`reports`](reports.md).

## States

An `allow` on a grant with a limit **reserves** one use the moment it is issued. Each such
allow is `reserved`, `consumed` or `released`. Two requests at once cannot both reserve
the last use: one gets the allow, the other the profile's usage-limit refusal.

## When a report arrives

**A `generated` report**, whatever answer it names:
1. If it names a `reserved` allow for this subject of the job, that allow is counted.
   Otherwise the earliest `reserved` allow is counted, so naming a refusal does not avoid
   a count. The counted allow becomes `consumed`.
2. If there is none, nothing is counted. This says nothing about permission: an allow on a
   policy rule counts nothing.
3. Every other `reserved` allow for this subject of the job is `released`, if it is inside
   the profile's give-back window.

**A `not_generated` report** releases its own allow, if it is inside the window. With
`answer: null`, the report of an allow the provider never received (lost, or expired before it
arrived), it names the ask by `request_id` and releases every `reserved` allow of that ask that
has expired, inside the window; those allows can never be reported again. An allow still valid
stays reserved. The ask is then closed: no new answer is issued for it (`PG_ASK_CLOSED`). Send
that report, never the request again, and only once any answer would have expired: no earlier
than the time the request was sent, plus the registry's answer lifetime (at most 900 seconds,
core), plus the request's own timeout. Without knowing the registry's lifetime, wait the 900.

**An allow never reported stays reserved** — that is, counted.

## Acknowledgement members

- `counted` — the message id of the counted allow, or `null`;
- `released` — the list of allow ids given back.

## Concurrency

Locks are taken in this order:
1. (provider, job);
2. (provider, job, subject);
3. the grant's counter.
