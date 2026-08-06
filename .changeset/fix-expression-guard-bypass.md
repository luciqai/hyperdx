---
'@hyperdx/api': patch
---

Close two bypasses in the `/api/v2` SQL expression guard.

SQL comments are now stripped before the guard matches, so a subquery hidden
behind a block comment — `(SELECT/**/groupArray(name) FROM system.users)` — is
rejected instead of accepted.

`POST /api/v2/charts/series` now guards `field` and `groupBy` as well as
`where`. Those two inputs become raw SQL value expressions, so they are the
direct analogue of `/search`'s `select`, and previously carried no guard at all.
`where` is guarded only when `whereLanguage` is `"sql"`, since a subquery-shaped
string is a legitimate literal in Lucene mode.

This is defence in depth, not a security boundary: a denylist over a SQL dialect
cannot be complete. Constraining the query path at the database layer with a
restricted ClickHouse user remains the durable fix.
