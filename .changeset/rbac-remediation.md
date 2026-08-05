---
'@hyperdx/api': minor
'@hyperdx/app': minor
---

Close 12 RBAC defects found by a manual test pass over the role-based access
control work.

Four of these change behaviour for existing deployments:

- **`/clickhouse-proxy` and `/v1/prometheus` now require `sources: read`.** All
  three system roles hold it, so Admin, Member and ReadOnly are unaffected. A
  custom role deliberately given `sources: none` loses browser query access —
  previously it could reach the proxy directly and run arbitrary read SQL
  against the whole ClickHouse cluster.
- **MCP prompts now require `sources: read`** and are hidden from `prompts/list`
  for roles that cannot reach them. An agent running under a restricted access
  key will stop seeing `create_dashboard`, `dashboard_examples` and
  `query_guide`. They enumerate the team's real source and connection names,
  which is why they are gated.
- **Invitation URLs are no longer returned to non-admins.** Any integration
  reading join links from `GET /team/invitations` or
  `GET /api/v2/team/invitations` under a non-admin key will no longer receive
  the `url` field. The list itself is unchanged.
- **`POST /team/roles` and `PATCH /team/roles/:id` now reject unknown keys.** The
  role request schemas are strict, so a client that previously sent extra
  properties alongside `name`, `description` and `permissions` and had them
  silently ignored now gets a 400 instead.

Also fixed: the last-admin guard no longer falls silent when an un-migrated
user exists; the RBAC Mongo migration aborts cleanly instead of half-seeding a
team whose roles collide by name; concurrent team creation can no longer
produce duplicate Admin roles; four UI surfaces no longer offer writes the
server rejects; the Team Settings Sources view no longer 403s for Member and
ReadOnly; role-less users are counted and warned about at startup; API rate
limiting no longer gives each guessed access key its own bucket; and the
`/api/v2/search` and `/api/v2/charts` expression guard no longer accepts
comment-obfuscated subqueries.
