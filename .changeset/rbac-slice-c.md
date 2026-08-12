---
'@hyperdx/api': minor
---

Enforce role-based access control on the Bearer-token path. Personal access
keys previously granted full administrative capability regardless of the
holder's role, so a Member-level key could create dashboards, edit sources, run
raw SQL and manage team members through the MCP server or the External API —
everything RBAC blocks in the browser.

All 28 MCP tools and all 40 External API v2 handlers now require a permission.
Raw SQL (`clickstack_sql`) requires `connections: manage`, which only Admin
holds by default, because free-form SQL bypasses Source mapping entirely.

**Breaking for existing integrations, deliberately.** Scripts using a
non-admin access key to write data or run SQL will start receiving permission
errors. Assign the key's user a role with the permissions it needs, or use an
Admin key.

Unlike the browser, a request whose user has no role assigned is now **denied**
rather than treated as an administrator: the browser's fail-open exists so an
operator is not locked out mid-incident, which does not apply to an unattended
agent.
