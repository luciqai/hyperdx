---
'@hyperdx/api': minor
---

Enforce role permissions on the Bearer-token path — the MCP server and External
API v2 — which were previously ungated.

**Behaviour change for access keys.** Unlike the browser path, a user with no
role assigned is denied rather than allowed as admin: an unattended agent token
has no claim to silent escalation. Deployments must run the RBAC migration
before upgrading, or agent tokens will start failing.

MCP prompts now require `sources: read` and are hidden from `prompts/list` for
roles that cannot reach them — they enumerate the team's real source and
connection names.
