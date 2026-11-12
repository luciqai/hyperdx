---
'@hyperdx/api': patch
---

Declare RBAC permissions for the routes and MCP tools that arrived with the
upstream merge. Creating, editing and revoking an org API key requires an admin;
listing them requires `team:read`. `clickstack_promql` requires `sources:read`.
`clickstack_describe_table` requires `connections:manage`, the same as
`clickstack_sql`, because it reaches tables that are not registered as sources.
