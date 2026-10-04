---
'@hyperdx/api': minor
'@hyperdx/app': minor
---

Add role-based access control. Teams now have three built-in roles (Admin,
Member, ReadOnly) and admins can create custom roles with per-resource
permissions from Team Settings → Access. All existing users are migrated to
Admin, so no one loses access on upgrade.

Also fixes a cross-tenant bug in `DELETE /team/invitation/:id`, which deleted
by id without scoping to the caller's team.

Note: source permissions currently govern the interface, not the underlying
data — a user can still query ClickHouse directly through the query proxy.
Gating the query path is tracked as follow-up work.
