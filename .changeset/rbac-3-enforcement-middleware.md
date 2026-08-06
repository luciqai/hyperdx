---
'@hyperdx/api': minor
---

Add the RBAC enforcement primitives: `requirePermission`, `requireAdmin` and
`noPermissionRequired`, over a shared verdict resolver. Missing-role handling
diverges by auth path — browser sessions resolve as admin so an operator
upgrading mid-incident is not locked out, while access-key callers are denied.
Both emit the `hyperdx.rbac.missing_role` counter.

No route calls these yet, so this has no effect on request handling.
