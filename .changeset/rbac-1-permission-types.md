---
'@hyperdx/common-utils': minor
---

Add the RBAC permission vocabulary: the `Resource` and `PermissionLevel` types,
the `RANK` ordering and `hasPermission` predicate, strict Zod schemas for role
create/update, and the permission maps for the Admin, Member and ReadOnly system
roles. Types only — nothing consumes them yet.
