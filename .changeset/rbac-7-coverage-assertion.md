---
'@hyperdx/api': minor
---

Fail startup when an authenticated route declares no RBAC permission.

Forgetting the annotation on a new route is otherwise silent and ships an
unguarded endpoint — the same omission class that produced the cross-tenant
invitation delete. This converts it into a failed deploy.
