---
'@hyperdx/app': minor
---

Add role management to Team Settings: a roles list, a per-resource permission
matrix editor for custom roles, and a role column with per-member assignment.

Surfaces that previously offered writes the server now rejects are hidden from
roles that lack the permission, and each Team Settings section is gated on the
permission its own data needs — so Member and ReadOnly no longer hit a 403 on
views they are allowed to see. Connection create, update and test now surface
the API's error message instead of a generic one.
