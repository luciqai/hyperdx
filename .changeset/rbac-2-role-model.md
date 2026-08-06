---
'@hyperdx/api': minor
---

Add the `Role` collection and a `role` reference on `User`, plus the migration
that seeds Admin, Member and ReadOnly for every team and assigns all existing
users to Admin. The migration validates before it writes and aborts cleanly on a
name collision rather than half-seeding a team.

Nothing reads `User.role` yet, so this has no effect on request handling.
