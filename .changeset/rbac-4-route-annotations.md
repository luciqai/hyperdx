---
'@hyperdx/api': minor
---

Enforce role permissions across the internal API. Every route now declares the
permission it needs, and admins can create, edit and delete custom roles.

Existing deployments are unaffected: the migration assigns everyone to Admin,
and a user with no role at all still resolves as admin on the browser path, so
nobody loses access on upgrade.

Also fixes two access-control defects on the team routes:
`DELETE /team/invitation/:id` is now scoped to the caller's team — it deleted by
id alone, so any authenticated user could remove another team's pending
invitations — and invitation URLs are withheld from non-admins, since they embed
an accept-capable token.
