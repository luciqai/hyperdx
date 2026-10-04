---
'@hyperdx/api': patch
'@hyperdx/app': patch
---

Fix upgraded installs booting with no RBAC roles and no way to reach the
admin-only routes.

System roles were only ever seeded during registration, invite acceptance,
Google user creation, and the local-app-mode boot. A team that already existed
when RBAC shipped was covered by none of them — its only seeding path was the
`add_rbac_roles` migrate-mongo migration, which no Docker entrypoint runs. Such
installs booted with an empty roles collection and an empty Roles list in Team
Settings, with every user resolving as admin through the session fail-open.

That state was one assignment away from being unrecoverable: creating a custom
role with every `manage` permission and assigning it to yourself traded the
fail-open for a role that can never satisfy `requireAdmin` (which does not
consult permissions, and `createRole` always writes `isAdmin: false`), leaving
nobody able to rotate the ingestion API key, assign roles, create roles, or
invite and remove members — with no API route left to undo it.

The API now bootstraps RBAC on every boot: it seeds the three system roles for
every team idempotently, assigns the Admin role to users who have none, and
repairs a team left with no admin-role holder by promoting its earliest member.
The bootstrap fails soft, so it can never prevent the API from starting.

The role editor now names the capabilities that stay with Admins — role
management, role assignment, member invites and removals, and ingestion key
rotation — so a "manage everything" custom role no longer reads as an
administrator.
