---
'@hyperdx/api': patch
'@hyperdx/app': patch
---

Assign the ReadOnly role to users auto-provisioned by Google SSO. Previously
they were created with no role at all, which the permission resolver treats as
fail-open on the browser session path — so a self-service Google sign-up
received admin-equivalent access. A provisioning attempt that cannot resolve
the team's ReadOnly role now refuses the login rather than creating a role-less
user. Promote from ReadOnly in Team Settings → Access.

Also declares the permissions three previously unannotated routes require:
`GET /alerts/:id/evaluations` (`alerts:read`), `GET|POST
/v1/prometheus/query_exemplars` (`sources:read`), and
`GET /iac/import-manifest` (`connections:read`, since the manifest lists
connections and webhooks). The "Export to Terraform" section is hidden from
roles without `connections:read` to match.
