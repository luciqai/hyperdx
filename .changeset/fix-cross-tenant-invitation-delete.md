---
'@hyperdx/api': patch
---

Scope `DELETE /team/invitation/:id` to the caller's team. The handler deleted by
id alone, so any authenticated user could remove another team's pending
invitations. Deleting an invitation that does not belong to the caller's team
now returns 404.
