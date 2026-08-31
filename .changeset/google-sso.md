---
'@hyperdx/api': minor
'@hyperdx/app': minor
'@hyperdx/common-utils': minor
---

Add optional Google SSO as an additional sign-in button. Password
authentication is unchanged, and the feature stays completely inert unless
`GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are set. New users are
auto-provisioned into the existing team only when their verified email domain
appears in `GOOGLE_ALLOWED_DOMAINS`; an empty list means no account is ever
created automatically. Existing users sign in regardless of domain, and an
existing password account is linked to its matching Google account on first use.
