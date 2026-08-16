# Google SSO as an additive sign-in option

Date: 2026-08-10
Status: Approved, ready for implementation planning

## Goal

Add a "Sign in with Google" button alongside the existing email/password form.
Password authentication must keep working exactly as it does today. The change
should be small and should be inert unless Google credentials are configured.

## Context

The current mechanism, as it exists in the repository today:

- `passport` + `express-session` with a Mongo-backed session store
  (`packages/api/src/api-app.ts`). A single local strategy lives in
  `packages/api/src/utils/passport.ts`.
- The login form posts natively (not via `fetch`) to `/api/login/password`. The
  Next app proxies `/api/*` to Express with `pathRewrite: { '^/api': '' }`
  (`packages/app/pages/api/[...all].ts`). Express replies with a 303 redirect
  back to the frontend.
- `User` uses `passport-local-mongoose` with a unique index on `email`. The
  `hasPasswordAuth` virtual is hardcoded to `true`.
- OSS is effectively single-team: `/register/password` returns 409 once any team
  exists, and further users arrive only through `TeamInvite` and
  `/team/setup/:token`.
- The session cookie's `domain` is pinned to `FRONTEND_URL`'s hostname.

That last point forces a routing decision: the OAuth callback must return
through the **app** origin (`/api/auth/google/callback`, rewritten by the proxy
to `/auth/google/callback` on Express), exactly as `/api/login/password` works
today. Pointing Google directly at a separate API host would set the session
cookie on the wrong domain.

## Policy

A single pure function holds the entire policy. Everything else is plumbing.

```
evaluateGoogleProfile(
  { googleId, email, emailVerified },
  { allowedDomains, existingUser, soleTeam },
)
  -> { action: 'login',     user, stampGoogleId } // matched by googleId, or by email
  -> { action: 'provision', email, team }         // no match, domain allowlisted
  -> { action: 'reject',    code }                // everything else
```

`soleTeam` is the single `Team` when the instance has exactly one, and `null`
otherwise. The caller collapses both the zero-team and the many-team cases into
`null`, because the function's response to each is the same rejection.

Rules, evaluated in order:

1. `emailVerified !== true` -> reject with `googleEmailUnverified`.
2. Look up by `googleId`. On miss, look up by `email` (case-insensitive, as the
   existing schema is configured). **If found, log in** — regardless of email
   domain. When found by email with no `googleId` set, stamp `googleId` on the
   document (silent account link).
3. If found by email but that user already carries a *different* `googleId`,
   reject with `googleAccountMismatch`. This is the email-reassignment case that
   storing `sub` exists to catch: the Google account presenting this address is
   provably not the one that linked it, so logging in would hand one person
   another person's account and data.
4. Not found: `GOOGLE_ALLOWED_DOMAINS` must be non-empty **and** contain the
   email's domain. Empty or non-matching -> reject with `googleDomainNotAllowed`.
5. Not found, domain permitted, but `soleTeam` is `null` -> reject with
   `googleNoTeam`. Zero teams means a fresh install, where the first user must
   still register with a password. More than one team is ambiguous, so refuse
   rather than guess.
6. Otherwise provision: `new User({ email, name: email, team, googleId }).save()`.
   This deliberately bypasses `User.register()`, so the document has no
   `salt`/`hash` and the local strategy cannot authenticate it.

### Decisions this encodes

| Question | Decision |
| --- | --- |
| Unknown Google account | Auto-provision into the existing team, gated on an email-domain allowlist |
| Empty/unset allowlist | Fail closed: existing users can still sign in, but nothing is ever auto-created |
| Domain matching | Require `email_verified === true`, then match the substring after `@` |
| Allowlist scope | Gates **new-user creation only**; existing users sign in regardless of domain |
| Existing password user, same email | Link silently and log them in; they keep their password |
| Google `sub` | Stored as `googleId`, sparse-unique; matched before email |
| `Team.allowedAuthMethods` | Not enforced for Google. Out of scope — nothing in this repo writes the field |

## Files touched

### packages/api

- **`package.json`** — add `passport-google-oauth20` and
  `@types/passport-google-oauth20`.
- **`src/config.ts`** — add `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`,
  `GOOGLE_ALLOWED_DOMAINS` (parsed into a lowercased, trimmed array),
  `GOOGLE_REDIRECT_URI` (defaults to
  `` `${FRONTEND_URL}/api/auth/google/callback` ``), and a derived
  `IS_GOOGLE_AUTH_ENABLED = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) && !IS_LOCAL_APP_MODE`.
- **`src/models/user.ts`** — add `googleId?: string` to `IUser` and the schema,
  with a `{ sparse: true, unique: true }` index. Change the `hasPasswordAuth`
  virtual from hardcoded `true` to `salt != null`.
- **`src/utils/googleAuth.ts`** *(new)* — `evaluateGoogleProfile` and its
  result types. Pure: no database access, no imports from `models`.
- **`src/utils/passport.ts`** — register `GoogleStrategy` only when
  `IS_GOOGLE_AUTH_ENABLED`, with `scope: ['openid', 'email', 'profile']` and
  `state: true` (CSRF protection backed by the already-configured session). The
  verify callback performs the two lookups and the team count, calls
  `evaluateGoogleProfile`, and acts on the verdict. A rejection calls
  `done(null, false, { message: <code> })`, which passport writes to
  `req.session.messages` (the session already carries this array, and
  `failureMessage: true` is already the established pattern on
  `/login/password`).
- **`src/middleware/auth.ts`** — `handleAuthError` currently maps two known
  message strings to `err` codes and falls through to `unknown`. Extend that
  mapping so the four Google rejection codes pass through to
  `/login?err=<code>` instead of collapsing into `unknown`. The two existing
  mappings are left untouched.
- **`src/routers/api/root.ts`** — add `GET /auth/google` and
  `GET /auth/google/callback`, both registered only when
  `IS_GOOGLE_AUTH_ENABLED`. The callback chains into the existing
  `redirectToDashboard` and `handleAuthError`. Extend the `/installation`
  response with `authProviders`.

### packages/common-utils

- **`src/types.ts`** — `InstallationApiResponseSchema` gains
  `authProviders: z.array(z.enum(['password', 'google'])).optional()`. Optional
  so a newer app deployed against an older API does not fail validation.

### packages/app

- **`src/components/GoogleSignInButton.tsx`** *(new)* — a plain
  `<a href="/api/auth/google">` styled as a Mantine `Button variant="secondary"`
  with the Google mark. It must be an anchor, not a `fetch` call: this is a
  full-page navigation. Extracted into its own file because `AuthPage.tsx` is
  already ~270 lines.
- **`src/AuthPage.tsx`** — render the button below a divider when
  `installation?.authProviders?.includes('google')`, on both `/login` and
  `/register`. Extend the existing `err` ternary chain with the new codes.

### Configuration and release

- **`packages/api/.env.development`** — commented placeholders for the four new
  variables. The dev API loads this file via dotenvx.
- **`.changeset/`** — a minor bump for `@hyperdx/api`, `@hyperdx/app`, and
  `@hyperdx/common-utils`.

## Environment variables

```
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_ALLOWED_DOMAINS=luciq.ai      # comma-separated; empty disables auto-provisioning
GOOGLE_REDIRECT_URI=                 # optional override
```

`GOOGLE_REDIRECT_URI` defaults to `${FRONTEND_URL}/api/auth/google/callback`,
which is already correct in development and in the Docker fullstack image. Set
it explicitly only when the public origin differs from `FRONTEND_URL`, such as
behind a proxy or CDN.

The authorized redirect URI to register in the Google Cloud Console for
development is `http://localhost:${HYPERDX_APP_PORT}/api/auth/google/callback`.

## Error surfacing

Each rejection redirects to `/login?err=<code>` with its own message in
`AuthPage`:

| Code | Message |
| --- | --- |
| `googleEmailUnverified` | Your Google email address is not verified. |
| `googleDomainNotAllowed` | This Google account is not permitted to sign in. Contact your admin. |
| `googleNoTeam` | No team has been set up yet. Register with a password first. |
| `googleAccountMismatch` | This email is already linked to a different Google account. Contact your admin. |
| `googleAuthFailed` | Google sign-in failed, please try again. |

`googleAuthFailed` is the fallback used when the flow fails before the verify
callback runs — for example when the user declines consent at Google, or the
token exchange errors. The other four are emitted by `evaluateGoogleProfile`.

The Google button is rendered on `/register` as well as `/login`. On a fresh OSS
install it will fail there with `googleNoTeam`, which is the intended and
clearly-messaged outcome, since Google cannot bootstrap a team.

## Why existing authentication is undisturbed

The local strategy, `/login/password`, `/register/password`, and
`/team/setup/:token` are not modified. The Google strategy and its two routes
are registered only when both credentials are present. With them unset,
`passport.ts` behaves identically to today, `/installation` reports
`['password']`, no button renders, and the new routes 404.

Two pieces of existing behavior do change, both intentionally:

- `hasPasswordAuth` becomes truthful rather than hardcoded, so the Team Members
  list stops claiming a Google-only user has password authentication.
- `/installation` gains one optional field.

`IS_LOCAL_APP_MODE` disables Google entirely, because passport is not
initialized in that mode at all.

## Testing

`packages/api/src/utils/__tests__/googleAuth.test.ts` covers every branch of
`evaluateGoogleProfile`:

- unverified email is rejected
- match by `googleId` logs in
- match by `email` logs in and reports that `googleId` should be stamped
- match by email wins even when the domain is not allowlisted
- permitted domain with exactly one team provisions
- non-permitted domain is rejected
- empty allowlist rejects provisioning but still permits an existing user
- zero teams rejects
- more than one team rejects
- domain and email comparison is case-insensitive

No network or OAuth transport mocking. The passport strategy stays a thin
adapter so that the logic worth testing is reachable without it.

Existing `packages/api/src/routers/api/__tests__/team.int.test.ts` snapshots
remain green: their fixtures register through `User.register()`, so `salt` is
set and `hasPasswordAuth` still resolves to `true`.

## Out of scope

- Bootstrapping a new team through Google. The first user registers with a
  password.
- Any account-linking or unlinking settings UI.
- Enforcing `Team.allowedAuthMethods` for Google.
- Providers other than Google.
