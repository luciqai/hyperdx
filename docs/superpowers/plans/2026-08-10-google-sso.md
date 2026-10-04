# Google SSO Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "Sign in with Google" button next to the existing email/password
form, without altering how password authentication behaves.

**Architecture:** All authorization policy lives in one pure, dependency-free
function (`evaluateGoogleProfile`). A `passport-google-oauth20` strategy is a
thin adapter that performs database lookups, calls that function, and acts on
its verdict. The strategy and its two routes are registered only when both
Google credentials are configured, so with them unset the API behaves exactly as
it does today. The OAuth callback returns through the Next.js app origin
(`/api/auth/google/callback`), which the existing proxy rewrites to
`/auth/google/callback` on Express — the same path `/api/login/password` already
takes, and the only path on which the session cookie lands on the right domain.

**Tech Stack:** TypeScript, Express, Passport (`passport-google-oauth20`),
Mongoose, Zod, Next.js, Mantine, Jest.

## Global Constraints

- Source spec: `docs/superpowers/specs/2026-08-10-google-sso-design.md`. Read it
  before starting.
- Password auth is untouched. `passport-local`, `/login/password`,
  `/register/password`, and `/team/setup/:token` must not change behavior.
- Everything Google-related is gated on
  `config.IS_GOOGLE_AUTH_ENABLED`. With `GOOGLE_CLIENT_ID` and
  `GOOGLE_CLIENT_SECRET` unset, no strategy is registered, no routes exist, and
  no button renders.
- Reject codes are exactly these five strings, used verbatim in the API, the URL
  query, and the frontend message map: `googleEmailUnverified`,
  `googleDomainNotAllowed`, `googleNoTeam`, `googleAccountMismatch`,
  `googleAuthFailed`.
- Environment variables are exactly: `GOOGLE_CLIENT_ID`,
  `GOOGLE_CLIENT_SECRET`, `GOOGLE_ALLOWED_DOMAINS`, `GOOGLE_REDIRECT_URI`.
- Path alias `@/` maps to `packages/api/src/` in the API package.
- API unit tests must not require MongoDB. Files matching `*.int.test.ts` are
  excluded from `yarn ci:unit` — do not name any new file that way.
- Run `yarn lint:fix` from the repo root after finishing edits.
- Do not use `git commit --no-verify`. If the pre-commit hook fails because
  husky is not installed in a worktree, run `npx lint-staged` manually first.
- Commit messages use the git author's default profile. Do not add
  `Co-Authored-By` trailers.

---

### Task 1: Pure authorization policy

The entire Google authorization decision, as a function with no imports, no
database access, and no framework coupling. Everything else in this plan is
plumbing around it.

**Files:**
- Create: `packages/api/src/utils/googleAuth.ts`
- Test: `packages/api/src/utils/__tests__/googleAuth.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type GoogleAuthRejectCode = 'googleEmailUnverified' | 'googleDomainNotAllowed' | 'googleNoTeam' | 'googleAccountMismatch'`
  - `type GoogleProfileInput = { googleId: string; email?: string; emailVerified: boolean }`
  - `type GoogleUserMatch<TUser> = { user: TUser; matchedBy: 'googleId' | 'email' }`
  - `type GoogleAuthContext<TUser, TTeam> = { allowedDomains: string[]; existingUser: GoogleUserMatch<TUser> | null; soleTeam: TTeam | null }`
  - `type GoogleAuthDecision<TUser, TTeam> = { action: 'login'; user: TUser; stampGoogleId: boolean } | { action: 'provision'; email: string; team: TTeam } | { action: 'reject'; code: GoogleAuthRejectCode }`
  - `function parseAllowedDomains(raw: string | undefined): string[]`
  - `function emailDomain(email: string): string`
  - `function evaluateGoogleProfile<TUser extends { googleId?: string | null }, TTeam>(profile: GoogleProfileInput, ctx: GoogleAuthContext<TUser, TTeam>): GoogleAuthDecision<TUser, TTeam>`

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/utils/__tests__/googleAuth.test.ts`:

```ts
import type {
  GoogleAuthContext,
  GoogleProfileInput,
} from '@/utils/googleAuth';
import {
  emailDomain,
  evaluateGoogleProfile,
  parseAllowedDomains,
} from '@/utils/googleAuth';

type TestUser = { _id: string; email: string; googleId?: string | null };
type TestTeam = { _id: string };

const TEAM: TestTeam = { _id: 'team-1' };

const profile = (over: Partial<GoogleProfileInput> = {}): GoogleProfileInput => ({
  googleId: 'sub-1',
  email: 'ada@luciq.ai',
  emailVerified: true,
  ...over,
});

const ctx = (
  over: Partial<GoogleAuthContext<TestUser, TestTeam>> = {},
): GoogleAuthContext<TestUser, TestTeam> => ({
  allowedDomains: ['luciq.ai'],
  existingUser: null,
  soleTeam: TEAM,
  ...over,
});

describe('parseAllowedDomains', () => {
  it('returns an empty array for undefined or blank input', () => {
    expect(parseAllowedDomains(undefined)).toEqual([]);
    expect(parseAllowedDomains('')).toEqual([]);
    expect(parseAllowedDomains('  ,  ,')).toEqual([]);
  });

  it('splits, trims, lowercases, and strips a leading @', () => {
    expect(parseAllowedDomains(' Luciq.ai , @Example.COM ')).toEqual([
      'luciq.ai',
      'example.com',
    ]);
  });
});

describe('emailDomain', () => {
  it('returns the lowercased portion after the last @', () => {
    expect(emailDomain('Ada@Luciq.AI')).toBe('luciq.ai');
  });

  it('returns an empty string when there is no @', () => {
    expect(emailDomain('not-an-email')).toBe('');
  });
});

describe('evaluateGoogleProfile', () => {
  it('rejects an unverified email', () => {
    expect(
      evaluateGoogleProfile(profile({ emailVerified: false }), ctx()),
    ).toEqual({ action: 'reject', code: 'googleEmailUnverified' });
  });

  it('rejects a profile with no email address', () => {
    expect(
      evaluateGoogleProfile(profile({ email: undefined }), ctx()),
    ).toEqual({ action: 'reject', code: 'googleEmailUnverified' });
  });

  it('logs in a user matched by googleId without re-stamping', () => {
    const user: TestUser = { _id: 'u1', email: 'ada@luciq.ai', googleId: 'sub-1' };
    expect(
      evaluateGoogleProfile(
        profile(),
        ctx({ existingUser: { user, matchedBy: 'googleId' } }),
      ),
    ).toEqual({ action: 'login', user, stampGoogleId: false });
  });

  it('logs in a user matched by email and asks for the googleId to be stamped', () => {
    const user: TestUser = { _id: 'u1', email: 'ada@luciq.ai' };
    expect(
      evaluateGoogleProfile(
        profile(),
        ctx({ existingUser: { user, matchedBy: 'email' } }),
      ),
    ).toEqual({ action: 'login', user, stampGoogleId: true });
  });

  it('logs in an existing user even when their domain is not allowlisted', () => {
    const user: TestUser = { _id: 'u1', email: 'bob@gmail.com' };
    expect(
      evaluateGoogleProfile(
        profile({ email: 'bob@gmail.com' }),
        ctx({ allowedDomains: ['luciq.ai'], existingUser: { user, matchedBy: 'email' } }),
      ),
    ).toEqual({ action: 'login', user, stampGoogleId: true });
  });

  it('logs in an existing user even when the allowlist is empty', () => {
    const user: TestUser = { _id: 'u1', email: 'ada@luciq.ai', googleId: 'sub-1' };
    expect(
      evaluateGoogleProfile(
        profile(),
        ctx({ allowedDomains: [], existingUser: { user, matchedBy: 'googleId' } }),
      ),
    ).toEqual({ action: 'login', user, stampGoogleId: false });
  });

  it('rejects when the email matches a user linked to a different Google account', () => {
    const user: TestUser = { _id: 'u1', email: 'ada@luciq.ai', googleId: 'sub-OLD' };
    expect(
      evaluateGoogleProfile(
        profile({ googleId: 'sub-NEW' }),
        ctx({ existingUser: { user, matchedBy: 'email' } }),
      ),
    ).toEqual({ action: 'reject', code: 'googleAccountMismatch' });
  });

  it('provisions a new user when the domain is allowlisted', () => {
    expect(evaluateGoogleProfile(profile(), ctx())).toEqual({
      action: 'provision',
      email: 'ada@luciq.ai',
      team: TEAM,
    });
  });

  it('lowercases the provisioned email', () => {
    expect(
      evaluateGoogleProfile(profile({ email: 'Ada@Luciq.AI' }), ctx()),
    ).toEqual({ action: 'provision', email: 'ada@luciq.ai', team: TEAM });
  });

  it('rejects an unknown user whose domain is not allowlisted', () => {
    expect(
      evaluateGoogleProfile(profile({ email: 'eve@evil.com' }), ctx()),
    ).toEqual({ action: 'reject', code: 'googleDomainNotAllowed' });
  });

  it('fails closed: an empty allowlist never provisions', () => {
    expect(
      evaluateGoogleProfile(profile(), ctx({ allowedDomains: [] })),
    ).toEqual({ action: 'reject', code: 'googleDomainNotAllowed' });
  });

  it('rejects provisioning when there is no sole team', () => {
    expect(
      evaluateGoogleProfile(profile(), ctx({ soleTeam: null })),
    ).toEqual({ action: 'reject', code: 'googleNoTeam' });
  });

  it('checks the domain before the team, so a stranger never learns the team state', () => {
    expect(
      evaluateGoogleProfile(
        profile({ email: 'eve@evil.com' }),
        ctx({ soleTeam: null }),
      ),
    ).toEqual({ action: 'reject', code: 'googleDomainNotAllowed' });
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd packages/api && yarn ci:unit src/utils/__tests__/googleAuth.test.ts
```

Expected: FAIL — `Cannot find module '@/utils/googleAuth'`.

- [ ] **Step 3: Write the implementation**

Create `packages/api/src/utils/googleAuth.ts`:

```ts
/**
 * Google SSO authorization policy.
 *
 * Deliberately pure: no imports, no database access, no Express or Passport
 * types. The Passport strategy performs the lookups and hands the results here,
 * so every branch below is reachable from a plain unit test.
 */

export type GoogleAuthRejectCode =
  | 'googleEmailUnverified'
  | 'googleDomainNotAllowed'
  | 'googleNoTeam'
  | 'googleAccountMismatch';

export type GoogleProfileInput = {
  googleId: string;
  email?: string;
  emailVerified: boolean;
};

export type GoogleUserMatch<TUser> = {
  user: TUser;
  matchedBy: 'googleId' | 'email';
};

export type GoogleAuthContext<TUser, TTeam> = {
  allowedDomains: string[];
  existingUser: GoogleUserMatch<TUser> | null;
  /** The single Team when the instance has exactly one, otherwise null. */
  soleTeam: TTeam | null;
};

export type GoogleAuthDecision<TUser, TTeam> =
  | { action: 'login'; user: TUser; stampGoogleId: boolean }
  | { action: 'provision'; email: string; team: TTeam }
  | { action: 'reject'; code: GoogleAuthRejectCode };

export function parseAllowedDomains(raw: string | undefined): string[] {
  return (raw ?? '')
    .split(',')
    .map(domain => domain.trim().toLowerCase().replace(/^@/, ''))
    .filter(Boolean);
}

export function emailDomain(email: string): string {
  const at = email.lastIndexOf('@');
  return at === -1 ? '' : email.slice(at + 1).toLowerCase();
}

export function evaluateGoogleProfile<
  TUser extends { googleId?: string | null },
  TTeam,
>(
  profile: GoogleProfileInput,
  ctx: GoogleAuthContext<TUser, TTeam>,
): GoogleAuthDecision<TUser, TTeam> {
  if (!profile.emailVerified || !profile.email) {
    return { action: 'reject', code: 'googleEmailUnverified' };
  }

  const email = profile.email.toLowerCase();

  if (ctx.existingUser) {
    const { user, matchedBy } = ctx.existingUser;

    if (matchedBy === 'googleId') {
      return { action: 'login', user, stampGoogleId: false };
    }

    // Matched by email. If that account is already linked to a different Google
    // account, the address has been reassigned and this is not the same person.
    if (user.googleId && user.googleId !== profile.googleId) {
      return { action: 'reject', code: 'googleAccountMismatch' };
    }

    return { action: 'login', user, stampGoogleId: true };
  }

  // No existing user, so this would be a provisioning. An empty allowlist has no
  // members, so `includes` is false and we fail closed.
  if (!ctx.allowedDomains.includes(emailDomain(email))) {
    return { action: 'reject', code: 'googleDomainNotAllowed' };
  }

  if (!ctx.soleTeam) {
    return { action: 'reject', code: 'googleNoTeam' };
  }

  return { action: 'provision', email, team: ctx.soleTeam };
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd packages/api && yarn ci:unit src/utils/__tests__/googleAuth.test.ts
```

Expected: PASS, 17 tests.

- [ ] **Step 5: Commit**

```bash
git add packages/api/src/utils/googleAuth.ts packages/api/src/utils/__tests__/googleAuth.test.ts
git commit -m "feat(api): add pure Google SSO authorization policy"
```

---

### Task 2: User model and lookup helpers

Add the `googleId` field the policy matches on, make `hasPasswordAuth` truthful,
and expose the two lookups the strategy needs.

**Files:**
- Modify: `packages/api/src/models/user.ts`
- Modify: `packages/api/src/controllers/user.ts`
- Modify: `packages/api/src/controllers/team.ts`
- Test: `packages/api/src/models/__tests__/user.test.ts`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces:
  - `IUser` gains `googleId?: string`
  - `function findUserByGoogleId(googleId: string)` in `@/controllers/user` — returns `Promise<UserDocument | null>`
  - `function getSoleTeam()` in `@/controllers/team` — returns `Promise<TeamDocument | null>`, non-null only when exactly one Team exists

- [ ] **Step 1: Write the failing test**

Mongoose models can be constructed without a database connection, so this is a
real unit test. Create `packages/api/src/models/__tests__/user.test.ts`:

```ts
import User from '@/models/user';

describe('User model', () => {
  describe('hasPasswordAuth virtual', () => {
    it('is false for a user with no password salt (Google-only)', () => {
      const user = new User({ email: 'ada@luciq.ai', name: 'ada@luciq.ai' });
      expect(user.get('hasPasswordAuth')).toBe(false);
    });

    it('is true once a password salt is present', () => {
      const user = new User({ email: 'ada@luciq.ai', name: 'ada@luciq.ai' });
      user.set('salt', 'some-salt');
      expect(user.get('hasPasswordAuth')).toBe(true);
    });
  });

  describe('googleId', () => {
    it('is undefined by default', () => {
      const user = new User({ email: 'ada@luciq.ai' });
      expect(user.get('googleId')).toBeUndefined();
    });

    it('round-trips a value', () => {
      const user = new User({ email: 'ada@luciq.ai', googleId: 'sub-1' });
      expect(user.get('googleId')).toBe('sub-1');
    });
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd packages/api && yarn ci:unit src/models/__tests__/user.test.ts
```

Expected: FAIL — the first test reports `true` instead of `false` (the virtual
is hardcoded), and `googleId` round-trip returns `undefined` (not in the schema).

- [ ] **Step 3: Modify the User model**

In `packages/api/src/models/user.ts`, add `googleId` to the `IUser` interface:

```ts
export interface IUser {
  _id: ObjectId;
  accessKey: string;
  createdAt: Date;
  email: string;
  googleId?: string;
  name: string;
  team: ObjectId;
}
```

Add the schema field, immediately after the `email` field:

```ts
    googleId: {
      type: String,
      required: false,
    },
```

Replace the hardcoded virtual:

```ts
UserSchema.virtual('hasPasswordAuth').get(function (this: { salt?: string }) {
  return this.salt != null;
});
```

Add the index alongside the existing two:

```ts
UserSchema.index({ googleId: 1 }, { unique: true, sparse: true });
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd packages/api && yarn ci:unit src/models/__tests__/user.test.ts
```

Expected: PASS, 4 tests.

- [ ] **Step 5: Add the lookup helpers**

Append to `packages/api/src/controllers/user.ts`, next to `findUserByEmail`:

```ts
export function findUserByGoogleId(googleId: string) {
  return User.findOne({ googleId });
}
```

Append to `packages/api/src/controllers/team.ts`, after `getAllTeams`:

```ts
/**
 * The single Team when the instance has exactly one, otherwise null.
 *
 * Google SSO only auto-provisions into an unambiguous team. Zero teams means a
 * fresh install (register with a password first); more than one is ambiguous, so
 * we refuse rather than guess. `limit(2)` is enough to tell those cases apart.
 */
export async function getSoleTeam() {
  const teams = await Team.find({}).limit(2);
  return teams.length === 1 ? teams[0] : null;
}
```

- [ ] **Step 6: Verify the whole API unit suite and types still pass**

```bash
cd packages/api && yarn ci:unit && npx tsc --noEmit -p tsconfig.json
```

Expected: PASS. In particular
`src/routers/api/__tests__/team.int.test.ts` is excluded from `ci:unit`, and its
snapshots asserting `hasPasswordAuth: true` remain correct because those fixtures
register through `User.register()`, which sets `salt`.

- [ ] **Step 7: Commit**

```bash
git add packages/api/src/models/user.ts packages/api/src/models/__tests__/user.test.ts packages/api/src/controllers/user.ts packages/api/src/controllers/team.ts
git commit -m "feat(api): add User.googleId and sole-team lookup for Google SSO"
```

---

### Task 3: Configuration and the Google strategy

Wire the environment variables and register the Passport strategy. Nothing is
reachable yet — Task 4 adds the routes.

**Files:**
- Modify: `packages/api/package.json`
- Modify: `packages/api/src/config.ts`
- Modify: `packages/api/src/utils/passport.ts`
- Modify: `packages/api/.env.development`

**Interfaces:**
- Consumes: `parseAllowedDomains`, `evaluateGoogleProfile` from Task 1;
  `findUserByGoogleId` and `getSoleTeam` from Task 2.
- Produces:
  - `config.GOOGLE_CLIENT_ID: string`
  - `config.GOOGLE_CLIENT_SECRET: string`
  - `config.GOOGLE_ALLOWED_DOMAINS: string[]`
  - `config.GOOGLE_REDIRECT_URI: string`
  - `config.IS_GOOGLE_AUTH_ENABLED: boolean`
  - A Passport strategy registered under the name `'google'`, present only when
    `IS_GOOGLE_AUTH_ENABLED`

- [ ] **Step 1: Install the dependency**

```bash
cd /Users/dohaelsawy/hyperdx && yarn workspace @hyperdx/api add passport-google-oauth20 && yarn workspace @hyperdx/api add -D @types/passport-google-oauth20
```

Expected: `packages/api/package.json` gains `passport-google-oauth20` under
`dependencies` and `@types/passport-google-oauth20` under `devDependencies`;
`yarn.lock` updates.

- [ ] **Step 2: Add the config values**

`packages/api/src/config.ts` currently has no imports. Add one as its first
line — `packages/api/src/utils/googleAuth.ts` imports nothing itself, so there
is no cycle:

```ts
import { parseAllowedDomains } from '@/utils/googleAuth';
```

Then append to the end of the same file. It must go at the end, after the
existing `FRONTEND_URL` and `IS_LOCAL_APP_MODE` declarations, because it reads
both:

```ts
// Google SSO (optional). Disabled entirely unless both credentials are set, so
// an unconfigured deployment behaves exactly as it did before this feature.
export const GOOGLE_CLIENT_ID = env.GOOGLE_CLIENT_ID ?? '';
export const GOOGLE_CLIENT_SECRET = env.GOOGLE_CLIENT_SECRET ?? '';
/** Empty means no auto-provisioning at all — existing users can still sign in. */
export const GOOGLE_ALLOWED_DOMAINS = parseAllowedDomains(
  env.GOOGLE_ALLOWED_DOMAINS,
);
export const GOOGLE_REDIRECT_URI =
  env.GOOGLE_REDIRECT_URI || `${FRONTEND_URL}/api/auth/google/callback`;
export const IS_GOOGLE_AUTH_ENABLED =
  Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) && !IS_LOCAL_APP_MODE;
```

- [ ] **Step 3: Add the placeholders to the dev env file**

Append to `packages/api/.env.development`:

```
# Google SSO — leave unset to disable the feature entirely.
# Redirect URI to register in the Google Cloud Console:
#   http://localhost:${HYPERDX_APP_PORT}/api/auth/google/callback
# GOOGLE_CLIENT_ID=
# GOOGLE_CLIENT_SECRET=
# GOOGLE_ALLOWED_DOMAINS=luciq.ai
# GOOGLE_REDIRECT_URI=
```

- [ ] **Step 4: Register the strategy**

In `packages/api/src/utils/passport.ts`, add these imports at the top, keeping
them in the existing grouping order:

```ts
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as LocalStrategy } from 'passport-local';

import * as config from '@/config';
import { getSoleTeam } from '@/controllers/team';
import {
  findUserByEmail,
  findUserByGoogleId,
  findUserById,
} from '@/controllers/user';
import type { UserDocument } from '@/models/user';
import User from '@/models/user';
import { evaluateGoogleProfile } from '@/utils/googleAuth';

import logger from './logger';
```

Then append to the end of the file, above `export default passport;`:

```ts
if (config.IS_GOOGLE_AUTH_ENABLED) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: config.GOOGLE_CLIENT_ID,
        clientSecret: config.GOOGLE_CLIENT_SECRET,
        callbackURL: config.GOOGLE_REDIRECT_URI,
        scope: ['openid', 'email', 'profile'],
        // Session-backed CSRF state. The session middleware is already
        // installed ahead of passport in api-app.ts.
        state: true,
      },
      async function (_accessToken, _refreshToken, profile, done) {
        try {
          const claims = profile._json as {
            email?: string;
            email_verified?: boolean;
          };
          const email = claims.email ?? profile.emails?.[0]?.value;
          const emailVerified = claims.email_verified === true;

          const byGoogleId = await findUserByGoogleId(profile.id);
          const byEmail =
            byGoogleId == null && email != null
              ? await findUserByEmail(email)
              : null;

          const existingUser = byGoogleId
            ? ({ user: byGoogleId, matchedBy: 'googleId' } as const)
            : byEmail
              ? ({ user: byEmail, matchedBy: 'email' } as const)
              : null;

          const decision = evaluateGoogleProfile(
            { googleId: profile.id, email, emailVerified },
            {
              allowedDomains: config.GOOGLE_ALLOWED_DOMAINS,
              existingUser,
              soleTeam: existingUser ? null : await getSoleTeam(),
            },
          );

          if (decision.action === 'reject') {
            logger.info({
              message: `Google login for "${email}" rejected: ${decision.code}`,
              type: 'user_login',
              authType: 'google',
            });
            return done(null, false, { message: decision.code });
          }

          if (decision.action === 'provision') {
            const created = new User({
              email: decision.email,
              name: decision.email,
              team: decision.team._id,
              googleId: profile.id,
            });
            await created.save();
            logger.info({
              message: `Provisioned user "${decision.email}" via Google`,
              type: 'user_login',
              authType: 'google',
            });
            return done(null, created);
          }

          if (decision.stampGoogleId) {
            decision.user.googleId = profile.id;
            await decision.user.save();
          }
          return done(null, decision.user);
        } catch (err) {
          logger.error({ err }, 'Google login failed with error');
          return done(err as Error);
        }
      },
    ),
  );
}
```

Note the `soleTeam` argument: the team lookup is skipped entirely when an
existing user was found, because the policy never consults it on that path.

- [ ] **Step 5: Verify types and the unit suite**

```bash
cd packages/api && npx tsc --noEmit -p tsconfig.json && yarn ci:unit
```

Expected: PASS. If `state: true` produces a type error, the option belongs to
`passport-oauth2`'s `StrategyOptions`; import
`import type { StrategyOptions } from 'passport-google-oauth20';` and annotate
the options object rather than removing the option — the CSRF protection is
required.

- [ ] **Step 6: Commit**

```bash
git add packages/api/package.json packages/api/src/config.ts packages/api/src/utils/passport.ts packages/api/.env.development yarn.lock
git commit -m "feat(api): register Google OAuth strategy behind config flag"
```

---

### Task 4: Routes, error codes, and provider discovery

Make the flow reachable, map rejection codes onto the redirect, and tell the
frontend whether Google is available.

**Files:**
- Modify: `packages/common-utils/src/types.ts` (`InstallationApiResponseSchema`)
- Modify: `packages/api/src/middleware/auth.ts` (`handleAuthError`)
- Modify: `packages/api/src/routers/api/root.ts`
- Test: `packages/api/src/middleware/__tests__/auth.test.ts`

**Interfaces:**
- Consumes: `config.IS_GOOGLE_AUTH_ENABLED` from Task 3; the `'google'` strategy
  from Task 3.
- Produces:
  - `InstallationApiResponse` gains `authProviders?: ('password' | 'google')[]`
  - `function makeAuthErrorHandler(fallbackErrorCode: string)` in
    `@/middleware/auth`
  - `const handleAuthError` — unchanged name and behavior, now
    `makeAuthErrorHandler('unknown')`
  - `const handleGoogleAuthError` — `makeAuthErrorHandler('googleAuthFailed')`
  - Routes `GET /auth/google` and `GET /auth/google/callback`

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/middleware/__tests__/auth.test.ts`. It follows the
mocking style already established in `src/middleware/__tests__/error.test.ts`:

```ts
import type { NextFunction, Request, Response } from 'express';

const mockLogger = { debug: jest.fn(), error: jest.fn(), warn: jest.fn() };

jest.mock('@/config', () => ({
  FRONTEND_REDIRECT_BASE: 'http://localhost:8080',
  IS_LOCAL_APP_MODE: false,
}));
jest.mock('@/utils/logger', () => ({ __esModule: true, default: mockLogger }));
jest.mock('@/utils/instrumentation', () => ({
  getStaticFeatureFlags: () => ({}),
  setBusinessContext: jest.fn(),
}));
jest.mock('@/controllers/user', () => ({ findUserByAccessKey: jest.fn() }));

import { handleAuthError, handleGoogleAuthError } from '@/middleware/auth';

const invoke = (
  handler: (e: any, req: Request, res: Response, next: NextFunction) => void,
  messages: string[],
) => {
  const res = { headersSent: false, redirect: jest.fn() } as unknown as Response;
  const req = { session: { messages } } as unknown as Request;
  handler(new Error('auth failed'), req, res, jest.fn());
  return res;
};

describe('handleAuthError', () => {
  it('maps the local-strategy failure to authFail', () => {
    const res = invoke(handleAuthError, ['Password or username is incorrect']);
    expect(res.redirect).toHaveBeenCalledWith(
      303,
      'http://localhost:8080/login?err=authFail',
    );
  });

  it('maps the team-policy failure to passwordAuthNotAllowed', () => {
    const res = invoke(handleAuthError, [
      'Authentication method password is not allowed by your team admin.',
    ]);
    expect(res.redirect).toHaveBeenCalledWith(
      303,
      'http://localhost:8080/login?err=passwordAuthNotAllowed',
    );
  });

  it('falls back to unknown for an unrecognised message', () => {
    const res = invoke(handleAuthError, ['something else entirely']);
    expect(res.redirect).toHaveBeenCalledWith(
      303,
      'http://localhost:8080/login?err=unknown',
    );
  });

  it.each([
    'googleEmailUnverified',
    'googleDomainNotAllowed',
    'googleNoTeam',
    'googleAccountMismatch',
  ])('passes the %s reject code through', code => {
    const res = invoke(handleGoogleAuthError, [code]);
    expect(res.redirect).toHaveBeenCalledWith(
      303,
      `http://localhost:8080/login?err=${code}`,
    );
  });

  it('falls back to googleAuthFailed when there is no message at all', () => {
    const res = invoke(handleGoogleAuthError, []);
    expect(res.redirect).toHaveBeenCalledWith(
      303,
      'http://localhost:8080/login?err=googleAuthFailed',
    );
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd packages/api && yarn ci:unit src/middleware/__tests__/auth.test.ts
```

Expected: FAIL — `handleGoogleAuthError` is not exported.

- [ ] **Step 3: Refactor handleAuthError into a factory**

In `packages/api/src/middleware/auth.ts`, replace the whole `handleAuthError`
function with:

```ts
/** Reject codes emitted by `evaluateGoogleProfile`, passed through verbatim. */
const GOOGLE_REJECT_CODES = new Set([
  'googleEmailUnverified',
  'googleDomainNotAllowed',
  'googleNoTeam',
  'googleAccountMismatch',
]);

export function makeAuthErrorHandler(fallbackErrorCode: string) {
  return function authErrorHandler(
    err: any,
    req: Request,
    res: Response,
    next: NextFunction,
  ) {
    logger.debug({ authErr: serializeError(err) }, 'Auth error');
    if (res.headersSent) {
      return next(err);
    }

    // Get the latest auth error message
    const lastMessage = req.session.messages?.at(-1);
    logger.debug(`Auth error last message: ${lastMessage}`);

    const returnErr =
      lastMessage === 'Password or username is incorrect'
        ? 'authFail'
        : lastMessage ===
            'Authentication method password is not allowed by your team admin.'
          ? 'passwordAuthNotAllowed'
          : lastMessage != null && GOOGLE_REJECT_CODES.has(lastMessage)
            ? lastMessage
            : fallbackErrorCode;

    // 303 forces GET on the redirected request even when the original request
    // was a POST (e.g. /login/password failure path).
    res.redirect(303, `${config.FRONTEND_REDIRECT_BASE}/login?err=${returnErr}`);
  };
}

export const handleAuthError = makeAuthErrorHandler('unknown');
export const handleGoogleAuthError = makeAuthErrorHandler('googleAuthFailed');
```

`handleAuthError` keeps its exported name and its exact previous behavior, so
`/login/password` is unaffected.

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd packages/api && yarn ci:unit src/middleware/__tests__/auth.test.ts
```

Expected: PASS, 8 tests.

- [ ] **Step 5: Extend the installation response schema**

In `packages/common-utils/src/types.ts`, replace
`InstallationApiResponseSchema`:

```ts
// Installation
export const InstallationApiResponseSchema = z.object({
  isTeamExisting: z.boolean(),
  // Optional so a newer app deployed against an older API still validates.
  authProviders: z.array(z.enum(['password', 'google'])).optional(),
});
```

Rebuild so the app package picks up the new type:

```bash
cd /Users/dohaelsawy/hyperdx && yarn build:common-utils
```

- [ ] **Step 6: Add the routes and report the providers**

In `packages/api/src/routers/api/root.ts`, update the import of the auth
middleware:

```ts
import {
  handleAuthError,
  handleGoogleAuthError,
  redirectToDashboard,
} from '@/middleware/auth';
```

Replace the body of the `/installation` handler:

```ts
router.get('/installation', async (_, res: InstallationEspRes, next) => {
  try {
    const _isTeamExisting = await isTeamExisting();
    return res.json({
      isTeamExisting: _isTeamExisting,
      authProviders: config.IS_GOOGLE_AUTH_ENABLED
        ? ['password', 'google']
        : ['password'],
    });
  } catch (e) {
    next(e);
  }
});
```

Add the two routes immediately after the existing `/login/password` route:

```ts
// Google SSO. Registered only when credentials are configured, so these paths
// 404 on an unconfigured deployment.
if (config.IS_GOOGLE_AUTH_ENABLED) {
  router.get(
    '/auth/google',
    passport.authenticate('google', { scope: ['openid', 'email', 'profile'] }),
  );

  router.get(
    '/auth/google/callback',
    passport.authenticate('google', {
      failWithError: true,
      failureMessage: true,
    }),
    redirectToDashboard,
    handleGoogleAuthError,
  );
}
```

- [ ] **Step 7: Verify types and the unit suite**

```bash
cd /Users/dohaelsawy/hyperdx && make ci-lint && cd packages/api && yarn ci:unit
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add packages/common-utils/src/types.ts packages/api/src/middleware/auth.ts packages/api/src/middleware/__tests__/auth.test.ts packages/api/src/routers/api/root.ts
git commit -m "feat(api): add Google SSO routes, reject codes, and provider discovery"
```

---

### Task 5: The sign-in button

**Files:**
- Create: `packages/app/src/components/GoogleSignInButton.tsx`
- Modify: `packages/app/src/AuthPage.tsx`

**Interfaces:**
- Consumes: `InstallationApiResponse.authProviders` from Task 4, via the
  existing `api.useInstallation()` hook; the reject codes from Tasks 1 and 4 as
  `?err=` query values.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Create the button component**

`AuthPage.tsx` is already ~270 lines, so the button and its mark live in their
own file. Create `packages/app/src/components/GoogleSignInButton.tsx`:

```tsx
import { Button } from '@mantine/core';

// Official Google "G" mark. Inlined so the button has no network dependency.
function GoogleMark() {
  return (
    <svg width={18} height={18} viewBox="0 0 48 48" aria-hidden="true">
      <path
        fill="#EA4335"
        d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"
      />
      <path
        fill="#4285F4"
        d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"
      />
      <path
        fill="#FBBC05"
        d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"
      />
      <path
        fill="#34A853"
        d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"
      />
    </svg>
  );
}

export default function GoogleSignInButton() {
  // A real anchor, not a fetch: the OAuth flow is a full-page navigation.
  return (
    <Button
      component="a"
      href="/api/auth/google"
      variant="secondary"
      size="md"
      fullWidth
      leftSection={<GoogleMark />}
      data-test-id="google-sign-in"
    >
      Sign in with Google
    </Button>
  );
}
```

- [ ] **Step 2: Replace the nested error ternary with a lookup map**

In `packages/app/src/AuthPage.tsx`, add above the `AuthPage` component (after
the `FormData` type):

```tsx
const AUTH_ERROR_MESSAGES: Record<string, string> = {
  missing: 'Please provide a valid email and password',
  invalid: 'Email or password is invalid',
  authFail: 'Failed to login with email and password, please try again.',
  passwordAuthNotAllowed:
    'Password authentication is not allowed by your team admin.',
  teamAlreadyExists: 'Team already exists, please login instead.',
  googleEmailUnverified:
    'Your Google email address is not verified. Verify it with Google and try again.',
  googleDomainNotAllowed:
    'This Google account is not permitted to sign in. Contact your admin.',
  googleNoTeam:
    'No team has been set up yet. Register with a password first.',
  googleAccountMismatch:
    'This email is already linked to a different Google account. Contact your admin.',
  googleAuthFailed: 'Google sign-in failed, please try again.',
};

const DEFAULT_AUTH_ERROR = 'Unknown error occurred, please try again later.';
```

Then replace the entire ternary chain inside the error `<Notification>` — the
block currently spanning from `{err === 'missing'` to
`: 'Unknown error occurred, please try again later.'}` — with:

```tsx
                  {AUTH_ERROR_MESSAGES[String(err)] ?? DEFAULT_AUTH_ERROR}
```

Every previously-handled code maps to its identical previous string, so this is
behavior-preserving.

- [ ] **Step 3: Render the button**

Add the imports at the top of `packages/app/src/AuthPage.tsx` — `Divider` joins
the existing `@mantine/core` import list, keeping it alphabetical:

```tsx
import {
  Button,
  Divider,
  Notification,
  Paper,
  PasswordInput,
  Stack,
  TextInput,
} from '@mantine/core';

import GoogleSignInButton from './components/GoogleSignInButton';
```

Add the derived flag next to the existing `installation` line:

```tsx
  const { data: installation } = api.useInstallation();
  const isGoogleAuthEnabled =
    installation?.authProviders?.includes('google') === true;
```

Render it inside the `<Paper>`, immediately after the closing tag of the submit
`<Button>` and before the closing `</Stack>`:

```tsx
                  {isGoogleAuthEnabled && (
                    <>
                      <Divider label="or" labelPosition="center" />
                      <GoogleSignInButton />
                    </>
                  )}
```

- [ ] **Step 4: Verify the app builds and its unit tests pass**

```bash
cd /Users/dohaelsawy/hyperdx && yarn build:common-utils && cd packages/app && npx tsc --noEmit && yarn ci:unit
```

Expected: PASS. The `authProviders` field must resolve on
`InstallationApiResponse`; if it does not, `yarn build:common-utils` did not run
after Task 4 Step 5.

- [ ] **Step 5: Commit**

```bash
git add packages/app/src/components/GoogleSignInButton.tsx packages/app/src/AuthPage.tsx
git commit -m "feat(app): add Sign in with Google button to the auth page"
```

---

### Task 6: Changeset and full verification

**Files:**
- Create: `.changeset/google-sso.md`

**Interfaces:**
- Consumes: everything above.
- Produces: nothing.

- [ ] **Step 1: Write the changeset**

Create `.changeset/google-sso.md`, following the format of the existing entries
in `.changeset/`:

```markdown
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
```

- [ ] **Step 2: Run lint and the full unit suite**

```bash
cd /Users/dohaelsawy/hyperdx && yarn lint:fix && make ci-lint && make ci-unit
```

Expected: PASS across all packages.

- [ ] **Step 3: Verify the feature is inert when unconfigured**

With `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` still commented out in
`packages/api/.env.development`, start the stack:

```bash
cd /Users/dohaelsawy/hyperdx && yarn dev
```

Then, from another shell, with `<APP_PORT>` taken from the dev portal at
http://localhost:9900:

```bash
curl -s http://localhost:<APP_PORT>/api/installation
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:<APP_PORT>/api/auth/google
```

Expected: the first prints `{"isTeamExisting":...,"authProviders":["password"]}`;
the second prints `404`. Load `/login` in a browser and confirm no Google button
renders and the password form still logs in.

- [ ] **Step 4: Verify the flow with credentials set**

Uncomment and fill `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and
`GOOGLE_ALLOWED_DOMAINS` in `packages/api/.env.development`, register
`http://localhost:<APP_PORT>/api/auth/google/callback` as an authorized redirect
URI in the Google Cloud Console, and restart `yarn dev`.

Expected: `/api/installation` now reports
`"authProviders":["password","google"]`; the button renders on `/login`;
clicking it reaches Google's consent screen and returns to the dashboard. Then
check the rejection path by removing your own domain from
`GOOGLE_ALLOWED_DOMAINS` while logged out with no matching User — the callback
should land on `/login?err=googleDomainNotAllowed` with the matching message.

- [ ] **Step 5: Commit**

```bash
git add .changeset/google-sso.md
git commit -m "chore: add changeset for Google SSO"
```

---

## Notes for the implementer

- **Do not add `googleId` to the OSS password registration path.** Provisioning
  a Google user deliberately bypasses `User.register()` so the document has no
  `salt`/`hash`, which is what makes the local strategy refuse to authenticate
  it. Calling `User.register()` for a Google user would be a bug.
- **The `unique: true, sparse: true` index on `googleId` matters.** Without
  `sparse`, every password-only user has `googleId: undefined` and MongoDB would
  reject the second such user for violating uniqueness.
- **Order matters in `evaluateGoogleProfile`.** The domain check runs before the
  team check so an unauthorized stranger cannot probe whether the instance has
  been set up.
- **`IS_LOCAL_APP_MODE` disables Google.** Passport is not initialized at all in
  that mode (`api-app.ts` skips `passport.initialize()`), so
  `IS_GOOGLE_AUTH_ENABLED` must stay false there.
