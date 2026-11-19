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
