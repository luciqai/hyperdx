import type { GoogleAuthContext, GoogleProfileInput } from '@/utils/googleAuth';
import {
  emailDomain,
  evaluateGoogleProfile,
  parseAllowedDomains,
} from '@/utils/googleAuth';

type TestUser = { _id: string; email: string; googleId?: string | null };
type TestTeam = { _id: string };

const TEAM: TestTeam = { _id: 'team-1' };

const profile = (
  over: Partial<GoogleProfileInput> = {},
): GoogleProfileInput => ({
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
    expect(evaluateGoogleProfile(profile({ email: undefined }), ctx())).toEqual(
      { action: 'reject', code: 'googleEmailUnverified' },
    );
  });

  it('logs in a user matched by googleId without re-stamping', () => {
    const user: TestUser = {
      _id: 'u1',
      email: 'ada@luciq.ai',
      googleId: 'sub-1',
    };
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
        ctx({
          allowedDomains: ['luciq.ai'],
          existingUser: { user, matchedBy: 'email' },
        }),
      ),
    ).toEqual({ action: 'login', user, stampGoogleId: true });
  });

  it('logs in an existing user even when the allowlist is empty', () => {
    const user: TestUser = {
      _id: 'u1',
      email: 'ada@luciq.ai',
      googleId: 'sub-1',
    };
    expect(
      evaluateGoogleProfile(
        profile(),
        ctx({
          allowedDomains: [],
          existingUser: { user, matchedBy: 'googleId' },
        }),
      ),
    ).toEqual({ action: 'login', user, stampGoogleId: false });
  });

  it('rejects when the email matches a user linked to a different Google account', () => {
    const user: TestUser = {
      _id: 'u1',
      email: 'ada@luciq.ai',
      googleId: 'sub-OLD',
    };
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
    expect(evaluateGoogleProfile(profile(), ctx({ soleTeam: null }))).toEqual({
      action: 'reject',
      code: 'googleNoTeam',
    });
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
