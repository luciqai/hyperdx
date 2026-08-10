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
  const res = {
    headersSent: false,
    redirect: jest.fn(),
  } as unknown as Response;
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

  it.each([
    'googleEmailUnverified',
    'googleDomainNotAllowed',
    'googleNoTeam',
    'googleAccountMismatch',
  ])(
    'does NOT pass the %s Google reject code through handleAuthError',
    code => {
      const res = invoke(handleAuthError, [code]);
      expect(res.redirect).toHaveBeenCalledWith(
        303,
        'http://localhost:8080/login?err=unknown',
      );
    },
  );
});

describe('handleGoogleAuthError', () => {
  it('does NOT pass through the local-strategy incorrect-password message', () => {
    const res = invoke(handleGoogleAuthError, [
      'Password or username is incorrect',
    ]);
    expect(res.redirect).toHaveBeenCalledWith(
      303,
      'http://localhost:8080/login?err=googleAuthFailed',
    );
  });

  it('does NOT pass through the local-strategy team-policy message', () => {
    const res = invoke(handleGoogleAuthError, [
      'Authentication method password is not allowed by your team admin.',
    ]);
    expect(res.redirect).toHaveBeenCalledWith(
      303,
      'http://localhost:8080/login?err=googleAuthFailed',
    );
  });
});

describe('session message hygiene', () => {
  it('clears req.session.messages after reading it, so a stale message from a prior attempt is never reused', () => {
    const req = {
      session: { messages: ['Password or username is incorrect'] },
    } as unknown as Request;
    const res1 = {
      headersSent: false,
      redirect: jest.fn(),
    } as unknown as Response;

    // First attempt: a mistyped password leaves a message in the session.
    handleAuthError(new Error('auth failed'), req, res1, jest.fn());
    expect(res1.redirect).toHaveBeenCalledWith(
      303,
      'http://localhost:8080/login?err=authFail',
    );
    expect(req.session.messages).toEqual([]);

    // Second attempt on the same session: the user cancels the Google
    // consent screen, which appends nothing to req.session.messages. The
    // stale password message must not resurface.
    const res2 = {
      headersSent: false,
      redirect: jest.fn(),
    } as unknown as Response;
    handleGoogleAuthError(new Error('cancelled'), req, res2, jest.fn());
    expect(res2.redirect).toHaveBeenCalledWith(
      303,
      'http://localhost:8080/login?err=googleAuthFailed',
    );
  });
});
