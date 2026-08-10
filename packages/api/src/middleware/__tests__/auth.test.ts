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
});
