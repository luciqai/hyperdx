import { Connection } from '@hyperdx/common-utils/dist/types';
import type { NextFunction, Request, Response } from 'express';
import { serializeError } from 'serialize-error';

import * as config from '@/config';
import { findUserByAccessKey } from '@/controllers/user';
import type { UserDocument } from '@/models/user';
import {
  getStaticFeatureFlags,
  setBusinessContext,
} from '@/utils/instrumentation';
import logger from '@/utils/logger';

declare global {
  // Express type augmentation requires `namespace` + interface merging; there is
  // no non-namespace / non-empty-interface equivalent for extending these types.
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    // eslint-disable-next-line @typescript-eslint/no-empty-object-type
    interface User extends UserDocument {}
    interface Request {
      _hdx_connection?: Connection;
      /** Set by validateUserAccessKey; absent on the session path. */
      _hdx_authPath?: 'access-key';
    }
  }
}

declare module 'express-session' {
  interface Session {
    messages: string[]; // Set by passport
    passport: { user: string }; // Set by passport
  }
}

export function redirectToDashboard(req: Request, res: Response) {
  // Use 303 See Other so browsers always follow the redirect with GET, even
  // when the original request was a POST (e.g. /login/password). Without an
  // explicit status, Express sends 302 and some browsers/proxies preserve the
  // POST method, which produces a 405 on Next.js pages that only accept GET.
  // The destination is the app root so client-side routing in LandingPage
  // decides where to send the user (/search if logged in, /login otherwise).
  // This avoids hard-coding /search here, which fails when the post-login
  // host differs from the configured FRONTEND_URL (e.g. Vercel previews).
  if (req?.user?.team) {
    return res.redirect(303, `${config.FRONTEND_REDIRECT_BASE}/`);
  } else {
    logger.error(
      { userId: req?.user?._id },
      'Login for user failed, user or team not found',
    );
    res.redirect(303, `${config.FRONTEND_REDIRECT_BASE}/login?err=unknown`);
  }
}

/** Reject codes emitted by `evaluateGoogleProfile`, passed through verbatim. */
const GOOGLE_REJECT_CODES = new Set([
  'googleEmailUnverified',
  'googleDomainNotAllowed',
  'googleNoTeam',
  'googleAccountMismatch',
]);

/**
 * Local-strategy failure messages (from passport-local-mongoose /
 * `failureMessage: true`), translated to their `/login?err=` codes. A
 * translation, not a passthrough, so it must stay scoped to
 * `handleAuthError` below — otherwise a stale message left in the session by
 * one handler could be misattributed to a later, unrelated failure handled
 * by the other (see `messageCodes`/`passThroughCodes` params).
 */
const PASSWORD_ERROR_CODES: ReadonlyMap<string, string> = new Map([
  ['Password or username is incorrect', 'authFail'],
  [
    'Authentication method password is not allowed by your team admin.',
    'passwordAuthNotAllowed',
  ],
]);

export function makeAuthErrorHandler(
  fallbackErrorCode: string,
  passThroughCodes: ReadonlySet<string> = new Set(),
  messageCodes: ReadonlyMap<string, string> = new Map(),
) {
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

    // Get the latest auth error message, then clear the list. Passport only
    // ever appends here, never removes, so without clearing, a stale message
    // from an earlier, unrelated attempt (e.g. a mistyped password) would be
    // misattributed to a later attempt that fails silently (e.g. declining
    // Google's consent screen appends nothing to this array). Clearing also
    // caps the array's otherwise-unbounded growth across a session.
    const lastMessage = req.session.messages?.at(-1);
    req.session.messages = [];
    logger.debug(`Auth error last message: ${lastMessage}`);

    // `messageCodes` and `passThroughCodes` are both allowlists scoped per
    // handler: only messages/codes explicitly known to belong to this
    // handler's flow may produce anything other than the fallback.
    // Reflecting `lastMessage` into the redirect without this check would let
    // attacker-influenced session content flow into the `Location` header.
    const returnErr =
      lastMessage != null && messageCodes.has(lastMessage)
        ? messageCodes.get(lastMessage)
        : lastMessage != null && passThroughCodes.has(lastMessage)
          ? lastMessage
          : fallbackErrorCode;

    // 303 forces GET on the redirected request even when the original request
    // was a POST (e.g. /login/password failure path).
    res.redirect(
      303,
      `${config.FRONTEND_REDIRECT_BASE}/login?err=${returnErr}`,
    );
  };
}

export const handleAuthError = makeAuthErrorHandler(
  'unknown',
  undefined,
  PASSWORD_ERROR_CODES,
);
export const handleGoogleAuthError = makeAuthErrorHandler(
  'googleAuthFailed',
  GOOGLE_REJECT_CODES,
);

export function getAccessKeyFromRequest(req: Request): string | undefined {
  return req.headers.authorization?.split('Bearer ')[1];
}

export async function validateUserAccessKey(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const key = getAccessKeyFromRequest(req);
  if (!key) {
    return res.sendStatus(401);
  }

  const user = await findUserByAccessKey(key);
  if (!user) {
    return res.sendStatus(401);
  }

  req.user = user;
  // Tells the RBAC resolver which fail mode applies when no role is assigned:
  // the browser fails open as admin, this path fails closed.
  req._hdx_authPath = 'access-key';

  // Attribute access-key authenticated requests (external API v2 + MCP HTTP)
  // with team/user context so their traces are searchable during incidents.
  setBusinessContext({
    teamId: user.team?.toString(),
    userId: user._id?.toString(),
    email: user.email,
    ...getStaticFeatureFlags(),
  });

  next();
}

export function isUserAuthenticated(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  if (config.IS_LOCAL_APP_MODE) {
    // If local app mode is enabled, skip authentication
    logger.warn('Skipping authentication in local app mode');
    req.user = {
      // @ts-expect-error local app mode uses a synthetic string id, not an ObjectId
      _id: '_local_user_',
      email: 'local-user@hyperdx.io',
      // @ts-expect-error local app mode uses a synthetic string team, not an ObjectId
      team: '_local_team_',
    };
    setBusinessContext({
      teamId: '_local_team_',
      userId: '_local_user_',
      'hyperdx.local_mode': true,
      ...getStaticFeatureFlags(),
    });
    return next();
  }

  if (req.isAuthenticated()) {
    // Attach incident-remediation context to the trace and active span.
    setBusinessContext({
      teamId: req.user?.team?.toString(),
      userId: req.user?._id?.toString(),
      email: req.user?.email,
      ...getStaticFeatureFlags(),
    });

    return next();
  }
  res.sendStatus(401);
}

export function getNonNullUserWithTeam(req: Request) {
  const user = req.user;

  if (!user) {
    throw new Error('User is not authenticated');
  }

  if (!user.team) {
    throw new Error(`User ${user._id} is not associated with a team`);
  }

  return { teamId: user.team, userId: user._id, email: user.email };
}
