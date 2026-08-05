import {
  hasPermission,
  type PermissionLevel,
  type Resource,
} from '@hyperdx/common-utils/dist/types';
import type { NextFunction, Request, RequestHandler, Response } from 'express';

import * as config from '@/config';
import { getCounter } from '@/utils/instrumentation';
import logger from '@/utils/logger';

/**
 * Generic-transparent handler type.
 *
 * Express unifies the generics of every handler passed to `router.get(...)`.
 * A concrete `RequestHandler` defaults `req.query` to `ParsedQs`, which
 * collides with routes whose `processRequest` narrows the query type — the
 * overload then silently collapses to `ParsedQs` and the handler stops
 * type-checking. Declaring `any` for each slot lets these middlewares sit in
 * any position without constraining the route's inferred types.
 */
type AnyRequestHandler = RequestHandler<any, any, any, any, any>;

export type RbacExemptReason = 'public' | 'personal-state';

export type RbacDeclaration =
  | { kind: 'permission'; resource: Resource; level: PermissionLevel }
  | { kind: 'admin' }
  | { kind: 'exempt'; reason: RbacExemptReason };

export const RBAC_DECLARATION = Symbol('rbacDeclaration');

const missingRoleCounter = getCounter('hyperdx.rbac.missing_role', {
  description:
    'Requests served with no role assigned, resolved as admin (fail-open). Non-zero means the RBAC migration has not run.',
});

const deniedCounter = getCounter('hyperdx.rbac.denied', {
  description:
    'Requests rejected by RBAC, labeled by resource and required level.',
});

function tag<T extends RequestHandler>(
  handler: T,
  declaration: RbacDeclaration,
): T {
  Object.defineProperty(handler, RBAC_DECLARATION, {
    value: declaration,
    enumerable: false,
  });
  return handler;
}

export function getRbacDeclaration(
  handler: unknown,
): RbacDeclaration | undefined {
  if (typeof handler !== 'function') return undefined;
  return (handler as any)[RBAC_DECLARATION];
}

/** Minimal shape the resolver needs. Populated `Role` document, or absent. */
export type RoleLike = {
  name?: string;
  isAdmin?: boolean;
  permissions?: Partial<Record<Resource, PermissionLevel>>;
} | null;

/** How the caller authenticated. Determines the missing-role fail mode. */
export type AuthPath = 'session' | 'access-key';

/**
 * `allow` — pass without consulting the permission map.
 * `deny`  — reject outright.
 * `check` — consult the permission map.
 */
export type Verdict = 'allow' | 'deny' | 'check';

/**
 * Shared resolution order, cheapest first. Pure so both the Express middleware
 * and the MCP tool wrapper use identical logic.
 *
 * The missing-role branch diverges by auth path deliberately. Slice A's
 * fail-open exists so a self-hosted operator upgrading mid-incident is not
 * locked out of their own observability tool — an argument about a human at a
 * browser. An unattended agent holding a Bearer token has no equivalent claim,
 * and silently granting it admin is worse than failing its tool call.
 */
export function resolveVerdict(
  role: RoleLike,
  authPath: AuthPath,
  actorId?: string,
): Verdict {
  if (config.IS_LOCAL_APP_MODE) return 'allow';

  if (role == null) {
    missingRoleCounter.add(1, { path: authPath });
    if (authPath === 'access-key') {
      logger.warn(
        { userId: actorId, authPath },
        'RBAC: access-key user has no role assigned; denying. Assign a role to this user.',
      );
      return 'deny';
    }
    logger.warn(
      { userId: actorId, authPath },
      'RBAC: user has no role assigned; allowing as admin. Run the RBAC migration.',
    );
    return 'allow';
  }

  return role.isAdmin === true ? 'allow' : 'check';
}

function verdictFor(req: Request): Verdict {
  return resolveVerdict(
    (req.user as any)?.role ?? null,
    (req as any)._hdx_authPath === 'access-key' ? 'access-key' : 'session',
    (req.user as any)?._id?.toString(),
  );
}

function deny(
  res: Response,
  required?: { resource: Resource; level: PermissionLevel },
) {
  if (required) {
    deniedCounter.add(1, {
      resource: required.resource,
      level: required.level,
    });
  } else {
    deniedCounter.add(1, { resource: 'admin', level: 'admin' });
  }

  return res.status(403).json({
    message: 'You do not have permission to perform this action.',
    ...(required ? { required } : { required: { resource: 'admin' } }),
  });
}

export function requirePermission(
  resource: Resource,
  level: PermissionLevel,
): AnyRequestHandler {
  const handler = (req: Request, res: Response, next: NextFunction) => {
    const verdict = verdictFor(req);
    if (verdict === 'allow') return next();
    if (verdict === 'deny') return deny(res, { resource, level });

    const held = (req.user as any).role?.permissions?.[resource];
    if (hasPermission(held, level)) return next();

    return deny(res, { resource, level });
  };

  return tag(handler, { kind: 'permission', resource, level });
}

/**
 * Hard capability. Deliberately not expressible as a permission, so no custom
 * role can grant it and no escalation check is needed.
 */
export function requireAdmin(): AnyRequestHandler {
  const handler = (req: Request, res: Response, next: NextFunction) => {
    // 'check' means "has a role but it is not admin" — admin is not
    // expressible as a permission, so anything short of 'allow' is a denial.
    if (verdictFor(req) === 'allow') return next();
    return deny(res);
  };

  return tag(handler, { kind: 'admin' });
}

/** Explicit opt-out. The reason string appears in the boot coverage report. */
export function noPermissionRequired(
  reason: RbacExemptReason,
): AnyRequestHandler {
  const handler = (_req: Request, _res: Response, next: NextFunction) => next();
  return tag(handler, { kind: 'exempt', reason });
}
