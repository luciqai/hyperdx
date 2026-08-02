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

export type RbacExemptReason =
  | 'public'
  | 'personal-state'
  | 'query-path-slice-B';

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

/**
 * Resolution order, cheapest first. Returns true when the request should pass
 * without consulting the permission map.
 */
function shortCircuits(req: Request): boolean {
  if (config.IS_LOCAL_APP_MODE) return true;

  const role = (req.user as any)?.role;

  if (role == null) {
    // Deliberate fail-open. A self-hosted operator upgrading mid-incident
    // should not be locked out of their own observability tool because a
    // migration step was missed. Loud, never silent.
    missingRoleCounter.add(1);
    logger.warn(
      { userId: (req.user as any)?._id?.toString() },
      'RBAC: user has no role assigned; allowing as admin. Run the RBAC migration.',
    );
    return true;
  }

  return role.isAdmin === true;
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
    if (shortCircuits(req)) return next();

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
    if (shortCircuits(req)) return next();
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
