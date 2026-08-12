import type { Application } from 'express';

import { getRbacDeclaration } from '@/middleware/rbac';
import logger from '@/utils/logger';

type Layer = {
  name?: string;
  regexp?: RegExp;
  handle?: { stack?: Layer[] };
  route?: {
    path: string;
    methods: Record<string, boolean>;
    stack: { handle: unknown }[];
  };
};

/** Recover a mount path from an Express layer's regexp. */
function mountPath(layer: Layer): string {
  if (!layer.regexp) return '';
  const source = layer.regexp.source;
  if (source === '^\\/?$' || source === '^\\/?(?=\\/|$)') return '';
  const match = source
    .replace('^\\/', '/')
    .replace('\\/?(?=\\/|$)', '')
    .replace(/\\\//g, '/')
    .replace(/\$$/, '');
  return match.startsWith('/') ? match : '';
}

function walk(
  stack: Layer[],
  prefix: string,
  out: { method: string; path: string; declared: boolean }[],
) {
  for (const layer of stack) {
    if (layer.route) {
      const declared = layer.route.stack.some(
        s => getRbacDeclaration(s.handle) != null,
      );
      for (const method of Object.keys(layer.route.methods)) {
        out.push({
          method: method.toUpperCase(),
          path: `${prefix}${layer.route.path}`.replace(/\/+/g, '/'),
          declared,
        });
      }
    } else {
      // A mounted express.Router() keeps its layers on `handle.stack`, but a
      // mounted Express *application* keeps them on `handle._router.stack`.
      // Only checking the former silently skips whole sub-apps — the walker
      // then reports success having seen none of their routes, which is the
      // exact blind spot this assertion exists to remove.
      const nested =
        layer.handle?.stack ??
        (layer.handle as any)?._router?.stack ??
        (layer.handle as any)?.router?.stack;
      if (nested) {
        walk(nested, `${prefix}${mountPath(layer)}`, out);
      }
    }
  }
}

/**
 * Fails startup when an authenticated route carries no RBAC declaration.
 *
 * Forgetting the annotation on a new route is otherwise silent and ships an
 * unguarded endpoint — the same omission class that produced the TeamInvite
 * cross-tenant delete. This converts it into a failed deploy.
 */
export function assertRbacCoverage(
  app: Application,
  opts: { exemptMounts?: string[] } = {},
): void {
  const exempt = opts.exemptMounts ?? [];
  const routes: { method: string; path: string; declared: boolean }[] = [];

  const stack = (app as any)._router?.stack ?? (app as any).router?.stack ?? [];
  walk(stack, '', routes);

  const uncovered = routes.filter(
    r => !r.declared && !exempt.some(m => r.path.startsWith(m)),
  );

  if (uncovered.length > 0) {
    const list = uncovered.map(r => `  ${r.method} ${r.path}`).join('\n');
    throw new Error(
      `RBAC coverage check failed. ${uncovered.length} route(s) declare no permission:\n${list}\n\n` +
        `Add requirePermission(), requireAdmin(), or noPermissionRequired() to each.`,
    );
  }

  logger.info(
    { routeCount: routes.length },
    'RBAC coverage check passed: every route declares a permission',
  );
}
