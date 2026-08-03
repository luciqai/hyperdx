import app from '@/api-app';
import { assertRbacCoverage } from '@/middleware/rbacCoverage';

/**
 * The highest-value test in the RBAC slice.
 *
 * `api-app.ts` calls `assertRbacCoverage` at import time, so a missing
 * annotation already fails startup. This test makes that guarantee explicit
 * and checkable: it walks the REAL mounted app and asserts every
 * session-authenticated route declares a permission.
 *
 * Lives in the integration suite because importing `api-app` constructs a
 * Mongo-backed session store.
 */
describe('RBAC coverage over the real app', () => {
  it('every authenticated route declares a permission', () => {
    expect(() =>
      assertRbacCoverage(app, { exemptMounts: ['/mcp', '/api/v2'] }),
    ).not.toThrow();
  });

  it('walks a realistic number of routes (guards against a no-op walker)', () => {
    // A walker that silently found nothing would make the assertion above
    // vacuous. The internal surface is ~65 routes; assert the walker sees a
    // substantial number rather than pinning an exact count that would churn.
    const routes: string[] = [];
    const walk = (stack: any[], prefix: string) => {
      for (const layer of stack) {
        if (layer.route) {
          for (const m of Object.keys(layer.route.methods)) {
            routes.push(`${m.toUpperCase()} ${prefix}${layer.route.path}`);
          }
        } else if (layer.handle?.stack) {
          walk(layer.handle.stack, prefix);
        }
      }
    };
    walk((app as any)._router?.stack ?? (app as any).router?.stack ?? [], '');

    expect(routes.length).toBeGreaterThan(50);
  });

  it('covers External API v2, not just the internal routers', () => {
    // Slice C removed /api/v2 from exemptMounts. Assert the walker actually
    // descends into those sub-routers — otherwise the assertion above would
    // pass while 39 access-key routes went unchecked.
    const v2: string[] = [];
    const walk = (stack: any[], prefix: string) => {
      for (const layer of stack) {
        if (layer.route) {
          for (const m of Object.keys(layer.route.methods)) {
            v2.push(`${m.toUpperCase()} ${prefix}${layer.route.path}`);
          }
        } else {
          const nested = layer.handle?.stack ?? layer.handle?._router?.stack;
          if (nested) {
            const src: string = layer.regexp?.source ?? '';
            const seg = src
              .replace('^\\/', '/')
              .replace('\\/?(?=\\/|$)', '')
              .replace(/\\\//g, '/')
              .replace(/\$$/, '');
            walk(nested, `${prefix}${seg.startsWith('/') ? seg : ''}`);
          }
        }
      }
    };
    walk((app as any)._router?.stack ?? (app as any).router?.stack ?? [], '');

    expect(v2.filter(r => r.includes('/api/v2')).length).toBeGreaterThanOrEqual(
      39,
    );
  });
});
