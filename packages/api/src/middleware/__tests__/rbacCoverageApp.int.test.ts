import express from 'express';

import app from '@/api-app';
import { assertRbacCoverage } from '@/middleware/rbacCoverage';
import { setupSwagger } from '@/utils/swagger';

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

  it('covers routes that are only mounted under a feature flag', () => {
    // Regression: /api/v2/docs.json is registered by setupSwagger, which only
    // runs when ENABLE_SWAGGER=true. The test env does not set it, so the
    // route did not exist here and the suite passed while the dev server —
    // where .env.development sets it — refused to boot.
    //
    // Build a throwaway app with the flag's routes mounted and assert they
    // declare permissions too.
    const flagged = express();
    setupSwagger(flagged);

    expect(() =>
      assertRbacCoverage(flagged, { exemptMounts: ['/mcp'] }),
    ).not.toThrow();
  });

  it('covers the Google SSO routes, which only mount when configured', () => {
    // Same blind spot as the swagger case above, and a worse one:
    // /auth/google and its callback live behind `IS_GOOGLE_AUTH_ENABLED`,
    // which is false in the test env. Without this the routes are absent
    // here, the suite passes, and a deployment that actually configures
    // Google SSO is the first to discover a missing declaration — by
    // failing to boot.
    jest.isolateModules(() => {
      jest.doMock('@/config', () => ({
        ...jest.requireActual('@/config'),
        IS_GOOGLE_AUTH_ENABLED: true,
        GOOGLE_CLIENT_ID: 'test-client-id',
        GOOGLE_CLIENT_SECRET: 'test-client-secret',
        GOOGLE_REDIRECT_URI: 'http://localhost/api/auth/google/callback',
        GOOGLE_ALLOWED_DOMAINS: ['example.com'],
      }));

      // Both the router and the assertion must come from THIS module
      // registry. `RBAC_DECLARATION` is a plain `Symbol(...)`, so an isolated
      // registry mints a fresh one — the outer `assertRbacCoverage` would
      // read a different symbol than the one `root.ts` tagged with here and
      // report every route undeclared.
      const rootRouter = require('@/routers/api/root').default;
      const { assertRbacCoverage: assertIsolated } =
        require('@/middleware/rbacCoverage') as typeof import('@/middleware/rbacCoverage');

      const withGoogle = express();
      withGoogle.use(rootRouter);

      const paths: string[] = [];
      const walk = (stack: any[]) => {
        for (const layer of stack) {
          if (layer.route) paths.push(layer.route.path);
          else if (layer.handle?.stack) walk(layer.handle.stack);
        }
      };
      walk(
        (withGoogle as any)._router?.stack ??
          (withGoogle as any).router?.stack ??
          [],
      );

      // Guard against a vacuous pass: if the config mock failed to take, the
      // routes would be absent and the assertion below would prove nothing.
      expect(paths).toContain('/auth/google');
      expect(paths).toContain('/auth/google/callback');

      expect(() =>
        assertIsolated(withGoogle, { exemptMounts: [] }),
      ).not.toThrow();
    });
  });
});
