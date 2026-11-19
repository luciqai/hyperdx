import express from 'express';

import { noPermissionRequired, requirePermission } from '@/middleware/rbac';
import { assertRbacCoverage } from '@/middleware/rbacCoverage';

jest.mock('@/config', () => ({ IS_LOCAL_APP_MODE: false }));

describe('assertRbacCoverage', () => {
  it('passes when every route declares a permission', () => {
    const app = express();
    const router = express.Router();
    router.get('/', requirePermission('alerts', 'read'), (_req, res) =>
      res.send(),
    );
    router.post('/', noPermissionRequired('public'), (_req, res) => res.send());
    app.use('/alerts', router);

    expect(() => assertRbacCoverage(app)).not.toThrow();
  });

  it('throws and names the offending route', () => {
    const app = express();
    const router = express.Router();
    router.get('/', requirePermission('alerts', 'read'), (_req, res) =>
      res.send(),
    );
    router.delete('/:id', (_req, res) => res.send()); // undeclared
    app.use('/alerts', router);

    expect(() => assertRbacCoverage(app)).toThrow(/DELETE \/alerts\/:id/);
  });

  it('ignores explicitly exempt mounts', () => {
    const app = express();
    const router = express.Router();
    router.post('/', (_req, res) => res.send());
    app.use('/mcp', router);

    expect(() =>
      assertRbacCoverage(app, { exemptMounts: ['/mcp'] }),
    ).not.toThrow();
  });
});
