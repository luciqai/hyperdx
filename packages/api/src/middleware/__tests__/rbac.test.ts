import type { NextFunction, Request, Response } from 'express';

import {
  getRbacDeclaration,
  noPermissionRequired,
  requireAdmin,
  requirePermission,
} from '@/middleware/rbac';

jest.mock('@/config', () => ({ IS_LOCAL_APP_MODE: false }));

function mockRes() {
  const res = {} as Response;
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
}

function reqWith(role: any): Request {
  return { user: { _id: 'u1', team: 't1', role } } as unknown as Request;
}

describe('requirePermission', () => {
  it('allows when the held level outranks the requirement', () => {
    const next = jest.fn() as NextFunction;
    const res = mockRes();

    requirePermission('dashboards', 'read')(
      reqWith({ isAdmin: false, permissions: { dashboards: 'manage' } }),
      res,
      next,
    );

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('denies with 403 and names the requirement', () => {
    const next = jest.fn() as NextFunction;
    const res = mockRes();

    requirePermission('connections', 'manage')(
      reqWith({ isAdmin: false, permissions: { connections: 'none' } }),
      res,
      next,
    );

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        required: { resource: 'connections', level: 'manage' },
      }),
    );
  });

  it('short-circuits for isAdmin regardless of the permission map', () => {
    const next = jest.fn() as NextFunction;
    const res = mockRes();

    requirePermission('connections', 'manage')(
      reqWith({ isAdmin: true, permissions: { connections: 'none' } }),
      res,
      next,
    );

    expect(next).toHaveBeenCalled();
  });

  it('fails open as admin when the role is missing', () => {
    const next = jest.fn() as NextFunction;
    const res = mockRes();

    requirePermission('connections', 'manage')(reqWith(undefined), res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });
});

describe('requireAdmin', () => {
  it('denies a non-admin even with every permission at manage', () => {
    const next = jest.fn() as NextFunction;
    const res = mockRes();

    requireAdmin()(
      reqWith({ isAdmin: false, permissions: { team: 'manage' } }),
      res,
      next,
    );

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('allows an admin', () => {
    const next = jest.fn() as NextFunction;
    const res = mockRes();

    requireAdmin()(reqWith({ isAdmin: true, permissions: {} }), res, next);

    expect(next).toHaveBeenCalled();
  });
});

describe('declarations', () => {
  it('tags each handler so the coverage walker can find it', () => {
    expect(getRbacDeclaration(requirePermission('alerts', 'read'))).toEqual({
      kind: 'permission',
      resource: 'alerts',
      level: 'read',
    });
    expect(getRbacDeclaration(requireAdmin())).toEqual({ kind: 'admin' });
    expect(getRbacDeclaration(noPermissionRequired('public'))).toEqual({
      kind: 'exempt',
      reason: 'public',
    });
    expect(getRbacDeclaration(() => {})).toBeUndefined();
  });
});
