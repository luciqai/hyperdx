import {
  hasPermission,
  RolePermissionsSchema,
  SYSTEM_ROLE_PERMISSIONS,
} from '../types';

describe('hasPermission', () => {
  it('grants when held level outranks required', () => {
    expect(hasPermission('manage', 'read')).toBe(true);
    expect(hasPermission('read', 'read')).toBe(true);
    expect(hasPermission('manage', 'manage')).toBe(true);
  });

  it('denies when held level is lower', () => {
    expect(hasPermission('read', 'manage')).toBe(false);
    expect(hasPermission('none', 'read')).toBe(false);
    expect(hasPermission('none', 'manage')).toBe(false);
  });

  it('denies when held level is undefined', () => {
    expect(hasPermission(undefined, 'read')).toBe(false);
  });
});

describe('RolePermissionsSchema', () => {
  it('rejects manage on users', () => {
    const result = RolePermissionsSchema.safeParse({
      ...SYSTEM_ROLE_PERMISSIONS.Member,
      users: 'manage',
    });
    expect(result.success).toBe(false);
  });

  it('rejects none on team', () => {
    const result = RolePermissionsSchema.safeParse({
      ...SYSTEM_ROLE_PERMISSIONS.Member,
      team: 'none',
    });
    expect(result.success).toBe(false);
  });

  it('accepts a valid matrix', () => {
    expect(
      RolePermissionsSchema.safeParse(SYSTEM_ROLE_PERMISSIONS.ReadOnly).success,
    ).toBe(true);
  });
});

describe('SYSTEM_ROLE_PERMISSIONS', () => {
  it('gives Member and ReadOnly no connection access', () => {
    expect(SYSTEM_ROLE_PERMISSIONS.Member.connections).toBe('none');
    expect(SYSTEM_ROLE_PERMISSIONS.ReadOnly.connections).toBe('none');
  });

  it('gives ReadOnly read on dashboards but none on webhooks', () => {
    expect(SYSTEM_ROLE_PERMISSIONS.ReadOnly.dashboards).toBe('read');
    expect(SYSTEM_ROLE_PERMISSIONS.ReadOnly.webhooks).toBe('none');
  });
});
