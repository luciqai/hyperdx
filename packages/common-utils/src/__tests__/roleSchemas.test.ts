import { RoleInputSchema, RolePermissionsSchema } from '@/types';

const VALID_PERMISSIONS = {
  dashboards: 'manage',
  savedSearches: 'manage',
  sources: 'read',
  alerts: 'manage',
  webhooks: 'read',
  connections: 'none',
  users: 'read',
  team: 'read',
} as const;

describe('role schemas', () => {
  it('accepts a well-formed permission map', () => {
    expect(RolePermissionsSchema.safeParse(VALID_PERMISSIONS).success).toBe(
      true,
    );
  });

  // BUG-10. Verified inert — enforcement reads top-level role.isAdmin and
  // permissions is only ever indexed by valid Resource names — but a key that
  // LOOKS like a capability sitting on a role document invites a future
  // misread.
  it('rejects an isAdmin key smuggled into the permission map', () => {
    const result = RolePermissionsSchema.safeParse({
      ...VALID_PERMISSIONS,
      isAdmin: true,
    });
    expect(result.success).toBe(false);
  });

  it('rejects unknown top-level keys on role input', () => {
    const result = RoleInputSchema.safeParse({
      name: 'Custom',
      permissions: VALID_PERMISSIONS,
      isAdmin: true,
    });
    expect(result.success).toBe(false);
  });

  it('still accepts valid role input', () => {
    const result = RoleInputSchema.safeParse({
      name: 'Custom',
      description: 'A role',
      permissions: VALID_PERMISSIONS,
    });
    expect(result.success).toBe(true);
  });
});
