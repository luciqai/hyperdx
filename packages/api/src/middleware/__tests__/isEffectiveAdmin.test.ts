import { isEffectiveAdmin } from '@/middleware/rbac';

jest.mock('@/config', () => ({ IS_LOCAL_APP_MODE: false }));

const req = (role: any, authPath?: string) =>
  ({ user: { _id: 'u1', role }, _hdx_authPath: authPath }) as any;

describe('isEffectiveAdmin', () => {
  it('is true for a role carrying isAdmin', () => {
    expect(isEffectiveAdmin(req({ name: 'Admin', isAdmin: true }))).toBe(true);
  });

  it('is false for a role without isAdmin, however permissive', () => {
    expect(
      isEffectiveAdmin(
        req({ name: 'Power', isAdmin: false, permissions: { team: 'manage' } }),
      ),
    ).toBe(false);
  });

  // Mirrors resolveVerdict's divergence: the browser fails open, the
  // access-key path fails closed.
  it('is true for a role-less session user (fail-open)', () => {
    expect(isEffectiveAdmin(req(null))).toBe(true);
  });

  it('is false for a role-less access-key user (fail-closed)', () => {
    expect(isEffectiveAdmin(req(null, 'access-key'))).toBe(false);
  });
});
