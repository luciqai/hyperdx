import { checkToolPermission } from '@/mcp/utils/permission';

jest.mock('@/config', () => ({ IS_LOCAL_APP_MODE: false }));

const ADMIN = { name: 'Admin', isAdmin: true, permissions: {} };
const MEMBER = {
  name: 'Member',
  isAdmin: false,
  permissions: {
    dashboards: 'manage' as const,
    sources: 'read' as const,
    connections: 'none' as const,
  },
};

describe('checkToolPermission', () => {
  it('allows an admin regardless of the permission map', () => {
    expect(checkToolPermission(ADMIN, 'connections:manage').ok).toBe(true);
    expect(checkToolPermission(ADMIN, 'admin').ok).toBe(true);
  });

  it('allows when the held level outranks the requirement', () => {
    expect(checkToolPermission(MEMBER, 'dashboards:read').ok).toBe(true);
    expect(checkToolPermission(MEMBER, 'dashboards:manage').ok).toBe(true);
    expect(checkToolPermission(MEMBER, 'sources:read').ok).toBe(true);
  });

  it('denies when the held level is lower', () => {
    const r = checkToolPermission(MEMBER, 'sources:manage');
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.message).toContain('sources: manage');
    expect(r.ok === false && r.message).toContain('"Member"');
  });

  it('denies clickstack_sql for a role without connections: manage', () => {
    // The decided gate: raw SQL is connection-level, so Member cannot run it.
    const r = checkToolPermission(MEMBER, 'connections:manage');
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.message).toContain('connections: manage');
  });

  it('denies an admin-only tool for a non-admin even at manage everywhere', () => {
    const powerful = {
      name: 'Power',
      isAdmin: false,
      permissions: { team: 'manage' as const },
    };
    const r = checkToolPermission(powerful, 'admin');
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.message).toContain('administrator access');
  });

  // The slice C divergence: the browser fails OPEN for a missing role, this
  // path fails CLOSED. An unattended agent must not silently become admin.
  it('fails CLOSED when no role is assigned', () => {
    const r = checkToolPermission(null, 'dashboards:read');
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.message).toContain('no role is assigned');
  });

  it('fails closed even for a read-only requirement', () => {
    expect(checkToolPermission(null, 'sources:read').ok).toBe(false);
  });
});
