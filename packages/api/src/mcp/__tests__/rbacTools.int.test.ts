import { SYSTEM_ROLE_PERMISSIONS } from '@hyperdx/common-utils/dist/types';
import { Types } from 'mongoose';

import { getServer } from '@/fixtures';

import { callTool, createTestClient, getFirstText } from './mcpTestUtils';

/**
 * End-to-end RBAC over the MCP surface: a real SDK client against a real
 * server, with a real role on the context.
 *
 * Asserts the shape slice C promises — a restricted role can read but not
 * write, cannot run raw SQL, and a role-less caller is denied outright.
 */
describe('MCP tool RBAC', () => {
  const server = getServer();
  const teamId = new Types.ObjectId().toString();
  const userId = new Types.ObjectId().toString();

  beforeAll(async () => {
    await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  const ctx = (role: unknown) => ({ teamId, userId, role }) as any;

  const MEMBER = {
    name: 'Member',
    isAdmin: false,
    permissions: SYSTEM_ROLE_PERMISSIONS.Member,
  };
  const READONLY = {
    name: 'ReadOnly',
    isAdmin: false,
    permissions: SYSTEM_ROLE_PERMISSIONS.ReadOnly,
  };
  const ADMIN = { name: 'Admin', isAdmin: true, permissions: {} };

  const denied = (text: string) => text.includes('Permission denied');

  it('lets a Member read dashboards', async () => {
    const c = await createTestClient(ctx(MEMBER));
    const res = await callTool(c, 'clickstack_get_dashboard', {});
    expect(denied(getFirstText(res))).toBe(false);
  });

  it('blocks a Member from editing a source (sources: read only)', async () => {
    const c = await createTestClient(ctx(MEMBER));
    const res = await callTool(c, 'clickstack_delete_source', {
      id: new Types.ObjectId().toString(),
    });
    const text = getFirstText(res);
    expect(denied(text)).toBe(true);
    expect(text).toContain('sources: manage');
  });

  it('blocks a Member from raw SQL (connections: manage)', async () => {
    const c = await createTestClient(ctx(MEMBER));
    const res = await callTool(c, 'clickstack_sql', {
      connectionId: new Types.ObjectId().toString(),
      sql: 'SELECT 1',
    });
    const text = getFirstText(res);
    expect(denied(text)).toBe(true);
    expect(text).toContain('connections: manage');
  });

  it('blocks ReadOnly from saving a dashboard', async () => {
    const c = await createTestClient(ctx(READONLY));
    const res = await callTool(c, 'clickstack_save_dashboard', {
      name: 'x',
      tiles: [],
      tags: [],
    });
    const text = getFirstText(res);
    expect(denied(text)).toBe(true);
    expect(text).toContain('dashboards: manage');
  });

  it('blocks ReadOnly from reading webhooks (webhooks: none)', async () => {
    const c = await createTestClient(ctx(READONLY));
    const res = await callTool(c, 'clickstack_get_webhook', {});
    expect(denied(getFirstText(res))).toBe(true);
  });

  it('allows an admin to run raw SQL', async () => {
    const c = await createTestClient(ctx(ADMIN));
    const res = await callTool(c, 'clickstack_sql', {
      connectionId: new Types.ObjectId().toString(),
      sql: 'SELECT 1',
    });
    // May still fail on connection lookup in this fixture, but must not be a
    // permission denial — that is what this asserts.
    expect(denied(getFirstText(res))).toBe(false);
  });

  // The slice C divergence from slice A's browser fail-open.
  it('denies every tool when the caller has no role', async () => {
    const c = await createTestClient(ctx(null));
    // NOTE: the SDK validates inputSchema before invoking the handler, so the
    // permission check runs after arg validation — each payload must be
    // schema-valid or the test asserts a validation error instead of a denial.
    const cases: [string, Record<string, unknown>][] = [
      ['clickstack_get_dashboard', {}],
      ['clickstack_list_sources', {}],
      [
        'clickstack_sql',
        { connectionId: new Types.ObjectId().toString(), sql: 'SELECT 1' },
      ],
    ];
    for (const [tool, args] of cases) {
      const res = await callTool(c, tool, args);
      const text = getFirstText(res);
      expect(denied(text)).toBe(true);
      expect(text).toContain('no role is assigned');
    }
  });

  it('does not advertise the permission field in the tool manifest', async () => {
    // registerTool strips `permission` before handing config to the SDK; if it
    // leaked, the whole permission model would be published to every client.
    const c = await createTestClient(ctx(ADMIN));
    const { tools } = await c.listTools();
    expect(tools.length).toBeGreaterThan(25);
    for (const t of tools) {
      expect(t).not.toHaveProperty('permission');
    }
  });
});
