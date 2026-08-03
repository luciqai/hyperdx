import { SYSTEM_ROLE_PERMISSIONS } from '@hyperdx/common-utils/dist/types';
import { Types } from 'mongoose';

import { callTool, createTestClient, getFirstText } from './mcpTestUtils';

/**
 * RBAC over the MCP surface: a real SDK client against a real server, with a
 * real role on the context.
 *
 * No database fixture: a permission denial returns before the tool handler
 * runs, so these need no Mongo or ClickHouse. That also keeps this file out of
 * the integration suite, where sharing the fixture perturbed trace.int.
 *
 * Allowed paths are covered purely in permission.test.ts. Asserting one here
 * would reach the tool handler, which blocks on a real Mongo/ClickHouse
 * connection — a 10s timeout for no extra signal. What this file proves is
 * that the wrapper intercepts BEFORE the handler, which is exactly what the
 * denial cases demonstrate.
 */
describe('MCP tool RBAC', () => {
  const teamId = new Types.ObjectId().toString();
  const userId = new Types.ObjectId().toString();

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
