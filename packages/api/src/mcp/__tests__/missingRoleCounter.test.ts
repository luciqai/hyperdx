import { Types } from 'mongoose';

import type { McpContext } from '@/mcp/tools/types';
import { resolveVerdict } from '@/middleware/rbac';

import { callTool, createTestClient } from './mcpTestUtils';

jest.mock('@/middleware/rbac', () => {
  const actual = jest.requireActual('@/middleware/rbac');
  return { ...actual, resolveVerdict: jest.fn(actual.resolveVerdict) };
});

/**
 * `hyperdx.rbac.missing_role` must fire exactly once per request that consults
 * a permission, and zero times for one that consults none. `resolveVerdict` is
 * the only thing that increments it, so counting calls to it is counting the
 * metric.
 *
 * Why this needs a whole server rather than a registrar: the defect lived in
 * the seam between the two registrars and `createServer`. The prompt registrar
 * resolved the verdict in its factory body — which runs inside `createServer`,
 * i.e. once per HTTP POST, before the JSON-RPC method is known — while the tool
 * wrapper resolved it again per invocation. A role-less key therefore counted
 * twice on `tools/call` and once each on `initialize`, `ping` and `tools/list`,
 * none of which consult a permission. Neither registrar's own tests could see
 * that; only their composition shows it.
 *
 * The in-memory transport keeps one server for the whole client session, where
 * the HTTP transport builds one per POST. That is the right model for this
 * property: "once per server" is exactly "once per request" in production, and
 * a test that reused a server across calls would catch a regression that a
 * per-POST test could not.
 *
 * No database fixture: a role-less caller is denied before any tool handler
 * runs, same as rbacTools.test.ts.
 */
describe('missing-role telemetry cardinality', () => {
  const ctx = (): McpContext => ({
    teamId: new Types.ObjectId().toString(),
    userId: new Types.ObjectId().toString(),
    // The population the counter exists to detect.
    role: null,
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('does not fire for the handshake, listing or ping', async () => {
    const c = await createTestClient(ctx());

    // createTestClient has already performed `initialize`.
    expect(resolveVerdict).not.toHaveBeenCalled();

    await c.listTools();
    await c.listPrompts();
    await c.ping();

    expect(resolveVerdict).not.toHaveBeenCalled();
  });

  it('fires exactly once for a request that consults a permission', async () => {
    const c = await createTestClient(ctx());

    await callTool(c, 'clickstack_get_webhook', {});

    expect(resolveVerdict).toHaveBeenCalledTimes(1);
  });

  it('does not fire again for further calls sharing the same server', async () => {
    const c = await createTestClient(ctx());

    await callTool(c, 'clickstack_get_webhook', {});
    await callTool(c, 'clickstack_list_sources', {});
    await callTool(c, 'clickstack_get_webhook', {});

    expect(resolveVerdict).toHaveBeenCalledTimes(1);
  });

  it('resolves the access-key path, so a role-less key is denied not allowed', async () => {
    const c = await createTestClient(ctx());

    await callTool(c, 'clickstack_get_webhook', {});

    expect(resolveVerdict).toHaveReturnedWith('deny');
  });
});
