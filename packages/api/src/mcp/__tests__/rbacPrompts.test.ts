import { Types } from 'mongoose';

import type { McpContext } from '@/mcp/tools/types';

import { createTestClient } from './mcpTestUtils';

/**
 * RBAC over the MCP *prompt* surface, driven by a real
 * `@modelcontextprotocol/sdk` client against a real server.
 *
 * SEC-1's root cause was an unverified assumption about SDK internals — the
 * coverage assertion inspected `_registeredTools` and could not see prompts at
 * all. Everything that has covered the fix since is either a hand-built object
 * literal (coverage.test.ts) or a `fakeServer` stand-in (registerPrompt.test.ts),
 * so the SDK-facing half of the guarantee — that `disable()` actually withdraws
 * a prompt from `prompts/list` and actually refuses `prompts/get` — has never
 * been checked against the SDK that ships. This is that check.
 *
 * No database fixture, and therefore not in the integration suite: a permission
 * denial returns before any prompt handler runs, so nothing here reaches Mongo
 * or ClickHouse. Same reasoning as rbacTools.test.ts, which documents why the
 * shared integration fixture is worth avoiding when it buys nothing.
 *
 * The Admin case only *lists* — it does not fetch. Fetching would run
 * create_dashboard's handler, which enumerates the team's real sources and
 * connections and would block on a real Mongo connection for no extra signal.
 */
describe('MCP prompt RBAC (real SDK client)', () => {
  const teamId = new Types.ObjectId().toString();
  const userId = new Types.ObjectId().toString();

  const ctx = (role: McpContext['role']): McpContext => ({
    teamId,
    userId,
    role,
  });

  const ADMIN = { name: 'Admin', isAdmin: true, permissions: {} };
  // Every prompt declares `sources:read` because each seeds its text from the
  // team's real source and connection inventory.
  const NO_SOURCES = {
    name: 'AlertsOnly',
    isAdmin: false,
    permissions: { sources: 'none' as const, alerts: 'manage' as const },
  };

  it('lists all three prompts for an Admin', async () => {
    const c = await createTestClient(ctx(ADMIN));
    const { prompts } = await c.listPrompts();

    expect(prompts.map(p => p.name).sort()).toEqual([
      'create_dashboard',
      'dashboard_examples',
      'query_guide',
    ]);
  });

  // The SEC-1 defect verbatim: a `sources: none` actor received byte-identical
  // full source and connection inventory from the prompt surface.
  it('lists no prompts at all for a sources:none role', async () => {
    const c = await createTestClient(ctx(NO_SOURCES));
    const { prompts } = await c.listPrompts();

    expect(prompts).toEqual([]);
  });

  it('lists no prompts at all for a role-less access key', async () => {
    const c = await createTestClient(ctx(null));
    const { prompts } = await c.listPrompts();

    expect(prompts).toEqual([]);
  });

  // Hiding from the listing is not enough on its own: a client that cached the
  // name from a previous, better-permissioned session can still ask for it.
  it('refuses prompts/get by cached name for a sources:none role', async () => {
    const c = await createTestClient(ctx(NO_SOURCES));

    await expect(
      c.getPrompt({ name: 'create_dashboard', arguments: {} }),
    ).rejects.toThrow();
  });

  it('refuses prompts/get by cached name for a role-less access key', async () => {
    const c = await createTestClient(ctx(null));

    await expect(
      c.getPrompt({ name: 'query_guide', arguments: {} }),
    ).rejects.toThrow();
  });
});
