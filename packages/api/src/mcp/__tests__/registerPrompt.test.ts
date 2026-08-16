import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { McpContext } from '@/mcp/tools/types';
import * as permission from '@/mcp/utils/permission';
import {
  createRegisterPrompt,
  type DeclaredPrompts,
} from '@/mcp/utils/registerPrompt';
import { resolveVerdict } from '@/middleware/rbac';

jest.mock('@/config', () => ({ IS_LOCAL_APP_MODE: false }));

jest.mock('@/middleware/rbac', () => {
  const actual = jest.requireActual('@/middleware/rbac');
  return { ...actual, resolveVerdict: jest.fn(actual.resolveVerdict) };
});

jest.mock('@/mcp/utils/permission', () => {
  const actual = jest.requireActual('@/mcp/utils/permission');
  return { ...actual, recordPromptDenial: jest.fn(actual.recordPromptDenial) };
});

const ADMIN = { name: 'Admin', isAdmin: true, permissions: {} };
const NO_SOURCES = {
  name: 'GrillAlertsOnly',
  isAdmin: false,
  permissions: { sources: 'none' as const, alerts: 'manage' as const },
};

/**
 * Stands in for `McpServer`. `getPrompt` mirrors the real SDK's GetPrompt
 * request handler, which checks `enabled` and throws `Prompt <name> disabled`
 * *before* invoking the callback
 * (`@modelcontextprotocol/sdk/server/mcp.js`, setPromptRequestHandlers).
 *
 * That check is why this harness has to honour `enabled`: an earlier version
 * invoked the callback regardless, which let a test assert behaviour inside
 * `guarded` that production could never reach for a disabled prompt.
 */
type PromptCallback = (args: unknown) => Promise<unknown>;
type Entry = {
  config: Record<string, unknown>;
  cb: PromptCallback;
  handle: { enabled: boolean; disable: () => void };
};

function fakeServer() {
  // A Map, not a plain object, so prompt names are never used as property keys.
  const registered = new Map<string, Entry>();

  const entry = (name: string): Entry => {
    const found = registered.get(name);
    if (!found) throw new Error(`Prompt ${name} not found`);
    return found;
  };

  return {
    registerPrompt: jest.fn(
      (name: string, config: Record<string, unknown>, cb: PromptCallback) => {
        const handle = {
          enabled: true,
          disable: () => {
            handle.enabled = false;
          },
        };
        registered.set(name, { config, cb, handle });
        return handle;
      },
    ),
    /** The config the SDK actually received. */
    configFor: (name: string) => entry(name).config,
    /**
     * The raw wrapper, reached without the `enabled` gate. Only for asserting
     * the backstop; a realistic request goes through `getPrompt`.
     */
    callbackFor: (name: string) => entry(name).cb,
    /** What a real `prompts/get` does. */
    getPrompt: async (name: string, args: unknown = {}) => {
      const found = entry(name);
      if (!found.handle.enabled) throw new Error(`Prompt ${name} disabled`);
      return found.cb(args);
    },
    /** What a real `prompts/list` returns. */
    listPrompts: () =>
      [...registered.entries()]
        .filter(([, p]) => p.handle.enabled)
        .map(([name]) => name),
  };
}

const ctx = (role: McpContext['role']): McpContext => ({
  teamId: 't1',
  userId: 'u1',
  role,
});

/**
 * One cast for the whole file. `fakeServer` implements only the sliver of
 * `McpServer` the registrar touches, and the registrar already reaches it
 * through a cast of its own.
 */
function registrarFor(role: McpContext['role'], declared?: DeclaredPrompts) {
  const server = fakeServer();
  const registerPrompt = createRegisterPrompt(
    server as unknown as McpServer,
    ctx(role),
    declared,
  );
  return { server, registerPrompt };
}

/** Every prompt in this file declares the same permission. */
const declare = (title = 'T') =>
  ({ title, description: 'D', permission: 'sources:read' }) as const;

const noopHandler = async () => ({ messages: [] });

describe('createRegisterPrompt', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('strips `permission` before the config reaches the SDK', () => {
    const { server, registerPrompt } = registrarFor(ADMIN);

    registerPrompt('create_dashboard', declare(), noopHandler);

    const passed = server.configFor('create_dashboard');
    expect(passed).not.toHaveProperty('permission');
    expect(passed).toEqual({ title: 'T', description: 'D' });
  });

  it('records the declaration for the coverage assertion', () => {
    const declared: DeclaredPrompts = new Map();
    const { registerPrompt } = registrarFor(ADMIN, declared);

    registerPrompt('query_guide', declare(), noopHandler);

    expect(declared.get('query_guide')).toBe('sources:read');
  });

  it('runs the handler for a role that holds the permission', async () => {
    const { server, registerPrompt } = registrarFor(ADMIN);
    const handler = jest.fn(async () => ({ messages: [] }));

    registerPrompt('create_dashboard', declare(), handler);

    await server.getPrompt('create_dashboard');
    expect(handler).toHaveBeenCalled();
    expect(server.listPrompts()).toEqual(['create_dashboard']);
  });

  // SEC-1: the defect was that every actor, including sources:none, received
  // byte-identical full source and connection inventory from prompts/get.
  it('hides the prompt from listing for a role that cannot reach it', () => {
    const { server, registerPrompt } = registrarFor(NO_SOURCES);

    registerPrompt('create_dashboard', declare(), noopHandler);

    expect(server.listPrompts().includes('create_dashboard')).toBe(false);
    expect(server.listPrompts()).toEqual([]);
  });

  it('refuses a prompts/get for a prompt the role cannot reach', async () => {
    const { server, registerPrompt } = registrarFor(NO_SOURCES);
    const handler = jest.fn(async () => ({ messages: [] }));

    registerPrompt('create_dashboard', declare(), handler);

    // The refusal a client actually gets: the SDK rejects a disabled prompt
    // before the callback runs, so the message is the SDK's, not ours. What
    // matters is that the request is refused and the handler never runs.
    await expect(server.getPrompt('create_dashboard')).rejects.toThrow(
      /disabled/,
    );
    expect(handler).not.toHaveBeenCalled();
  });

  it('keeps the guarded callback as a backstop if the SDK ever routes to it', async () => {
    const { server, registerPrompt } = registrarFor(NO_SOURCES);
    const handler = jest.fn(async () => ({ messages: [] }));

    registerPrompt('create_dashboard', declare(), handler);

    // Deliberately bypasses the `enabled` gate to reach the wrapper directly —
    // unreachable in production today, which is precisely why the denial metric
    // cannot live in here.
    await expect(server.callbackFor('create_dashboard')({})).rejects.toThrow(
      /sources: read/,
    );
    expect(handler).not.toHaveBeenCalled();
  });

  // The access-key path fails closed (slice C §7). MCP is always access-key
  // authenticated, so a role-less caller must not reach prompt content.
  it('fails closed when no role is assigned', async () => {
    const { server, registerPrompt } = registrarFor(null);

    registerPrompt('create_dashboard', declare(), noopHandler);

    expect(server.listPrompts()).toEqual([]);
    await expect(server.getPrompt('create_dashboard')).rejects.toThrow(
      /disabled/,
    );
    // And the backstop, reached directly, gives the role-less message.
    await expect(server.callbackFor('create_dashboard')({})).rejects.toThrow(
      /no role is assigned/,
    );
  });

  // Regression for the missing_role-fires-per-prompt defect, and for its
  // follow-up: the MCP server is rebuilt per HTTP request and every prompt
  // file registers against it, *before* the JSON-RPC method is known. So
  // registration must not record at all — that attributed a missing-role
  // event to `initialize`, `ping` and `tools/list`, which consult no
  // permission — and the guarded handler must record exactly once however
  // many prompts the request touches.
  it('records no RBAC verdict at registration time', () => {
    const { server, registerPrompt } = registrarFor(null);

    registerPrompt('create_dashboard', declare(), noopHandler);
    registerPrompt('query_guide', declare(), noopHandler);

    // Still hidden from listing — the decision is taken, just without the
    // telemetry side effect.
    expect(server.listPrompts().includes('create_dashboard')).toBe(false);
    expect(resolveVerdict).not.toHaveBeenCalled();
  });

  // Uses a role that CAN reach the prompts, so the calls go through the real
  // `prompts/get` path rather than the backstop: for a denied role every prompt
  // is disabled and `guarded` is never reached at all.
  it('resolves the RBAC verdict once per request, not once per prompt call', async () => {
    const { server, registerPrompt } = registrarFor(ADMIN);

    registerPrompt('create_dashboard', declare(), noopHandler);
    registerPrompt('query_guide', declare(), noopHandler);

    await server.getPrompt('create_dashboard');
    await server.getPrompt('query_guide');

    expect(resolveVerdict).toHaveBeenCalledTimes(1);
  });

  // The denial metric cannot be an attempted-call event the way recordToolDenial
  // is: the SDK refuses a disabled prompt before the callback runs, so a metric
  // inside `guarded` is dead code in production for exactly the case it exists
  // to record. The listing decision is the last point where the RBAC verdict is
  // ours to observe, so that is where it fires.
  it('records the denial where the prompt is withdrawn from listing', async () => {
    const { server, registerPrompt } = registrarFor(NO_SOURCES);

    registerPrompt('create_dashboard', declare(), noopHandler);

    expect(server.listPrompts()).toEqual([]);
    expect(permission.recordPromptDenial).toHaveBeenCalledTimes(1);
    expect(permission.recordPromptDenial).toHaveBeenCalledWith(
      'create_dashboard',
      'sources:read',
    );

    // A real prompts/get adds no second increment — the SDK never reaches the
    // wrapper, and the wrapper would not record even if it did.
    await expect(server.getPrompt('create_dashboard')).rejects.toThrow(
      /disabled/,
    );
    expect(permission.recordPromptDenial).toHaveBeenCalledTimes(1);
  });

  it('records nothing for a prompt the role can reach', () => {
    const { registerPrompt } = registrarFor(ADMIN);

    registerPrompt('create_dashboard', declare(), noopHandler);

    expect(permission.recordPromptDenial).not.toHaveBeenCalled();
  });
});
