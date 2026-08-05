import * as permission from '@/mcp/utils/permission';
import { createRegisterPrompt } from '@/mcp/utils/registerPrompt';
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

function fakeServer() {
  const registered: Record<string, any> = {};
  return {
    registered,
    registerPrompt: jest.fn((name: string, config: any, cb: any) => {
      const handle = { enabled: true, disable: () => (handle.enabled = false) };
      registered[name] = { config, cb, handle };
      return handle;
    }),
  };
}

const ctx = (role: any) => ({ teamId: 't1', userId: 'u1', role }) as any;

describe('createRegisterPrompt', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('strips `permission` before the config reaches the SDK', () => {
    const server = fakeServer();
    const registerPrompt = createRegisterPrompt(server as any, ctx(ADMIN));

    registerPrompt(
      'create_dashboard',
      { title: 'T', description: 'D', permission: 'sources:read' },
      async () => ({ messages: [] }),
    );

    const passed = server.registerPrompt.mock.calls[0][1];
    expect(passed).not.toHaveProperty('permission');
    expect(passed).toEqual({ title: 'T', description: 'D' });
  });

  it('records the declaration for the coverage assertion', () => {
    const server = fakeServer();
    const declared = new Map();
    const registerPrompt = createRegisterPrompt(
      server as any,
      ctx(ADMIN),
      declared,
    );

    registerPrompt(
      'query_guide',
      { title: 'T', description: 'D', permission: 'sources:read' },
      async () => ({ messages: [] }),
    );

    expect(declared.get('query_guide')).toBe('sources:read');
  });

  it('runs the handler for a role that holds the permission', async () => {
    const server = fakeServer();
    const registerPrompt = createRegisterPrompt(server as any, ctx(ADMIN));
    const handler = jest.fn(async () => ({ messages: [] }));

    registerPrompt(
      'create_dashboard',
      { title: 'T', description: 'D', permission: 'sources:read' },
      handler,
    );

    await server.registered.create_dashboard.cb({});
    expect(handler).toHaveBeenCalled();
    expect(server.registered.create_dashboard.handle.enabled).toBe(true);
  });

  // SEC-1: the defect was that every actor, including sources:none, received
  // byte-identical full source and connection inventory from prompts/get.
  it('hides the prompt from listing for a role that cannot reach it', () => {
    const server = fakeServer();
    const registerPrompt = createRegisterPrompt(server as any, ctx(NO_SOURCES));

    registerPrompt(
      'create_dashboard',
      { title: 'T', description: 'D', permission: 'sources:read' },
      async () => ({ messages: [] }),
    );

    expect(server.registered.create_dashboard.handle.enabled).toBe(false);
  });

  it('refuses the handler by name even when listing is bypassed', async () => {
    const server = fakeServer();
    const registerPrompt = createRegisterPrompt(server as any, ctx(NO_SOURCES));
    const handler = jest.fn(async () => ({ messages: [] }));

    registerPrompt(
      'create_dashboard',
      { title: 'T', description: 'D', permission: 'sources:read' },
      handler,
    );

    await expect(server.registered.create_dashboard.cb({})).rejects.toThrow(
      /sources: read/,
    );
    expect(handler).not.toHaveBeenCalled();
  });

  // The access-key path fails closed (slice C §7). MCP is always access-key
  // authenticated, so a role-less caller must not reach prompt content.
  it('fails closed when no role is assigned', async () => {
    const server = fakeServer();
    const registerPrompt = createRegisterPrompt(server as any, ctx(null));

    registerPrompt(
      'create_dashboard',
      { title: 'T', description: 'D', permission: 'sources:read' },
      async () => ({ messages: [] }),
    );

    expect(server.registered.create_dashboard.handle.enabled).toBe(false);
    await expect(server.registered.create_dashboard.cb({})).rejects.toThrow(
      /no role is assigned/,
    );
  });

  // Regression for the missing_role-fires-per-prompt defect: the MCP server
  // is rebuilt per HTTP request and every prompt file registers against it,
  // so `resolveVerdict` (and the counter/WARN log it drives) must be called
  // once per request, not once per prompt registered. Nothing before this
  // test registered more than one prompt per context, which is why the
  // defect slipped through review.
  it('resolves the RBAC verdict once per request, not once per prompt', () => {
    const server = fakeServer();
    const registerPrompt = createRegisterPrompt(server as any, ctx(null));

    registerPrompt(
      'create_dashboard',
      { title: 'T', description: 'D', permission: 'sources:read' },
      async () => ({ messages: [] }),
    );
    registerPrompt(
      'query_guide',
      { title: 'T', description: 'D', permission: 'sources:read' },
      async () => ({ messages: [] }),
    );
    registerPrompt(
      'edit_dashboard',
      { title: 'T', description: 'D', permission: 'dashboards:manage' },
      async () => ({ messages: [] }),
    );

    expect(resolveVerdict).toHaveBeenCalledTimes(1);
  });

  // Corrected semantics: the denial metric is an attempted-call event, not a
  // registration-time event. Mirrors recordToolDenial in registerTool.ts,
  // which fires inside the guarded handler on an actual call.
  it('emits no denial metric at registration, and exactly one on an actual guarded call', async () => {
    const server = fakeServer();
    const registerPrompt = createRegisterPrompt(server as any, ctx(NO_SOURCES));

    registerPrompt(
      'create_dashboard',
      { title: 'T', description: 'D', permission: 'sources:read' },
      async () => ({ messages: [] }),
    );

    // Registration disabled the prompt, but must not have recorded a denial:
    // the server is rebuilt per HTTP request, so recording here would count
    // once per denied prompt on every request, even if no client ever calls it.
    expect(server.registered.create_dashboard.handle.enabled).toBe(false);
    expect(permission.recordPromptDenial).not.toHaveBeenCalled();

    await expect(server.registered.create_dashboard.cb({})).rejects.toThrow(
      /sources: read/,
    );

    expect(permission.recordPromptDenial).toHaveBeenCalledTimes(1);
    expect(permission.recordPromptDenial).toHaveBeenCalledWith(
      'create_dashboard',
      'sources:read',
    );
  });
});
