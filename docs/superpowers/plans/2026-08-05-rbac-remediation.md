# RBAC Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the 2 Critical, 4 High and 6 Medium defects found by the RBAC manual test pass over slices A and C.

**Architecture:** Each fix lands at the layer that caused the defect. MCP prompts get the guarded registrar the tools already have. The browser query path gets a coarse `sources: read` gate. The last-admin invariant moves off the fail-open population and onto the explicit `isAdmin` grant. The migration becomes pre-flight-abort instead of half-write. UI stubs get wired to the real permission hook, and the Sources view stops depending on a permission its own gate does not imply.

**Tech Stack:** TypeScript, Express, Mongoose/MongoDB, `@modelcontextprotocol/sdk`, Zod, Jest, Next.js + Mantine, React Testing Library.

**Spec:** [`docs/superpowers/specs/2026-08-05-rbac-remediation-design.md`](../specs/2026-08-05-rbac-remediation-design.md)

## Global Constraints

- **Never use `--no-verify`.** If the pre-commit hook fails (husky missing in a worktree), run `npx lint-staged` manually, fix, then commit.
- **Run `yarn lint:fix` from the repo root after finishing all code edits** in a task.
- **Git author:** the repo's default git profile. **Do not add `Co-Authored-By` trailers.**
- **`express-rate-limit` is pinned at 6.7.1.** `ipKeyGenerator` does not exist in v6 — do not import it. Use `req.ip`.
- **`packages/api/src/utils/instrumentation.ts` exports only `getCounter` and `getHistogram`.** There is no gauge helper. Do not invent one.
- **Changing `packages/common-utils` requires a rebuild** before `packages/api` or `packages/app` can see it: `yarn build:common-utils` from the repo root.
- **Multi-tenancy:** every query added must be team-scoped.
- **Observability:** new countable events emit a metric; `hyperdx.rbac.missing_role` must fire exactly once per request — never call `resolveVerdict` a second time in the same request just to read admin-ness.
- Test commands: `cd packages/api && yarn ci:unit <path>` · `cd packages/app && yarn ci:unit <path>` · `cd packages/common-utils && yarn ci:unit <path>`. Integration: `cd packages/api && make dev-int FILE=<name>`.

---

# Phase 1 — Security

### Task 1: MCP prompt registrar

**Files:**
- Modify: `packages/api/src/mcp/tools/types.ts:78`
- Create: `packages/api/src/mcp/utils/registerPrompt.ts`
- Test: `packages/api/src/mcp/__tests__/registerPrompt.test.ts`

**Interfaces:**
- Consumes: `resolveVerdict(role, authPath, actorId)` from `@/middleware/rbac`.
- Produces: `createRegisterPrompt(server, context, declared?): RegisterPromptFn` and `type DeclaredPrompts = Map<string, ToolPermission>` from `@/mcp/utils/registerPrompt`; types `RegisterPromptFn`, `PromptRegistrar`, and the changed `PromptDefinition` from `@/mcp/tools/types`.
- Also produces, in `@/mcp/utils/permission`: `checkPermissionForVerdict(verdict, role, permission)` — the side-effect-free core split out of `checkToolPermission`, which becomes a thin wrapper that resolves the verdict and delegates. `checkToolPermission`'s behaviour must not change; `registerTool.ts` and `permission.test.ts` are the regression guard. Also `recordPromptDenial(name, permission)`, a counter `hyperdx.mcp.prompt.denied` mirroring `recordToolDenial`.

> **Why the split:** `resolveVerdict` increments `hyperdx.rbac.missing_role` and logs a WARN. That counter counts *requests*, and the MCP server is rebuilt per POST — so resolving the verdict inside the per-prompt registration closure fires it once per prompt, three times per request for a role-less caller. This violates the Global Constraint above.

- [ ] **Step 1: Replace the `PromptDefinition` type**

In `packages/api/src/mcp/tools/types.ts`, replace the last line (`export type PromptDefinition = (server: McpServer, context: McpContext) => void;`) with:

```ts
/**
 * Prompt argument shapes are raw Zod shapes, not a ZodObject. The SDK's own
 * generics over them do not compose with our wrapper without a cast, so the
 * handler's args are deliberately loose here — the same pragmatic choice
 * documented on RegisterToolFn's SDK generics.
 */
export type PromptArgsShape = Record<string, ZodTypeAny>;

export type RegisterPromptFn = (
  name: string,
  config: {
    title: string;
    description: string;
    argsSchema?: PromptArgsShape;
    /**
     * Required. A prompt that declares nothing fails to compile, which is the
     * compile-time half of the coverage guarantee; assertMcpCoverage is the
     * runtime half. Prompts enumerate real source and connection names, so
     * they are a permissioned surface exactly like tools (SEC-1).
     */
    permission: ToolPermission;
  },
  handler: (args: any) => Promise<GetPromptResult>,
) => void;

export type PromptRegistrar = {
  server: McpServer;
  context: McpContext;
  registerPrompt: RegisterPromptFn;
};

export type PromptDefinition = (registrar: PromptRegistrar) => void;
```

Add these two imports at the top of the same file, alongside the existing type imports:

```ts
import type { GetPromptResult } from '@modelcontextprotocol/sdk/types.js';
import type { ZodTypeAny } from 'zod';
```

- [ ] **Step 2: Write the failing test**

Create `packages/api/src/mcp/__tests__/registerPrompt.test.ts`:

```ts
import { createRegisterPrompt } from '@/mcp/utils/registerPrompt';

jest.mock('@/config', () => ({ IS_LOCAL_APP_MODE: false }));

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
});
```

- [ ] **Step 3: Run the test to verify it fails**

```bash
cd packages/api && yarn ci:unit src/mcp/__tests__/registerPrompt.test.ts
```

Expected: FAIL — `Cannot find module '@/mcp/utils/registerPrompt'`.

- [ ] **Step 4: Write the implementation**

Create `packages/api/src/mcp/utils/registerPrompt.ts`:

```ts
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type {
  McpContext,
  RegisterPromptFn,
  ToolPermission,
} from '@/mcp/tools/types';

import { resolveVerdict } from '@/middleware/rbac';

import { checkPermissionForVerdict, recordPromptDenial } from './permission';

/**
 * Permissions declared during prompt registration, keyed by prompt name.
 * Mirrors `DeclaredPermissions` for tools, and for the same reason: the SDK
 * does not expose registered handlers for inspection, so `assertMcpCoverage`
 * reads this map against the server's registered prompt names.
 */
export type DeclaredPrompts = Map<string, ToolPermission>;

/**
 * Creates a `registerPrompt` bound to a server and context, wrapping every
 * prompt with a permission check.
 *
 * SEC-1: prompts were previously registered straight onto the raw server,
 * bypassing the chokepoint that covers all 28 tools. They enumerate the team's
 * real source and connection names, so they are a permissioned surface.
 */
export function createRegisterPrompt(
  server: McpServer,
  context: McpContext,
  declared: DeclaredPrompts = new Map(),
): RegisterPromptFn {
  // Resolve the verdict ONCE per registrar, not once per prompt.
  // `resolveVerdict` increments `hyperdx.rbac.missing_role` and logs a WARN,
  // and that counter counts *requests*. The MCP server is rebuilt per POST, so
  // calling it inside the loop below would fire it once per registered prompt —
  // three times per request for a role-less caller. `checkPermissionForVerdict`
  // is side-effect-free, so calling that per prompt is free.
  const verdict = resolveVerdict(context.role, 'access-key', context.userId);

  return (name, config, handler) => {
    // `permission` must NOT reach the SDK: it serialises `config` into the
    // prompt manifest advertised to clients, which would publish the whole
    // permission model to every connected agent. Same reasoning as
    // createRegisterTool.
    const { permission, ...sdkConfig } = config;
    declared.set(name, permission);

    const decision = checkPermissionForVerdict(verdict, context.role, permission);

    const guarded = async (args: any) => {
      // Prompts return `{ messages }`, so there is no isError result shape to
      // carry a denial the way mcpUserError does for tools — throwing is the
      // protocol-level answer. Prompts are not wrapped by withToolTracing, so
      // this reaches no alerting path.
      //
      // The denial metric fires HERE, on an actual attempted call — matching
      // recordToolDenial. Recording it at registration instead would count a
      // passive non-event on every request an under-permissioned role makes,
      // and miss the real "someone tried and was refused".
      if (!decision.ok) {
        recordPromptDenial(name, permission);
        throw new Error(decision.message);
      }
      return handler(args);
    };

    const registered = (server as any).registerPrompt(name, sdkConfig, guarded);

    // ClickStack's rule: a resource a role cannot reach is hidden from it
    // entirely, not advertised and then refused. Disabling keeps it out of
    // prompts/list while leaving it in _registeredPrompts, so the coverage
    // assertion still sees it. `guarded` remains the enforcement backstop for
    // a client calling a cached name.
    if (!decision.ok) registered.disable();
  };
}
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
cd packages/api && yarn ci:unit src/mcp/__tests__/registerPrompt.test.ts
```

Expected: PASS, 6 tests.

- [ ] **Step 6: Commit**

```bash
git add packages/api/src/mcp/tools/types.ts packages/api/src/mcp/utils/registerPrompt.ts packages/api/src/mcp/__tests__/registerPrompt.test.ts
git commit -m "feat(api): guarded registrar for MCP prompts"
```

---

### Task 2: MCP coverage assertion over prompts, and wiring

**Files:**
- Create: `packages/api/src/mcp/utils/coverage.ts`
- Modify: `packages/api/src/mcp/utils/registerTool.ts` (remove `assertToolCoverage`)
- Modify: `packages/api/src/mcp/mcpServer.ts`
- Modify: `packages/api/src/mcp/prompts/dashboards/index.ts`
- Test: `packages/api/src/mcp/__tests__/coverage.test.ts`

**Interfaces:**
- Consumes: `DeclaredPermissions` from `@/mcp/utils/registerTool`; `DeclaredPrompts`, `createRegisterPrompt` from `@/mcp/utils/registerPrompt`; `PromptDefinition`, `PromptRegistrar` from `@/mcp/tools/types`.
- Produces: `assertMcpCoverage(server, declaredTools, declaredPrompts): void`, `MIN_REGISTERED_TOOLS = 26`, `MIN_REGISTERED_PROMPTS = 3` from `@/mcp/utils/coverage`.

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/mcp/__tests__/coverage.test.ts`:

```ts
import { assertMcpCoverage } from '@/mcp/utils/coverage';

function serverWith(tools: string[], prompts: string[]) {
  return {
    _registeredTools: Object.fromEntries(tools.map(t => [t, {}])),
    _registeredPrompts: Object.fromEntries(prompts.map(p => [p, {}])),
  } as any;
}

const TOOLS = Array.from({ length: 28 }, (_, i) => `tool_${i}`);
const PROMPTS = ['create_dashboard', 'dashboard_examples', 'query_guide'];

const allDeclared = (names: string[]) =>
  new Map(names.map(n => [n, 'sources:read' as const]));

describe('assertMcpCoverage', () => {
  it('passes when every tool and prompt declares a permission', () => {
    expect(() =>
      assertMcpCoverage(
        serverWith(TOOLS, PROMPTS),
        allDeclared(TOOLS),
        allDeclared(PROMPTS),
      ),
    ).not.toThrow();
  });

  // SEC-1's root cause: the assertion inspected _registeredTools only, so an
  // undeclared prompt sailed past a check that was passing on 28 tools.
  it('fails when a prompt declares no permission', () => {
    expect(() =>
      assertMcpCoverage(
        serverWith(TOOLS, PROMPTS),
        allDeclared(TOOLS),
        allDeclared(['query_guide']),
      ),
    ).toThrow(/prompt.*create_dashboard/s);
  });

  it('fails when a tool declares no permission', () => {
    expect(() =>
      assertMcpCoverage(
        serverWith(TOOLS, PROMPTS),
        allDeclared(TOOLS.slice(1)),
        allDeclared(PROMPTS),
      ),
    ).toThrow(/tool.*tool_0/s);
  });

  // Non-vacuity, per slice C §12: a walker that enumerates nothing must not
  // pass. Guards each surface independently.
  it('fails vacuously-empty tool enumeration', () => {
    expect(() =>
      assertMcpCoverage(serverWith([], PROMPTS), new Map(), allDeclared(PROMPTS)),
    ).toThrow(/could not enumerate registered tools/);
  });

  it('fails vacuously-empty prompt enumeration', () => {
    expect(() =>
      assertMcpCoverage(serverWith(TOOLS, []), allDeclared(TOOLS), new Map()),
    ).toThrow(/could not enumerate registered prompts/);
  });

  it('fails a tool list that shrank below the expected floor', () => {
    const few = TOOLS.slice(0, 5);
    expect(() =>
      assertMcpCoverage(serverWith(few, PROMPTS), allDeclared(few), allDeclared(PROMPTS)),
    ).toThrow(/could not enumerate registered tools/);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd packages/api && yarn ci:unit src/mcp/__tests__/coverage.test.ts
```

Expected: FAIL — `Cannot find module '@/mcp/utils/coverage'`.

- [ ] **Step 3: Write the coverage module**

Create `packages/api/src/mcp/utils/coverage.ts`:

```ts
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { ToolPermission } from '@/mcp/tools/types';

/**
 * Floors for the non-vacuity guard. A walker that finds nothing — or far less
 * than the surface actually registers — must fail rather than pass on an empty
 * list. Set below the real counts (28 tools, 3 prompts) so adding or removing
 * one tool does not trip the guard, but a broken enumeration does.
 */
export const MIN_REGISTERED_TOOLS = 26;
export const MIN_REGISTERED_PROMPTS = 3;

type Declared = Map<string, ToolPermission>;

function readRegistry(server: McpServer, key: string): string[] {
  // The SDK keeps registrations in internal records; read defensively so a
  // shape change degrades to "cannot verify" rather than a false pass.
  return Object.keys((server as any)[key] ?? {});
}

function assertSurface(
  kind: 'tool' | 'prompt',
  registered: string[],
  declared: Declared,
  minimum: number,
): void {
  if (registered.length < minimum) {
    throw new Error(
      `MCP ${kind} coverage check could not enumerate registered ${kind}s ` +
        `(found ${registered.length}, expected at least ${minimum}). The SDK ` +
        `internals may have changed — verify before shipping, since a short ` +
        `list would otherwise pass this assertion vacuously.`,
    );
  }

  const uncovered = registered.filter(name => !declared.has(name));
  if (uncovered.length > 0) {
    throw new Error(
      `MCP ${kind} coverage check failed. ${uncovered.length} ${kind}(s) declare no permission:\n` +
        uncovered.map(n => `  ${n}`).join('\n') +
        `\n\nAdd a \`permission\` to each ${kind}'s registration config.`,
    );
  }
}

/**
 * Fails startup when a registered tool or prompt declares no permission.
 *
 * Covers prompts as well as tools: SEC-1 was a prompt surface registered
 * straight onto the server, invisible to an assertion that read
 * `_registeredTools` alone. Disabled prompts remain in `_registeredPrompts`,
 * so role-based hiding cannot make this pass vacuously.
 */
export function assertMcpCoverage(
  server: McpServer,
  declaredTools: Declared,
  declaredPrompts: Declared,
): void {
  assertSurface(
    'tool',
    readRegistry(server, '_registeredTools'),
    declaredTools,
    MIN_REGISTERED_TOOLS,
  );
  assertSurface(
    'prompt',
    readRegistry(server, '_registeredPrompts'),
    declaredPrompts,
    MIN_REGISTERED_PROMPTS,
  );
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd packages/api && yarn ci:unit src/mcp/__tests__/coverage.test.ts
```

Expected: PASS, 6 tests.

- [ ] **Step 5: Delete the superseded assertion**

In `packages/api/src/mcp/utils/registerTool.ts`, delete the entire `assertToolCoverage` function and its doc comment (everything from `/**\n * Fails startup when a registered tool declares no permission.` to the closing brace at end of file). Leave `createRegisterTool` and `DeclaredPermissions` untouched.

- [ ] **Step 6: Route the prompts through the registrar**

In `packages/api/src/mcp/prompts/dashboards/index.ts`:

Change the signature line from `const dashboardPrompts: PromptDefinition = (server, context) => {` to:

```ts
const dashboardPrompts: PromptDefinition = ({ context, registerPrompt }) => {
```

Then change all three registration calls from `server.registerPrompt(` to `registerPrompt(`, and add `permission: 'sources:read',` as the last field of each config object. The three configs become:

```ts
  registerPrompt(
    'create_dashboard',
    {
      title: 'Create a Dashboard',
      description:
        'Create a ClickStack dashboard with the MCP tools. ' +
        'Follow the recommended workflow, pick tile types, write queries, ' +
        'and validate results against your real data sources.',
      argsSchema: {
        description: z
          .string()
          .optional()
          .describe(
            'What the dashboard should monitor (e.g. "API error rates and latency")',
          ),
      },
      // Seeds its text from the team's real sources and connections, so it
      // enumerates them (slice C §9).
      permission: 'sources:read',
    },
```

```ts
  registerPrompt(
    'dashboard_examples',
    {
      title: 'Dashboard Examples',
      description:
        'Concrete dashboard example shapes for common observability patterns: ' +
        'service_inventory, service_detail, log_analytics, backend_dependencies, drilldown_links, infrastructure_sql. ' +
        'Each example carries a "when to use" header. Adapt the structure to the user\'s request; ' +
        'do not copy literal column names or status values without verifying via clickstack_list_sources first.',
      argsSchema: {
        pattern: z
          .string()
          .optional()
          .describe(
            'Filter to a specific pattern: service_inventory, service_detail, log_analytics, backend_dependencies, drilldown_links, infrastructure_sql',
          ),
      },
      permission: 'sources:read',
    },
```

```ts
  registerPrompt(
    'query_guide',
    {
      title: 'Query Writing Guide',
      description:
        'Look up HyperDX query syntax: aggregation functions, ' +
        'Lucene/SQL filters, raw SQL macros, column naming, ' +
        'per-tile constraints, and common mistakes.',
      permission: 'sources:read',
    },
```

The handler bodies are unchanged.

- [ ] **Step 7: Wire it in `mcpServer.ts`**

Replace the body of `createServer` in `packages/api/src/mcp/mcpServer.ts` with:

```ts
export function createServer(context: McpContext) {
  const server = new McpServer({
    name: 'clickstack',
    version: `${CODE_VERSION}-beta`,
  });

  const declaredTools: DeclaredPermissions = new Map();
  const declaredPrompts: DeclaredPrompts = new Map();
  const registerTool = createRegisterTool(server, context, declaredTools);
  const registerPrompt = createRegisterPrompt(server, context, declaredPrompts);
  const registrar = { server, context, registerTool };

  sourcesTools(registrar);
  alertsTools(registrar);
  dashboardsTools(registrar);
  queryTools(registrar);
  savedSearchesTools(registrar);
  traceTools(registrar);
  dashboardPrompts({ server, context, registerPrompt });

  // Every tool AND prompt must declare a permission. A new one that forgets
  // fails here rather than shipping ungated — the runtime half of the
  // guarantee. Prompts are included because SEC-1 was exactly a prompt
  // surface that this assertion could not see.
  assertMcpCoverage(server, declaredTools, declaredPrompts);

  return server;
}
```

And update its imports:

```ts
import { assertMcpCoverage } from './utils/coverage';
import {
  createRegisterPrompt,
  type DeclaredPrompts,
} from './utils/registerPrompt';
import {
  createRegisterTool,
  type DeclaredPermissions,
} from './utils/registerTool';
```

- [ ] **Step 8: Verify typecheck and the full MCP suite**

```bash
cd packages/api && npx tsc --noEmit && yarn ci:unit src/mcp
```

Expected: no type errors; all MCP unit tests pass.

- [ ] **Step 9: Commit**

```bash
git add packages/api/src/mcp
git commit -m "fix(api): gate the MCP prompt surface and assert its coverage

SEC-1. mcpServer passed the raw server to the prompt registrar, bypassing the
chokepoint covering all 28 tools, and assertToolCoverage read _registeredTools
only. The three prompts enumerate the team's real source and connection names
and were reachable by every actor, including sources:none.

Prompts now register through a guarded registrar and are hidden from
prompts/list for roles that cannot reach them, per ClickStack's rule that a
resource a role cannot reach is hidden entirely. The coverage assertion covers
both surfaces with an independent non-vacuity floor on each."
```

---

### Task 3: Coarse gate on the browser query path

**Files:**
- Modify: `packages/api/src/routers/api/clickhouseProxy.ts:349,357`
- Modify: `packages/api/src/routers/api/prometheus.ts:9,18,376,377,484,485,497`
- Modify: `packages/api/src/middleware/rbac.ts:24-27`
- Test: `packages/api/src/routers/api/__tests__/queryPathRbac.test.ts`

**Interfaces:**
- Consumes: `requirePermission(resource, level)` from `@/middleware/rbac`.
- Produces: nothing new. `RbacExemptReason` loses its `'query-path-slice-B'` member.

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/routers/api/__tests__/queryPathRbac.test.ts`:

```ts
import { getRbacDeclaration } from '@/middleware/rbac';

// SEC-2: a role holding sources:none and connections:none was denied
// GET /sources, GET /connections and MCP list_sources, then reached
// POST /clickhouse-proxy and ran arbitrary read SQL against the cluster.
// These routes must declare a permission, not an exemption.
describe('query path RBAC declarations', () => {
  const layersOf = (router: any) =>
    router.stack
      .filter((l: any) => l.route)
      .flatMap((l: any) =>
        l.route.stack.map((s: any) => ({
          path: l.route.path,
          declaration: getRbacDeclaration(s.handle),
        })),
      )
      .filter((e: any) => e.declaration);

  it('gates the clickhouse proxy passthrough on sources: read', () => {
    const router = require('@/routers/api/clickhouseProxy').default;
    const passthrough = layersOf(router).filter((e: any) => e.path === '/*');

    expect(passthrough.length).toBeGreaterThan(0);
    for (const entry of passthrough) {
      expect(entry.declaration).toEqual({
        kind: 'permission',
        resource: 'sources',
        level: 'read',
      });
    }
  });

  it('gates every prometheus route on sources: read', () => {
    const router = require('@/routers/api/prometheus').default;
    const entries = layersOf(router);

    expect(entries.length).toBe(5);
    for (const entry of entries) {
      expect(entry.declaration).toEqual({
        kind: 'permission',
        resource: 'sources',
        level: 'read',
      });
    }
  });

  it('leaves no route claiming the retired query-path exemption', () => {
    for (const mod of ['clickhouseProxy', 'prometheus']) {
      const router = require(`@/routers/api/${mod}`).default;
      for (const entry of layersOf(router)) {
        expect(entry.declaration.kind).not.toBe('exempt');
      }
    }
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd packages/api && yarn ci:unit src/routers/api/__tests__/queryPathRbac.test.ts
```

Expected: FAIL — declarations are `{ kind: 'exempt', reason: 'query-path-slice-B' }`.

- [ ] **Step 3: Gate the proxy**

In `packages/api/src/routers/api/clickhouseProxy.ts`, at lines 349 and 357, replace:

```ts
  noPermissionRequired('query-path-slice-B'),
```

with:

```ts
  // SEC-2. Slice B still owns data-level enforcement, but leaving this
  // ungated let a sources:none role reach arbitrary read SQL against the
  // whole cluster. All three system roles hold sources:read, so no system
  // role loses anything.
  requirePermission('sources', 'read'),
```

Then change the import on line 11 from:

```ts
import { noPermissionRequired, requirePermission } from '@/middleware/rbac';
```

to:

```ts
import { requirePermission } from '@/middleware/rbac';
```

- [ ] **Step 4: Gate prometheus**

In `packages/api/src/routers/api/prometheus.ts`, change the import on line 9 from `import { noPermissionRequired } from '@/middleware/rbac';` to:

```ts
import { requirePermission } from '@/middleware/rbac';
```

Replace line 18 with:

```ts
// SEC-2. Was noPermissionRequired('query-path-slice-B'); the PromQL path is a
// query path and was reachable by a role holding sources: none.
const queryPathGate = () => requirePermission('sources', 'read');
```

Then replace `queryPathExempt()` with `queryPathGate()` at lines 376, 377, 484, 485 and 497.

- [ ] **Step 5: Retire the exemption reason**

In `packages/api/src/middleware/rbac.ts`, replace:

```ts
export type RbacExemptReason =
  | 'public'
  | 'personal-state'
  | 'query-path-slice-B';
```

with:

```ts
export type RbacExemptReason = 'public' | 'personal-state';
```

- [ ] **Step 6: Run the test and the full unit suite**

```bash
cd packages/api && yarn ci:unit src/routers/api/__tests__/queryPathRbac.test.ts && npx tsc --noEmit && yarn ci:unit
```

Expected: the new test PASSES; no type errors (a leftover `'query-path-slice-B'` anywhere fails the typecheck); the existing suite stays green.

- [ ] **Step 7: Commit**

```bash
git add packages/api/src/routers/api/clickhouseProxy.ts packages/api/src/routers/api/prometheus.ts packages/api/src/middleware/rbac.ts packages/api/src/routers/api/__tests__/queryPathRbac.test.ts
git commit -m "fix(api): require sources:read on the browser query path

SEC-2. A role holding sources:none and connections:none was correctly denied
GET /sources, GET /connections and MCP list_sources, then harvested a
connectionId and ran SHOW DATABASES plus a credential-scraping SELECT through
POST /clickhouse-proxy.

Slice B still owns data-level enforcement — a sources:read holder can still
run arbitrary read SQL — but the path is no longer reachable by a role
deliberately denied sources. The exemption reason is retired with its last
user."
```

---

### Task 4: Redact invitation tokens from non-admins

**Files:**
- Modify: `packages/api/src/middleware/rbac.ts` (add `isEffectiveAdmin`)
- Modify: `packages/api/src/routers/api/team.ts:215-241`
- Modify: `packages/api/src/routers/external-api/v2/team.ts:188-211`
- Test: `packages/api/src/middleware/__tests__/isEffectiveAdmin.test.ts`

**Interfaces:**
- Produces: `isEffectiveAdmin(req: Request): boolean` from `@/middleware/rbac`.

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/middleware/__tests__/isEffectiveAdmin.test.ts`:

```ts
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
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd packages/api && yarn ci:unit src/middleware/__tests__/isEffectiveAdmin.test.ts
```

Expected: FAIL — `isEffectiveAdmin is not a function`.

- [ ] **Step 3: Add the helper**

Append to `packages/api/src/middleware/rbac.ts`:

```ts
/**
 * The same predicate `requireAdmin()` gates on, for handlers that need to
 * *shape* a response by admin-ness rather than reject the request.
 *
 * Deliberately mirrors `resolveVerdict` rather than calling it: that function
 * increments `hyperdx.rbac.missing_role`, which must fire exactly once per
 * request. Calling it a second time to read admin-ness would double-count
 * every role-less request.
 */
export function isEffectiveAdmin(req: Request): boolean {
  if (config.IS_LOCAL_APP_MODE) return true;

  const role = (req.user as any)?.role ?? null;
  if (role == null) {
    // Session fail-open, access-key fail-closed — slice C §7.
    return (req as any)._hdx_authPath !== 'access-key';
  }

  return role.isAdmin === true;
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd packages/api && yarn ci:unit src/middleware/__tests__/isEffectiveAdmin.test.ts
```

Expected: PASS, 4 tests.

- [ ] **Step 5: Redact on the internal route**

In `packages/api/src/routers/api/team.ts`, add `isEffectiveAdmin` to the existing `@/middleware/rbac` import, then replace the handler body at lines 217-241 with:

```ts
  async (req, res: TeamInviteExpressRes, next) => {
    try {
      const teamId = req.user?.team;
      if (teamId == null) {
        throw new Error(`User ${req.user?._id} not associated with a team`);
      }

      // BUG-7. The invite URL embeds an accept-capable token, and users:read is
      // held by Member. Members keep seeing which invitations are outstanding;
      // the token is not projected for them, so it never enters the process.
      const isAdmin = isEffectiveAdmin(req);

      const teamInvites = await TeamInvite.find(
        { teamId },
        {
          createdAt: 1,
          email: 1,
          name: 1,
          ...(isAdmin ? { token: 1 } : {}),
        },
      );
      res.json({
        data: teamInvites.map(ti => ({
          _id: ti._id.toString(),
          createdAt: ti.createdAt.toISOString(),
          email: ti.email,
          name: ti.name,
          ...(isAdmin ? { url: getTeamInviteUrl(ti.token) } : {}),
        })),
      });
```

- [ ] **Step 6: Redact on the v2 route**

In `packages/api/src/routers/external-api/v2/team.ts`, add `isEffectiveAdmin` to the existing `@/middleware/rbac` import, then replace the handler body at lines 191-211 with:

```ts
  async (req, res, next) => {
    try {
      const teamId = req.user?.team;
      if (!teamId) {
        return res.sendStatus(403);
      }

      // BUG-7 — same redaction as the internal route.
      const isAdmin = isEffectiveAdmin(req);

      const teamInvites = await TeamInvite.find(
        { teamId: teamId.toString() },
        { createdAt: 1, email: 1, name: 1, ...(isAdmin ? { token: 1 } : {}) },
      );

      return res.json({
        data: teamInvites.map(ti => ({
          id: ti._id.toString(),
          createdAt: ti.createdAt,
          email: ti.email,
          name: ti.name,
          ...(isAdmin ? { url: getTeamInviteUrl(ti.token) } : {}),
        })),
      });
```

- [ ] **Step 7: Typecheck and commit**

```bash
cd packages/api && npx tsc --noEmit && yarn ci:unit
```

Expected: no type errors, suite green.

```bash
git add packages/api/src/middleware packages/api/src/routers/api/team.ts packages/api/src/routers/external-api/v2/team.ts
git commit -m "fix(api): withhold invitation tokens from non-admins

BUG-7. GET /team/invitations returned each pending invite's full
join-team?token= URL at users:read, which Member holds — so a Member could
read a live token and hand it to an outsider, while invite creation stayed
requireAdmin. The list stays at users:read so Members still see which
invitations are outstanding; the accept-capable token is admin-only."
```

---

# Phase 2 — Invariants

### Task 5: Last-admin invariant on the explicit grant

**Files:**
- Modify: `packages/api/src/controllers/role.ts` (`countEffectiveAdmins`, `assignRole`, `isLastAdmin`)
- Test: `packages/api/src/controllers/__tests__/lastAdmin.int.test.ts`

**Interfaces:**
- Produces: `countAdminRoleHolders(teamId, excludeUserId?)` and `holdsAdminRole(teamId, user)` — both module-private. `assignRole` and `isLastAdmin` keep their existing signatures.

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/controllers/__tests__/lastAdmin.int.test.ts`, following the harness in the sibling `role.int.test.ts` exactly:

```ts
import { Types } from 'mongoose';

import {
  assignRole,
  isLastAdmin,
  RoleConflictError,
  seedSystemRoles,
} from '@/controllers/role';
import { getServer } from '@/fixtures';
import Role from '@/models/role';
import User from '@/models/user';

describe('last-admin invariant', () => {
  const server = getServer();

  beforeAll(async () => {
    await server.start();
    await Role.init();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  async function team(): Promise<string> {
    const teamId = new Types.ObjectId().toString();
    await seedSystemRoles(teamId);
    return teamId;
  }

  const roleId = async (teamId: string, name: string) =>
    (await Role.findOne({ team: teamId, name }))!._id;

  let seq = 0;
  const user = async (teamId: string, role: any) =>
    User.create({
      team: teamId,
      email: `u${seq++}@x.test`,
      name: 'u',
      role,
    });

  // BUG-1, the exact A/B the manual test ran: same request, different outcome
  // depending on whether a role-less user happened to exist.
  it('blocks demoting the last Admin even when a role-less user exists', async () => {
    const t = await team();
    const admin = await user(t, await roleId(t, 'Admin'));
    await user(t, undefined); // role-less: previously made the guard silent

    await expect(
      assignRole(t, admin._id.toString(), (await roleId(t, 'Member')).toString()),
    ).rejects.toThrow(RoleConflictError);

    const reread = await User.findById(admin._id);
    expect(reread!.role!.toString()).toBe((await roleId(t, 'Admin')).toString());
  });

  it('allows demoting an Admin while another Admin remains', async () => {
    const t = await team();
    const a1 = await user(t, await roleId(t, 'Admin'));
    await user(t, await roleId(t, 'Admin'));

    await assignRole(t, a1._id.toString(), (await roleId(t, 'Member')).toString());

    const reread = await User.findById(a1._id);
    expect(reread!.role!.toString()).toBe((await roleId(t, 'Member')).toString());
  });

  // The clause that keeps un-migrated teams usable: nobody there holds an
  // isAdmin role, so the guard must not fire at all.
  it('does not fire for a role-less user on an un-migrated team', async () => {
    const t = await team();
    const u = await user(t, undefined);

    await assignRole(t, u._id.toString(), (await roleId(t, 'Member')).toString());

    const reread = await User.findById(u._id);
    expect(reread!.role!.toString()).toBe((await roleId(t, 'Member')).toString());
  });

  it('reports isLastAdmin only for a holder of an isAdmin role', async () => {
    const t = await team();
    const admin = await user(t, await roleId(t, 'Admin'));
    const roleless = await user(t, undefined);

    expect(await isLastAdmin(t, admin._id.toString())).toBe(true);
    expect(await isLastAdmin(t, roleless._id.toString())).toBe(false);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd packages/api && make dev-int FILE=lastAdmin
```

Expected: the first test FAILS — `assignRole` resolves instead of rejecting, because the role-less user is counted as an admin.

- [ ] **Step 3: Replace the counting helpers**

In `packages/api/src/controllers/role.ts`, replace `countEffectiveAdmins` (and its doc comment) with:

```ts
async function getAdminRoleIds(
  teamId: string | ObjectId,
): Promise<ObjectId[]> {
  const roles = await Role.find({ team: teamId, isAdmin: true })
    .select('_id')
    .lean();
  return roles.map(r => r._id);
}

/**
 * Users holding an `isAdmin` role.
 *
 * BUG-1: this deliberately does NOT count role-less users. They pass
 * `requireAdmin` via the session fail-open, so counting them made the guard
 * fall silent whenever any un-migrated user existed — the same demotion
 * returning 200 or 409 depending on invisible state. The guard's callers
 * instead check that the *target* holds an admin role, which keeps
 * un-migrated teams usable without weakening the invariant.
 */
async function countAdminRoleHolders(
  teamId: string | ObjectId,
  excludeUserId?: ObjectId | string,
): Promise<number> {
  const adminRoleIds = await getAdminRoleIds(teamId);
  if (adminRoleIds.length === 0) return 0;

  return User.countDocuments({
    team: teamId,
    role: { $in: adminRoleIds },
    ...(excludeUserId ? { _id: { $ne: excludeUserId } } : {}),
  });
}

/** Whether this user currently holds one of the team's isAdmin roles. */
async function holdsAdminRole(
  teamId: string | ObjectId,
  user: { role?: ObjectId | null },
): Promise<boolean> {
  if (user.role == null) return false;
  const adminRoleIds = await getAdminRoleIds(teamId);
  return adminRoleIds.some(id => id.toString() === user.role!.toString());
}
```

- [ ] **Step 4: Rewrite `assignRole`'s guard**

In the same file, replace the body of `assignRole` after the `if (!nextRole) throw ...` line with:

```ts
  const previousRoleId = user.role;
  // Captured before the write: the rollback below must know whether this user
  // was an admin, and the answer changes once the write lands.
  const wasAdmin = await holdsAdminRole(teamId, user);

  // Last-admin protection. §9.2: the last user *holding* an isAdmin role
  // cannot be demoted. A user who holds no admin role cannot be the last one,
  // so the guard does not fire for them — which is what keeps an un-migrated
  // team (nobody holds an admin role) from becoming unmanageable.
  if (!nextRole.isAdmin && wasAdmin) {
    const remaining = await countAdminRoleHolders(teamId, user._id);
    if (remaining === 0) {
      throw new RoleConflictError(
        'This is the last Admin. Promote someone else to Admin first.',
      );
    }
  }

  user.role = nextRole._id;
  await user.save();

  // Re-check after the write. Two concurrent demotions can each observe one
  // other admin remaining and both commit, leaving zero — an unrecoverable
  // state. Roll this one back if that happened.
  if (
    !nextRole.isAdmin &&
    wasAdmin &&
    (await countAdminRoleHolders(teamId)) === 0
  ) {
    user.role = previousRoleId;
    await user.save();
    throw new RoleConflictError(
      'This is the last Admin. Promote someone else to Admin first.',
    );
  }
}
```

- [ ] **Step 5: Rewrite `isLastAdmin`**

Replace `isLastAdmin` (and its doc comment) with:

```ts
/**
 * True when removing this user would leave the team with no admin-role holder.
 *
 * Only ever true for a user who currently holds an `isAdmin` role — see
 * `countAdminRoleHolders` for why role-less users are not counted.
 */
export async function isLastAdmin(
  teamId: string | ObjectId,
  userId: string | ObjectId,
): Promise<boolean> {
  const user = await User.findOne({ _id: userId, team: teamId });
  if (!user) return false;
  if (!(await holdsAdminRole(teamId, user))) return false;

  return (await countAdminRoleHolders(teamId, userId)) === 0;
}
```

- [ ] **Step 6: Run the tests**

```bash
cd packages/api && make dev-int FILE=lastAdmin
```

Expected: PASS, 4 tests. Then run the existing role suites to catch regressions:

```bash
cd packages/api && yarn ci:unit src/controllers && npx tsc --noEmit
```

- [ ] **Step 7: Commit**

```bash
git add packages/api/src/controllers/role.ts packages/api/src/controllers/__tests__/lastAdmin.int.test.ts
git commit -m "fix(api): guard the last Admin on the explicit isAdmin grant

BUG-1. countEffectiveAdmins counted role-less users as admins, so the guard
fell silent whenever any un-migrated user existed: the same demotion returned
200 or 409 depending on invisible state, and Team Settings could show nobody
with Admin.

The count now covers holders of an isAdmin role only, and the guard fires only
when the target holds one — so an un-migrated team, where nobody does, stays
manageable. Failure is a recoverable 409, never a lockout."
```

---

### Task 6: Migration pre-flight abort

**Files:**
- Modify: `packages/api/migrations/mongo/20260802120000-add_rbac_roles.ts`
- Test: `packages/api/migrations/mongo/__tests__/addRbacRoles.int.test.ts`

**Interfaces:**
- Consumes: nothing new. `up(db)` and `down(db)` keep their signatures.

- [ ] **Step 1: Write the failing test**

Create `packages/api/migrations/mongo/__tests__/addRbacRoles.int.test.ts`. The migration takes a raw `Db`, not Mongoose models, so reach it through the connection the fixtures already open:

```ts
import mongoose from 'mongoose';

import { getServer } from '@/fixtures';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const migration = require('../20260802120000-add_rbac_roles');

describe('add_rbac_roles migration', () => {
  const server = getServer();
  let db: mongoose.mongo.Db;

  beforeAll(async () => {
    await server.start();
    db = mongoose.connection.db as mongoose.mongo.Db;
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  // BUG-3: the $setOnInsert upsert matched the existing role by {team,name}
  // and inserted nothing, so findOne({isAdmin:true}) returned null and
  // admin!._id threw — leaving Member + ReadOnly seeded, no admin role, no
  // user assigned, and no migrate-mongo changelog entry.
  it('aborts before any write when a non-system role uses a reserved name', async () => {
    const teamId = new mongoose.Types.ObjectId();
    await db.collection('teams').insertOne({ _id: teamId, name: 'T' });
    await db.collection('roles').insertOne({
      team: teamId,
      name: 'Admin',
      isSystem: false,
      isAdmin: false,
      permissions: {},
    });

    await expect(migration.up(db)).rejects.toThrow(/aborted before any write/);

    // Nothing was seeded — the operator repairs from a clean state.
    const roles = await db.collection('roles').find({ team: teamId }).toArray();
    expect(roles).toHaveLength(1);
    expect(roles[0].name).toBe('Admin');
    expect(roles[0].isSystem).toBe(false);
  });

  it('names the offending team and role in the error', async () => {
    const teamId = new mongoose.Types.ObjectId();
    await db.collection('teams').insertOne({ _id: teamId, name: 'T' });
    await db
      .collection('roles')
      .insertOne({ team: teamId, name: 'ReadOnly', isSystem: false, permissions: {} });

    await expect(migration.up(db)).rejects.toThrow(
      new RegExp(`${teamId.toString()}[\\s\\S]*ReadOnly`),
    );
  });

  it('seeds normally when no reserved name is taken', async () => {
    const teamId = new mongoose.Types.ObjectId();
    await db.collection('teams').insertOne({ _id: teamId, name: 'T' });
    await db.collection('users').insertOne({ team: teamId, email: 'a@x.test' });

    await migration.up(db);

    const roles = await db.collection('roles').find({ team: teamId }).toArray();
    expect(roles).toHaveLength(3);
    const admin = roles.find((r: any) => r.isAdmin === true);
    expect(admin).toBeDefined();

    const user = await db.collection('users').findOne({ team: teamId });
    expect(user!.role.toString()).toBe(admin!._id.toString());
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd packages/api && make dev-int FILE=addRbacRoles
```

Expected: the first test FAILS — `up` throws `Cannot read properties of null (reading '_id')` rather than the pre-flight message, and Member + ReadOnly are already seeded.

- [ ] **Step 3: Add the pre-flight check**

In `packages/api/migrations/mongo/20260802120000-add_rbac_roles.ts`, insert this immediately after the `SYSTEM_ROLES` array and before `module.exports`:

```ts
const SYSTEM_ROLE_NAMES = SYSTEM_ROLES.map(r => r.name);
```

Then replace the first two statements of `up` (the `createIndex` call and the `teams` find) with:

```ts
  async up(db: Db, _client?: MongoClient) {
    // BUG-3. The roles API is live pre-migration (the session path fails open
    // as admin), so an operator can create a custom role named "Admin" first.
    // The $setOnInsert upsert below would then match it, insert nothing, and
    // leave the team with Member + ReadOnly and no admin role — and because
    // the throw happens mid-loop, migrate-mongo records no changelog entry, so
    // the operator must hand-repair before the migration can advance.
    //
    // Check every team before touching anything, so the failure mode is
    // "nothing happened, here is what to rename".
    const conflicts = await db
      .collection('roles')
      .find({ name: { $in: SYSTEM_ROLE_NAMES }, isSystem: { $ne: true } })
      .toArray();

    if (conflicts.length > 0) {
      const lines = conflicts
        .map(r => `  team ${r.team}: role "${r.name}" (_id ${r._id})`)
        .join('\n');
      throw new Error(
        'RBAC migration aborted before any write.\n\n' +
          `${conflicts.length} non-system role(s) use a reserved system role name:\n${lines}\n\n` +
          'Each would collide with the {team, name} unique index and leave its ' +
          'team seeded without an admin role. Rename them, then re-run the ' +
          'migration.',
      );
    }

    await db
      .collection('roles')
      .createIndex({ team: 1, name: 1 }, { unique: true });

    const teams = await db.collection('teams').find({}).toArray();
    const now = new Date();
```

- [ ] **Step 4: Replace the unchecked `admin!`**

Further down in `up`, replace:

```ts
      const admin = await db
        .collection('roles')
        .findOne({ team: team._id, isAdmin: true });
```

...through the `updateMany` call, with:

```ts
      const admin = await db
        .collection('roles')
        .findOne({ team: team._id, isAdmin: true });

      // Belt and braces behind the pre-flight: never dereference this blind.
      // Reaching here means something created a colliding role between the
      // check and now.
      if (!admin) {
        throw new Error(
          `RBAC migration: team ${team._id} has no isAdmin role after seeding. ` +
            'Inspect the roles collection for this team before re-running.',
        );
      }

      // Every existing user becomes an Admin of their own team. Downgrading
      // people is then a deliberate act, rather than something an upgrade
      // does to them silently.
      //
      // Only users who have no role yet: on a re-run this must not clobber
      // assignments an admin has already made since the first run.
      await db
        .collection('users')
        .updateMany(
          { team: team._id, role: { $in: [null, undefined] } },
          { $set: { role: admin._id } },
        );
```

- [ ] **Step 5: Run the tests**

```bash
cd packages/api && make dev-int FILE=addRbacRoles
```

Expected: PASS, 3 tests.

- [ ] **Step 6: Commit**

```bash
git add packages/api/migrations/mongo
git commit -m "fix(api): abort the RBAC migration before any write on a name collision

BUG-3. A team holding a non-system role named Admin made the upsert match and
insert nothing, so findOne({isAdmin:true}) returned null and admin!._id threw
mid-loop — leaving Member and ReadOnly seeded, no admin role, no user assigned
and no migrate-mongo changelog entry, so the operator had to hand-repair before
the migration could advance.

A pre-flight pass over every team now aborts before the first write, naming
each offending team and role."
```

---

### Task 7: Index barrier for role seeding

**Files:**
- Modify: `packages/api/src/controllers/role.ts` (`seedSystemRoles`)
- Test: `packages/api/src/controllers/__tests__/seedRace.int.test.ts`

**Interfaces:**
- Consumes: `Role.init()` from Mongoose. `seedSystemRoles(teamId)` keeps its signature.

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/controllers/__tests__/seedRace.int.test.ts`:

```ts
import { Types } from 'mongoose';

import { seedSystemRoles } from '@/controllers/role';
import { getServer } from '@/fixtures';
import Role from '@/models/role';

describe('seedSystemRoles concurrency', () => {
  const server = getServer();

  // BUG-4. Deliberately NO `await Role.init()` in this beforeAll, unlike
  // role.int.test.ts. That barrier in the *tests* is exactly what hid the
  // defect — the application had none. The barrier must come from
  // seedSystemRoles itself or this suite is meaningless.
  beforeAll(async () => {
    await server.start();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('produces exactly 3 roles and 1 admin under parallel calls', async () => {
    const teamId = new Types.ObjectId().toString();
    await Promise.all(
      Array.from({ length: 12 }, () => seedSystemRoles(teamId)),
    );

    const roles = await Role.find({ team: teamId });
    expect(roles).toHaveLength(3);
    expect(roles.filter(r => r.isAdmin)).toHaveLength(1);
  });

  it('returns all three roles to every caller', async () => {
    const teamId = new Types.ObjectId().toString();
    const results = await Promise.all(
      Array.from({ length: 6 }, () => seedSystemRoles(teamId)),
    );

    for (const created of results) {
      expect(created).toHaveLength(3);
      expect(created.every(r => r != null)).toBe(true);
    }
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd packages/api && make dev-int FILE=seedRace
```

Expected: FAIL — more than 3 roles, or more than 1 admin.

**This failure is intermittent by nature.** The manual test reproduced it in 7 of 20 trials, because it depends on losing a race against the background index build. Run it at least five times before concluding it passes pre-fix; a single green run proves nothing here.

- [ ] **Step 3: Add the barrier and the duplicate-key recovery**

In `packages/api/src/controllers/role.ts`, insert above `seedSystemRoles`:

```ts
/**
 * Mongoose builds indexes in the background, so the {team, name} unique index
 * may not exist yet during the first registration on a fresh database — the
 * exact window BUG-4 reproduced, where 12 parallel seeds produced duplicate
 * Admin roles in 7 of 20 trials. Once duplicates exist the index can never
 * build, which also wedges the migration's own createIndex.
 *
 * Memoised: only the first caller in the process waits.
 */
let roleIndexesReady: Promise<unknown> | null = null;
function ensureRoleIndexes(): Promise<unknown> {
  roleIndexesReady ??= Role.init();
  return roleIndexesReady;
}
```

Then replace the body of `seedSystemRoles` with:

```ts
export async function seedSystemRoles(
  teamId: string | ObjectId,
): Promise<RoleDocument[]> {
  await ensureRoleIndexes();

  const created: RoleDocument[] = [];

  for (const name of SYSTEM_ROLE_NAMES) {
    let role: RoleDocument | null;
    try {
      role = await Role.findOneAndUpdate(
        { team: teamId, name },
        {
          $setOnInsert: {
            team: teamId,
            name,
            description: SYSTEM_ROLE_DESCRIPTIONS[name],
            isSystem: true,
            isAdmin: name === 'Admin',
            permissions: SYSTEM_ROLE_PERMISSIONS[name],
          },
        },
        { upsert: true, new: true, setDefaultsOnInsert: true },
      );
    } catch (e) {
      // Two upserts racing a *present* index both attempt the insert and the
      // loser gets E11000. The document exists either way, so re-read rather
      // than fail the caller's registration. The index barrier above prevents
      // duplicate documents; this prevents a duplicate request failing.
      if (!isDuplicateKey(e)) throw e;
      role = await Role.findOne({ team: teamId, name });
      if (!role) throw e;
    }

    created.push(role);
  }

  return created;
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd packages/api && make dev-int FILE=seedRace
```

Expected: PASS. Run it three times — this test guards a race, so a single green run proves less than a repeated one.

- [ ] **Step 5: Commit**

```bash
git add packages/api/src/controllers/role.ts packages/api/src/controllers/__tests__/seedRace.int.test.ts
git commit -m "fix(api): barrier the role index build before seeding

BUG-4. seedSystemRoles relied entirely on the {team, name} unique index for
concurrency safety, but Mongoose builds it in the background — so during first
registration on a fresh database, 12 parallel calls produced duplicate Admin
roles in 7 of 20 trials. Once duplicates exist the index can never build, which
also wedges the migration's own createIndex.

The application now awaits the index build once per process, and recovers from
E11000 by re-reading rather than failing the caller."
```

---

### Task 8: Strict role schemas

**Files:**
- Modify: `packages/common-utils/src/types.ts:2250,2274`
- Test: `packages/common-utils/src/__tests__/roleSchemas.test.ts`

**Interfaces:**
- Produces: `RolePermissionsSchema` and `RoleInputSchema` reject unknown keys.

- [ ] **Step 1: Write the failing test**

Create `packages/common-utils/src/__tests__/roleSchemas.test.ts`:

```ts
import { RoleInputSchema, RolePermissionsSchema } from '../types';

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
    expect(RolePermissionsSchema.safeParse(VALID_PERMISSIONS).success).toBe(true);
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
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd packages/common-utils && yarn ci:unit src/__tests__/roleSchemas.test.ts
```

Expected: FAIL on both rejection tests — unknown keys are accepted.

- [ ] **Step 3: Make both schemas strict**

In `packages/common-utils/src/types.ts`, append `.strict()` to the `z.object({ ... })` that defines `RolePermissionsSchema` (line 2250) and to the one defining `RoleInputSchema` (line 2274). `RoleInputSchema` becomes:

```ts
export const RoleInputSchema = z
  .object({
    name: z.string().min(1).max(64),
    description: z.string().max(256).optional(),
    permissions: RolePermissionsSchema,
  })
  // BUG-10: an unknown key on a role document that looks like a capability
  // (permissions.isAdmin) is inert today and a misread waiting to happen.
  .strict();
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd packages/common-utils && yarn ci:unit src/__tests__/roleSchemas.test.ts
```

Expected: PASS, 4 tests.

- [ ] **Step 5: Rebuild common-utils and re-run the dependent suites**

```bash
yarn build:common-utils
cd packages/api && yarn ci:unit && npx tsc --noEmit
cd ../app && yarn ci:unit
```

Expected: green. If a role-creation test now fails, it was passing an unknown key — fix the test payload, not the schema.

- [ ] **Step 6: Commit**

```bash
git add packages/common-utils/src/types.ts packages/common-utils/src/__tests__/roleSchemas.test.ts
git commit -m "fix(common-utils): reject unknown keys on role schemas

BUG-10. permissions was a non-strict Zod object, so junk keys persisted to the
role document — including permissions.isAdmin: true. Verified inert, since
enforcement reads top-level role.isAdmin and permissions is only ever indexed
by valid Resource names, but storing a key that looks like a capability invites
a future misread."
```

---

# Phase 3 — UI

### Task 9: Inline the connection name on `GET /sources`

**Files:**
- Modify: `packages/api/src/routers/api/sources.ts:21-39`
- Modify: `packages/common-utils/src/types.ts` (`SourceSchema`)
- Modify: `packages/app/src/components/Sources/SourcesList.tsx:62-83,116-119,225`
- Modify: `packages/app/src/components/__tests__/SourcesList.test.tsx`

**Interfaces:**
- Consumes: `getConnectionsByTeam(teamId)` from `@/controllers/connection`.
- Produces: `GET /sources` response objects gain `connectionName: string | null`.

- [ ] **Step 1: Add the field to the shared schema**

**Do not use the `connection: z.string()` at line 1265 — that belongs to `_ChartConfigSchema`, not to sources.** Sources are a discriminated union: `BaseSourceSchema` (~line 1820) is extended by `LogSourceSchema`, `TraceSourceSchema`, `SessionSourceSchema`, `MetricSourceSchema` and `PromqlSourceSchema`, and `SourceSchema` (line 1916) is the union of those five.

Add the field to **`BaseSourceSchema`**, so all five variants inherit it:

```ts
  /**
   * Display-only, derived server-side by GET /sources. Lets the sources list
   * render a connection's name without holding connections:read — which
   * Member and ReadOnly do not (BUG-5). Never accepted on writes; see
   * SourceSchemaNoId below.
   */
  connectionName: z.string().nullable().optional(),
```

Then omit it from the write schema alongside `id`, which is already omitted for the same reason — it is server-assigned, not client-supplied. `SourceSchemaNoId` becomes:

```ts
export const SourceSchemaNoId = z.discriminatedUnion('kind', [
  LogSourceSchema.omit({ id: true, connectionName: true }),
  TraceSourceSchema.omit({ id: true, connectionName: true }),
  SessionSourceSchema.omit({ id: true, connectionName: true }),
  MetricSourceSchema.omit({ id: true, connectionName: true }),
  PromqlSourceSchema.omit({ id: true, connectionName: true }),
]);
```

Then rebuild:

```bash
yarn build:common-utils
```

- [ ] **Step 2: Write the failing API test**

Create `packages/api/src/routers/api/__tests__/sourcesConnectionName.int.test.ts`. `getServer` and `getLoggedInAgent` both come from `@/fixtures`; read a sibling router `*.int.test.ts` to confirm the exact shape `getLoggedInAgent` returns before writing the arrange block.

```ts
import { Types } from 'mongoose';

import { getLoggedInAgent, getServer } from '@/fixtures';
import { createConnection } from '@/controllers/connection';
import { createSource } from '@/controllers/sources';

describe('GET /sources', () => {
  const server = getServer();

  beforeAll(async () => {
    await server.start();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  // BUG-5: TeamPage gated the section on sources:read, but SourcesList also
  // called GET /connections (connections:read — `none` for Member and
  // ReadOnly), so the section rendered and then permanently 403'd.
  it('inlines the connection name so the view needs no connections:read', async () => {
    const { agent, team } = await getLoggedInAgent(server);
    const connection = await createConnection(team._id, { name: 'Local CH' });
    await createSource(team._id, { name: 'Logs', connection: connection._id });

    const res = await agent.get('/sources').expect(200);

    expect(res.body).toHaveLength(1);
    expect(res.body[0].connectionName).toBe('Local CH');
  });

  it('returns null rather than failing when the connection is missing', async () => {
    const { agent, team } = await getLoggedInAgent(server);
    await createSource(team._id, {
      name: 'Orphan',
      connection: new Types.ObjectId(),
    });

    const res = await agent.get('/sources').expect(200);

    expect(res.body[0].connectionName).toBeNull();
  });
});
```

- [ ] **Step 3: Run it to verify it fails**

```bash
cd packages/api && make dev-int FILE=sourcesConnectionName
```

Expected: FAIL — `connectionName` is `undefined`.

- [ ] **Step 4: Implement on the route**

In `packages/api/src/routers/api/sources.ts`, add the import:

```ts
import { getConnectionsByTeam } from '@/controllers/connection';
```

Replace the `GET /` handler body (lines 24-37) with:

```ts
    try {
      const { teamId } = getNonNullUserWithTeam(req);

      // BUG-5. The list view previously fetched /connections itself just to
      // render a name, which requires connections:read — `none` for Member and
      // ReadOnly, so a sources:read grant produced a permanent 403 banner.
      // Resolving the name here keeps the section's data need inside its own
      // gate.
      const [sources, connections] = await Promise.all([
        getSources(teamId.toString()),
        getConnectionsByTeam(teamId.toString()),
      ]);

      const connectionNameById = new Map(
        connections.map(c => [c._id.toString(), c.name]),
      );

      return res.json(
        sources.map(source => ({
          // @ts-expect-error source.toJSON has incompatible type signatures but is actually a safe operation
          ...source.toJSON({ getters: true }),
          connectionName:
            connectionNameById.get(source.connection?.toString()) ?? null,
        })),
      );
    } catch (e) {
      next(e);
    }
```

- [ ] **Step 5: Run the API test**

```bash
cd packages/api && make dev-int FILE=sourcesConnectionName
```

Expected: PASS, 2 tests.

- [ ] **Step 6: Drop the connections dependency from `SourcesList`**

In `packages/app/src/components/Sources/SourcesList.tsx`:

Delete the `useConnections` import (line 31) and replace lines 62-73 with:

```ts
  const {
    data: sources,
    isLoading,
    error,
    refetch: refetchSources,
  } = useSources();
```

Delete lines 82-83 (`const isLoading = ...` and `const error = ...`) — they are now redundant.

Replace `handleRetry` (lines 116-119) with:

```ts
  const handleRetry = () => {
    refetchSources();
  };
```

Replace line 225 with:

```ts
                      {s.connectionName}
```

- [ ] **Step 7: Update the component test**

In `packages/app/src/components/__tests__/SourcesList.test.tsx`, delete the `useConnections` import, the `jest.mock('@/connection', ...)` block, and the `asMock(useConnections).mockReturnValue(...)` line. Give each mocked source a `connectionName` and assert it renders:

```ts
  it('renders the connection name inlined by GET /sources', () => {
    asMock(useSources).mockReturnValue({
      data: [{ id: 's1', name: 'Logs', kind: 'log', connection: 'c1', connectionName: 'Local CH' }],
      isLoading: false,
      error: null,
      refetch: jest.fn(),
    });

    renderWithMantine(<SourcesList withCard={false} />);

    expect(screen.getByText('Local CH')).toBeInTheDocument();
  });
```

- [ ] **Step 8: Run the app tests and typecheck**

```bash
cd packages/app && yarn ci:unit src/components/__tests__/SourcesList.test.tsx && npx tsc --noEmit
```

Expected: PASS, no type errors.

- [ ] **Step 9: Commit**

```bash
git add packages/common-utils/src/types.ts packages/api/src/routers/api/sources.ts packages/api/src/routers/api/__tests__/sourcesConnectionName.int.test.ts packages/app/src/components/Sources/SourcesList.tsx packages/app/src/components/__tests__/SourcesList.test.tsx
git commit -m "fix: inline the connection name on GET /sources

BUG-5. TeamPage gated the Sources section on sources:read, but SourcesList
also called GET /connections (connections:read — none for Member and ReadOnly)
purely to render a name. The section rendered, then showed a permanent
'Failed to load sources · 403' with a Retry that re-failed.

The section's data need now sits inside its own gate. Hiding it from Member and
ReadOnly was the wrong direction: ClickStack's ReadOnly can read Sources, and a
read grant that produces an error page is broken whichever gate you move."
```

---

### Task 10: Wire the UI permission gates

**Files:**
- Modify: `packages/app/src/components/TeamSettings/ApiKeysSection.tsx:43`
- Modify: `packages/app/src/components/TeamSettings/TeamQueryConfigSection.tsx:67,174,246,256`
- Modify: `packages/app/src/components/TeamSettings/WebhooksSection.tsx:79,148-176,198`
- Modify: `packages/app/src/components/Dashboards/DashboardsListPage.tsx:225,284,295,355,364,396,429`
- Test: `packages/app/src/components/TeamSettings/__tests__/permissionGating.test.tsx`

**Interfaces:**
- Consumes: `useMyPermissions()` from `@/hooks/useMyPermissions`, exposing `{ isAdmin, isLoading, can(resource, level) }`.

- [ ] **Step 1: Write the failing test**

Create `packages/app/src/components/TeamSettings/__tests__/permissionGating.test.tsx`.

Two harness facts to copy rather than invent: there is no shared `asMock` export — sibling tests declare it locally (`const asMock = (fn: unknown) => fn as jest.Mock;`) — and `renderWithMantine` is a **global** defined in `packages/app/src/setupTests.tsx`, so it needs no import. Read a sibling test in that directory first to copy its `api` mock.

```tsx
import { screen } from '@testing-library/react';

import { useMyPermissions } from '@/hooks/useMyPermissions';

import ApiKeysSection from '../ApiKeysSection';
import WebhooksSection from '../WebhooksSection';

jest.mock('@/hooks/useMyPermissions');

const asMock = (fn: unknown) => fn as jest.Mock;

const perms = (isAdmin: boolean, granted: Record<string, string> = {}) =>
  asMock(useMyPermissions).mockReturnValue({
    isAdmin,
    isLoading: false,
    can: (resource: string, level: string) =>
      isAdmin || granted[resource] === level || granted[resource] === 'manage',
  });

// BUG-2 §10.3: whole sections a role cannot reach are absent, not disabled —
// the UI must never advertise something the server will reject.
describe('Team Settings permission gating', () => {
  it('hides Rotate API Key from a non-admin', () => {
    perms(false, { team: 'read' });
    renderWithMantine(<ApiKeysSection />);
    expect(screen.queryByTestId('rotate-api-key-button')).toBeNull();
  });

  it('shows Rotate API Key to an admin', () => {
    perms(true);
    renderWithMantine(<ApiKeysSection />);
    expect(screen.getByTestId('rotate-api-key-button')).toBeInTheDocument();
  });

  it('hides Add Webhook from a role holding only webhooks: read', () => {
    perms(false, { webhooks: 'read' });
    renderWithMantine(<WebhooksSection />);
    expect(screen.queryByTestId('add-webhook-section-button')).toBeNull();
  });

  it('shows Add Webhook to a role holding webhooks: manage', () => {
    perms(false, { webhooks: 'manage' });
    renderWithMantine(<WebhooksSection />);
    expect(screen.getByTestId('add-webhook-section-button')).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd packages/app && yarn ci:unit src/components/TeamSettings/__tests__/permissionGating.test.tsx
```

Expected: FAIL — the API key and Add Webhook controls render for everyone.

- [ ] **Step 3: Wire `ApiKeysSection`**

In `packages/app/src/components/TeamSettings/ApiKeysSection.tsx`, add the import:

```ts
import { useMyPermissions } from '@/hooks/useMyPermissions';
```

Replace line 43 (`const hasAdminAccess = true;`) with:

```ts
  // PATCH /team/apiKey is requireAdmin(); rotation is a hard capability.
  const { isAdmin: hasAdminAccess } = useMyPermissions();
```

- [ ] **Step 4: Wire `TeamQueryConfigSection`**

In `packages/app/src/components/TeamSettings/TeamQueryConfigSection.tsx`, add the same import, then replace line 67 (`const hasAdminAccess = true;`) with:

```ts
  // PATCH /team/clickhouse-settings requires team: manage, NOT admin. The old
  // name is how this drifted — keeping it would invite the same drift back.
  const { can } = useMyPermissions();
  const canManageTeam = can('team', 'manage');
```

Then rename the three usages: line 174 `isEditing && hasAdminAccess` → `isEditing && canManageTeam`; line 246 `{hasAdminAccess && (` → `{canManageTeam && (`; line 256 `{hasAdminAccess && isCustomValue` → `{canManageTeam && isCustomValue`.

- [ ] **Step 5: Wire `WebhooksSection`**

In `packages/app/src/components/TeamSettings/WebhooksSection.tsx`, add the import, then insert after line 84 (the `api.useWebhooks` call):

```ts
  // Webhook CRUD is webhooks: manage. A stock Member holds webhooks: read,
  // which makes the tab visible — so the controls have to be gated separately.
  const { can } = useMyPermissions();
  const canManageWebhooks = can('webhooks', 'manage');
```

Replace lines 148-176 (the `<Group gap="xs">` wrapping the Edit/Delete/Cancel controls) with:

```tsx
                        {canManageWebhooks && (
                          <Group gap="xs">
                            {editedWebhookId !== webhook._id ? (
                              <>
                                <Button
                                  variant="subtle"
                                  color="gray.4"
                                  onClick={() => setEditedWebhookId(webhook._id)}
                                  size="compact-xs"
                                  leftSection={<IconPencil size={14} />}
                                >
                                  Edit
                                </Button>
                                <DeleteWebhookButton
                                  webhookId={webhook._id}
                                  webhookName={webhook.name}
                                  onSuccess={refetchWebhooks}
                                />
                              </>
                            ) : (
                              <Button
                                variant="subtle"
                                color="gray.4"
                                onClick={() => setEditedWebhookId(null)}
                                size="compact-xs"
                              >
                                <IconX size={16} /> Cancel
                              </Button>
                            )}
                          </Group>
                        )}
```

Replace the `{!isAddWebhookModalOpen ? (` block opening at line 198 with:

```tsx
      {!canManageWebhooks ? null : !isAddWebhookModalOpen ? (
```

- [ ] **Step 6: Wire `DashboardsListPage`**

In `packages/app/src/components/Dashboards/DashboardsListPage.tsx`, add the import, then insert after line 83 (`const deleteDashboard = useDeleteDashboard();`):

```ts
  // §10.4 puts list-level mutating actions in scope. ReadOnly holds
  // dashboards: read and was being offered New / Import / Delete, all of which
  // 403 on submit.
  const { can } = useMyPermissions();
  const canManageDashboards = can('dashboards', 'manage');
```

Wrap the header Import + New Dashboard controls — replace lines 284-328 (from `<Button component={Link} href="/dashboards/import"` through the closing `</Menu>`) by wrapping the existing markup unchanged in:

```tsx
            {canManageDashboards && (
              <>
                {/* ...the existing Import <Button> and the entire <Menu> block, unchanged... */}
              </>
            )}
```

Do the same for the empty-state pair at lines 355-372: wrap both `<Button>` elements in `{canManageDashboards && (<>…</>)}`.

Then gate the three delete affordances. `ListingCard` declares `onDelete?: () => void` and renders the control only under `{onDelete && (`; `ListingListRow` declares `onDelete?: (id: string) => void` with the same guard — so passing `undefined` hides the control with no change to either component.

- Line 225: `onDelete={() => handleDelete(d.id)}` → `onDelete={canManageDashboards ? () => handleDelete(d.id) : undefined}`
- Line 396: `onDelete={handleDelete}` → `onDelete={canManageDashboards ? handleDelete : undefined}`
- Line 429: `onDelete={() => handleDelete(d.id)}` → `onDelete={canManageDashboards ? () => handleDelete(d.id) : undefined}`

- [ ] **Step 7: Verify no stubs remain**

```bash
grep -rn "hasAdminAccess = true" packages/app/src
```

Expected: no output.

- [ ] **Step 8: Run the tests and typecheck**

```bash
cd packages/app && yarn ci:unit && npx tsc --noEmit
```

Expected: the new gating tests PASS; existing suites green. Any sibling test that rendered these sections without mocking `useMyPermissions` will need the mock added.

- [ ] **Step 9: Commit**

```bash
git add packages/app/src/components
git commit -m "fix(app): gate the four surfaces that advertised admin-only writes

BUG-2. Two hasAdminAccess = true stubs survived slice A §10.2, and two
list-level surfaces named in §10.4 were never gated. The server 403s all of
them, so there was no server hole — but §10.3 requires that a section a role
cannot reach is absent, not disabled.

Rotate API Key is now isAdmin. Query Settings is can('team','manage') — the
route requires team: manage, not admin, and the old local name is how it
drifted. Webhook CRUD and the dashboard list's New / Import / Delete follow
their own resources."
```

---

# Phase 4 — Hardening

### Task 11: Boot-time warning for role-less users

**Files:**
- Create: `packages/api/src/utils/rbacStartup.ts`
- Modify: `packages/api/src/server.ts:88`
- Modify: `packages/api/src/middleware/rbac.ts` (dedupe the per-request warn)
- Test: `packages/api/src/utils/__tests__/rbacStartup.test.ts`

**Interfaces:**
- Produces: `warnOnRoleLessUsers(): Promise<number>` from `@/utils/rbacStartup`, returning the count found.

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/utils/__tests__/rbacStartup.test.ts`:

```ts
import { warnOnRoleLessUsers } from '@/utils/rbacStartup';
import User from '@/models/user';
import logger from '@/utils/logger';

jest.mock('@/models/user', () => ({ countDocuments: jest.fn() }));
jest.mock('@/utils/logger', () => ({ warn: jest.fn(), error: jest.fn() }));

describe('warnOnRoleLessUsers', () => {
  beforeEach(() => jest.clearAllMocks());

  // BUG-6. §11.3 rests the entire safety case for the fail-open on it being
  // "loud, never silent", but the only boot-time RBAC output was the coverage
  // line — nothing counted or warned about users with role == null.
  it('warns with the count when role-less users exist', async () => {
    (User.countDocuments as jest.Mock).mockResolvedValue(7);

    const count = await warnOnRoleLessUsers();

    expect(count).toBe(7);
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ roleLessUserCount: 7 }),
      expect.stringContaining('RBAC migration'),
    );
  });

  it('stays silent on a clean boot', async () => {
    (User.countDocuments as jest.Mock).mockResolvedValue(0);

    const count = await warnOnRoleLessUsers();

    expect(count).toBe(0);
    expect(logger.warn).not.toHaveBeenCalled();
  });

  // Startup diagnostics must never be able to prevent startup.
  it('does not throw when the count query fails', async () => {
    (User.countDocuments as jest.Mock).mockRejectedValue(new Error('no db'));

    await expect(warnOnRoleLessUsers()).resolves.toBe(0);
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd packages/api && yarn ci:unit src/utils/__tests__/rbacStartup.test.ts
```

Expected: FAIL — `Cannot find module '@/utils/rbacStartup'`.

- [ ] **Step 3: Write the module**

Create `packages/api/src/utils/rbacStartup.ts`:

```ts
import User from '@/models/user';
import { getCounter } from '@/utils/instrumentation';
import logger from '@/utils/logger';

const roleLessAtBootCounter = getCounter(
  'hyperdx.rbac.users_without_role_at_boot',
  {
    description:
      'Users with no role assigned, counted once at startup. Non-zero means the RBAC migration has not run and those users resolve as admin via the session fail-open.',
  },
);

/**
 * Boot-time half of §11.3's "loud, never silent" guarantee.
 *
 * BUG-6: the only boot-time RBAC output was the coverage line. The fail-open's
 * entire safety case rests on being noticed, and a per-request WARN that
 * accrues 128 lines an hour is noise, not signal. Returns the count so callers
 * and tests can assert on it.
 */
export async function warnOnRoleLessUsers(): Promise<number> {
  try {
    const count = await User.countDocuments({
      role: { $in: [null, undefined] },
    });

    // A clean boot stays clean — logging zero would train operators to skim.
    if (count === 0) return 0;

    roleLessAtBootCounter.add(count);
    logger.warn(
      { roleLessUserCount: count },
      'RBAC: users have no role assigned and will resolve as admin (fail-open). ' +
        'Run the RBAC migration to assign roles.',
    );

    return count;
  } catch (e) {
    // Never let a startup diagnostic prevent startup.
    logger.error({ err: e }, 'RBAC: failed to count users without a role');
    return 0;
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd packages/api && yarn ci:unit src/utils/__tests__/rbacStartup.test.ts
```

Expected: PASS, 3 tests.

- [ ] **Step 5: Call it at boot**

In `packages/api/src/server.ts`, add the import:

```ts
import { warnOnRoleLessUsers } from '@/utils/rbacStartup';
```

Then immediately after `await connectDB();` (line 88), add:

```ts
    await warnOnRoleLessUsers();
```

- [ ] **Step 6: Dedupe the per-request warning**

In `packages/api/src/middleware/rbac.ts`, insert above `resolveVerdict`:

```ts
/**
 * Users already warned about in this process. The counter below stays
 * un-deduplicated — it is the durable half of §11.3 and must count every
 * request — but the log line accrued 128+ entries in hours of probing, which
 * buries the signal it exists to raise.
 */
const warnedMissingRole = new Set<string>();

function warnMissingRoleOnce(
  actorId: string | undefined,
  authPath: AuthPath,
  message: string,
): void {
  const key = `${authPath}:${actorId ?? 'unknown'}`;
  if (warnedMissingRole.has(key)) return;
  warnedMissingRole.add(key);
  logger.warn({ userId: actorId, authPath }, message);
}
```

Then in `resolveVerdict`, replace the two `logger.warn(...)` calls in the `role == null` branch with:

```ts
    if (authPath === 'access-key') {
      warnMissingRoleOnce(
        actorId,
        authPath,
        'RBAC: access-key user has no role assigned; denying. Assign a role to this user.',
      );
      return 'deny';
    }
    warnMissingRoleOnce(
      actorId,
      authPath,
      'RBAC: user has no role assigned; allowing as admin. Run the RBAC migration.',
    );
    return 'allow';
```

- [ ] **Step 7: Run the suite and commit**

```bash
cd packages/api && yarn ci:unit && npx tsc --noEmit
```

Expected: green. If an existing rbac test asserts the warn fires on every call, update it to assert once-per-user and reference BUG-6.

```bash
git add packages/api/src/utils/rbacStartup.ts packages/api/src/utils/__tests__/rbacStartup.test.ts packages/api/src/server.ts packages/api/src/middleware/rbac.ts
git commit -m "feat(api): count and warn about role-less users at boot

BUG-6. §11.3 rests the entire safety case for the fail-open on it being loud,
never silent — but the only boot-time RBAC output was the coverage line, and
the per-request WARN accrued 128+ un-aggregated lines in hours of probing.

Startup now counts users with no role and warns once with the total, plus a
counter. The per-request log is deduplicated per user; the missing_role counter
stays un-deduplicated, since it is the durable half of the argument."
```

---

### Task 12: Rate-limit on identity, meter failures by origin

**Files:**
- Modify: `packages/api/src/utils/rateLimiter.ts`
- Modify: `packages/api/src/routers/external-api/v2/index.ts`
- Modify: `packages/api/src/mcp/app.ts:16-22,39`
- Test: `packages/api/src/utils/__tests__/rateLimiter.test.ts`

**Interfaces:**
- Produces: `rateLimiterKeyGenerator(req)` (unchanged name, new behaviour) and `ipOnlyKeyGenerator(req)` from `@/utils/rateLimiter`.

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/utils/__tests__/rateLimiter.test.ts`:

```ts
import {
  ipOnlyKeyGenerator,
  rateLimiterKeyGenerator,
} from '@/utils/rateLimiter';

const req = (over: any = {}) => ({ ip: '203.0.113.9', headers: {}, ...over }) as any;

describe('rateLimiterKeyGenerator', () => {
  // BUG-8. Keying on the Authorization header gave every guessed key its own
  // bucket: 105 distinct garbage bearers from one origin produced zero 429s.
  it('never keys on the credential', () => {
    const a = rateLimiterKeyGenerator(req({ headers: { authorization: 'Bearer aaa' } }));
    const b = rateLimiterKeyGenerator(req({ headers: { authorization: 'Bearer bbb' } }));

    expect(a).not.toContain('aaa');
    expect(b).not.toContain('bbb');
    expect(a).toBe(b);
  });

  it('buckets an authenticated caller per user', () => {
    const key = rateLimiterKeyGenerator(
      req({ user: { _id: 'user-1' }, headers: { authorization: 'Bearer x' } }),
    );
    expect(key).toBe('user:user-1');
  });

  it('gives two users distinct buckets', () => {
    expect(rateLimiterKeyGenerator(req({ user: { _id: 'a' } }))).not.toBe(
      rateLimiterKeyGenerator(req({ user: { _id: 'b' } })),
    );
  });

  it('falls back to origin when unauthenticated', () => {
    expect(rateLimiterKeyGenerator(req())).toBe('ip:203.0.113.9');
  });
});

describe('ipOnlyKeyGenerator', () => {
  it('ignores identity entirely so failed guesses share one bucket', () => {
    expect(ipOnlyKeyGenerator(req({ user: { _id: 'a' } }))).toBe(
      ipOnlyKeyGenerator(req({ headers: { authorization: 'Bearer zzz' } })),
    );
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd packages/api && yarn ci:unit src/utils/__tests__/rateLimiter.test.ts
```

Expected: FAIL — the generator returns the `Authorization` header.

- [ ] **Step 3: Rewrite the generators**

Replace `packages/api/src/utils/rateLimiter.ts` with:

```ts
import express from 'express';
import rateLimit, { Options } from 'express-rate-limit';

/**
 * Buckets authenticated traffic per user.
 *
 * BUG-8: this previously returned `req.headers.authorization`, which gives
 * every *guessed* key its own bucket — 105 distinct garbage bearers from one
 * origin produced zero 429s. Never key a limiter on the credential it is meant
 * to protect. Callers must place this AFTER authentication so `req.user` is
 * populated; before it, every request collapses to the origin bucket.
 *
 * express-rate-limit is pinned at 6.x, which has no `ipKeyGenerator` helper,
 * so IPv6 addresses are bucketed exactly rather than by subnet.
 */
export const rateLimiterKeyGenerator = (req: express.Request): string => {
  const userId = (req.user as any)?._id?.toString();
  if (userId) return `user:${userId}`;
  return `ip:${req.ip ?? 'unknown'}`;
};

/**
 * Buckets by origin regardless of identity, for limiters that sit in FRONT of
 * authentication so failed key guesses are metered.
 */
export const ipOnlyKeyGenerator = (req: express.Request): string =>
  `ip:${req.ip ?? 'unknown'}`;

export default (config?: Partial<Options>) => {
  return rateLimit({
    ...config,
  });
};
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cd packages/api && yarn ci:unit src/utils/__tests__/rateLimiter.test.ts
```

Expected: PASS, 5 tests.

- [ ] **Step 5: Reorder the v2 limiters**

In `packages/api/src/routers/external-api/v2/index.ts`, change the import to:

```ts
import rateLimiter, {
  ipOnlyKeyGenerator,
  rateLimiterKeyGenerator,
} from '@/utils/rateLimiter';
```

Replace the `defaultRateLimiter` definition with:

```ts
// Runs AFTER validateUserAccessKey so it can key on the authenticated user.
const defaultRateLimiter = rateLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // Limit each user to 100 requests per `window`
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: rateLimiterKeyGenerator,
});

// Runs BEFORE authentication, so failed key guesses from one origin share a
// bucket (BUG-8). Generous enough not to bite a legitimate multi-user NAT.
const authAttemptRateLimiter = rateLimiter({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: ipOnlyKeyGenerator,
});
```

Then change every `router.use('/<name>', defaultRateLimiter, validateUserAccessKey, <x>Router);` to put the attempt limiter first and the per-user limiter after auth:

```ts
router.use(
  '/alerts',
  authAttemptRateLimiter,
  validateUserAccessKey,
  defaultRateLimiter,
  alertsRouter,
);
```

Apply that same ordering to `/charts`, `/connections`, `/dashboards`, `/sources`, and every other `router.use` in the file.

Finally, give `GET /api/v2/` the limiters it lacks — it currently has none and returns 200 with the user record, which makes it a validity oracle:

```ts
router.get(
  '/',
  authAttemptRateLimiter,
  validateUserAccessKey,
  defaultRateLimiter,
  // Identity check: returns the caller's own user record.
  noPermissionRequired('personal-state'),
  (req, res) => {
    res.json({
      version: 'v2',
      user: req.user?.toJSON(),
    });
  },
);
```

- [ ] **Step 6: Reorder the MCP limiter**

In `packages/api/src/mcp/app.ts`, change the import to include `ipOnlyKeyGenerator`, then add alongside `mcpRateLimiter`:

```ts
const mcpAuthAttemptRateLimiter = rateLimiter({
  windowMs: 60 * 1000,
  max: 900,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: ipOnlyKeyGenerator,
});
```

Change line 39 from `app.post('/', mcpRateLimiter, validateUserAccessKey, async (req, res) => {` to:

```ts
app.post(
  '/',
  mcpAuthAttemptRateLimiter,
  validateUserAccessKey,
  mcpRateLimiter,
  async (req, res) => {
```

(Close the extra paren at the end of the handler.) Leave the `app.get` and `app.delete` 405 handlers on `mcpRateLimiter` — they run before auth, so switch those two to `mcpAuthAttemptRateLimiter`.

- [ ] **Step 7: Verify and commit**

```bash
cd packages/api && npx tsc --noEmit && yarn ci:unit
```

Expected: green.

```bash
git add packages/api/src/utils/rateLimiter.ts packages/api/src/utils/__tests__/rateLimiter.test.ts packages/api/src/routers/external-api/v2/index.ts packages/api/src/mcp/app.ts
git commit -m "fix(api): stop rate-limiting on the credential being guessed

BUG-8. rateLimiterKeyGenerator returned the Authorization header, so every
guessed key got its own bucket — 105 distinct garbage bearers from one origin
produced zero 429s. GET /api/v2/ had no limiter at all and returns the user
record, making it a validity oracle.

Limiters now run after authentication and key on the user, with an
origin-keyed limiter in front of auth so failed attempts are metered."
```

---

### Task 13: Close the expression-guard bypasses

**Files:**
- Modify: `packages/api/src/routers/external-api/v2/search.ts:157-165` and the request schema
- Modify: `packages/api/src/routers/external-api/v2/charts.ts` (series request schema)
- Test: `packages/api/src/routers/external-api/v2/__tests__/expressionGuard.test.ts`

**Interfaces:**
- Produces: `validateColumnsExpression(value: string): boolean` exported from `@/routers/external-api/v2/search` so charts can reuse it.

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/routers/external-api/v2/__tests__/expressionGuard.test.ts`:

```ts
import { validateColumnsExpression } from '@/routers/external-api/v2/search';

describe('validateColumnsExpression', () => {
  it('accepts ordinary column expressions', () => {
    expect(validateColumnsExpression('Timestamp, ServiceName')).toBe(true);
    expect(validateColumnsExpression('count()')).toBe(true);
    expect(validateColumnsExpression('')).toBe(true);
  });

  it('accepts identifiers that merely contain the keyword', () => {
    expect(validateColumnsExpression('selectId')).toBe(true);
  });

  it('rejects semicolons and bare subqueries', () => {
    expect(validateColumnsExpression('a; DROP TABLE x')).toBe(false);
    expect(validateColumnsExpression('(SELECT 1)')).toBe(false);
  });

  // BUG-9, demonstrated live: /**/ defeated the bare SELECT\s anchor and
  // returned 200 on (SELECT/**/groupArray(name) FROM system.users).
  it('rejects a subquery hidden behind a block comment', () => {
    expect(
      validateColumnsExpression('(SELECT/**/groupArray(name) FROM system.users)'),
    ).toBe(false);
  });

  it('rejects a subquery hidden behind a line comment', () => {
    expect(validateColumnsExpression('(SELECT--x\ngroupArray(name))')).toBe(false);
  });

  it('rejects a comment-split semicolon', () => {
    expect(validateColumnsExpression('a/**/;/**/b')).toBe(false);
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cd packages/api && yarn ci:unit src/routers/external-api/v2/__tests__/expressionGuard.test.ts
```

Expected: FAIL — the three comment cases return `true`, and the import fails because the function is not exported.

- [ ] **Step 3: Strip comments and export**

In `packages/api/src/routers/external-api/v2/search.ts`, replace lines 157-165 with:

```ts
// Comments let a caller break up the keyword this pattern anchors on:
// `(SELECT/**/groupArray(name) FROM system.users)` defeated the bare pattern
// and returned 200 (BUG-9). Strip them before matching.
const SQL_COMMENT_PATTERN = /\/\*[\s\S]*?\*\/|--[^\n]*/g;

// Rejects semicolons and SELECT subqueries in column expressions.
// Word-boundary anchor prevents blocking identifiers like "selectId".
const DISALLOWED_COLUMNS_PATTERN = /;|(?<!\w)SELECT\s/i;

/**
 * Defence-in-depth, NOT a security boundary.
 *
 * This is a denylist, and a denylist over a SQL dialect cannot be complete —
 * slice C §8.3, as amended. It closes the demonstrated bypasses; the class
 * stays open until slice B constrains the query path at the database layer
 * with a restricted ClickHouse user.
 */
export function validateColumnsExpression(value: string): boolean {
  if (!value) return true;
  // Replace with a space, not '': `a/**/;` must not become `a;`-free.
  const stripped = value.replace(SQL_COMMENT_PATTERN, ' ');
  return !DISALLOWED_COLUMNS_PATTERN.test(stripped);
}
```

- [ ] **Step 4: Run the unit test**

```bash
cd packages/api && yarn ci:unit src/routers/external-api/v2/__tests__/expressionGuard.test.ts
```

Expected: PASS, 6 tests.

- [ ] **Step 5: Apply the guard to `where`**

`where` on `/search` defaults to Lucene, where a literal search for `SELECT foo` is legitimate — so the guard must apply only when `whereLanguage` is `sql`. Attach a `superRefine` to `searchRequestSchema` (after the closing `})` of the `z.object({...})`, before it is used):

```ts
  // `where` was unguarded entirely (BUG-9). Guard it only in SQL mode: in
  // Lucene mode a literal search for "SELECT foo" is a legitimate query and
  // must not 400.
  .superRefine((val, ctx) => {
    if (val.whereLanguage === 'sql' && !validateColumnsExpression(val.where)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['where'],
        message:
          'where must not contain semicolons or subqueries when whereLanguage is "sql"',
      });
    }
  });
```

- [ ] **Step 6: Apply the guard on `/charts/series`**

In `packages/api/src/routers/external-api/v2/charts.ts`, import the validator:

```ts
import { validateColumnsExpression } from '@/routers/external-api/v2/search';
```

Then attach the same `superRefine` to the series request schema — `/charts/series` had no regex at all, so a plain subquery worked:

```ts
  .superRefine((val, ctx) => {
    // BUG-9: this route carried no expression guard whatsoever.
    if (val.whereLanguage === 'sql' && !validateColumnsExpression(val.where ?? '')) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['where'],
        message:
          'where must not contain semicolons or subqueries when whereLanguage is "sql"',
      });
    }
  });
```

- [ ] **Step 7: Verify and commit**

```bash
cd packages/api && npx tsc --noEmit && yarn ci:unit
```

Expected: green.

```bash
git add packages/api/src/routers/external-api/v2
git commit -m "fix(api): close the demonstrated expression-guard bypasses

BUG-9. DISALLOWED_COLUMNS_PATTERN was defeated by a comment —
(SELECT/**/groupArray(name) FROM system.users) returned 200 — the refinement
covered select only, where on /search was unguarded, and /charts/series had no
regex at all.

Comments are stripped before matching and both routes now guard where, in SQL
mode only so Lucene searches for the literal 'SELECT' still work. This remains
a denylist and therefore defence-in-depth, not a boundary: the class stays open
until slice B constrains the query path at the database layer."
```

---

### Task 14: Changeset and full verification

**Files:**
- Create: `.changeset/rbac-remediation.md`

- [ ] **Step 1: Write the changeset**

Create `.changeset/rbac-remediation.md`:

```markdown
---
'@hyperdx/api': minor
'@hyperdx/app': minor
---

Close 12 RBAC defects found by a manual test pass over the role-based access
control work.

Three of these change behaviour for existing deployments:

- **`/clickhouse-proxy` and `/v1/prometheus` now require `sources: read`.** All
  three system roles hold it, so Admin, Member and ReadOnly are unaffected. A
  custom role deliberately given `sources: none` loses browser query access —
  previously it could reach the proxy directly and run arbitrary read SQL
  against the whole ClickHouse cluster.
- **MCP prompts now require `sources: read`** and are hidden from `prompts/list`
  for roles that cannot reach them. An agent running under a restricted access
  key will stop seeing `create_dashboard`, `dashboard_examples` and
  `query_guide`. They enumerate the team's real source and connection names,
  which is why they are gated.
- **Invitation URLs are no longer returned to non-admins.** Any integration
  reading join links from `GET /team/invitations` or
  `GET /api/v2/team/invitations` under a non-admin key will no longer receive
  the `url` field. The list itself is unchanged.

Also fixed: the last-admin guard no longer falls silent when an un-migrated
user exists; the RBAC Mongo migration aborts cleanly instead of half-seeding a
team whose roles collide by name; concurrent team creation can no longer
produce duplicate Admin roles; four UI surfaces no longer offer writes the
server rejects; the Team Settings Sources view no longer 403s for Member and
ReadOnly; role-less users are counted and warned about at startup; API rate
limiting no longer gives each guessed access key its own bucket; and the
`/api/v2/search` and `/api/v2/charts` expression guard no longer accepts
comment-obfuscated subqueries.
```

- [ ] **Step 2: Run the full verification suite**

```bash
make ci-lint
make ci-unit
```

Expected: both green. Fix anything that fails before proceeding — do not commit over a red suite.

- [ ] **Step 3: Confirm the boot assertion still holds**

The RBAC coverage assertion runs at startup and throws on any undeclared route. Task 3 removed an exemption reason and Task 12 reordered middleware, so start the API once and confirm it boots:

```bash
cd ~/hyperdx && . ./scripts/dev-env.sh && cd packages/api && npx dotenvx run --convention=nextjs -- npx ts-node -r tsconfig-paths/register src/index.ts
```

Expected: the RBAC coverage line prints and the server listens. Ctrl-C once confirmed. A throw here names the offending method and path.

- [ ] **Step 4: Confirm no stubs or retired identifiers survive**

```bash
grep -rn "hasAdminAccess = true" packages/app/src
grep -rn "query-path-slice-B" packages/api/src --include='*.ts' | grep -v coverage/lcov-report
grep -rn "assertToolCoverage" packages/api/src --include='*.ts' | grep -v coverage/lcov-report
grep -rn "countEffectiveAdmins" packages/api/src --include='*.ts' | grep -v coverage/lcov-report
```

Expected: no output from any of the four.

- [ ] **Step 5: Commit**

```bash
git add .changeset/rbac-remediation.md
git commit -m "chore: changeset for the RBAC remediation"
```

---

## Verification Summary

| Finding | Task | Test that would have caught it |
|---|---|---|
| SEC-1 | 1, 2 | `coverage.test.ts` — "fails when a prompt declares no permission" |
| SEC-2 | 3 | `queryPathRbac.test.ts` — proxy and prometheus declare `sources: read` |
| BUG-1 | 5 | `lastAdmin.int.test.ts` — the reported A/B, role-less user present |
| BUG-2 | 10 | `permissionGating.test.tsx` — controls absent for non-admins |
| BUG-3 | 6 | `addRbacRoles.int.test.ts` — aborts with zero writes |
| BUG-4 | 7 | `seedRace.int.test.ts` — 12 parallel seeds, no `Role.init()` in the test |
| BUG-5 | 9 | `sourcesConnectionName.int.test.ts` + `SourcesList.test.tsx` |
| BUG-6 | 11 | `rbacStartup.test.ts` — warns with the count, silent when clean |
| BUG-7 | 4 | `isEffectiveAdmin.test.ts` + redaction in both handlers |
| BUG-8 | 12 | `rateLimiter.test.ts` — "never keys on the credential" |
| BUG-9 | 13 | `expressionGuard.test.ts` — the `/**/ ` payload |
| BUG-10 | 8 | `roleSchemas.test.ts` — rejects `permissions.isAdmin` |
