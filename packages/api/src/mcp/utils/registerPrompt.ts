import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type {
  McpContext,
  RegisterPromptFn,
  ToolPermission,
} from '@/mcp/tools/types';

import {
  checkPermissionForVerdict,
  createVerdictGate,
  recordPromptDenial,
  type VerdictGate,
} from './permission';

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
  gate: VerdictGate = createVerdictGate(context),
): RegisterPromptFn {
  return (name, config, handler) => {
    // `permission` must NOT reach the SDK: it serialises `config` into the
    // prompt manifest advertised to clients, which would publish the whole
    // permission model to every connected agent. Same reasoning as
    // createRegisterTool.
    const { permission, ...sdkConfig } = config;
    declared.set(name, permission);

    // Listing decision, taken at registration. `gate.peek()` and not
    // `gate.get()`: this factory runs inside createServer, which runs once per
    // HTTP POST regardless of the JSON-RPC method, so recording here would
    // count a missing-role event for `initialize`, `ping` and `tools/list` —
    // requests that consult no permission at all. Same verdict either way;
    // only the telemetry differs.
    const listable = checkPermissionForVerdict(
      gate.peek(),
      context.role,
      permission,
    ).ok;

    const guarded = async (args: any) => {
      // Enforcement backstop only. In production this branch is unreachable for
      // a denied prompt: `disable()` below makes the SDK's `prompts/get`
      // handler throw `Prompt <name> disabled` before it ever reaches the
      // callback. It is kept because it is the thing that would still refuse if
      // the SDK's disable semantics ever changed, and because `listable` and
      // this check must not be allowed to drift apart.
      //
      // It deliberately does NOT call recordPromptDenial — that would
      // double-count the moment the branch did become reachable. The denial is
      // recorded at the listing decision instead; see below.
      const decision = checkPermissionForVerdict(
        gate.get(),
        context.role,
        permission,
      );

      // Prompts return `{ messages }`, so there is no isError result shape to
      // carry a denial the way mcpUserError does for tools — throwing is the
      // protocol-level answer. Prompts are not wrapped by withToolTracing, so
      // this reaches no alerting path.
      if (!decision.ok) {
        throw new Error(decision.message);
      }
      return handler(args);
    };

    const registered = (server as any).registerPrompt(name, sdkConfig, guarded);

    // ClickStack's rule: a resource a role cannot reach is hidden from it
    // entirely, not advertised and then refused. Disabling keeps it out of
    // prompts/list while leaving it in _registeredPrompts, so the coverage
    // assertion still sees it.
    if (!listable) {
      // The denial has to be recorded HERE, not in `guarded`. The SDK's
      // GetPrompt handler rejects a disabled prompt before invoking the
      // callback, so a metric inside `guarded` can never fire in production for
      // exactly the case it exists to record — `hyperdx.mcp.prompt.denied` was
      // dead. This is the last point at which the RBAC decision is ours to
      // observe.
      //
      // Cardinality: `createServer` runs once per HTTP POST, so this counts
      // once per denied prompt per POST — including on `initialize`, `ping` and
      // `tools/list`, which never touch a prompt. The counter therefore means
      // "denied prompt registrations", which is what its description has always
      // said, and not "attempted prompt gets". `prompt` and `permission` are
      // both low-cardinality, so the attribute set is unchanged.
      //
      // It is emphatically NOT `gate.get()`: recording the *metric* here is
      // cheap, but resolving the verdict here would fire
      // `hyperdx.rbac.missing_role` on every POST regardless of JSON-RPC
      // method, which is the defect the previous commit fixed and which
      // missingRoleCounter.test.ts pins.
      recordPromptDenial(name, permission);
      registered.disable();
    }
  };
}
