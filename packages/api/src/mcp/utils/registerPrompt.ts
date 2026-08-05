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
      // Enforcement decision, taken on an actual `prompts/get`. This is where
      // the request genuinely consults a permission, so this is where the
      // gate records — once, however many prompts the request touches.
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
        // Mirrors registerTool.ts: the metric fires on an actual attempted
        // call, not on registration. The server is rebuilt per HTTP request,
        // so recording at registration/disable time would count once per
        // denied prompt on every request from an under-permissioned role,
        // even when the client never lists or requests it.
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
    // a client calling a cached name, and is where the denial metric fires.
    if (!listable) {
      registered.disable();
    }
  };
}
