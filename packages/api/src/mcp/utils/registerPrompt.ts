import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type {
  McpContext,
  RegisterPromptFn,
  ToolPermission,
} from '@/mcp/tools/types';

import { checkToolPermission } from './permission';

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
  return (name, config, handler) => {
    // `permission` must NOT reach the SDK: it serialises `config` into the
    // prompt manifest advertised to clients, which would publish the whole
    // permission model to every connected agent. Same reasoning as
    // createRegisterTool.
    const { permission, ...sdkConfig } = config;
    declared.set(name, permission);

    // The server is constructed per connection with the caller's role, so the
    // decision is fixed for this server's lifetime — evaluate it once.
    const decision = checkToolPermission(
      context.role,
      permission,
      context.userId,
    );

    const guarded = async (args: any) => {
      // Prompts return `{ messages }`, so there is no isError result shape to
      // carry a denial the way mcpUserError does for tools — throwing is the
      // protocol-level answer. Prompts are not wrapped by withToolTracing, so
      // this reaches no alerting path.
      if (!decision.ok) throw new Error(decision.message);
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
