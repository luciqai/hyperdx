import type {
  McpServer,
  ToolCallback,
} from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AnyZodObject } from 'zod';

import type {
  McpContext,
  RegisterToolFn,
  ToolPermission,
} from '@/mcp/tools/types';

import { mcpUserError } from './errors';
import {
  checkPermissionForVerdict,
  createVerdictGate,
  recordToolDenial,
  type VerdictGate,
} from './permission';
import { withToolTracing } from './tracing';

/**
 * Permissions declared during registration, keyed by tool name.
 *
 * A map rather than a symbol tagged onto the handler (the trick slice A uses
 * for Express layers) because the MCP SDK does not expose registered handlers
 * for inspection — `assertMcpCoverage` reads this against the server's
 * registered tool names.
 */
export type DeclaredPermissions = Map<string, ToolPermission>;

/**
 * Creates a `registerTool` function bound to a specific server and context.
 * The returned function wraps every handler with a permission check and
 * `withToolTracing`, so individual tool files don't need to import or call
 * either.
 *
 * `gate` should be the same gate the prompt registrar gets — `createServer`
 * builds one per request — so `hyperdx.rbac.missing_role` fires once for the
 * whole request rather than once per tool invoked and once again for the
 * prompts. Defaulted so a test can construct this registrar alone.
 */
export function createRegisterTool(
  server: McpServer,
  context: McpContext,
  declared: DeclaredPermissions = new Map(),
  gate: VerdictGate = createVerdictGate(context),
): RegisterToolFn {
  return (name, config, handler) => {
    // `permission` must NOT reach the SDK: it serialises `config` into the
    // tool manifest advertised to clients, which would publish the whole
    // permission model to every connected agent.
    const { permission, ...sdkConfig } = config;
    declared.set(name, permission);

    const guarded = async (args: any) => {
      // `gate.get()` rather than resolving here: this runs on every tool
      // invocation, and the missing-role counter must not scale with the
      // number of calls in a request.
      const check = checkPermissionForVerdict(
        gate.get(),
        context.role,
        permission,
      );
      if (!check.ok) {
        recordToolDenial(name, permission);
        // A restricted agent hitting a wall is normal operation, not an
        // incident — mcpUserError keeps it out of recordException/alerting.
        return mcpUserError(check.message);
      }
      return handler(args);
    };

    // Wrap with tracing, then register.  The explicit InputArgs generic
    // binds the SDK's own type parameter to AnyZodObject so TypeScript
    // resolves ToolCallback via the AnySchema branch of BaseToolCallback.
    // This lets it accept our traced callback without a type assertion —
    // both sides reduce to (args: SchemaOutput<AnyZodObject>, extra) => ….
    const traced: ToolCallback<AnyZodObject> = withToolTracing(
      name,
      context,
      guarded as Parameters<typeof withToolTracing>[2],
    );
    server.registerTool<AnyZodObject, AnyZodObject>(name, sdkConfig, traced);
  };
}
