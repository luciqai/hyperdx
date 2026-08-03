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
import { checkToolPermission, recordToolDenial } from './permission';
import { withToolTracing } from './tracing';

/**
 * Permissions declared during registration, keyed by tool name.
 *
 * A map rather than a symbol tagged onto the handler (the trick slice A uses
 * for Express layers) because the MCP SDK does not expose registered handlers
 * for inspection — `assertToolCoverage` reads this against the server's
 * registered tool names.
 */
export type DeclaredPermissions = Map<string, ToolPermission>;

/**
 * Creates a `registerTool` function bound to a specific server and context.
 * The returned function wraps every handler with a permission check and
 * `withToolTracing`, so individual tool files don't need to import or call
 * either.
 */
export function createRegisterTool(
  server: McpServer,
  context: McpContext,
  declared: DeclaredPermissions = new Map(),
): RegisterToolFn {
  return (name, config, handler) => {
    // `permission` must NOT reach the SDK: it serialises `config` into the
    // tool manifest advertised to clients, which would publish the whole
    // permission model to every connected agent.
    const { permission, ...sdkConfig } = config;
    declared.set(name, permission);

    const guarded = async (args: any) => {
      const check = checkToolPermission(
        context.role,
        permission,
        context.userId,
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

/**
 * Fails startup when a registered tool declares no permission.
 *
 * `permission` is required at the type level, so this is the runtime backstop
 * for anything reaching registration another way (a cast, a tool registered
 * directly on the server, a future refactor). Mirrors slice A's route
 * coverage assertion.
 */
export function assertToolCoverage(
  server: McpServer,
  declared: DeclaredPermissions,
): void {
  // The SDK keeps registered tools in an internal record; read defensively so
  // a shape change degrades to "cannot verify" rather than a false pass.
  const registered: string[] = Object.keys(
    (server as any)._registeredTools ?? {},
  );

  if (registered.length === 0) {
    throw new Error(
      'MCP tool coverage check could not enumerate registered tools. The SDK ' +
        'internals may have changed — verify before shipping, since an empty ' +
        'list would otherwise pass this assertion vacuously.',
    );
  }

  const uncovered = registered.filter(name => !declared.has(name));
  if (uncovered.length > 0) {
    throw new Error(
      `MCP tool coverage check failed. ${uncovered.length} tool(s) declare no permission:\n` +
        uncovered.map(n => `  ${n}`).join('\n') +
        `\n\nAdd a \`permission\` to each tool's registerTool config.`,
    );
  }
}
