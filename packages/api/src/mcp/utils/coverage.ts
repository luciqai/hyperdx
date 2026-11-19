import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { ToolPermission } from '@/mcp/tools/types';

/**
 * Floors for the non-vacuity guard. A walker that finds nothing — or far less
 * than the surface actually registers — must fail rather than pass on an empty
 * list.
 *
 * The two floors are set differently on purpose. The tool floor sits below the
 * real count (28) so adding or removing one tool does not trip it. The prompt
 * floor is deliberately EXACT (3 registered, 3 required): with a surface this
 * small any slack makes the guard nearly vacuous — a floor of 2 would pass an
 * enumeration that found only two thirds of the surface. The cost is that
 * deliberately removing a prompt fails server construction until this constant
 * is updated in the same change, which the error below spells out.
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
        `(found ${registered.length}, expected at least ${minimum}). Either a ` +
        `${kind} was intentionally removed — lower the floor in the same ` +
        `change — or the SDK internals changed and enumeration is now broken. ` +
        `Verify which before shipping, since a short list would otherwise pass ` +
        `this assertion vacuously.`,
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
