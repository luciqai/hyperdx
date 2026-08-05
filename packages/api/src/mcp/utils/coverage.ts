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
