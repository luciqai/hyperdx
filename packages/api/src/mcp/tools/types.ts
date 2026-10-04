import type {
  PermissionLevel,
  Resource,
} from '@hyperdx/common-utils/dist/types';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type {
  CallToolResult,
  GetPromptResult,
  ToolAnnotations,
} from '@modelcontextprotocol/sdk/types.js';
import type { AnyZodObject, ZodTypeAny } from 'zod';

import type { McpClientInfo } from '@/mcp/utils/mcpClient';
import type { RoleLike } from '@/middleware/rbac';

export type McpContext = {
  teamId: string;
  userId: string;
  /**
   * The caller's populated role, or null when none is assigned.
   *
   * Carried on the context rather than read from the request because tool
   * handlers are not Express middleware — there is no `req` at call time.
   * A null role denies: MCP is always access-key authenticated, and that path
   * fails closed (see the slice C spec, §7).
   */
  role: RoleLike;
  /**
   * Identity of the calling MCP client application, parsed from User-Agent.
   */
  mcpClient?: McpClientInfo;
};

/**
 * What a tool requires to run. `'admin'` is the hard capability — not
 * expressible as a permission, so no custom role can be granted it.
 */
export type ToolPermission = `${Resource}:${PermissionLevel}` | 'admin';

/**
 * The result shape every MCP tool handler should return.
 *
 * Intersects the SDK's `CallToolResult` (which carries an index signature
 * from the `$loose` Zod modifier) with a narrower `content` array so tool
 * handlers are constrained to text-only content blocks.
 */
export type ToolResult = CallToolResult & {
  content: { type: 'text'; text: string }[];
};

/**
 * A simplified tool registration function that wraps `server.registerTool`
 * with automatic tracing. Eliminates the need to:
 * - Pass the tool name twice (once to registerTool, once to withToolTracing)
 * - Import and manually wire up withToolTracing in every tool file
 * - Import McpServer type in every tool file
 */
export type RegisterToolFn = <TSchema extends AnyZodObject>(
  name: string,
  config: {
    title: string;
    description: string;
    inputSchema: TSchema;
    /**
     * Advisory MCP tool annotations (readOnlyHint, destructiveHint, etc.).
     * These are hints only — clients must not rely on them for safety.
     * Enforcement lives in `permission` below.
     */
    annotations?: ToolAnnotations;
    /**
     * Required. A tool that declares nothing fails to compile, which is the
     * compile-time half of the coverage guarantee; assertMcpCoverage is the
     * runtime half.
     */
    permission: ToolPermission;
  },
  handler: (args: TSchema['_output']) => Promise<ToolResult>,
) => void;

export type ToolRegistrar = {
  server: McpServer;
  context: McpContext;
  registerTool: RegisterToolFn;
};

export type ToolDefinition = (registrar: ToolRegistrar) => void;

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
