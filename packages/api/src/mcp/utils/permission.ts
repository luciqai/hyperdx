import {
  hasPermission,
  type PermissionLevel,
  type Resource,
} from '@hyperdx/common-utils/dist/types';

import type { McpContext, ToolPermission } from '@/mcp/tools/types';
import { resolveVerdict, type RoleLike, type Verdict } from '@/middleware/rbac';
import { getCounter } from '@/utils/instrumentation';

const deniedCounter = getCounter('hyperdx.mcp.tool.denied', {
  description:
    'MCP tool calls rejected by RBAC, labeled by tool and required permission.',
});

const promptDeniedCounter = getCounter('hyperdx.mcp.prompt.denied', {
  description:
    'MCP prompt registrations rejected by RBAC, labeled by prompt and required permission.',
});

export type PermissionCheck = { ok: true } | { ok: false; message: string };

/**
 * Pure permission decision for an MCP tool, given an already-resolved
 * verdict. Split out of `checkToolPermission` so callers that must resolve
 * the verdict once and reuse it across multiple permission checks (the
 * prompt registrar registers several prompts per server, but the verdict is
 * fixed for the server's lifetime) don't re-trigger `resolveVerdict`'s
 * side effects — notably the `hyperdx.rbac.missing_role` counter and its
 * WARN log, which must fire once per request, not once per registration.
 */
export function checkPermissionForVerdict(
  verdict: Verdict,
  role: RoleLike,
  permission: ToolPermission,
): PermissionCheck {
  if (verdict === 'allow') return { ok: true };

  if (verdict === 'deny') {
    return {
      ok: false,
      message:
        'Permission denied: no role is assigned to this access key. ' +
        'Ask an admin to assign you a role in Team Settings → Access.',
    };
  }

  // verdict === 'check'
  if (permission === 'admin') {
    return {
      ok: false,
      message:
        `Permission denied: this action requires administrator access. ` +
        `Your role is "${role?.name ?? 'unknown'}".`,
    };
  }

  const [resource, level] = permission.split(':') as [
    Resource,
    PermissionLevel,
  ];
  if (hasPermission(role?.permissions?.[resource], level)) return { ok: true };

  return {
    ok: false,
    message:
      `Permission denied: this action requires ${resource}: ${level}. ` +
      `Your role is "${role?.name ?? 'unknown'}".`,
  };
}

/**
 * Pure permission decision for an MCP tool. Kept separate from the wrapper so
 * it is unit-testable without constructing a server or a transport.
 *
 * MCP is always access-key authenticated, so a missing role denies — the
 * browser's fail-open does not apply here (slice C spec §7).
 *
 * Resolves the verdict itself, so it must only be called once per decision —
 * `resolveVerdict` increments `hyperdx.rbac.missing_role` and logs a WARN on
 * every call. `registerTool.ts` calls this once per tool invocation (the
 * right cardinality: one call, one verdict). Callers that need the same
 * verdict for several permission checks in one request (the prompt
 * registrar registering multiple prompts per server construction) must
 * resolve the verdict once via `resolveVerdict` and call
 * `checkPermissionForVerdict` directly instead of this wrapper.
 */
export function checkToolPermission(
  role: RoleLike,
  permission: ToolPermission,
  userId?: string,
): PermissionCheck {
  return checkPermissionForVerdict(
    resolveVerdict(role, 'access-key', userId),
    role,
    permission,
  );
}

/** Records the denial for observability. Tool name is low-cardinality. */
export function recordToolDenial(name: string, permission: ToolPermission) {
  deniedCounter.add(1, { tool: name, permission });
}

/** Records the denial for observability. Prompt name is low-cardinality. */
export function recordPromptDenial(name: string, permission: ToolPermission) {
  promptDeniedCounter.add(1, { prompt: name, permission });
}

export function describeContextRole(context: McpContext): string {
  return context.role?.name ?? 'none';
}
