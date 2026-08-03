import {
  hasPermission,
  type PermissionLevel,
  type Resource,
} from '@hyperdx/common-utils/dist/types';

import type { McpContext, ToolPermission } from '@/mcp/tools/types';
import { resolveVerdict, type RoleLike } from '@/middleware/rbac';
import { getCounter } from '@/utils/instrumentation';

const deniedCounter = getCounter('hyperdx.mcp.tool.denied', {
  description:
    'MCP tool calls rejected by RBAC, labeled by tool and required permission.',
});

export type PermissionCheck = { ok: true } | { ok: false; message: string };

/**
 * Pure permission decision for an MCP tool. Kept separate from the wrapper so
 * it is unit-testable without constructing a server or a transport.
 *
 * MCP is always access-key authenticated, so a missing role denies — the
 * browser's fail-open does not apply here (slice C spec §7).
 */
export function checkToolPermission(
  role: RoleLike,
  permission: ToolPermission,
  userId?: string,
): PermissionCheck {
  const verdict = resolveVerdict(role, 'access-key', userId);

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

/** Records the denial for observability. Tool name is low-cardinality. */
export function recordToolDenial(name: string, permission: ToolPermission) {
  deniedCounter.add(1, { tool: name, permission });
}

export function describeContextRole(context: McpContext): string {
  return context.role?.name ?? 'none';
}
