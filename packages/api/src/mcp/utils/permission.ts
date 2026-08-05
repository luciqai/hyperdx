import {
  hasPermission,
  type PermissionLevel,
  type Resource,
} from '@hyperdx/common-utils/dist/types';

import type { McpContext, ToolPermission } from '@/mcp/tools/types';
import {
  computeVerdict,
  resolveVerdict,
  type RoleLike,
  type Verdict,
} from '@/middleware/rbac';
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
 * Pure permission decision for an MCP tool or prompt, given an
 * already-resolved verdict. Split out of `checkToolPermission` so callers
 * that must resolve the verdict once and reuse it across multiple permission
 * checks (the prompt registrar registers several prompts per server, but the
 * verdict is fixed for the server's lifetime) can avoid re-triggering
 * `resolveVerdict`'s side effects. See `checkToolPermission` for why that
 * matters.
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
 * Resolves the verdict itself, and therefore fires `resolveVerdict`'s side
 * effects (`hyperdx.rbac.missing_role` and its WARN) on every call. That must
 * happen once per request, so the registrars do NOT use this — they share a
 * `createVerdictGate` instead. This remains the single-shot entry point for
 * callers that make exactly one decision per request, and the unit-test
 * surface for the decision logic.
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

/**
 * Reads the verdict, with the side effects deferred to the first *permission
 * consultation* and then memoised.
 *
 * `hyperdx.rbac.missing_role` must fire exactly once per request that consults
 * a permission, and zero times for requests that consult none. Both MCP
 * registrars run inside `createServer`, which runs once per HTTP POST —
 * *before* the JSON-RPC method is known — so neither registration time nor
 * per-check resolution gives that property on its own:
 *
 * - `peek()` has no side effects. Registration uses it, because it happens on
 *   every POST including `initialize`, `ping` and `tools/list`, which consult
 *   no permission. It only decides what a client is allowed to see listed.
 * - `get()` records, once per gate. The guarded tool and prompt handlers use
 *   it, so a `tools/call` or `prompts/get` counts exactly one missing-role
 *   event no matter how many tools were registered against the same server.
 *
 * Both return the same verdict for the same context — `resolveVerdict` is
 * `computeVerdict` plus telemetry — so nothing about what the verdict *means*
 * differs between the listing decision and the enforcement decision.
 */
export type VerdictGate = { peek: () => Verdict; get: () => Verdict };

export function createVerdictGate(context: McpContext): VerdictGate {
  let recorded: Verdict | undefined;
  return {
    peek: () => computeVerdict(context.role, 'access-key'),
    get: () =>
      (recorded ??= resolveVerdict(context.role, 'access-key', context.userId)),
  };
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
