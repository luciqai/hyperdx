# RBAC Slice C — the Bearer path (MCP + External API v2)

- **Date:** 2026-08-03
- **Status:** Awaiting review
- **Depends on:** [Slice A](./2026-08-02-rbac-design.md) — shipped, 18 commits on `claude/rbac-design-spec`
- **Supersedes:** Slice A §3's "Slice C" row and §14's slice-C sketch

---

## 1. Summary

Slice A gated the 65 session-authenticated routes. It left the **Bearer-token path**
entirely ungated: the MCP server's 28 tools and External API v2's 40 handlers. A
personal access key therefore grants full administrative capability regardless of the
holder's role — including the ingestion-key rotation and member management that slice A
just locked down for the browser.

Slice C closes that path. One identity fix serves both consumers; each gets enforcement
at its own natural chokepoint.

## 2. Why the Bearer path is currently wide open

`findUserByAccessKey` does not populate the role:

```ts
// packages/api/src/controllers/user.ts:6
export function findUserByAccessKey(accessKey: string) {
  return User.findOne({ accessKey });   // no .populate('role')
}
```

`findUserById` (the session path) does. So on the Bearer path `req.user.role` is always
`undefined`, and slice A's resolver treats a missing role as **fail-open Admin**
(§11.3). Adding `requirePermission` to an MCP route today would pass 100% of the time.

This is why "just add the middleware" is not the change.

## 3. Goals

1. `role` is populated for access-key requests, so the Bearer path has a real identity.
2. All 28 MCP tools declare a required permission, verified at startup.
3. All 40 External API v2 handlers declare one, verified by slice A's existing assertion.
4. A role-less Bearer request is **denied**, not silently promoted to Admin.
5. Denials on the MCP path surface as agent-readable tool errors, not alerts.

## 4. Non-goals

| Deferred | Consequence |
|---|---|
| **Slice B** — `/api/clickhouse-proxy`, `/v1/prometheus` | Browser query path stays ungated |
| **Slice D** — per-source rules | A holder of `sources: read` can query *any* source through the structured tools, exactly as in the browser. Slice C does not worsen this |
| Separate MCP tokens with independent scopes | An access key remains the user; it inherits their role rather than carrying its own |
| Hardening `/api/v2/search`'s `select` guard | See §8.3 |
| OpAMP server | Still unauthenticated; out of scope for RBAC entirely |

---

## 5. Decision log

Decisions taken during the design interview, with reasoning, so they are not silently
relitigated.

| Decision | Chosen | Why |
|---|---|---|
| Scope | MCP **and** External API v2 | Same token, same gap. Closing one leaves the other as a bypass: a key blocked from `clickstack_save_dashboard` could still `POST /api/v2/dashboards` |
| `clickstack_sql` | `connections: manage` | It takes free-form SQL and ignores Source mapping, so it operates at connection level. Defaults to admin-only (only Admin holds it) while staying grantable to a custom role via the existing builder |
| `/api/v2/search`, `/api/v2/charts` | `sources: read` | **Corrected mid-design.** Both are source-bound — search requires `sourceId`, charts calls `getSource()` at `charts.ts:589`. Gating them at `connections: manage` would have made the External API's primary read endpoints admin-only and broken every Member-level integration |
| Role-less Bearer request | **Fail closed** (browser keeps fail-open) | Slice A's fail-open protects a human debugging an outage. An unattended agent silently holding Admin is the worse failure, and the warning log scrolls past unread |
| MCP prompts | `sources: read` | `create_dashboard` and `query_guide` fetch the team's real sources to seed their text, so they enumerate source names |
| Denial category | `mcpUserError` | A 403 is normal operation for a restricted agent, not an incident. Keeps it out of `recordException` |

---

## 6. Identity fix

```ts
// packages/api/src/controllers/user.ts
export function findUserByAccessKey(accessKey: string) {
  return User.findOne({ accessKey }).populate('role');
}
```

One line, serves MCP and API v2 both. `validateUserAccessKey`
(`middleware/auth.ts:99`) additionally marks the request so the resolver can tell the
two paths apart:

```ts
req._hdx_authPath = 'access-key';
req.user = user;
```

## 7. Path-aware fail mode

`shortCircuits` in `middleware/rbac.ts` gains one branch. Resolution order, cheapest
first:

1. `IS_LOCAL_APP_MODE` → allow
2. `role == null`:
   - session path → allow as Admin, warn + `hyperdx.rbac.missing_role` *(slice A, unchanged)*
   - **access-key path → deny**, warn + `hyperdx.rbac.missing_role{path="access-key"}`
3. `role.isAdmin` → allow
4. `rank(held) >= rank(required)` → allow
5. otherwise → deny

The divergence is deliberate and justified by threat model, not left inconsistent by
accident: step 2's browser branch exists to keep a human out of a lockout during an
incident; an automated agent has no equivalent claim.

## 8. Enforcement

### 8.1 MCP — one chokepoint

`createRegisterTool` (`mcp/utils/registerTool.ts`) already wraps every tool with
`withToolTracing`. Permission enforcement composes into the same place, so all 28 tools
are covered by one change:

```
registerTool(name, { permission, ...config }, handler)
  └─► withPermission(permission, context,
        withToolTracing(name, context, handler))
```

`permission` is either a `` `${Resource}:${PermissionLevel}` `` string or the literal
`'admin'`. `ToolDefinition`'s config type gains the field as **required**, so a tool that
declares nothing fails to typecheck — the compile-time half of the guarantee.

**`permission` must be stripped before the config reaches the SDK.** `registerTool`
currently forwards `config` straight to `server.registerTool(name, config, traced)`, and
the SDK serialises that object into the tool manifest it advertises to clients. Passing
the field through would publish the whole permission model to every connected agent.
Destructure it out:

```ts
return (name, { permission, ...sdkConfig }, handler) => {
  const traced = withPermission(permission, context,
    withToolTracing(name, context, handler));
  server.registerTool(name, sdkConfig, traced);
  declaredPermissions.set(name, permission);   // for assertToolCoverage
};
```

The declaration is recorded in a map keyed by tool name rather than tagged onto the
handler, because unlike Express layers the SDK does not expose registered handlers for
inspection — `assertToolCoverage` reads that map against the server's registered tool
names.

**Ordering, discovered during implementation:** the SDK validates `inputSchema` *before*
invoking the tool callback, so the permission check runs **after** argument validation. A
denied caller sending malformed arguments therefore receives a validation error rather
than a permission error.

That is acceptable — the only thing it reveals is schema shape, which `listTools` already
publishes to every client — but it has two practical consequences worth recording:

1. Permission denial is not the outermost gate. Moving it earlier would mean
   reimplementing the SDK's dispatch, which is not worth it.
2. Tests asserting a denial **must pass schema-valid arguments**, or they assert a
   validation error and pass for the wrong reason. This bit the first draft of
   `rbacTools.int.test.ts`.

`assertToolCoverage(server)` is the runtime half: after registration, assert every tool
on the server carries a declaration, and throw at startup listing any that don't. Mirrors
slice A §7.3.

### 8.2 External API v2 — reuse slice A

Its handlers *are* Express routes, so `requirePermission` / `requireAdmin` apply directly
with no new machinery. `/api/v2` is removed from `assertRbacCoverage`'s `exemptMounts` in
`api-app.ts`, so the existing boot assertion covers these 40 routes too.

`/mcp` stays exempt from that walker — MCP tools are not Express routes and get
`assertToolCoverage` instead.

### 8.3 What the guards do not cover

`/api/v2/search` and `/api/v2/charts` accept free-form `select` / `where` **expressions**
against the resolved source's table, guarded by a single regex
(`DISALLOWED_COLUMNS_PATTERN = /;|(?<!\w)SELECT\s/i`, `search.ts:158`). That is weak: it
blocks semicolons and a bare `SELECT` keyword, not table functions or every subquery form.

A determined caller holding `sources: read` may therefore reach data outside the named
source. This is the same class of hole as slice B and applies equally to the browser, so
slice C neither introduces nor fixes it. Recorded here so it is not mistaken for closed.

---

## 9. MCP tool → permission table

All 28 tools. This is the implementation checklist.

### `sources: read` (11)
`clickstack_list_sources`, `clickstack_describe_source`, `clickstack_list_metrics`,
`clickstack_describe_metric`, `clickstack_search`, `clickstack_timeseries`,
`clickstack_table`, `clickstack_event_patterns`, `clickstack_event_deltas`,
`clickstack_trace_waterfall`, `clickstack_trace_top_time_consuming_operations`

### `sources: manage` (2)
`clickstack_save_source`, `clickstack_delete_source`

### `dashboards: read` (4)
`clickstack_get_dashboard`, `clickstack_search_dashboards`,
`clickstack_get_dashboard_tile`, `clickstack_query_tile`

> `query_tile` executes a query defined by an already-saved tile, so it is dashboard
> read access rather than source access.

### `dashboards: manage` (3)
`clickstack_save_dashboard`, `clickstack_patch_dashboard`, `clickstack_delete_dashboard`

### `savedSearches` (2)
`clickstack_get_saved_search` → read · `clickstack_save_saved_search` → manage

### `alerts` (2)
`clickstack_get_alert` → read · `clickstack_save_alert` → manage

### `webhooks` (3)
`clickstack_get_webhook` → read · `clickstack_save_webhook`,
`clickstack_delete_webhook` → manage

### `connections: manage` (1)
**`clickstack_sql`** — see §5.

### Prompts (3, via `server.registerPrompt`)
`create_dashboard`, `dashboard_examples`, `query_guide` → `sources: read`

---

## 10. External API v2 route → permission table

40 handlers. `/api/v2/` root plus nine sub-routers.

| Method | Path | Declaration |
|---|---|---|
| GET | `/api/v2/` | `noPermissionRequired('personal-state')` — identity check, returns the caller's own user |
| GET | `/alerts`, `/alerts/:id` | `alerts: read` |
| POST | `/alerts` · PUT `/alerts/:id` · DELETE `/alerts/:id` | `alerts: manage` |
| POST | `/charts/series` | `sources: read` |
| GET | `/connections`, `/connections/:id` | `connections: read` |
| POST | `/connections` · PUT `/connections/:id` · DELETE `/connections/:id` | `connections: manage` |
| GET | `/dashboards`, `/dashboards/:id` | `dashboards: read` |
| POST | `/dashboards/validate` | `dashboards: read` — validates a payload, persists nothing |
| POST | `/dashboards` · PUT `/dashboards/:id` · DELETE `/dashboards/:id` | `dashboards: manage` |
| GET | `/saved-searches`, `/saved-searches/:id` | `savedSearches: read` |
| POST | `/saved-searches` · PUT `/saved-searches/:id` · DELETE `/saved-searches/:id` | `savedSearches: manage` |
| POST | `/search` | `sources: read` |
| GET | `/sources`, `/sources/:id` | `sources: read` |
| POST | `/sources` · PUT `/sources/:id` · DELETE `/sources/:id` | `sources: manage` |
| GET | `/team` | `team: read` |
| GET | `/team/members` · GET `/team/invitations` | `users: read` |
| POST | `/team/invitation` · DELETE `/team/invitation/:id` · DELETE `/team/member/:id` | `requireAdmin()` |
| GET | `/webhooks` | `webhooks: read` |
| POST | `/webhooks` · PUT `/webhooks/:id` · DELETE `/webhooks/:id` | `webhooks: manage` |

**Rider — checked, does not apply.** `DELETE /api/v2/team/invitation/:id` was inspected
for the same unscoped-delete bug slice A fixed internally. It is already team-scoped
(`TeamInvite.findOneAndDelete({ _id, teamId })`, 404 on miss, `team.ts:238`). The IDOR was
internal-only; no change needed here.

---

## 11. Error surface

MCP tools return JSON text blocks, not HTTP statuses. A denial becomes:

```
mcpUserError(
  `Permission denied: this action requires ${resource}: ${level}. ` +
  `Your role is "${roleName}".`
)
```

Routed through `mcpUserError` so the existing `WeakMap` categorisation marks it `user`
rather than `server` — a restricted agent hitting a wall is normal operation and must not
page anyone. The message names the missing permission so an agent can adapt or report
usefully instead of retrying blindly.

API v2 keeps slice A's shape: `403 { message, required: { resource, level } }`.

---

## 12. Testing

**Highest value:** `assertToolCoverage` run as a test that builds the real MCP server and
asserts every tool declares a permission — the slice-C twin of slice A's
`rbacCoverageApp.int.test.ts`, and it must include a non-vacuity guard (tool count > 25)
so a walker that finds nothing cannot pass.

- **Unit:** `withPermission` allow/deny per level; the access-key fail-closed branch;
  denial is categorised `user` not `server`.
- **Integration (MCP):** drive a real `@modelcontextprotocol/sdk` client with a
  Member-role access key — `clickstack_save_dashboard` denied, `clickstack_get_dashboard`
  allowed, `clickstack_sql` denied; then with an Admin key, `clickstack_sql` allowed.
  Existing `mcpTestUtils.ts` already provides the client harness.
- **Integration (API v2):** table-driven, mirroring slice A §12.3 — representative route
  per resource per level for each system role.
- **Integration (fail-closed):** a user with `role: null` and a valid access key is
  denied on both MCP and API v2, and the counter fires.
- **Regression:** every existing `*.int.test.ts` under `mcp/` and `external-api/` must
  still pass. They authenticate with `getLoggedInAgent`-style keys whose users are now
  role-bearing Admins, so they should be unaffected — but this is a behavioural change
  under the whole suite and is the most likely source of surprise.

**Changeset:** `@hyperdx/api` minor. No `@hyperdx/app` change — slice C is server-side only.

---

## 13. Expected fallout

**`hdx-eval` runs as the founder (Admin), so it is unaffected.** But any eval run under a
non-admin key loses `clickstack_sql`, which was the single most-invoked tool in a 6-day
scan window (17 calls). Agent scores will move under such a config. That is the feature
working, not a regression — worth knowing before it is read as one.

**Existing integrations may break, correctly.** Any customer script using a
non-admin key to create dashboards or run SQL through `/api/v2` or MCP starts getting
403s. This is the point of the change, but it is a breaking change in effect and belongs
in the changeset prose.

---

## 14. Follow-ups

- **Slice B** — gate `/api/clickhouse-proxy` and `/v1/prometheus`. After slice C,
  raw-SQL access is admin-gated on the *agent* path but still open in the browser.
  The asymmetry is worth closing.
- **Slice D** — per-source rules, the last piece of the ClickStack parity story.
- Harden `DISALLOWED_COLUMNS_PATTERN` (§8.3) or replace it with real parsing.



! cd ~/hyperdx && . ./scripts/dev-env.sh && cd packages/api && npx dotenvx run --convention=nextjs -- npx nodemon --exec ts-node -r tsconfig-paths/register src/index.ts

! cd ~/hyperdx && . ./scripts/dev-env.sh && cd packages/app && npx dotenvx run --convention=nextjs -- npx next dev --turbopack -p 30296