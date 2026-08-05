# RBAC Remediation — closing the manual-test findings

- **Date:** 2026-08-05
- **Status:** Approved for planning
- **Remediates:** [Slice A](./2026-08-02-rbac-design.md) · [Slice C](./2026-08-03-rbac-slice-c-design.md)
- **Source:** RBAC Manual Test Report (10 flows, 555+ route×actor checks, live stack)
- **Reference:** [ClickStack RBAC docs](https://clickhouse.com/docs/clickstack/managing/rbac)

---

## 1. Summary

A black-box test pass over the shipped slice A and slice C work found 2 Critical,
4 High and 6 Medium defects. The enforcement core held — 555+ checks passed, the boot
assertion genuinely refuses to start on an undeclared route, and privilege escalation
remains impossible by construction. The defects are in the seams: a registration path
that bypasses the chokepoint, an invariant that counts the wrong population, a
migration that can halt mid-write, and UI gates that were never wired.

This spec closes all twelve. It does not open new capability.

**Amendments to prior specs are recorded in §9** and supersede the corresponding
sections of slice A and slice C, which are left unedited as shipped records.

## 2. Goals

1. Every MCP surface — tools *and* prompts — is gated at one chokepoint and verified
   at startup.
2. The browser query path is no longer reachable by a role holding `sources: none`.
3. The last-admin invariant is literally true as §9.2 states it.
4. The Mongo migration is all-or-nothing; it never leaves a team half-seeded with no
   changelog entry.
5. No UI advertises an action the server will reject.

## 3. Non-goals

| Deferred | Consequence while deferred |
|---|---|
| **Slice B** — data-level query enforcement | `sources: read` remains sufficient to run arbitrary read SQL against the whole cluster. §4.2 narrows *who* can reach the path; it does not narrow *what* they can run. |
| **Slice D** — per-resource rules | Permissions stay team-wide. |
| Real expression parsing on `/search` and `/charts` | §6.5 closes the demonstrated bypasses; the class stays open. |
| Separate MCP tokens with independent scopes | An access key remains the user. |

### 3.1 Prior art considered

ClickStack governs **resource metadata** — Dashboards, Saved Searches, Sources,
Alerts, Webhooks, Notebooks — at `No Access | Read | Manage`, and defines No Access as
*"the resource type is hidden from the role entirely."* That wording drives §7's
absent-not-disabled rule and §4.1's hidden-not-denied choice for prompts.

ClickStack's documentation is silent on the query path, raw SQL, API keys and MCP.
ClickHouse Cloud solves data-level isolation *below* the application, with ClickHouse's
own GRANTs and `readonly` settings on the connection user — not with application-layer
string filtering. That is the direction slice B should take, and it is why §6.5 hardens
the existing guard rather than investing in a parser that would still be the wrong
layer.

---

## 4. Critical

### 4.1 SEC-1 — the three MCP prompts are ungated

**Defect.** `mcpServer.ts:35` passes the raw `server` to `dashboardPrompts`, bypassing
the `createRegisterTool` chokepoint that covers all 28 tools. `assertToolCoverage`
inspects only `_registeredTools`, and slice C §8.2 exempts `/mcp` from the Express
walker — so the gap falls between all three mechanisms. Every actor, including a role
holding `sources: none`, receives full source and connection inventory from
`prompts/get`.

**Fix — give prompts the tools' chokepoint.**

New `packages/api/src/mcp/utils/registerPrompt.ts`, mirroring `createRegisterTool`:

```
registerPrompt(name, { permission, ...sdkConfig }, handler)
  ├─ declared.set(name, permission)
  ├─ handle = server.registerPrompt(name, sdkConfig, guarded)
  └─ if role cannot reach `permission` → handle.disable()
```

- `permission` is destructured out before the config reaches the SDK, for the same
  reason `registerTool` does it: the SDK serialises `config` into the manifest it
  advertises to clients, and passing the field through would publish the permission
  model to every connected agent.
- `PromptDefinition` changes from `(server, context) => void` to
  `(registrar: PromptRegistrar) => void`, where
  `PromptRegistrar = { server, context, registerPrompt }`. `permission` is **required**
  on the config type, so a prompt declaring nothing fails to compile — the same
  compile-time half of the guarantee the tools have.
- All three prompts declare `sources: read`, per slice C §9.

**Hidden, not denied.** The MCP server is constructed per connection with the caller's
role (`createServer(context)`), so enforcement can be decided at registration.
`server.registerPrompt` returns a `RegisteredPrompt` carrying `enable()` / `disable()`
(verified present in the installed SDK). When the role cannot reach the declared
permission the prompt is disabled, so `prompts/list` omits it entirely — matching
ClickStack's "hidden from the role entirely" rather than advertising something that
will be refused.

A get-time permission check remains as the enforcement backstop, throwing
`Permission denied: this prompt requires sources: read. Your role is "<name>".` It
covers a client that calls a cached name, and it survives any change to the SDK's
disable semantics. Prompts are not currently wrapped by `withToolTracing`, so this
throw reaches no alerting path; that stays true.

**Coverage.** `assertToolCoverage` becomes `assertMcpCoverage(server, declaredTools,
declaredPrompts)`, reading `_registeredPrompts` alongside `_registeredTools`, with the
existing defensive non-vacuity guard applied to **each** list independently. Disabled
prompts remain in `_registeredPrompts`, so role-based disabling cannot make the
assertion pass vacuously.

### 4.2 SEC-2 — alerts-only role reaches arbitrary read SQL

**Defect.** A role holding `sources: none` and `connections: none` is correctly denied
`GET /sources`, `GET /connections` and `clickstack_list_sources` — then harvests a
`connectionId` and feeds it to `POST /clickhouse-proxy`, which carries
`noPermissionRequired('query-path-slice-B')`. The report demonstrated `SHOW DATABASES`
and a `SELECT` returning 1841 rows containing the platform's own logged ingestion key.

**Fix — coarse gate now.**

| File | Route | Was | Becomes |
|---|---|---|---|
| `routers/api/clickhouseProxy.ts:347` | `GET /*` | `noPermissionRequired('query-path-slice-B')` | `requirePermission('sources','read')` |
| `routers/api/clickhouseProxy.ts:355` | `POST /*` | same | same |
| `routers/api/prometheus.ts:376,377,484,485,497` | 5 routes via `queryPathExempt()` | same | same |

`POST /clickhouse-proxy/test` keeps `connections: manage` — it validates supplied
credentials and is not a query path.

Those seven routes are the **only** users of the exemption (verified by grep across
`packages/api/src` and `packages/common-utils/src`), so `queryPathExempt`
(`prometheus.ts:18`) and the `'query-path-slice-B'` member of `RbacExemptReason`
(`middleware/rbac.ts:27`) are removed outright. An exemption reason with no users is a
falsehood the boot coverage report would keep printing.

**Why this and not more.** All three system roles hold `sources: read`, so no system
role loses anything. What changes is that a custom role with `sources: none` can no
longer reach the query path at all — which is the entire chain the report demonstrated.
It does **not** stop a `sources: read` holder from running arbitrary SQL; that is slice
B, and §9 rewrites the product-copy requirement to say so plainly.

**Fixing SEC-1 alone would not have closed this.** ID-obscurity was never a control: a
role with `sources: none` and `dashboards: read` can read connection ids straight out of
saved dashboard tiles. Removing the prompt leak lengthens the chain by one step; gating
the path ends it.

---

## 5. High

### 5.1 BUG-1 — last-admin protection bypassable

**Defect.** `countEffectiveAdmins()` counts role-less users as admins, deliberately —
they pass `requireAdmin` via the session fail-open. So whenever any role-less user
exists, an admin can demote the last actual Admin-role holder and the guard stays
silent. Same request, different outcome depending on invisible state.

**Fix — guard the explicit grant, scoped to holders.**

`countEffectiveAdmins` → `countAdminRoleHolders(teamId, excludeUserId)`, counting only
users whose `role` is in the team's `isAdmin` role ids. Role-less users are no longer
counted.

The guard fires **only when the target user currently holds an `isAdmin` role**:

```
assignRole:  if (!nextRole.isAdmin && userHoldsAdminRole(user)
                 && await countAdminRoleHolders(teamId, user._id) === 0) → 409
isLastAdmin: userHoldsAdminRole(user)
                 && await countAdminRoleHolders(teamId, userId) === 0
```

where `userHoldsAdminRole(user)` is `user.role != null && adminRoleIds.includes(user.role)`
— the same `adminRoleIds` lookup `countAdminRoleHolders` already performs, so it costs no
extra query.

That second clause is load-bearing. Counting strictly *without* it would block removing
or demoting **anyone** on an un-migrated team, since nobody there holds an admin role —
a usability regression worse than the bug. With it:

- Un-migrated team → no guard fires; the fail-open still means admin access exists.
- Migrated team → the invariant is exact, and Team Settings can never show zero Admins.

The failure is a recoverable 409 — *"This is the last Admin. Promote someone else to
Admin first."* — never a lockout. The post-write recheck that catches two concurrent
demotions keeps its current shape, using the new count.

Grafana enforces the equivalent invariant on the explicit admin role and the pain it
causes them comes entirely from LDAP/OAuth bulk role sync rewriting memberships on
login. HyperDX has no such sync, so that argument against strictness does not transfer.

### 5.2 BUG-2 — `hasAdminAccess = true` stubs survived

**Defect.** Two stubs were missed when slice A §10.2 replaced them, and two list-level
surfaces named in §10.4 were never gated. The server 403s all of them correctly, so
there is no server hole — but the UI advertises actions it knows will fail, violating
§10.3.

| Surface | File | Gate |
|---|---|---|
| S1 · Rotate API Key | `ApiKeysSection.tsx:43` | `useMyPermissions().isAdmin` |
| S2 · Query Settings write controls (12) | `TeamQueryConfigSection.tsx:67` | `can('team','manage')` |
| S3 · Webhook CRUD | `WebhooksSection.tsx` | `can('webhooks','manage')` |
| S4 · New / Import / Delete dashboard | `DashboardsListPage.tsx` | `can('dashboards','manage')` |

S2's local is **renamed** as well as rewired. `PATCH /team/clickhouse-settings` requires
`team: manage`, not admin; calling the local `hasAdminAccess` is how it drifted in the
first place, and leaving the name would invite the same drift back.

Rule applied throughout, per ClickStack and §10.3: **absent, not disabled.**

### 5.3 BUG-3 — migration halts mid-way on a name collision

**Defect.** The `$setOnInsert` upsert matches an existing role by `{team, name}` and
inserts nothing, so no `isAdmin: true` role exists; `findOne({isAdmin: true})` returns
null and `admin!._id` throws. The team is left with Member and ReadOnly seeded, no admin
role, no users assigned, and **no migrate-mongo changelog entry** — the operator must
hand-repair before the migration can advance. Reachable because the roles API is live
pre-migration via the session fail-open, so an operator can create a custom role named
`Admin` first.

**Fix — pre-flight abort, before any write.**

```
up:
  pre-flight: find every role where name ∈ SYSTEM_ROLE_NAMES and isSystem !== true
              if any → throw, listing team id + role name, with rename instructions
  createIndex
  per team: bulkWrite upserts
            admin = findOne({ team, isAdmin: true })
            if (!admin) → throw naming the team    // checked, not `admin!`
            users.updateMany(...)
```

The pre-flight runs across all teams before the first write, so the failure mode is
"nothing happened, here is what to rename" rather than "half of team X is seeded".
`admin!._id` becomes a checked read as a second line of defence for anything the
pre-flight cannot foresee.

### 5.4 BUG-4 — seeding race can violate the one-Admin-per-team invariant

**Defect.** `seedSystemRoles` relies entirely on the `{team, name}` unique index for
concurrency safety. With the index absent — precisely the window during first
registration on a fresh database, before the background build finishes — 12 parallel
calls violated the invariant in 7 of 20 trials (`roles=5, admins=3`). Once duplicates
exist the index can never build, which wedges the migration's own `createIndex`. The
repo's tests paper over this with `await Role.init()`; the application has no equivalent
barrier.

**Fix — supply the barrier, and survive the race anyway.**

1. `seedSystemRoles` awaits a **memoised** `Role.init()` before the upsert loop, so the
   unique index is guaranteed built before the first concurrent write. Memoised because
   this runs on every team creation and only the first call needs to wait.
2. The `findOneAndUpdate` upsert catches E11000 and re-reads
   `Role.findOne({ team, name })`. `init()` prevents duplicate *documents*; the catch
   prevents the *request* failing when two upserts race a present index.

Both are needed. Neither alone is sufficient.

---

## 6. Medium

### 6.1 BUG-5 — Sources section renders, then permanently 403s

**Defect.** `TeamPage.tsx:122` gates the section on `can('sources','read')`, but its data
path also calls `GET /connections`, which requires `connections: read` — `none` for both
Member and ReadOnly. The section renders, then shows *"Failed to load sources · 403"*
with a Retry that re-fails.

**Fix — remove the dependency, not the section.** The internal `GET /sources` inlines
each source's connection **name** alongside its id, so the list view never calls
`/connections` and the `sources: read` gate becomes self-consistent.

Scoped to the internal route. `GET /api/v2/sources` shapes its response through
`formatExternalSource`, and changing that ripples across two handlers and a published
schema to serve no finding — v2 has no equivalent UI dependency. It can follow later if
an API consumer asks for it.

Hiding the section from Member and ReadOnly was rejected: ClickStack's ReadOnly can read
Sources, and a permission model where a `read` grant produces an error page is broken
regardless of which gate you tighten.

The source **editor's** connection picker still needs the full list, and it is reached
through two controls on the list: the per-source expand chevron and the "Add source"
button.

**Correction (post-implementation).** An earlier draft of this section justified leaving
those two controls ungated by claiming the editor was "reachable with `connections: none`
only by a custom role". That was wrong. `SYSTEM_ROLE_PERMISSIONS` gives **both Member and
ReadOnly** `sources: read` with `connections: none`, so both stock non-admin roles reached
the editor, got an empty connection picker, and would have been 403'd on save. Removing
the list's `/connections` dependency fixed the reported red banner but left that second
surface advertising a write the server rejects, which §7's rule forbids.

Both controls are therefore gated on `can('sources','manage')` in `SourcesList.tsx` —
absent, not disabled, per §7 — along with the `#source-<id>` deep link that expands the
editor without going through the chevron.

### 6.2 BUG-6 — the promised loud startup warning does not exist

**Defect.** Slice A §11.3 rests the entire safety case for the fail-open on it being
"loud, never silent". The only boot-time RBAC output is the coverage line. Nothing at
startup counts or warns about users with `role == null`; the warning is purely
per-request, un-aggregated, and accrued 128+ lines in hours of probing.

**Fix.**

- At boot, after the Mongo connection is established:
  `User.countDocuments({ role: { $in: [null, undefined] } })`. If non-zero, emit a WARN
  naming the count and the remedy, and record a `hyperdx.rbac.users_without_role` gauge.
  Zero is not logged — a clean boot stays clean.

  **Deviation as shipped.** The instrument is a **counter** named
  `hyperdx.rbac.users_without_role_at_boot`, not a gauge named
  `hyperdx.rbac.users_without_role`. `packages/api/src/utils/instrumentation.ts` exposes
  `getCounter` and `getHistogram` but no gauge helper, and adding one for a single
  once-per-process observation was not worth the surface. A counter incremented once at
  boot carries the same information for this purpose — the value is a boot-time snapshot
  either way — and the `_at_boot` suffix keeps the name honest about that, distinguishing
  it from the per-request `hyperdx.rbac.missing_role`. Revisit if a gauge helper lands.
- The per-request WARN is deduplicated per `userId` per process, so the signal survives
  and the noise does not. `hyperdx.rbac.missing_role` keeps counting every request; the
  counter is the durable half and must not be deduplicated.

### 6.3 BUG-7 — a Member can harvest live invitation tokens

**Defect.** `GET /team/invitations` (internal, `team.ts:215`) and
`GET /api/v2/team/invitations` (`team.ts:188`) both return each pending invite's full
`join-team?token=…` URL at `users: read`, which Member holds. Creating invites is
correctly `requireAdmin()`, but a Member can read a token and hand it to an outsider.

**Fix — redact the secret, keep the list.** Both routes stay at `users: read`. The `url`
field is included only when the caller is admin; the `token` projection is dropped from
the query for everyone else so the secret never enters the process. `_id`, `createdAt`,
`email` and `name` are unchanged, so the Members view keeps showing which invitations are
outstanding.

The published guidance is to avoid returning accept-capable invitation identifiers to
users who should not act on them — not to hide that invitations exist. `requireAdmin()`
would satisfy the first at the cost of the second.

### 6.4 BUG-8 — access-key guessing is unmetered

**Defect.** `rateLimiterKeyGenerator` returns `req.headers.authorization`, so **every
guessed key gets its own bucket**: 105 distinct garbage bearers produced zero 429s.
Keying a limiter on the credential being guessed defeats it by construction.
`GET /api/v2/` has no limiter at all and returns 200 with the user record, making it a
validity oracle.

**Fix — key on identity, meter failures by origin.**

The limiter currently runs *before* `validateUserAccessKey`
(`external-api/v2/index.ts`, `mcp/app.ts:39`), which is why it can only see the header.

1. **Swap the order** — authenticate, then rate-limit — and key on
   `req.user._id.toString()`. One bucket per user, regardless of how many keys they
   present.
2. **Add a stricter IP-keyed limiter in front of auth** to meter failed attempts, using
   express-rate-limit's IPv6-safe `ipKeyGenerator` helper rather than raw `req.ip`.
3. Apply both to `GET /api/v2/`, which has neither today.
4. Same treatment in `mcp/app.ts`, which shares the generator and the ordering.

### 6.5 BUG-9 — expression guard is bypassable and unevenly applied

**Defect.** `DISALLOWED_COLUMNS_PATTERN = /;|(?<!\w)SELECT\s/i` (`search.ts:159`) is
defeated by a comment — `(SELECT/**/groupArray(name) FROM system.users)` returns 200. The
refinement is applied to `select` only; `where` on `/search` is unguarded and
`/charts/series` has no regex at all.

**Fix — close the demonstrated gaps; stop calling it a boundary.**

1. Strip SQL comments (`/*…*/` and `--…` to end of line) before matching, so comment
   insertion cannot break up a keyword.
2. Apply the refinement to `where` as well as `select`.
3. Apply it on `/charts/series`, which has none.
4. Reword slice C §8.3 (see §9) to state that this is defence-in-depth and **not** a
   security boundary.

A denylist is the wrong shape and the fix above does not change that — it closes three
demonstrated bypasses, not the class. Real expression parsing was rejected as the wrong
layer as well as the wrong size: ClickHouse Cloud constrains this with database-level
GRANTs on the connection user, which is where slice B should put it.

### 6.6 BUG-10 — `permissions` is a non-strict Zod object

**Defect.** `RoleInputSchema` and `RolePermissionsSchema` (`common-utils/src/types.ts:2250,
2274`) accept and store unknown keys, including `permissions.isAdmin: true`. Verified
inert — enforcement reads top-level `role.isAdmin`, and `permissions` is only ever
indexed by valid `Resource` names — but a key that *looks* like a capability sitting on a
role document invites a future misread.

**Fix.** `.strict()` on both schemas. Unknown keys become a 400 rather than stored junk.

---

## 7. UI gating rule

One rule, applied to every surface touched in §5.2 and §6.1, restating slice A §10.3 with
ClickStack's wording behind it:

> A section or control a role cannot reach is **absent**, not disabled. Disabled-with-
> tooltip is reserved for cases where the reason teaches something — the last admin.

A `read` grant must never produce an error page. Where a view needs data behind a
permission its own gate does not imply, the fix is to remove the dependency (§6.1), not
to widen the gate or tighten it.

---

## 8. Testing

Each fix gets the test that would have caught it. Several are lifted directly from the
report's reproductions, which is the point — they are known to fail against the current
code.

### 8.1 Highest value

`assertMcpCoverage` as a unit test that builds the real MCP server and asserts every
registered tool **and prompt** declares a permission, non-vacuous on each list
independently. This is the assertion whose blindness to `_registeredPrompts` caused
SEC-1.

### 8.2 Unit — `packages/api`

- `registerPrompt` strips `permission` from the SDK config.
- Prompt permission check: allow, deny, and the role-less access-key deny.
- `countAdminRoleHolders` — role-less users excluded.
- Last-admin guard: fires for an admin-role holder, does not fire for a role-less user
  on an un-migrated team.
- Rate limiter key generator: authenticated → user id; unauthenticated → IPv6-safe IP
  key.
- Comment-stripped expression guard against `(SELECT/**/…)`.
- `.strict()` rejects `permissions.isAdmin`.

### 8.3 Integration — `packages/api`

- **MCP:** a `sources: none` role sees no prompts in `prompts/list`; an Admin sees three.
  `prompts/get` by cached name is refused for the denied role.
- **Query path:** `sources: none` → 403 on `/clickhouse-proxy` and each
  `/v1/prometheus` route; Member → 200.
- **BUG-1 A/B, exactly as reported:** with a role-less user present, demoting the last
  Admin-role holder returns 409 — the case that returned 200.
- **BUG-4 harness:** 12 parallel `seedSystemRoles` calls with **no `Role.init()` in the
  test**. The application must supply the barrier; a test that supplies it asserts
  nothing.
- **Invitations:** admin receives `url`; Member receives the invitation without `url` or
  `token`, on both the internal and v2 routes.
- **Rate limiting:** 105 distinct garbage bearers from one IP → 429.
- **Boot assertion regression:** the coverage walker still passes with
  `'query-path-slice-B'` removed from the exemption vocabulary.

### 8.4 Migration

- A team holding a non-system role named `Admin` aborts the migration with **zero
  writes** and **no changelog entry**; the error names the team and the role.
- The existing multi-team fixture still assigns every user their own team's Admin.
- `down` / `up` round-trip stays clean.

### 8.5 App unit — `packages/app`

- `ApiKeysSection` and `TeamQueryConfigSection` render no write controls for a non-admin
  and for a `team: read` role respectively.
- `WebhooksSection` renders no CRUD for `webhooks: read`.
- `DashboardsListPage` renders no New / Import / Delete for `dashboards: read`.
- Sources list renders connection names with no `/connections` request.

---

## 9. Amendments to prior specs

Recorded here rather than edited into the shipped documents.

| Spec | Section | Amendment |
|---|---|---|
| Slice A | §3, deferred-slice-B row | Replace *"can still reach the proxy and name the table directly"* with: **any user holding `sources: read` can run arbitrary read SQL against the entire ClickHouse cluster, including system tables and other teams' query text.** This is the statement §3 requires in product copy. |
| Slice A | §8, `clickhouseProxy.ts` / `prometheus.ts` tables | `GET`/`POST /*` and all five prometheus routes become `sources: read`. |
| Slice A | §7.1 | `'query-path-slice-B'` removed from `RbacExemptReason`. |
| Slice A | §9.2, first invariant | Unchanged in wording; §5.1 makes the implementation match it. The guard applies to users **holding** an `isAdmin` role, which is what it always said. |
| Slice A | §11.3 | The "loud startup warning" is now a real boot-time count plus a boot-time metric (§6.2 — a counter, not the gauge originally specified), not only a per-request log. |
| Slice C | §8.3 | Restate: the expression guard is **defence-in-depth, not a security boundary.** Comment stripping and coverage of `where` and `/charts/series` close the demonstrated bypasses; the class stays open until slice B constrains it at the database layer. |
| Slice C | §9, Prompts | Prompts are registered through a guarded chokepoint and **hidden** from `prompts/list` for roles that cannot reach them, rather than refused on call. |

---

## 10. Sequencing

Four phases, ordered by risk. Each is independently shippable.

| Phase | Contents | Rationale |
|---|---|---|
| 1 · Security | SEC-1, SEC-2, BUG-7 | The two Criticals and the live token exposure. Smallest diff, highest value. |
| 2 · Invariants | BUG-1, BUG-3, BUG-4, BUG-10 | Server-side correctness; all four are data-integrity guards. |
| 3 · UI | BUG-2, BUG-5 | Depends on §6.1's `GET /sources` change landing first. |
| 4 · Hardening | BUG-6, BUG-8, BUG-9 | Observability and defence-in-depth; no behavioural dependency on 1–3. |

## 11. Release

**Changeset:** `@hyperdx/api` and `@hyperdx/app` (same fixed version group), **minor**.

Three changes are breaking in effect and must be named in the changeset prose:

1. `/clickhouse-proxy` and `/v1/prometheus` now require `sources: read`. Any custom role
   with `sources: none` loses browser query access — which is the point, but it will look
   like a regression to whoever built that role.
2. MCP prompts now require `sources: read` and are hidden from `prompts/list` otherwise.
   An agent running under a restricted key will stop seeing them.
3. Invitation URLs are no longer returned to non-admins. Any integration reading invite
   links from `GET /team/invitations` under a Member key breaks.

## 12. Decision log

| Decision | Chosen | Why |
|---|---|---|
| SEC-2 scope | Coarse gate on the query path now | Two lines; no system role loses anything; converts the blast radius from "any authenticated user" to "any user deliberately granted `sources: read`". Full slice B would swallow eleven other fixes. |
| Prompt denial surface | Hidden from `prompts/list`, backstopped by a get-time check | ClickStack: No Access means hidden entirely. The server is per-connection, so this is decidable at registration. |
| Last-admin invariant | Guard the explicit `isAdmin` grant, only when the target holds one | Makes §9.2 literally true without regressing un-migrated teams; failure is a recoverable 409, never a lockout. |
| BUG-5 remedy | Inline the connection name server-side | Fixes the cause — a `sources: read` view should not need `connections: read`. Widening the permission would reverse §5.2's deliberate default on the most sensitive object in the system. |
| BUG-7 remedy | Redact the URL, keep the list at `users: read` | Guidance is to withhold accept-capable identifiers, not to hide that invitations exist. |
| BUG-9 depth | Close the demonstrated bypasses; keep the denylist | A parser is the wrong layer as well as the wrong size — ClickHouse Cloud constrains this with database GRANTs. Paired with copy that stops implying it is a boundary. |
| Where the fixes are recorded | One new spec amending two shipped ones | Slice A and slice C are approved records of what shipped; the amendment table is the more useful artifact. |
