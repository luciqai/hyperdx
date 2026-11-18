# RBAC for HyperDX — Design (Slice A)

- **Date:** 2026-08-02
- **Status:** Approved for planning
- **Mockups:** [`2026-08-02-rbac-mockups.html`](./2026-08-02-rbac-mockups.html)
- **Reference:** [ClickStack RBAC docs](https://clickhouse.com/docs/clickstack/managing/rbac)

---

## 1. Summary

HyperDX has no authorization model. `User` is `{name, email, team, accessKey}`; the only
primitive is "are you a member of this team", hand-written per route. This design adds
role-based access control: a `Role` collection with a stored permission map, three seeded
system roles, admin-authored custom roles, and declarative enforcement across all 65
internal API routes.

This is **slice A** of four. It makes the *interface* respect permissions. It does not yet
make the *data* respect them — see §3.

---

## 2. Goals

1. Every team has three system roles (Admin, Member, ReadOnly), seeded on creation.
2. Admins can create, edit and delete custom roles with a per-resource permission matrix.
3. Every member has exactly one role; admins assign it.
4. All 65 internal API routes declare a required permission, verified at boot.
5. Existing deployments upgrade without anyone losing access.

## 3. Non-goals

Recorded so the boundary survives review.

| Deferred | Consequence while deferred |
|---|---|
| **Slice B** — query-path enforcement (`/clickhouse-proxy`, `/v1/prometheus`, `/api/v2/search`, `clickstack_sql`) | **`sources` permissions are UI-level only.** A user with `sources: none` can still reach the proxy and name the table directly. This must be stated in product copy, not just here. |
| **Slice C** — MCP server + External API v2 | 67 enforcement points on the Bearer-token path stay ungated. |
| **Slice D** — fine-grained per-resource rules (match by Name/Tag/ID) | All permissions are team-wide. |
| Notebooks | No such model exists in this repo. |
| Ingestion-key field redaction | Rotation is Admin-only; visibility stays at `team: read`. A ReadOnly user can therefore read a *write* credential. Not a regression — today every user can — but not fixed here. |
| General team-scoping enforcement | Except one rider, §9.3. |
| Multi-team users | `User.team` is singular; roles are per-team, so this stays consistent. |

---

## 4. Data model

### 4.1 New collection: `Role`

```ts
// packages/api/src/models/role.ts
interface IRole {
  _id:         ObjectId;
  team:        ObjectId;   // ref Team, required, indexed
  name:        string;     // required
  description?: string;
  isSystem:    boolean;    // default false — blocks edit and delete
  isAdmin:     boolean;    // default false — ONLY the seeded Admin role
  permissions: Record<Resource, Level>;
  createdAt:   Date;
  updatedAt:   Date;
}

RoleSchema.index({ team: 1, name: 1 }, { unique: true });
```

### 4.2 `User` gains one field

```ts
role: { type: Schema.Types.ObjectId, ref: 'Role' }
```

Populated in `deserializeUser` via `.populate('role')`, so `req.user.role` is always
available for both enforcement and response shaping.

### 4.3 Why `isAdmin` is a flag, not a permission

Admin is **not** "a role with every permission set to `manage`". It is a role carrying a
flag that short-circuits every check. `isAdmin` and `isSystem` are stripped from all API
input, so no custom role can ever acquire it.

This is what makes privilege escalation impossible *by construction*: the only capability
that matters isn't in the permission vocabulary, so there is nothing for a subset-check to
police. No escalation guard is needed, and none is written.

---

## 5. Permission taxonomy

Two vocabularies, mirroring the ClickStack model.

**Resources** — `none | read | manage`, ordered `manage ⊃ read ⊃ none`:

```
dashboards, savedSearches, sources, alerts, webhooks, connections
```

**Administrative** — narrower ranges:

```
users : none | read
team  : read | manage
```

**Hard capabilities** — `isAdmin` only, not expressible in any role:

```
role CRUD · ingestion API key rotation · invite / remove members
```

### 5.1 Level semantics

- `read` — list and get.
- `manage` — read, plus create, update, delete.
- `sources: read` — view the source definition and build queries against it in the UI. It
  does **not** confer or restrict access to the underlying ClickHouse data (§3).
- `connections: read` — name and host only. The password field is `select: false` at the
  schema level and stays that way.

### 5.2 Departures from the ClickStack doc

| Difference | Reason |
|---|---|
| `Notebooks` omitted | No such model in this repo. |
| `Connections` added | Not in the doc, but a `Connection` holds ClickHouse credentials — the most sensitive object in the system. Defaults to `none` below Admin. |
| No `apiKeys` resource | Per product decision: the only requirement was Admin-only rotation, which is a hard capability. Key *visibility* remains under `team: read`. |

---

## 6. System roles

Seeded per team on creation. Immutable (`isSystem: true`).

| Permission | Admin | Member | ReadOnly |
|---|---|---|---|
| dashboards | manage | manage | read |
| savedSearches | manage | manage | read |
| sources | manage | read | read |
| alerts | manage | manage | read |
| webhooks | manage | read | none |
| connections | manage | none | none |
| users | read | read | none |
| team | manage | read | read |

Admin's row is display-only; `isAdmin` already grants everything.

---

## 7. Enforcement

### 7.1 Three declarations

`packages/api/src/middleware/rbac.ts`:

```ts
requirePermission(resource, level)
requireAdmin()
noPermissionRequired(reason)   // reason: 'public' | 'personal-state' | 'query-path-slice-B'
```

Each returns an Express handler **tagged with a symbol** carrying what it declared. The
middleware is simultaneously the enforcement and the registration — which is what makes
§7.3 possible. `noPermissionRequired` takes a mandatory reason string so every exemption is
self-documenting in the boot report.

### 7.2 Resolution order

Cheapest first:

1. `IS_LOCAL_APP_MODE` → allow. The fabricated `_local_user_` is implicitly Admin.
2. `req.user.role` missing → allow as Admin, emit warn log + `hyperdx.rbac.missing_role` counter. See §11.3.
3. `req.user.role.isAdmin` → allow.
4. `rank(role.permissions[resource]) >= rank(required)` where `rank = {none:0, read:1, manage:2}` → allow.
5. Otherwise `403 { message, required: { resource, level } }`.

403, not 404. Within a team, resource existence is not itself a secret, and 403 makes the
UI's "why can't I do this" story tractable.

### 7.3 Boot assertion

After routers mount, walk `app._router.stack` recursively. Every route under an
authenticated mount must carry at least one RBAC-tagged handler. Any that do not → **throw
at startup**, listing method and path.

This is the highest-value piece of the design. It converts "someone forgot the annotation"
from a silent production hole into a failed deploy — and that omission class is precisely
what produced the `TeamInvite` IDOR (§9.3).

---

## 8. Route → permission table

All 65 internal routes. This is the implementation checklist.

### `root.ts` (7) — mounted before auth

| Method | Path | Declaration |
|---|---|---|
| GET | `/health` | `noPermissionRequired('public')` |
| GET | `/installation` | `noPermissionRequired('public')` |
| POST | `/login/password` | `noPermissionRequired('public')` |
| POST | `/register/password` | `noPermissionRequired('public')` |
| GET | `/logout` | `noPermissionRequired('public')` |
| POST | `/team/setup/:token` | `noPermissionRequired('public')` — token-authenticated |
| GET | `/ext/silence-alert/:token` | `noPermissionRequired('public')` — token-authenticated |

### `me.ts` (1)

| Method | Path | Declaration |
|---|---|---|
| GET | `/` | `noPermissionRequired('personal-state')` — returns the caller's own `accessKey`; gating it would deny every non-admin CLI and MCP access |

### `favorites.ts` (3) — per-user (`{team, user, resourceType, resourceId}`)

| Method | Path | Declaration |
|---|---|---|
| GET | `/` | `noPermissionRequired('personal-state')` |
| PUT | `/` | `noPermissionRequired('personal-state')` |
| DELETE | `/:resourceType/:resourceId` | `noPermissionRequired('personal-state')` |

### `pinnedFilters.ts` (2) — **team-scoped, not per-user**

`PinnedFilter` is unique on `{team, source}`: one shared document per source. Writing it
changes what every member sees, so it is **not** personal state.

| Method | Path | Declaration |
|---|---|---|
| GET | `/` | `requirePermission('sources', 'read')` |
| PUT | `/` | `requirePermission('sources', 'manage')` |

### `alerts.ts` (8)

| Method | Path | Declaration |
|---|---|---|
| GET | `/` | `alerts: read` |
| GET | `/:id` | `alerts: read` |
| GET | `/:id/history` | `alerts: read` |
| POST | `/` | `alerts: manage` |
| PUT | `/:id` | `alerts: manage` |
| POST | `/:id/silenced` | `alerts: manage` |
| DELETE | `/:id/silenced` | `alerts: manage` |
| DELETE | `/:id` | `alerts: manage` |

### `dashboards.ts` (8)

| Method | Path | Declaration |
|---|---|---|
| GET | `/` | `dashboards: read` |
| POST | `/` | `dashboards: manage` |
| PATCH | `/:id` | `dashboards: manage` |
| DELETE | `/:id` | `dashboards: manage` |
| GET | `/preset/:presetDashboard/filters` | `dashboards: read` |
| PUT | `/preset/:presetDashboard/filter` | `dashboards: manage` |
| POST | `/preset/:presetDashboard/filter` | `dashboards: manage` |
| DELETE | `/preset/:presetDashboard/filter/:id` | `dashboards: manage` |

### `savedSearch.ts` (4)

| Method | Path | Declaration |
|---|---|---|
| GET | `/` | `savedSearches: read` |
| POST | `/` | `savedSearches: manage` |
| PATCH | `/:id` | `savedSearches: manage` |
| DELETE | `/:id` | `savedSearches: manage` |

### `sources.ts` (4)

| Method | Path | Declaration |
|---|---|---|
| GET | `/` | `sources: read` |
| POST | `/` | `sources: manage` |
| PUT | `/:id` | `sources: manage` |
| DELETE | `/:id` | `sources: manage` |

### `connections.ts` (4)

| Method | Path | Declaration |
|---|---|---|
| GET | `/` | `connections: read` |
| POST | `/` | `connections: manage` |
| PUT | `/:id` | `connections: manage` |
| DELETE | `/:id` | `connections: manage` |

### `webhooks.ts` (5)

| Method | Path | Declaration |
|---|---|---|
| GET | `/` | `webhooks: read` |
| POST | `/` | `webhooks: manage` |
| PUT | `/:id` | `webhooks: manage` |
| DELETE | `/:id` | `webhooks: manage` |
| POST | `/test` | `webhooks: manage` — sends a real outbound request |

### `team.ts` (10)

| Method | Path | Declaration | Change |
|---|---|---|---|
| GET | `/` | `team: read` | |
| PATCH | `/apiKey` | `requireAdmin()` | **restricted** |
| PATCH | `/name` | `team: manage` | |
| PATCH | `/clickhouse-settings` | `team: manage` | |
| POST | `/invitation` | `requireAdmin()` | **restricted** |
| GET | `/invitations` | `users: read` | |
| DELETE | `/invitation/:id` | `requireAdmin()` | **restricted + IDOR fix (§9.3)** |
| GET | `/members` | `users: read` | |
| DELETE | `/member/:id` | `requireAdmin()` | **restricted** |
| GET | `/tags` | `team: read` | |

### `ai.ts` (1)

| Method | Path | Declaration |
|---|---|---|
| POST | `/assistant` | `sources: read` — generates queries against sources |

### `clickhouseProxy.ts` (3)

| Method | Path | Declaration |
|---|---|---|
| POST | `/test` | `connections: manage` — validates supplied credentials |
| GET | `/*` | `noPermissionRequired('query-path-slice-B')` |
| POST | `/*` | `noPermissionRequired('query-path-slice-B')` |

### `prometheus.ts` (5)

| Method | Path | Declaration |
|---|---|---|
| GET | `/query_range` | `noPermissionRequired('query-path-slice-B')` |
| POST | `/query_range` | `noPermissionRequired('query-path-slice-B')` |
| GET | `/query` | `noPermissionRequired('query-path-slice-B')` |
| POST | `/query` | `noPermissionRequired('query-path-slice-B')` |
| GET | `/label/:name/values` | `noPermissionRequired('query-path-slice-B')` |

**Total: 65 routes.** The boot assertion (§7.3) is what keeps this table honest as routes
are added.

---

## 9. API surface

### 9.1 New routes

| Method | Path | Declaration | Behaviour |
|---|---|---|---|
| GET | `/team/roles` | `team: read` | List roles with member counts |
| POST | `/team/roles` | `requireAdmin()` | Create custom role |
| PATCH | `/team/roles/:id` | `requireAdmin()` | `409` if `isSystem` |
| DELETE | `/team/roles/:id` | `requireAdmin()` | `409` if assigned to any user |
| PATCH | `/team/members/:id/role` | `requireAdmin()` | `409` if it would demote the last admin |

### 9.2 Invariants

- The last user holding an `isAdmin` role cannot be demoted or removed.
- A role assigned to ≥1 user cannot be deleted; reassign first.
- `isSystem` roles reject `PATCH` and `DELETE`.
- `isAdmin` and `isSystem` are stripped from all request bodies.
- Role `name` is unique per team.

### 9.3 IDOR rider

`DELETE /team/invitation/:id` currently calls `TeamInvite.findByIdAndDelete(id)` with **no
team filter** — a verified cross-tenant IDOR (any authenticated user of any team can delete
another team's pending invite given its ObjectId). Every sibling endpoint in the same file
scopes correctly.

We are rewriting this route's guard anyway. Adding the missing `team` filter is a two-word
change on a line already being edited. Leaving a known cross-tenant bug in a route we just
modified is not defensible; this is in scope.

---

## 10. UI

All under `packages/app/src/`. Follows the existing `components/TeamSettings/*Section.tsx`
convention.

### 10.1 New components

| File | Purpose |
|---|---|
| `components/TeamSettings/RbacRolesSection.tsx` | Role list: name, description, member count, `System` badge, `+ Add role`, edit/delete |
| `components/TeamSettings/RoleEditorModal.tsx` | Name, description, permission matrix. Doubles as read-only viewer for system roles, which offer **Duplicate as custom role** — opens the create form prefilled from that role's matrix, so the built-ins act as starting points. Pure client-side prefill; no extra endpoint |
| `components/TeamSettings/PermissionMatrix.tsx` | Pure, no fetching. One `SegmentedControl` per resource row. Supports a `readOnly` mode |
| `hooks/useMyPermissions.ts` | Over `/me`; exposes `isAdmin` and `can(resource, level)` |

`SegmentedControl` rather than `Select`: the screen's job is comparing a role's whole
posture at a glance, which eight collapsed dropdowns defeat.

### 10.2 Modified

| File | Change |
|---|---|
| `components/TeamSettings/TeamMembersSection.tsx` | Role column + inline role `Select` (Admin-only). Disabled with tooltip on the last admin |
| `TeamPage.tsx` | Access tab becomes unconditional (currently gated on `hasAllowedAuthMethods`); Security Policies stays conditional *inside* it. Replace the `hasAdminAccess = true` stub at line 61 with the real value |

### 10.3 Gating rules

- **Whole sections a role cannot reach are absent, not disabled** — the UI never advertises
  something the server will reject.
- **Disabled + tooltip is reserved** for cases where the reason is worth teaching, e.g. the
  last admin.
- Greyed cells in the matrix (`users: manage`, `team: none`) mean *does not exist*, not
  *not permitted*. Annotated in the UI copy.

### 10.4 Scope boundary

**In scope:** Team Settings, plus mutating actions at **list level** — Sources, Alerts,
Webhooks, dashboard list, saved-search list. All small, focused files.

**Out of scope:** inline gating inside `DBDashboardPage.tsx` (3,211 lines) and
`DBSearchPage.tsx` (2,709 lines).

Accepted consequence: a user may find a mutating affordance deep in a chart editor that
returns 403 on submit. The server is authoritative and rejects correctly; the UX is a late
error rather than a hidden control. Smearing this slice across the two largest files in the
repo is the worse trade.

---

## 11. Migration

### 11.1 Mongo migration

`packages/api/migrations/mongo/<timestamp>-add_rbac_roles.ts`, using `migrate-mongo`
(existing mechanism; precedent at `20231130053610-add_accessKey_field_to_user_collection.ts`).

```
up:
  for each team:
    insert Admin (isSystem, isAdmin), Member (isSystem), ReadOnly (isSystem)
    users.updateMany({ team }, { $set: { role: <that team's Admin _id> } })

down:
  users.updateMany({}, { $unset: { role: '' } })
  drop 'roles' collection
```

> Do **not** copy the precedent's `updateMany({}, {$set: {...}})` shape — it assigns one
> identical value to every user across all teams. Ours needs a per-team loop.

**Everyone becomes Admin.** The alternative silently strips capabilities from working users
mid-upgrade. Admins then downgrade people deliberately — a decision someone makes, rather
than one that happens to them.

### 11.2 Seeding on team creation

Two call sites must seed the three system roles:

- the registration flow in `routers/api/root.ts`
- `setupDefaults.ts` (local / all-in-one mode)

### 11.3 The one deliberate fail-open

If `user.role` is missing (migration not run), the user resolves to **Admin**, with a loud
startup warning and a `hyperdx.rbac.missing_role` counter.

This is a fail-open default and the opposite of the usual instinct. Rationale: this is
self-hosted software, operators frequently upgrade *during* an incident, and locking every
user out of their own observability tool because a migration step was missed is a worse
outcome than a window of unenforced RBAC. The log and metric are what stop it being silent.

Reversing this is a one-line change if the team prefers fail-closed.

---

## 12. Testing

### 12.1 Highest-value test

**The boot assertion, run as a unit test**: mount the app, assert every authenticated route
declares a permission. One test that permanently retires the "forgot to annotate" bug class.

### 12.2 Unit — `packages/api`

- `rank()` comparison across all level pairs
- `isAdmin` short-circuit
- `isAdmin` / `isSystem` stripped from input bodies
- last-admin invariant (demote and remove paths)
- role-in-use delete guard
- missing-role fail-open path emits the counter

### 12.3 Integration — `*.int.test.ts`

Table-driven: for each system role, a representative route per resource per level,
asserting 200/403. Representative rather than all 195 combinations — the boot assertion
covers *coverage*, these cover *semantics*.

Plus: role CRUD happy path, `409` on system-role edit, `409` on in-use delete, `409` on
last-admin demotion, and the `DELETE /team/invitation/:id` cross-tenant regression test
(§9.3).

### 12.4 Migration test

Run `up` against a seeded multi-team fixture; assert every user holds *their own team's*
Admin role (not another team's). Run `down`; assert clean.

### 12.5 App unit — `packages/app`

`useMyPermissions`, `PermissionMatrix` (including `readOnly` mode).

### 12.6 E2E — fullstack mode

One spec: admin creates a custom role, assigns it to a second user, that user sees a
reduced UI.

### 12.7 Release

Changeset required — user-facing change to `@hyperdx/api` and `@hyperdx/app`, which are in
the same fixed version group. **Minor** bump.

---

## 13. Decision log

Decisions taken during design, with the reasoning, so they are not silently relitigated.

| Decision | Chosen | Why |
|---|---|---|
| Role configurability | Full parity — CRUD + builder UI | Product requirement; matches ClickStack |
| Who administers roles | `requireAdmin` only | Makes escalation impossible by construction; no subset-check needed |
| Admin representation | `isAdmin` flag outside the permission vocabulary | Same reason |
| Enforcement mechanism | Declarative middleware + boot assertion | Matches existing middleware idiom; closes the omission class |
| API keys | No `apiKeys` resource; rotation is `requireAdmin` | Stated goal was only rotation control |
| Own personal key | Ungated | Gating `/me` would deny every non-admin CLI/MCP access |
| Migration target role | Admin for all existing users | No deployment loses access on upgrade |
| Missing role | Fail **open** as Admin, loud | Lockout during an incident is the worse failure |
| Deep UI gating | Deferred | Would require touching the two largest files in the repo |

---

## 14. Follow-up slices

- **B — Close the query path.** Gate `/clickhouse-proxy`, `/v1/prometheus`, `/api/v2/search`,
  `clickstack_sql`. Converts this model from interface-level to data-level. Likely requires
  either per-role ClickHouse users or SQL parsing; both are substantial.
- **C — API-key path.** External API v2 (39 handlers) + MCP (28 tools) on Bearer auth.
  Controller-layer enforcement is the natural shape, and needs a system-actor bypass for the
  alert cron task.
- **D — Fine-grained resource rules.** Match by Name / Tag / ID with `is` / `contains` and OR
  logic, per the ClickStack doc.
