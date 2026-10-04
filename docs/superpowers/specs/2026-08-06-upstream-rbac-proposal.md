# Upstream proposal — ready to paste as a GitHub issue

- **Date:** 2026-08-06
- **Target:** `hyperdxio/hyperdx` → Issues (label: `enhancement`, or Discussions
  if the repo prefers)
- **Companion:**
  [`2026-08-06-upstream-contribution-plan.md`](./2026-08-06-upstream-contribution-plan.md)

**Before filing, resolve these:**

1. Search the repo for existing RBAC issues/PRs and check whether ClickStack
   already ships or plans this. If it does, reframe the opening as "an
   implementation of the model you already document" rather than a new proposal.
2. Do **not** include the three security defects from §3 of the plan in this
   issue. They go through a private channel first.
3. Replace `<FORK-URL>` and confirm the route count (65) still matches `main`.

---

## Title

`Proposal: role-based access control for teams — design review requested before I open PRs`

---

## Body

### Summary

HyperDX currently has no authorization model. `User` is
`{name, email, team, accessKey}`, and the only primitive is "are you a member of
this team", hand-written per route. Every authenticated member of a team can do
everything: rotate the ingestion key, delete any dashboard, read and modify
ClickHouse connection settings, remove other members.

For teams beyond a handful of trusted engineers this is a blocker. I hit it on a
self-hosted deployment and built a full implementation, which is working and
tested on a fork.

**I am opening this issue before opening any PR, because this is a security
boundary and a data migration — it constrains every route you write from here
on. I would rather find out now that you want it built differently, or do not
want it at all, than hand you a large PR built on assumptions I never checked.**

Everything below is a proposal. I am happy to change the model, the boundaries,
the migration strategy, or the slicing — or to close this if it does not fit
your roadmap.

### Why this, rather than something smaller

I considered narrower options first:

- **An admin flag on `User`.** Two tiers only. Does not express "can edit
  dashboards but cannot touch ClickHouse connections", which was the actual
  need.
- **Per-resource ACLs.** Far more flexible, but every object grows an ownership
  model and the UI becomes a permissions browser. Much larger surface, and it
  does not match how observability teams actually organize.
- **Nothing; document the limitation.** Reasonable for small teams, but the
  ingestion key and the ClickHouse connection credentials are reachable by every
  member today.

Roles with a per-resource permission map landed in the middle: it covers the
real need, the vocabulary stays small, and it matches the model already
documented for
[ClickStack](https://clickhouse.com/docs/clickstack/managing/rbac) — which
seemed like the right thing to align with rather than invent a parallel scheme.
**If that alignment is wrong, or if there is an internal plan I should be
matching instead, that is the single most useful thing you could tell me.**

### The model

**Resources** — levels `none | read | manage`, ordered `manage ⊃ read ⊃ none`:

```
dashboards · savedSearches · sources · alerts · webhooks · connections
```

**Administrative scopes** — deliberately narrower ranges:

```
users : none | read
team  : read | manage
```

**Hard capabilities** — not expressible in any role, gated on an `isAdmin` flag:

```
role CRUD · ingestion key rotation · invite / remove members
```

Three roles seed on team creation:

|               | Admin  | Member | ReadOnly |
| ------------- | ------ | ------ | -------- |
| dashboards    | manage | manage | read     |
| savedSearches | manage | manage | read     |
| sources       | manage | read   | read     |
| alerts        | manage | manage | read     |
| webhooks      | manage | read   | none     |
| connections   | manage | none   | none     |
| users         | read   | read   | none     |
| team          | manage | read   | read     |

Admins can author custom roles from a permission matrix in Team Settings. Every
user has exactly one role.

#### One design decision worth your attention

Admin is a **flag that short-circuits every check**, not "a role with everything
set to `manage`". `isAdmin` and `isSystem` are stripped from all API input, so
no custom role can acquire them.

This makes privilege escalation impossible by construction rather than by guard:
the only capability that matters is not in the permission vocabulary, so there
is no subset-check to get wrong. No escalation guard is written, because none is
needed. If you would rather have admin be expressible and policed by an explicit
check, that is a real trade-off and I'll take your call on it.

### Enforcement

Routes declare their requirement inline:

```ts
router.get('/', requirePermission('dashboards', 'read'), handler);
router.delete('/invitation/:id', requireAdmin(), handler);
router.get('/me', noPermissionRequired('personal-state'), handler);
```

A startup assertion walks the Express router tree and **fails the boot** if any
authenticated route carries no declaration. Forgetting the annotation on a new
route is otherwise silent and ships an unguarded endpoint; this converts that
omission into a failed deploy rather than a vulnerability.

### Upgrade safety

This is the part I would most like reviewed.

A migration seeds the three roles per team and assigns every existing user to
Admin, so nobody loses access on upgrade. But the enforcement path also **fails
open for browser sessions with no role**:

| Auth path                 | `role == null` | Reason                                                                                                            |
| ------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------- |
| session (browser)         | **allow**      | A self-hosted operator upgrading mid-incident must not be locked out of their own observability tool.             |
| access-key (MCP / API v2) | **deny**       | An unattended agent token has no equivalent claim, and silently granting it admin is worse than failing the call. |

Both emit a `hyperdx.rbac.missing_role` counter and a warning, so a deployment
sitting in the fail-open state is visible rather than silent.

If you consider fail-open unacceptable even transitionally, the alternative is a
hard requirement that the migration run before the API starts. I chose
availability over strictness for the browser path; I can see the argument the
other way.

### Scope — what this does and does not do

Built and tested:

- Role collection, three seeded system roles, custom role CRUD
- Declarative enforcement across all internal API routes, verified at boot
- Team Settings UI: role list, permission matrix editor, per-member assignment
- MCP server and External API v2 (the Bearer-token path)
- Browser query path (`/clickhouse-proxy`, `/v1/prometheus`) requires
  `sources: read`
- Mongo migration with pre-flight validation and rollback on name collision

Deliberately not included:

- **Fine-grained per-resource rules** (match by name/tag/id). All permissions
  are team-wide.
- **Data-level source isolation.** `sources: read` governs the interface. A user
  who can reach the query path can still name any table. Gating the interface
  and gating the data are different problems; this is the first.
- **Multi-team users.** `User.team` is singular, so roles stay per-team by
  construction.
- **Ingestion key redaction.** Rotation is Admin-only; visibility stays at
  `team: read`, so a ReadOnly user can still read a write credential. Not a
  regression — every user can today — but not fixed here.

### How I would like to submit it

The work is roughly **4,500 lines of production code plus tests**, which is too
much for one review. Derived from the code's own dependency constraints, it
splits into seven PRs:

| #   | PR                                                  | Merge effect on an existing deployment            |
| --- | --------------------------------------------------- | ------------------------------------------------- |
| 1   | Permission types and role matrices (`common-utils`) | none — types only                                 |
| 2   | `Role` model, `User.role`, migration                | none — nothing reads it yet                       |
| 3   | Enforcement middleware primitives                   | none — nothing calls them yet                     |
| 4   | Route annotations + role CRUD API                   | enforcement begins; un-migrated users fail open   |
| 5   | Team Settings UI                                    | roles become manageable                           |
| 6   | MCP + External API v2                               | Bearer path enforced — **requires 2 to have run** |
| 7   | Startup coverage assertion                          | annotation becomes mandatory — **must be last**   |

PRs 1–3 are inert and safe to merge and sit on indefinitely. 7 must come last:
it fails the boot on any unannotated route, so merging it early breaks `main`.

Branch, if you want to read the whole thing before deciding: `<FORK-URL>`

### What I'm asking

1. **Do you want RBAC in HyperDX at all**, or is this out of scope / already
   planned internally?
2. **Does the permission model match how you'd want it done** — particularly the
   `isAdmin`-as-flag decision, and the resource vocabulary?
3. **Is fail-open-for-sessions acceptable** as an upgrade strategy?
4. **Does the 7-PR split match how you'd want to review it**, or would you
   rather have fewer, larger PRs — or different boundaries entirely?

Happy to jump on Discord if that's easier than issue back-and-forth. And
genuinely, if the answer to (1) is no, please just say so — I'd rather know now
than after seven PRs.
