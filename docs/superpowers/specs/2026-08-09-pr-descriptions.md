# PR descriptions for the RBAC stack

Drafted against `.github/PULL_REQUEST_TEMPLATE.md`. One section per PR; fill in
the rest as each is opened.

**Before opening any of these:** rewrite the 53 in-code references to internal
artifacts (`BUG-N`, `slice A/B/C/D`, `design spec §N`). They resolve against
planning docs that stay in the fork, so upstream reviewers cannot follow them.

---

## PR 1 — `rbac-1-permission-types` → `main`

**Title:**
`feat(common-utils): add RBAC permission vocabulary and system role matrices`

---

### Summary

HyperDX has no authorization model today — `User` is
`{name, email, team, accessKey}`, and the only primitive is "are you a member of
this team", hand-written per route. This PR adds the shared vocabulary an
authorization model needs, and nothing else: the permission types, the level
ordering, the Zod schemas, and the three built-in role definitions.

**This PR changes no behaviour.** It adds exported types and constants to
`@hyperdx/common-utils`. Nothing imports them yet — enforcement arrives later in
the stack. It is safe to merge and leave sitting indefinitely.

#### What's in it

**The permission vocabulary.** Two ranges, deliberately not one:

- `dashboards`, `savedSearches`, `sources`, `alerts`, `webhooks`, `connections`
  take the full `none | read | manage`.
- `users` is `none | read` and `team` is `read | manage`. Those missing cells do
  not exist in the vocabulary, so no role can express them — enforced by the Zod
  enums rather than by a runtime check.

`RANK` orders the levels and `hasPermission(held, required)` is the single
comparison every future call site uses, so the `manage ⊃ read ⊃ none` rule is
defined once.

**The three built-in roles** (`SYSTEM_ROLE_PERMISSIONS`):

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

`connections` defaults to `none` below Admin because a `Connection` holds
ClickHouse credentials — the most sensitive object in the system.

**Response-shape additions**, so later PRs can populate them without a second
schema change: `TeamMember` gains `roleId`/`roleName`, and `MeApiResponse` gains
a nullable `role`. Both are optional and nullable, so existing clients are
unaffected.

#### One change that is not a permission type

`BaseSourceSchema` gains `connectionName`, a display-only field derived
server-side by `GET /sources`. It is here because it exists _for_ the permission
model: the sources list needs to render a connection's name, but Member and
ReadOnly hold `connections: none`, so they cannot fetch connections to resolve
the id. Without it, restricting `connections` makes the sources list unusable.

It is never persisted from a write — `SourceSchemaNoId` omits it, so
`POST /sources` rejects it outright, and while `PUT /sources/:id` validates
against the full schema and so accepts the key, it is absent from the Mongoose
schema and dropped before the database.

I can split this into its own PR if you would rather keep this one purely to the
permission vocabulary.

#### Design decision worth flagging

Admin is **not** modelled as "a role with everything set to `manage`". It is a
separate flag (added in the next PR) that short-circuits every check, and it is
deliberately absent from this permission map. That makes privilege escalation
impossible by construction rather than by guard — the only capability that
matters is not in the vocabulary, so there is no subset-check to get wrong.

The two `.strict()` calls enforce the boundary: a client sending
`permissions: { isAdmin: true }` gets a 400 rather than having it silently
ignored. It is inert either way, but an ignored key that _looks_ like a
capability is a misread waiting to happen.

#### Where this sits

1 of 7. The full stack is: permission types (this) → `Role` model + migration →
enforcement middleware → route annotations + role CRUD → Team Settings UI → MCP
and External API v2 → startup coverage assertion. PRs 1–3 are inert; enforcement
begins at 4.

Happy to reshape the boundaries — this split is derived from the code's own
dependency constraints, not a preference. See the proposal issue for the full
design and the rationale for asking before opening the rest.

### Screenshots or video

N/A — no UI changes.

### How to test on Vercel preview

N/A — non-UI change. `@hyperdx/common-utils` types only.

**Preview routes:** N/A

**Steps:** N/A

### References

- Proposal issue: `<link to the RBAC design issue>`
- Related PRs: none yet — this is the base of the stack.

---

### Test evidence

Run on this branch, with `common-utils` rebuilt from a clean `dist`
(`rm -rf packages/common-utils/dist && NX_SKIP_NX_CACHE=true yarn build:common-utils`):

| Check                         | Result      |
| ----------------------------- | ----------- |
| `packages/common-utils` unit  | 1568 passed |
| `packages/api` unit           | 601 passed  |
| `packages/app` unit           | 2456 passed |
| `packages/api` `tsc --noEmit` | clean       |
| `packages/app` `tsc --noEmit` | clean       |

New tests: `rbac.test.ts` covers `hasPermission` across the rank order and the
system role matrices; `roleSchemas.test.ts` covers the strict-mode rejections
and the restricted `users`/`team` ranges.

Not run: integration and E2E. Neither exercises this PR — it adds no runtime
behaviour — but both should run before the enforcement PRs.
