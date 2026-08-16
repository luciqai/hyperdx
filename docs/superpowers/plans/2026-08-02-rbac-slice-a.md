# RBAC Slice A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add role-based access control to HyperDX — a `Role` collection with a stored permission map, three seeded system roles, admin-authored custom roles, and declarative enforcement across all 65 internal API routes.

**Architecture:** Permissions are data (`Role.permissions`), not code. `isAdmin` is a flag *outside* the permission vocabulary that short-circuits every check, which makes privilege escalation impossible by construction. Enforcement is declarative Express middleware that tags each handler with a symbol; a boot-time walker then asserts every authenticated route carries a tag, so a forgotten annotation fails the deploy rather than leaking in production.

**Tech Stack:** TypeScript, Express, Mongoose, Zod, `migrate-mongo`, Jest (unit + `*.int.test.ts`), Next.js, Mantine, TanStack Query, Playwright.

**Spec:** [`docs/superpowers/specs/2026-08-02-rbac-design.md`](../specs/2026-08-02-rbac-design.md)
**Mockups:** [`docs/superpowers/specs/2026-08-02-rbac-mockups.html`](../specs/2026-08-02-rbac-mockups.html)

## Global Constraints

- **Branch:** work continues on `claude/rbac-design-spec` (or a new `claude/rbac-slice-a`). Never commit to `main`.
- **Commits:** use the git author's default profile. **Do not** add `Co-Authored-By` trailers.
- **Pre-commit hooks must pass.** Never use `--no-verify`. If husky is missing in a worktree, run `npx lint-staged` manually.
- **Resource vocabulary** (exact strings): `dashboards`, `savedSearches`, `sources`, `alerts`, `webhooks`, `connections`, `users`, `team`.
- **Level vocabulary** (exact strings): `none`, `read`, `manage`. Rank: `none=0`, `read=1`, `manage=2`.
- **`users` never takes `manage`. `team` never takes `none`.** Enforced by Zod.
- **Hard capabilities** (`isAdmin` only, never a permission): role CRUD, ingestion API-key rotation, invite/remove members.
- **`isAdmin` and `isSystem` are stripped from every API request body.**
- **UI variants:** only `primary` / `secondary` / `danger` / `subtle` / `link` on `Button` and `ActionIcon`. `variant="light|filled|outline|default"` is an ESLint error.
- **No `Date.now()` / `new Date()`** in `packages/app/src` outside tests — use `NOW` from `@/config`. ESLint error.
- **Icons:** `@tabler/icons-react` only. Literal `bi-` strings are an ESLint error.
- **Imports in `packages/app/src`:** use the `@/` alias, never `../`.
- **`packages/common-utils` must be rebuilt** (`yarn build:common-utils`) after Task 1 before `api`/`app` can resolve the new types.
- **Changeset required** at the end: `@hyperdx/api` + `@hyperdx/app` are a fixed version group. **Minor** bump.

---

## File Structure

**`packages/common-utils/src/`**
| File | Responsibility |
|---|---|
| `types.ts` (modify) | `PermissionLevel`, `Resource`, `RolePermissions`, `Role` Zod schemas; `SYSTEM_ROLE_PERMISSIONS`; extend `MeApiResponseSchema` and `TeamMembersApiResponseSchema` |

**`packages/api/src/`**
| File | Responsibility |
|---|---|
| `models/role.ts` (create) | `Role` Mongoose model |
| `models/user.ts` (modify) | `role` field |
| `controllers/role.ts` (create) | Seeding, CRUD, member counts, last-admin guard |
| `controllers/user.ts` (modify) | Populate `role` on `findUserById` |
| `middleware/rbac.ts` (create) | `requirePermission` / `requireAdmin` / `noPermissionRequired`, rank, resolution |
| `middleware/rbacCoverage.ts` (create) | Boot-time route-coverage assertion |
| `routers/api/roles.ts` (create) | `/team/roles` CRUD |
| `routers/api/*.ts` (modify ×14) | Route annotations |
| `api-app.ts` (modify) | Invoke coverage assertion |
| `setupDefaults.ts`, `routers/api/root.ts` (modify) | Seed roles on team creation |
| `migrations/mongo/<ts>-add_rbac_roles.ts` (create) | Backfill |

**`packages/app/src/`**
| File | Responsibility |
|---|---|
| `hooks/useMyPermissions.ts` (create) | `isAdmin`, `can(resource, level)` |
| `api.ts` (modify) | Role query/mutation hooks |
| `components/TeamSettings/PermissionMatrix.tsx` (create) | Pure matrix control |
| `components/TeamSettings/RoleEditorModal.tsx` (create) | Create/edit/view role |
| `components/TeamSettings/RbacRolesSection.tsx` (create) | Role list |
| `components/TeamSettings/TeamMembersSection.tsx` (modify) | Role column |
| `TeamPage.tsx` (modify) | Unconditional Access tab; real `hasAdminAccess` |

---

## Task 1: Shared permission types

**Files:**
- Modify: `packages/common-utils/src/types.ts`
- Test: `packages/common-utils/src/__tests__/rbac.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces: `PermissionLevel`, `RESOURCES`, `Resource`, `RolePermissionsSchema`, `RolePermissions`, `RoleSchema`, `Role`, `SYSTEM_ROLE_PERMISSIONS`, `RANK`, `hasPermission(held, required)`.

- [ ] **Step 1: Write the failing test**

Create `packages/common-utils/src/__tests__/rbac.test.ts`:

```ts
import {
  hasPermission,
  RolePermissionsSchema,
  SYSTEM_ROLE_PERMISSIONS,
} from '../types';

describe('hasPermission', () => {
  it('grants when held level outranks required', () => {
    expect(hasPermission('manage', 'read')).toBe(true);
    expect(hasPermission('read', 'read')).toBe(true);
    expect(hasPermission('manage', 'manage')).toBe(true);
  });

  it('denies when held level is lower', () => {
    expect(hasPermission('read', 'manage')).toBe(false);
    expect(hasPermission('none', 'read')).toBe(false);
    expect(hasPermission('none', 'manage')).toBe(false);
  });

  it('denies when held level is undefined', () => {
    expect(hasPermission(undefined, 'read')).toBe(false);
  });
});

describe('RolePermissionsSchema', () => {
  it('rejects manage on users', () => {
    const result = RolePermissionsSchema.safeParse({
      ...SYSTEM_ROLE_PERMISSIONS.Member,
      users: 'manage',
    });
    expect(result.success).toBe(false);
  });

  it('rejects none on team', () => {
    const result = RolePermissionsSchema.safeParse({
      ...SYSTEM_ROLE_PERMISSIONS.Member,
      team: 'none',
    });
    expect(result.success).toBe(false);
  });

  it('accepts a valid matrix', () => {
    expect(
      RolePermissionsSchema.safeParse(SYSTEM_ROLE_PERMISSIONS.ReadOnly).success,
    ).toBe(true);
  });
});

describe('SYSTEM_ROLE_PERMISSIONS', () => {
  it('gives Member and ReadOnly no connection access', () => {
    expect(SYSTEM_ROLE_PERMISSIONS.Member.connections).toBe('none');
    expect(SYSTEM_ROLE_PERMISSIONS.ReadOnly.connections).toBe('none');
  });

  it('gives ReadOnly read on dashboards but none on webhooks', () => {
    expect(SYSTEM_ROLE_PERMISSIONS.ReadOnly.dashboards).toBe('read');
    expect(SYSTEM_ROLE_PERMISSIONS.ReadOnly.webhooks).toBe('none');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd packages/common-utils && yarn ci:unit src/__tests__/rbac.test.ts
```
Expected: FAIL — `hasPermission is not a function` / export not found.

- [ ] **Step 3: Add the schemas to `types.ts`**

Append to `packages/common-utils/src/types.ts`:

```ts
// ---------------------------------------------------------------------------
// RBAC
// ---------------------------------------------------------------------------

export const PermissionLevelSchema = z.enum(['none', 'read', 'manage']);
export type PermissionLevel = z.infer<typeof PermissionLevelSchema>;

/** Resources taking the full none|read|manage range. */
export const RESOURCES = [
  'dashboards',
  'savedSearches',
  'sources',
  'alerts',
  'webhooks',
  'connections',
] as const;

/** Every key addressable by requirePermission, including admin scopes. */
export const PERMISSION_KEYS = [...RESOURCES, 'users', 'team'] as const;
export type Resource = (typeof PERMISSION_KEYS)[number];

export const RANK: Record<PermissionLevel, number> = {
  none: 0,
  read: 1,
  manage: 2,
};

export function hasPermission(
  held: PermissionLevel | undefined,
  required: PermissionLevel,
): boolean {
  if (held == null) return false;
  return RANK[held] >= RANK[required];
}

// `users` has no manage level and `team` has no none level: those cells do not
// exist in the vocabulary, so no role can ever hold them.
export const RolePermissionsSchema = z.object({
  dashboards: PermissionLevelSchema,
  savedSearches: PermissionLevelSchema,
  sources: PermissionLevelSchema,
  alerts: PermissionLevelSchema,
  webhooks: PermissionLevelSchema,
  connections: PermissionLevelSchema,
  users: z.enum(['none', 'read']),
  team: z.enum(['read', 'manage']),
});
export type RolePermissions = z.infer<typeof RolePermissionsSchema>;

export const RoleSchema = z.object({
  id: z.string(),
  name: z.string().min(1).max(64),
  description: z.string().max(256).optional(),
  isSystem: z.boolean(),
  isAdmin: z.boolean(),
  permissions: RolePermissionsSchema,
  memberCount: z.number().optional(),
});
export type Role = z.infer<typeof RoleSchema>;

/** Client-supplied role payload. isSystem/isAdmin are absent by construction. */
export const RoleInputSchema = z.object({
  name: z.string().min(1).max(64),
  description: z.string().max(256).optional(),
  permissions: RolePermissionsSchema,
});
export type RoleInput = z.infer<typeof RoleInputSchema>;

export const SYSTEM_ROLE_NAMES = ['Admin', 'Member', 'ReadOnly'] as const;
export type SystemRoleName = (typeof SYSTEM_ROLE_NAMES)[number];

export const SYSTEM_ROLE_PERMISSIONS: Record<SystemRoleName, RolePermissions> = {
  Admin: {
    dashboards: 'manage',
    savedSearches: 'manage',
    sources: 'manage',
    alerts: 'manage',
    webhooks: 'manage',
    connections: 'manage',
    users: 'read',
    team: 'manage',
  },
  Member: {
    dashboards: 'manage',
    savedSearches: 'manage',
    sources: 'read',
    alerts: 'manage',
    webhooks: 'read',
    connections: 'none',
    users: 'read',
    team: 'read',
  },
  ReadOnly: {
    dashboards: 'read',
    savedSearches: 'read',
    sources: 'read',
    alerts: 'read',
    webhooks: 'none',
    connections: 'none',
    users: 'none',
    team: 'read',
  },
};

export const SYSTEM_ROLE_DESCRIPTIONS: Record<SystemRoleName, string> = {
  Admin: 'Full access, including roles and API key rotation',
  Member: 'Build dashboards and alerts; read-only on sources',
  ReadOnly: 'View dashboards, searches and alerts',
};

export const RolesApiResponseSchema = z.object({
  data: z.array(RoleSchema),
});
export type RolesApiResponse = z.infer<typeof RolesApiResponseSchema>;
```

- [ ] **Step 4: Add `role` to the `/me` and members responses**

In `packages/common-utils/src/types.ts`, change `MeApiResponseSchema` (~line 2281) to add a `role` field after `name`:

```ts
  name: z.string(),
  role: RoleSchema.nullable(),
```

And in `TeamMembersApiResponseSchema` (~line 2224), add to each member object:

```ts
  roleId: z.string().nullable(),
  roleName: z.string().nullable(),
```

> `RoleSchema` must be declared *before* these schemas reference it. If the RBAC block was appended at the end of the file, move it above `TeamMembersApiResponseSchema` instead.

- [ ] **Step 5: Run test to verify it passes**

```bash
cd packages/common-utils && yarn ci:unit src/__tests__/rbac.test.ts
```
Expected: PASS, 8 tests.

- [ ] **Step 6: Rebuild common-utils so api/app resolve the new exports**

```bash
cd /Users/dohaelsawy/hyperdx && yarn build:common-utils
```
Expected: build succeeds, `packages/common-utils/dist/types.d.ts` contains `RolePermissionsSchema`.

- [ ] **Step 7: Commit**

```bash
git add packages/common-utils/src/types.ts packages/common-utils/src/__tests__/rbac.test.ts
git commit -m "feat(common-utils): add RBAC permission types and system role matrices"
```

---

## Task 2: Role model and User.role field

**Files:**
- Create: `packages/api/src/models/role.ts`
- Modify: `packages/api/src/models/user.ts`
- Test: `packages/api/src/models/__tests__/role.int.test.ts`

**Interfaces:**
- Consumes: `RolePermissions`, `SYSTEM_ROLE_PERMISSIONS` from `@hyperdx/common-utils/dist/types`.
- Produces: default export `Role` (Mongoose model), `IRole`, `RoleDocument`. `IUser` gains `role?: ObjectId`.

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/models/__tests__/role.int.test.ts`:

```ts
import { SYSTEM_ROLE_PERMISSIONS } from '@hyperdx/common-utils/dist/types';
import { Types } from 'mongoose';

import { getServer } from '@/fixtures';
import Role from '@/models/role';

describe('Role model', () => {
  const server = getServer();

  beforeAll(async () => {
    await server.start();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('defaults isSystem and isAdmin to false', async () => {
    const role = await Role.create({
      team: new Types.ObjectId(),
      name: 'On-call engineer',
      permissions: SYSTEM_ROLE_PERMISSIONS.Member,
    });

    expect(role.isSystem).toBe(false);
    expect(role.isAdmin).toBe(false);
  });

  it('enforces unique name per team', async () => {
    const team = new Types.ObjectId();
    await Role.create({
      team,
      name: 'Duplicate',
      permissions: SYSTEM_ROLE_PERMISSIONS.Member,
    });

    await expect(
      Role.create({
        team,
        name: 'Duplicate',
        permissions: SYSTEM_ROLE_PERMISSIONS.Member,
      }),
    ).rejects.toThrow();
  });

  it('allows the same name in a different team', async () => {
    await Role.create({
      team: new Types.ObjectId(),
      name: 'Shared',
      permissions: SYSTEM_ROLE_PERMISSIONS.Member,
    });

    await expect(
      Role.create({
        team: new Types.ObjectId(),
        name: 'Shared',
        permissions: SYSTEM_ROLE_PERMISSIONS.Member,
      }),
    ).resolves.toBeDefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/dohaelsawy/hyperdx && make dev-int FILE=role.int
```
Expected: FAIL — `Cannot find module '@/models/role'`.

- [ ] **Step 3: Create the model**

Create `packages/api/src/models/role.ts`:

```ts
import type { RolePermissions } from '@hyperdx/common-utils/dist/types';
import mongoose, { Schema } from 'mongoose';

import type { ObjectId } from '.';

export interface IRole {
  _id: ObjectId;
  team: ObjectId;
  name: string;
  description?: string;
  isSystem: boolean;
  isAdmin: boolean;
  permissions: RolePermissions;
  createdAt: Date;
  updatedAt: Date;
}

export type RoleDocument = mongoose.HydratedDocument<IRole>;

const RoleSchema = new Schema<IRole>(
  {
    team: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'Team',
      index: true,
    },
    name: { type: String, required: true },
    description: String,
    // Seeded roles. Blocks PATCH and DELETE.
    isSystem: { type: Boolean, default: false },
    // Hard capability: short-circuits every permission check. Only ever true
    // on the seeded Admin role; stripped from all API input so no custom role
    // can acquire it.
    isAdmin: { type: Boolean, default: false },
    permissions: { type: Schema.Types.Mixed, required: true },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  },
);

RoleSchema.index({ team: 1, name: 1 }, { unique: true });

export default mongoose.model<IRole>('Role', RoleSchema);
```

- [ ] **Step 4: Add the `role` field to `User`**

In `packages/api/src/models/user.ts`, add to `IUser`:

```ts
  role?: ObjectId;
```

and to the schema object, after `team`:

```ts
    role: { type: mongoose.Schema.Types.ObjectId, ref: 'Role' },
```

- [ ] **Step 5: Run test to verify it passes**

```bash
cd /Users/dohaelsawy/hyperdx && make dev-int FILE=role.int
```
Expected: PASS, 3 tests.

- [ ] **Step 6: Commit**

```bash
git add packages/api/src/models/role.ts packages/api/src/models/user.ts \
        packages/api/src/models/__tests__/role.int.test.ts
git commit -m "feat(api): add Role model and User.role reference"
```

---

## Task 3: Role controller — seeding, CRUD, invariants

**Files:**
- Create: `packages/api/src/controllers/role.ts`
- Test: `packages/api/src/controllers/__tests__/role.int.test.ts`

**Interfaces:**
- Consumes: `Role` model (Task 2), `RoleInput`/`SYSTEM_ROLE_PERMISSIONS` (Task 1).
- Produces:
  - `seedSystemRoles(teamId: string | ObjectId): Promise<RoleDocument[]>`
  - `getAdminRole(teamId): Promise<RoleDocument | null>`
  - `getRolesWithCounts(teamId): Promise<(IRole & { memberCount: number })[]>`
  - `createRole(teamId, input: RoleInput): Promise<RoleDocument>`
  - `updateRole(teamId, roleId, input: RoleInput): Promise<RoleDocument>`
  - `deleteRole(teamId, roleId): Promise<void>`
  - `assignRole(teamId, userId, roleId): Promise<void>`
  - `RoleConflictError` (has `.statusCode = 409`)

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/controllers/__tests__/role.int.test.ts`:

```ts
import { SYSTEM_ROLE_PERMISSIONS } from '@hyperdx/common-utils/dist/types';
import { Types } from 'mongoose';

import {
  assignRole,
  createRole,
  deleteRole,
  getAdminRole,
  getRolesWithCounts,
  RoleConflictError,
  seedSystemRoles,
  updateRole,
} from '@/controllers/role';
import { getServer } from '@/fixtures';
import Role from '@/models/role';
import User from '@/models/user';

describe('role controller', () => {
  const server = getServer();
  const teamId = new Types.ObjectId();

  beforeAll(async () => {
    await server.start();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('seeds exactly three system roles, one of them admin', async () => {
    await seedSystemRoles(teamId);

    const roles = await Role.find({ team: teamId }).sort({ name: 1 });
    expect(roles.map(r => r.name)).toEqual(['Admin', 'Member', 'ReadOnly']);
    expect(roles.filter(r => r.isAdmin)).toHaveLength(1);
    expect(roles.every(r => r.isSystem)).toBe(true);
  });

  it('is idempotent', async () => {
    await seedSystemRoles(teamId);
    await seedSystemRoles(teamId);

    expect(await Role.countDocuments({ team: teamId })).toBe(3);
  });

  it('strips isAdmin and isSystem from created roles', async () => {
    const role = await createRole(teamId, {
      name: 'Sneaky',
      permissions: SYSTEM_ROLE_PERMISSIONS.Member,
      // @ts-expect-error deliberately passing fields the type forbids
      isAdmin: true,
      isSystem: true,
    });

    expect(role.isAdmin).toBe(false);
    expect(role.isSystem).toBe(false);
  });

  it('refuses to update a system role', async () => {
    await seedSystemRoles(teamId);
    const member = await Role.findOne({ team: teamId, name: 'Member' });

    await expect(
      updateRole(teamId, member!._id.toString(), {
        name: 'Renamed',
        permissions: SYSTEM_ROLE_PERMISSIONS.Member,
      }),
    ).rejects.toBeInstanceOf(RoleConflictError);
  });

  it('refuses to delete a role that is assigned', async () => {
    const role = await createRole(teamId, {
      name: 'In use',
      permissions: SYSTEM_ROLE_PERMISSIONS.Member,
    });
    await User.create({
      email: 'a@example.com',
      team: teamId,
      role: role._id,
    });

    await expect(
      deleteRole(teamId, role._id.toString()),
    ).rejects.toBeInstanceOf(RoleConflictError);
  });

  it('refuses to demote the last admin', async () => {
    await seedSystemRoles(teamId);
    const admin = await getAdminRole(teamId);
    const member = await Role.findOne({ team: teamId, name: 'Member' });
    const user = await User.create({
      email: 'solo@example.com',
      team: teamId,
      role: admin!._id,
    });

    await expect(
      assignRole(teamId, user._id.toString(), member!._id.toString()),
    ).rejects.toBeInstanceOf(RoleConflictError);
  });

  it('allows demoting an admin when another remains', async () => {
    await seedSystemRoles(teamId);
    const admin = await getAdminRole(teamId);
    const member = await Role.findOne({ team: teamId, name: 'Member' });
    const first = await User.create({
      email: 'one@example.com',
      team: teamId,
      role: admin!._id,
    });
    await User.create({
      email: 'two@example.com',
      team: teamId,
      role: admin!._id,
    });

    await assignRole(teamId, first._id.toString(), member!._id.toString());

    const reloaded = await User.findById(first._id);
    expect(reloaded!.role!.toString()).toBe(member!._id.toString());
  });

  it('reports member counts per role', async () => {
    await seedSystemRoles(teamId);
    const admin = await getAdminRole(teamId);
    await User.create({ email: 'c@example.com', team: teamId, role: admin!._id });

    const roles = await getRolesWithCounts(teamId);
    const adminRow = roles.find(r => r.name === 'Admin');
    expect(adminRow!.memberCount).toBe(1);
    expect(roles.find(r => r.name === 'Member')!.memberCount).toBe(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/dohaelsawy/hyperdx && make dev-int FILE=role.int
```
Expected: FAIL — `Cannot find module '@/controllers/role'`.

- [ ] **Step 3: Write the controller**

Create `packages/api/src/controllers/role.ts`:

```ts
import {
  type RoleInput,
  SYSTEM_ROLE_DESCRIPTIONS,
  SYSTEM_ROLE_NAMES,
  SYSTEM_ROLE_PERMISSIONS,
} from '@hyperdx/common-utils/dist/types';

import type { ObjectId } from '@/models';
import Role, { type IRole, type RoleDocument } from '@/models/role';
import User from '@/models/user';

/** Thrown when an invariant blocks the write. Surfaces as HTTP 409. */
export class RoleConflictError extends Error {
  statusCode = 409;
  constructor(message: string) {
    super(message);
    this.name = 'RoleConflictError';
  }
}

export async function seedSystemRoles(
  teamId: string | ObjectId,
): Promise<RoleDocument[]> {
  const created: RoleDocument[] = [];

  for (const name of SYSTEM_ROLE_NAMES) {
    const role = await Role.findOneAndUpdate(
      { team: teamId, name },
      {
        $setOnInsert: {
          team: teamId,
          name,
          description: SYSTEM_ROLE_DESCRIPTIONS[name],
          isSystem: true,
          isAdmin: name === 'Admin',
          permissions: SYSTEM_ROLE_PERMISSIONS[name],
        },
      },
      { upsert: true, new: true, setDefaultsOnInsert: true },
    );
    created.push(role);
  }

  return created;
}

export function getAdminRole(teamId: string | ObjectId) {
  return Role.findOne({ team: teamId, isAdmin: true });
}

export async function getRolesWithCounts(
  teamId: string | ObjectId,
): Promise<(IRole & { memberCount: number })[]> {
  const roles = await Role.find({ team: teamId }).sort({
    isSystem: -1,
    name: 1,
  });

  const counts = await User.aggregate<{ _id: ObjectId; count: number }>([
    { $match: { team: typeof teamId === 'string' ? undefined : teamId } },
    { $group: { _id: '$role', count: { $sum: 1 } } },
  ]);

  const byRole = new Map(counts.map(c => [c._id?.toString(), c.count]));

  return roles.map(role => ({
    ...(role.toObject() as IRole),
    memberCount: byRole.get(role._id.toString()) ?? 0,
  }));
}

export async function createRole(
  teamId: string | ObjectId,
  input: RoleInput,
): Promise<RoleDocument> {
  // isSystem/isAdmin are never taken from input — that is the escalation guard.
  return Role.create({
    team: teamId,
    name: input.name,
    description: input.description,
    permissions: input.permissions,
    isSystem: false,
    isAdmin: false,
  });
}

export async function updateRole(
  teamId: string | ObjectId,
  roleId: string,
  input: RoleInput,
): Promise<RoleDocument> {
  const role = await Role.findOne({ _id: roleId, team: teamId });
  if (!role) {
    throw new RoleConflictError('Role not found');
  }
  if (role.isSystem) {
    throw new RoleConflictError('System roles cannot be edited');
  }

  role.name = input.name;
  role.description = input.description;
  role.permissions = input.permissions;
  await role.save();

  return role;
}

export async function deleteRole(
  teamId: string | ObjectId,
  roleId: string,
): Promise<void> {
  const role = await Role.findOne({ _id: roleId, team: teamId });
  if (!role) {
    throw new RoleConflictError('Role not found');
  }
  if (role.isSystem) {
    throw new RoleConflictError('System roles cannot be deleted');
  }

  const inUse = await User.countDocuments({ team: teamId, role: roleId });
  if (inUse > 0) {
    throw new RoleConflictError(
      `${role.name} is assigned to ${inUse} member${inUse === 1 ? '' : 's'}. Move them to another role first.`,
    );
  }

  await Role.deleteOne({ _id: roleId, team: teamId });
}

export async function assignRole(
  teamId: string | ObjectId,
  userId: string,
  roleId: string,
): Promise<void> {
  const [user, nextRole] = await Promise.all([
    User.findOne({ _id: userId, team: teamId }),
    Role.findOne({ _id: roleId, team: teamId }),
  ]);

  if (!user) throw new RoleConflictError('User not found');
  if (!nextRole) throw new RoleConflictError('Role not found');

  // Last-admin protection: if this user currently holds an admin role and the
  // target role does not, refuse unless another admin remains.
  if (!nextRole.isAdmin && user.role != null) {
    const currentRole = await Role.findById(user.role);
    if (currentRole?.isAdmin) {
      const adminRoleIds = await Role.find({ team: teamId, isAdmin: true })
        .select('_id')
        .lean();
      const remaining = await User.countDocuments({
        team: teamId,
        role: { $in: adminRoleIds.map(r => r._id) },
        _id: { $ne: user._id },
      });
      if (remaining === 0) {
        throw new RoleConflictError(
          "The last admin can't be changed. Promote someone else first.",
        );
      }
    }
  }

  user.role = nextRole._id;
  await user.save();
}

/** True when removing this user would leave the team with no admin. */
export async function isLastAdmin(
  teamId: string | ObjectId,
  userId: string | ObjectId,
): Promise<boolean> {
  const adminRoleIds = await Role.find({ team: teamId, isAdmin: true })
    .select('_id')
    .lean();
  if (adminRoleIds.length === 0) return false;

  const ids = adminRoleIds.map(r => r._id);
  const user = await User.findOne({ _id: userId, team: teamId });
  if (!user?.role || !ids.some(id => id.equals(user.role!))) return false;

  const remaining = await User.countDocuments({
    team: teamId,
    role: { $in: ids },
    _id: { $ne: userId },
  });
  return remaining === 0;
}
```

- [ ] **Step 4: Fix the aggregate `$match` for string teamIds**

The `$match` above breaks when `teamId` arrives as a string. Replace the `counts` block in `getRolesWithCounts` with:

```ts
  const teamObjectId =
    typeof teamId === 'string' ? new mongoose.Types.ObjectId(teamId) : teamId;

  const counts = await User.aggregate<{ _id: ObjectId; count: number }>([
    { $match: { team: teamObjectId } },
    { $group: { _id: '$role', count: { $sum: 1 } } },
  ]);
```

and add `import mongoose from 'mongoose';` at the top of the file.

- [ ] **Step 5: Run test to verify it passes**

```bash
cd /Users/dohaelsawy/hyperdx && make dev-int FILE=role.int
```
Expected: PASS, 11 tests (3 model + 8 controller).

- [ ] **Step 6: Commit**

```bash
git add packages/api/src/controllers/role.ts \
        packages/api/src/controllers/__tests__/role.int.test.ts
git commit -m "feat(api): add role controller with seeding, CRUD and last-admin guard"
```

---

## Task 4: Populate role on the session user

**Files:**
- Modify: `packages/api/src/controllers/user.ts:11-13`
- Modify: `packages/api/src/routers/api/me.ts`
- Test: `packages/api/src/controllers/__tests__/user.int.test.ts`

**Interfaces:**
- Consumes: `Role` model, `findUserById`.
- Produces: `req.user.role` is a populated `RoleDocument` (not an ObjectId) on every session-authenticated request. `GET /me` returns `role`.

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/controllers/__tests__/user.int.test.ts`:

```ts
import { Types } from 'mongoose';

import { seedSystemRoles } from '@/controllers/role';
import { findUserById } from '@/controllers/user';
import { getServer } from '@/fixtures';
import Role from '@/models/role';
import User from '@/models/user';

describe('findUserById', () => {
  const server = getServer();

  beforeAll(async () => {
    await server.start();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('populates the role document', async () => {
    const teamId = new Types.ObjectId();
    await seedSystemRoles(teamId);
    const admin = await Role.findOne({ team: teamId, isAdmin: true });
    const user = await User.create({
      email: 'p@example.com',
      team: teamId,
      role: admin!._id,
    });

    const found = await findUserById(user._id.toString());

    expect((found!.role as any).name).toBe('Admin');
    expect((found!.role as any).isAdmin).toBe(true);
  });

  it('returns a user with no role without throwing', async () => {
    const user = await User.create({
      email: 'norole@example.com',
      team: new Types.ObjectId(),
    });

    const found = await findUserById(user._id.toString());
    expect(found!.role).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/dohaelsawy/hyperdx && make dev-int FILE=user.int
```
Expected: FAIL — `expect(undefined).toBe('Admin')`.

- [ ] **Step 3: Populate in the controller**

In `packages/api/src/controllers/user.ts`, replace `findUserById`:

```ts
// Populated on every session request via passport's deserializeUser, so RBAC
// middleware can read req.user.role without an extra round trip.
export function findUserById(id: string) {
  return User.findById(id).populate('role');
}
```

- [ ] **Step 4: Return the role from `GET /me`**

In `packages/api/src/routers/api/me.ts`, add `role` to the response object. The
handler already destructures the user; add:

```ts
      role: (req.user as any)?.role
        ? {
            id: (req.user as any).role._id.toString(),
            name: (req.user as any).role.name,
            description: (req.user as any).role.description,
            isSystem: (req.user as any).role.isSystem,
            isAdmin: (req.user as any).role.isAdmin,
            permissions: (req.user as any).role.permissions,
          }
        : null,
```

- [ ] **Step 5: Run test to verify it passes**

```bash
cd /Users/dohaelsawy/hyperdx && make dev-int FILE=user.int
```
Expected: PASS, 2 tests.

- [ ] **Step 6: Commit**

```bash
git add packages/api/src/controllers/user.ts packages/api/src/routers/api/me.ts \
        packages/api/src/controllers/__tests__/user.int.test.ts
git commit -m "feat(api): populate role on session user and expose it on /me"
```

---

## Task 5: RBAC middleware

**Files:**
- Create: `packages/api/src/middleware/rbac.ts`
- Test: `packages/api/src/middleware/__tests__/rbac.test.ts`

**Interfaces:**
- Consumes: `hasPermission`, `Resource`, `PermissionLevel` (Task 1).
- Produces:
  - `requirePermission(resource: Resource, level: PermissionLevel): RequestHandler`
  - `requireAdmin(): RequestHandler`
  - `noPermissionRequired(reason: RbacExemptReason): RequestHandler`
  - `RBAC_DECLARATION: unique symbol` — attached to every handler above
  - `getRbacDeclaration(handler): RbacDeclaration | undefined`
  - `type RbacExemptReason = 'public' | 'personal-state' | 'query-path-slice-B'`

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/middleware/__tests__/rbac.test.ts`:

```ts
import type { NextFunction, Request, Response } from 'express';

import {
  getRbacDeclaration,
  noPermissionRequired,
  requireAdmin,
  requirePermission,
} from '@/middleware/rbac';

jest.mock('@/config', () => ({ IS_LOCAL_APP_MODE: false }));

function mockRes() {
  const res = {} as Response;
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
}

function reqWith(role: any): Request {
  return { user: { _id: 'u1', team: 't1', role } } as unknown as Request;
}

describe('requirePermission', () => {
  it('allows when the held level outranks the requirement', () => {
    const next = jest.fn() as NextFunction;
    const res = mockRes();

    requirePermission('dashboards', 'read')(
      reqWith({ isAdmin: false, permissions: { dashboards: 'manage' } }),
      res,
      next,
    );

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('denies with 403 and names the requirement', () => {
    const next = jest.fn() as NextFunction;
    const res = mockRes();

    requirePermission('connections', 'manage')(
      reqWith({ isAdmin: false, permissions: { connections: 'none' } }),
      res,
      next,
    );

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        required: { resource: 'connections', level: 'manage' },
      }),
    );
  });

  it('short-circuits for isAdmin regardless of the permission map', () => {
    const next = jest.fn() as NextFunction;
    const res = mockRes();

    requirePermission('connections', 'manage')(
      reqWith({ isAdmin: true, permissions: { connections: 'none' } }),
      res,
      next,
    );

    expect(next).toHaveBeenCalled();
  });

  it('fails open as admin when the role is missing', () => {
    const next = jest.fn() as NextFunction;
    const res = mockRes();

    requirePermission('connections', 'manage')(reqWith(undefined), res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });
});

describe('requireAdmin', () => {
  it('denies a non-admin even with every permission at manage', () => {
    const next = jest.fn() as NextFunction;
    const res = mockRes();

    requireAdmin()(
      reqWith({ isAdmin: false, permissions: { team: 'manage' } }),
      res,
      next,
    );

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('allows an admin', () => {
    const next = jest.fn() as NextFunction;
    const res = mockRes();

    requireAdmin()(reqWith({ isAdmin: true, permissions: {} }), res, next);

    expect(next).toHaveBeenCalled();
  });
});

describe('declarations', () => {
  it('tags each handler so the coverage walker can find it', () => {
    expect(getRbacDeclaration(requirePermission('alerts', 'read'))).toEqual({
      kind: 'permission',
      resource: 'alerts',
      level: 'read',
    });
    expect(getRbacDeclaration(requireAdmin())).toEqual({ kind: 'admin' });
    expect(getRbacDeclaration(noPermissionRequired('public'))).toEqual({
      kind: 'exempt',
      reason: 'public',
    });
    expect(getRbacDeclaration(() => {})).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd packages/api && yarn ci:unit src/middleware/__tests__/rbac.test.ts
```
Expected: FAIL — `Cannot find module '@/middleware/rbac'`.

- [ ] **Step 3: Write the middleware**

Create `packages/api/src/middleware/rbac.ts`:

```ts
import {
  hasPermission,
  type PermissionLevel,
  type Resource,
} from '@hyperdx/common-utils/dist/types';
import type { NextFunction, Request, RequestHandler, Response } from 'express';

import * as config from '@/config';
import { getCounter } from '@/utils/instrumentation';
import logger from '@/utils/logger';

export type RbacExemptReason =
  | 'public'
  | 'personal-state'
  | 'query-path-slice-B';

export type RbacDeclaration =
  | { kind: 'permission'; resource: Resource; level: PermissionLevel }
  | { kind: 'admin' }
  | { kind: 'exempt'; reason: RbacExemptReason };

export const RBAC_DECLARATION = Symbol('rbacDeclaration');

const missingRoleCounter = getCounter('hyperdx.rbac.missing_role', {
  description:
    'Requests served with no role assigned, resolved as admin (fail-open). Non-zero means the RBAC migration has not run.',
});

const deniedCounter = getCounter('hyperdx.rbac.denied', {
  description:
    'Requests rejected by RBAC, labeled by resource and required level.',
});

function tag<T extends RequestHandler>(
  handler: T,
  declaration: RbacDeclaration,
): T {
  Object.defineProperty(handler, RBAC_DECLARATION, {
    value: declaration,
    enumerable: false,
  });
  return handler;
}

export function getRbacDeclaration(
  handler: unknown,
): RbacDeclaration | undefined {
  if (typeof handler !== 'function') return undefined;
  return (handler as any)[RBAC_DECLARATION];
}

/**
 * Resolution order, cheapest first. Returns true when the request should pass
 * without consulting the permission map.
 */
function shortCircuits(req: Request): boolean {
  if (config.IS_LOCAL_APP_MODE) return true;

  const role = (req.user as any)?.role;

  if (role == null) {
    // Deliberate fail-open. A self-hosted operator upgrading mid-incident
    // should not be locked out of their own observability tool because a
    // migration step was missed. Loud, never silent.
    missingRoleCounter.add(1);
    logger.warn(
      { userId: (req.user as any)?._id?.toString() },
      'RBAC: user has no role assigned; allowing as admin. Run the RBAC migration.',
    );
    return true;
  }

  return role.isAdmin === true;
}

function deny(
  res: Response,
  required?: { resource: Resource; level: PermissionLevel },
) {
  if (required) {
    deniedCounter.add(1, {
      resource: required.resource,
      level: required.level,
    });
  } else {
    deniedCounter.add(1, { resource: 'admin', level: 'admin' });
  }

  return res.status(403).json({
    message: 'You do not have permission to perform this action.',
    ...(required ? { required } : { required: { resource: 'admin' } }),
  });
}

export function requirePermission(
  resource: Resource,
  level: PermissionLevel,
): RequestHandler {
  const handler = (req: Request, res: Response, next: NextFunction) => {
    if (shortCircuits(req)) return next();

    const held = (req.user as any).role?.permissions?.[resource];
    if (hasPermission(held, level)) return next();

    return deny(res, { resource, level });
  };

  return tag(handler, { kind: 'permission', resource, level });
}

/**
 * Hard capability. Deliberately not expressible as a permission, so no custom
 * role can grant it and no escalation check is needed.
 */
export function requireAdmin(): RequestHandler {
  const handler = (req: Request, res: Response, next: NextFunction) => {
    if (shortCircuits(req)) return next();
    return deny(res);
  };

  return tag(handler, { kind: 'admin' });
}

/** Explicit opt-out. The reason string appears in the boot coverage report. */
export function noPermissionRequired(
  reason: RbacExemptReason,
): RequestHandler {
  const handler = (_req: Request, _res: Response, next: NextFunction) =>
    next();
  return tag(handler, { kind: 'exempt', reason });
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd packages/api && yarn ci:unit src/middleware/__tests__/rbac.test.ts
```
Expected: PASS, 8 tests.

- [ ] **Step 5: Commit**

```bash
git add packages/api/src/middleware/rbac.ts \
        packages/api/src/middleware/__tests__/rbac.test.ts
git commit -m "feat(api): add RBAC enforcement middleware"
```

---

## Task 6: Annotate resource and personal routers

**Files:**
- Modify: `packages/api/src/routers/api/{alerts,dashboards,savedSearch,sources,connections,webhooks,pinnedFilters,favorites,me,ai}.ts`
- Test: `packages/api/src/routers/api/__tests__/rbacEnforcement.int.test.ts`

**Interfaces:**
- Consumes: `requirePermission`, `noPermissionRequired` (Task 5).
- Produces: 38 annotated routes. No signature changes.

Add the middleware as the **first** argument after the path, before `validateRequest`.

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/routers/api/__tests__/rbacEnforcement.int.test.ts`:

```ts
import { SYSTEM_ROLE_PERMISSIONS } from '@hyperdx/common-utils/dist/types';

import { getLoggedInAgent, getServer } from '@/fixtures';
import Role from '@/models/role';
import User from '@/models/user';

/** Re-point the logged-in user at a freshly created role. */
async function withRole(
  teamId: string,
  userId: string,
  permissions = SYSTEM_ROLE_PERMISSIONS.ReadOnly,
) {
  const role = await Role.create({
    team: teamId,
    name: `test-${Math.random().toString(36).slice(2)}`,
    permissions,
    isSystem: false,
    isAdmin: false,
  });
  await User.findByIdAndUpdate(userId, { role: role._id });
  return role;
}

describe('RBAC route enforcement', () => {
  const server = getServer();

  beforeAll(async () => {
    await server.start();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('allows a read-level role to list dashboards', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await withRole(team._id.toString(), user._id.toString());

    await agent.get('/dashboards').expect(200);
  });

  it('denies a read-level role creating a dashboard', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await withRole(team._id.toString(), user._id.toString());

    const res = await agent.post('/dashboards').send({ name: 'x', tiles: [] });

    expect(res.status).toBe(403);
    expect(res.body.required).toEqual({
      resource: 'dashboards',
      level: 'manage',
    });
  });

  it('denies connections entirely at none', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await withRole(team._id.toString(), user._id.toString());

    await agent.get('/connections').expect(403);
  });

  it('treats pinned filters as shared team config, not personal state', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await withRole(team._id.toString(), user._id.toString());

    // ReadOnly holds sources:read, so GET passes and PUT does not.
    await agent.get('/pinned-filters').expect(200);
    await agent.put('/pinned-filters').send({}).expect(403);
  });

  it('leaves personal state ungated', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await withRole(team._id.toString(), user._id.toString());

    await agent.get('/me').expect(200);
    await agent.get('/favorites').expect(200);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/dohaelsawy/hyperdx && make dev-int FILE=rbacEnforcement.int
```
Expected: FAIL — POST `/dashboards` returns 200, not 403.

- [ ] **Step 3: Annotate the routers**

Add to each file's imports:

```ts
import { noPermissionRequired, requirePermission } from '@/middleware/rbac';
```

Then insert the middleware as the first handler argument:

**`alerts.ts`** (8)
```
GET  '/'              requirePermission('alerts', 'read')
GET  '/:id'           requirePermission('alerts', 'read')
GET  '/:id/history'   requirePermission('alerts', 'read')
POST '/'              requirePermission('alerts', 'manage')
PUT  '/:id'           requirePermission('alerts', 'manage')
POST '/:id/silenced'  requirePermission('alerts', 'manage')
DELETE '/:id/silenced' requirePermission('alerts', 'manage')
DELETE '/:id'         requirePermission('alerts', 'manage')
```

**`dashboards.ts`** (8)
```
GET    '/'                                     requirePermission('dashboards', 'read')
POST   '/'                                     requirePermission('dashboards', 'manage')
PATCH  '/:id'                                  requirePermission('dashboards', 'manage')
DELETE '/:id'                                  requirePermission('dashboards', 'manage')
GET    '/preset/:presetDashboard/filters'      requirePermission('dashboards', 'read')
PUT    '/preset/:presetDashboard/filter'       requirePermission('dashboards', 'manage')
POST   '/preset/:presetDashboard/filter'       requirePermission('dashboards', 'manage')
DELETE '/preset/:presetDashboard/filter/:id'   requirePermission('dashboards', 'manage')
```

**`savedSearch.ts`** (4)
```
GET '/' read · POST '/' manage · PATCH '/:id' manage · DELETE '/:id' manage
```
with resource `'savedSearches'`.

**`sources.ts`** (4) — resource `'sources'`
```
GET '/' read · POST '/' manage · PUT '/:id' manage · DELETE '/:id' manage
```

**`connections.ts`** (4) — resource `'connections'`
```
GET '/' read · POST '/' manage · PUT '/:id' manage · DELETE '/:id' manage
```

**`webhooks.ts`** (5) — resource `'webhooks'`
```
GET '/' read · POST '/' manage · PUT '/:id' manage · DELETE '/:id' manage
POST '/test' manage   // sends a real outbound request
```

**`pinnedFilters.ts`** (2) — PinnedFilter is unique on `{team, source}`: one
shared document per source, so writing it changes what every member sees.
```
GET '/' requirePermission('sources', 'read')
PUT '/' requirePermission('sources', 'manage')
```

**`favorites.ts`** (3) — per-user, `{team, user, resourceType, resourceId}`
```
GET '/' · PUT '/' · DELETE '/:resourceType/:resourceId'
  → noPermissionRequired('personal-state')
```

**`me.ts`** (1)
```
GET '/' noPermissionRequired('personal-state')
```
Gating this would deny every non-admin their own access key, and therefore all
CLI and MCP access.

**`ai.ts`** (1)
```
POST '/assistant' requirePermission('sources', 'read')
```

Worked example — `sources.ts` `POST /`:

```ts
router.post(
  '/',
  requirePermission('sources', 'manage'),
  validateRequest({
    body: SourceSchemaNoId,
  }),
  async (req, res, next) => {
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /Users/dohaelsawy/hyperdx && make dev-int FILE=rbacEnforcement.int
```
Expected: PASS, 5 tests.

- [ ] **Step 5: Verify nothing regressed**

```bash
cd /Users/dohaelsawy/hyperdx && make ci-lint && cd packages/api && yarn ci:unit
```
Expected: lint clean, unit tests pass.

- [ ] **Step 6: Commit**

```bash
git add packages/api/src/routers/api/ 
git commit -m "feat(api): annotate resource and personal routers with RBAC declarations"
```

---

## Task 7: Annotate team, root and query-path routers + IDOR fix

**Files:**
- Modify: `packages/api/src/routers/api/{team,root,clickhouseProxy,prometheus}.ts`
- Test: `packages/api/src/routers/api/__tests__/teamRbac.int.test.ts`

**Interfaces:**
- Consumes: `requirePermission`, `requireAdmin`, `noPermissionRequired`.
- Produces: remaining 27 routes annotated. `DELETE /team/invitation/:id` becomes team-scoped.

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/routers/api/__tests__/teamRbac.int.test.ts`:

```ts
import { SYSTEM_ROLE_PERMISSIONS } from '@hyperdx/common-utils/dist/types';
import { Types } from 'mongoose';

import { getLoggedInAgent, getServer } from '@/fixtures';
import Role from '@/models/role';
import TeamInvite from '@/models/teamInvite';
import User from '@/models/user';

async function demote(teamId: string, userId: string) {
  const role = await Role.create({
    team: teamId,
    name: 'demoted',
    permissions: SYSTEM_ROLE_PERMISSIONS.Member,
    isSystem: false,
    isAdmin: false,
  });
  await User.findByIdAndUpdate(userId, { role: role._id });
}

describe('team router RBAC', () => {
  const server = getServer();

  beforeAll(async () => {
    await server.start();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('blocks a non-admin from rotating the ingestion key', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await demote(team._id.toString(), user._id.toString());

    await agent.patch('/team/apiKey').expect(403);
  });

  it('blocks a non-admin from inviting a member', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await demote(team._id.toString(), user._id.toString());

    await agent
      .post('/team/invitation')
      .send({ email: 'new@example.com' })
      .expect(403);
  });

  it('allows a member-level role to read team settings', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await demote(team._id.toString(), user._id.toString());

    await agent.get('/team').expect(200);
  });

  // Regression: DELETE /team/invitation/:id previously used
  // TeamInvite.findByIdAndDelete(id) with no team filter — a cross-tenant IDOR.
  it('cannot delete another team invitation', async () => {
    const { agent } = await getLoggedInAgent(server);

    const foreignInvite = await TeamInvite.create({
      teamId: new Types.ObjectId(),
      email: 'victim@other-team.com',
      token: 'foreign-token',
    });

    await agent.delete(`/team/invitation/${foreignInvite._id}`).expect(404);

    expect(await TeamInvite.findById(foreignInvite._id)).not.toBeNull();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/dohaelsawy/hyperdx && make dev-int FILE=teamRbac.int
```
Expected: FAIL — apiKey rotation returns 200; the foreign invite is deleted.

- [ ] **Step 3: Annotate `team.ts` and fix the IDOR**

Add imports:

```ts
import { requireAdmin, requirePermission } from '@/middleware/rbac';
```

Annotations:
```
GET    '/'                     requirePermission('team', 'read')
PATCH  '/apiKey'               requireAdmin()
PATCH  '/name'                 requirePermission('team', 'manage')
PATCH  '/clickhouse-settings'  requirePermission('team', 'manage')
POST   '/invitation'           requireAdmin()
GET    '/invitations'          requirePermission('users', 'read')
DELETE '/invitation/:id'       requireAdmin()
GET    '/members'              requirePermission('users', 'read')
DELETE '/member/:id'           requireAdmin()
GET    '/tags'                 requirePermission('team', 'read')
```

Replace the `DELETE /invitation/:id` handler body (currently at
`team.ts:228-238`) with a team-scoped delete:

```ts
  async (req, res, next) => {
    try {
      const id = req.params.id;
      const teamId = req.user?.team;
      if (teamId == null) {
        throw new Error(`User ${req.user?._id} not associated with a team`);
      }

      // Scoped by team: deleting by _id alone let any authenticated user of
      // any team remove another team's pending invite.
      const deleted = await TeamInvite.findOneAndDelete({ _id: id, teamId });
      if (!deleted) {
        return res.status(404).json({ message: 'TeamInvite not found' });
      }

      return res.json({ message: 'TeamInvite deleted' });
    } catch (e) {
      next(e);
    }
  },
```

- [ ] **Step 4: Annotate `root.ts` (7), `clickhouseProxy.ts` (3), `prometheus.ts` (5)**

`root.ts` — add `import { noPermissionRequired } from '@/middleware/rbac';` and
annotate all seven with `noPermissionRequired('public')`:
`GET /health`, `GET /installation`, `POST /login/password`,
`POST /register/password`, `GET /logout`, `POST /team/setup/:token`,
`GET /ext/silence-alert/:token`.

`clickhouseProxy.ts`:
```
POST '/test'  requirePermission('connections', 'manage')
GET  '/*'     noPermissionRequired('query-path-slice-B')
POST '/*'     noPermissionRequired('query-path-slice-B')
```

`prometheus.ts` — all five `noPermissionRequired('query-path-slice-B')`:
`GET|POST /query_range`, `GET|POST /query`, `GET /label/:name/values`.

> These query paths are intentionally ungated in slice A. Source permissions are
> UI-level until slice B closes them.

- [ ] **Step 5: Run test to verify it passes**

```bash
cd /Users/dohaelsawy/hyperdx && make dev-int FILE=teamRbac.int
```
Expected: PASS, 4 tests.

- [ ] **Step 6: Commit**

```bash
git add packages/api/src/routers/api/
git commit -m "feat(api): annotate team, auth and query-path routes; scope invite deletion by team"
```

---

## Task 8: Boot-time coverage assertion

**Files:**
- Create: `packages/api/src/middleware/rbacCoverage.ts`
- Modify: `packages/api/src/api-app.ts`
- Test: `packages/api/src/middleware/__tests__/rbacCoverage.test.ts`

**Interfaces:**
- Consumes: `getRbacDeclaration` (Task 5).
- Produces: `assertRbacCoverage(app: Express, opts?: { exemptMounts?: string[] }): void` — throws listing uncovered routes.

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/middleware/__tests__/rbacCoverage.test.ts`:

```ts
import express from 'express';

import { noPermissionRequired, requirePermission } from '@/middleware/rbac';
import { assertRbacCoverage } from '@/middleware/rbacCoverage';

jest.mock('@/config', () => ({ IS_LOCAL_APP_MODE: false }));

describe('assertRbacCoverage', () => {
  it('passes when every route declares a permission', () => {
    const app = express();
    const router = express.Router();
    router.get('/', requirePermission('alerts', 'read'), (_req, res) =>
      res.send(),
    );
    router.post('/', noPermissionRequired('public'), (_req, res) => res.send());
    app.use('/alerts', router);

    expect(() => assertRbacCoverage(app)).not.toThrow();
  });

  it('throws and names the offending route', () => {
    const app = express();
    const router = express.Router();
    router.get('/', requirePermission('alerts', 'read'), (_req, res) =>
      res.send(),
    );
    router.delete('/:id', (_req, res) => res.send()); // undeclared
    app.use('/alerts', router);

    expect(() => assertRbacCoverage(app)).toThrow(/DELETE \/alerts\/:id/);
  });

  it('ignores explicitly exempt mounts', () => {
    const app = express();
    const router = express.Router();
    router.post('/', (_req, res) => res.send());
    app.use('/mcp', router);

    expect(() =>
      assertRbacCoverage(app, { exemptMounts: ['/mcp'] }),
    ).not.toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd packages/api && yarn ci:unit src/middleware/__tests__/rbacCoverage.test.ts
```
Expected: FAIL — `Cannot find module '@/middleware/rbacCoverage'`.

- [ ] **Step 3: Write the walker**

Create `packages/api/src/middleware/rbacCoverage.ts`:

```ts
import type { Express } from 'express';

import { getRbacDeclaration } from '@/middleware/rbac';
import logger from '@/utils/logger';

type Layer = {
  name?: string;
  regexp?: RegExp;
  handle?: { stack?: Layer[] };
  route?: {
    path: string;
    methods: Record<string, boolean>;
    stack: { handle: unknown }[];
  };
};

/** Recover a mount path from an Express layer's regexp. */
function mountPath(layer: Layer): string {
  if (!layer.regexp) return '';
  const source = layer.regexp.source;
  if (source === '^\\/?$' || source === '^\\/?(?=\\/|$)') return '';
  const match = source
    .replace('^\\/', '/')
    .replace('\\/?(?=\\/|$)', '')
    .replace(/\\\//g, '/')
    .replace(/\$$/, '');
  return match.startsWith('/') ? match : '';
}

function walk(
  stack: Layer[],
  prefix: string,
  out: { method: string; path: string; declared: boolean }[],
) {
  for (const layer of stack) {
    if (layer.route) {
      const declared = layer.route.stack.some(
        s => getRbacDeclaration(s.handle) != null,
      );
      for (const method of Object.keys(layer.route.methods)) {
        out.push({
          method: method.toUpperCase(),
          path: `${prefix}${layer.route.path}`.replace(/\/+/g, '/'),
          declared,
        });
      }
    } else if (layer.handle?.stack) {
      walk(layer.handle.stack, `${prefix}${mountPath(layer)}`, out);
    }
  }
}

/**
 * Fails startup when an authenticated route carries no RBAC declaration.
 *
 * Forgetting the annotation on a new route is otherwise silent and ships an
 * unguarded endpoint — the same omission class that produced the TeamInvite
 * cross-tenant delete. This converts it into a failed deploy.
 */
export function assertRbacCoverage(
  app: Express,
  opts: { exemptMounts?: string[] } = {},
): void {
  const exempt = opts.exemptMounts ?? [];
  const routes: { method: string; path: string; declared: boolean }[] = [];

  const stack = (app as any)._router?.stack ?? (app as any).router?.stack ?? [];
  walk(stack, '', routes);

  const uncovered = routes.filter(
    r => !r.declared && !exempt.some(m => r.path.startsWith(m)),
  );

  if (uncovered.length > 0) {
    const list = uncovered.map(r => `  ${r.method} ${r.path}`).join('\n');
    throw new Error(
      `RBAC coverage check failed. ${uncovered.length} route(s) declare no permission:\n${list}\n\n` +
        `Add requirePermission(), requireAdmin(), or noPermissionRequired() to each.`,
    );
  }

  logger.info(
    { routeCount: routes.length },
    'RBAC coverage check passed: every route declares a permission',
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd packages/api && yarn ci:unit src/middleware/__tests__/rbacCoverage.test.ts
```
Expected: PASS, 3 tests.

- [ ] **Step 5: Wire it into the app**

In `packages/api/src/api-app.ts`, after `app.use('/api/v2', externalRoutersV2);`
and before `app.use(appErrorHandler);`:

```ts
// Fails startup if any route is missing an RBAC declaration. /mcp and /api/v2
// authenticate by access key and are gated in slice C.
assertRbacCoverage(app, { exemptMounts: ['/mcp', '/api/v2'] });
```

with the import:

```ts
import { assertRbacCoverage } from '@/middleware/rbacCoverage';
```

- [ ] **Step 6: Verify the real app passes coverage**

```bash
cd packages/api && yarn ci:unit
```
Expected: PASS. If it throws, the error lists exactly which routes Tasks 6–7 missed — annotate them and re-run.

- [ ] **Step 7: Commit**

```bash
git add packages/api/src/middleware/rbacCoverage.ts \
        packages/api/src/middleware/__tests__/rbacCoverage.test.ts \
        packages/api/src/api-app.ts
git commit -m "feat(api): fail startup when a route declares no RBAC permission"
```

---

## Task 9: Role CRUD and assignment routes

**Files:**
- Create: `packages/api/src/routers/api/roles.ts`
- Modify: `packages/api/src/routers/api/team.ts` (mount sub-router, add member-role route)
- Test: `packages/api/src/routers/api/__tests__/roles.int.test.ts`

**Interfaces:**
- Consumes: role controller (Task 3), `requireAdmin`/`requirePermission` (Task 5).
- Produces: `GET|POST /team/roles`, `PATCH|DELETE /team/roles/:id`, `PATCH /team/members/:id/role`.

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/routers/api/__tests__/roles.int.test.ts`:

```ts
import { SYSTEM_ROLE_PERMISSIONS } from '@hyperdx/common-utils/dist/types';

import { seedSystemRoles } from '@/controllers/role';
import { getLoggedInAgent, getServer } from '@/fixtures';
import Role from '@/models/role';
import User from '@/models/user';

describe('/team/roles', () => {
  const server = getServer();

  beforeAll(async () => {
    await server.start();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  async function asAdmin() {
    const ctx = await getLoggedInAgent(server);
    await seedSystemRoles(ctx.team._id);
    const admin = await Role.findOne({ team: ctx.team._id, isAdmin: true });
    await User.findByIdAndUpdate(ctx.user._id, { role: admin!._id });
    return ctx;
  }

  it('lists roles with member counts', async () => {
    const { agent } = await asAdmin();

    const res = await agent.get('/team/roles').expect(200);

    expect(res.body.data.map((r: any) => r.name).sort()).toEqual([
      'Admin',
      'Member',
      'ReadOnly',
    ]);
    expect(res.body.data.find((r: any) => r.isAdmin).memberCount).toBe(1);
  });

  it('creates a custom role', async () => {
    const { agent } = await asAdmin();

    const res = await agent
      .post('/team/roles')
      .send({
        name: 'On-call engineer',
        description: 'Alerts and webhooks',
        permissions: SYSTEM_ROLE_PERMISSIONS.Member,
      })
      .expect(200);

    expect(res.body.isSystem).toBe(false);
    expect(res.body.isAdmin).toBe(false);
  });

  it('strips isAdmin from the request body', async () => {
    const { agent } = await asAdmin();

    const res = await agent
      .post('/team/roles')
      .send({
        name: 'Escalation attempt',
        permissions: SYSTEM_ROLE_PERMISSIONS.Member,
        isAdmin: true,
        isSystem: true,
      })
      .expect(200);

    expect(res.body.isAdmin).toBe(false);
    expect(res.body.isSystem).toBe(false);
  });

  it('rejects manage on users', async () => {
    const { agent } = await asAdmin();

    await agent
      .post('/team/roles')
      .send({
        name: 'Invalid',
        permissions: { ...SYSTEM_ROLE_PERMISSIONS.Member, users: 'manage' },
      })
      .expect(400);
  });

  it('409s editing a system role', async () => {
    const { agent, team } = await asAdmin();
    const member = await Role.findOne({ team: team._id, name: 'Member' });

    await agent
      .patch(`/team/roles/${member!._id}`)
      .send({ name: 'Renamed', permissions: SYSTEM_ROLE_PERMISSIONS.Member })
      .expect(409);
  });

  it('409s deleting a role that is in use', async () => {
    const { agent, team, user } = await asAdmin();
    const role = await Role.create({
      team: team._id,
      name: 'Busy',
      permissions: SYSTEM_ROLE_PERMISSIONS.Member,
    });
    await User.findByIdAndUpdate(user._id, { role: role._id });

    await agent.delete(`/team/roles/${role._id}`).expect(409);
  });

  it('409s demoting the last admin', async () => {
    const { agent, team, user } = await asAdmin();
    const member = await Role.findOne({ team: team._id, name: 'Member' });

    await agent
      .patch(`/team/members/${user._id}/role`)
      .send({ roleId: member!._id.toString() })
      .expect(409);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/dohaelsawy/hyperdx && make dev-int FILE=roles.int
```
Expected: FAIL — 404 on `/team/roles`.

- [ ] **Step 3: Write the roles router**

Create `packages/api/src/routers/api/roles.ts`:

```ts
import { RoleInputSchema } from '@hyperdx/common-utils/dist/types';
import express from 'express';
import { z } from 'zod';
import { validateRequest } from 'zod-express-middleware';

import {
  createRole,
  deleteRole,
  getRolesWithCounts,
  RoleConflictError,
  updateRole,
} from '@/controllers/role';
import { getNonNullUserWithTeam } from '@/middleware/auth';
import { requireAdmin, requirePermission } from '@/middleware/rbac';
import { objectIdSchema } from '@/utils/zod';

const router = express.Router();

function serialize(role: any) {
  return {
    id: role._id.toString(),
    name: role.name,
    description: role.description,
    isSystem: role.isSystem,
    isAdmin: role.isAdmin,
    permissions: role.permissions,
    ...(role.memberCount != null ? { memberCount: role.memberCount } : {}),
  };
}

router.get('/', requirePermission('team', 'read'), async (req, res, next) => {
  try {
    const { teamId } = getNonNullUserWithTeam(req);
    const roles = await getRolesWithCounts(teamId);
    res.json({ data: roles.map(serialize) });
  } catch (e) {
    next(e);
  }
});

router.post(
  '/',
  requireAdmin(),
  // RoleInputSchema has no isAdmin/isSystem keys, so Zod drops them.
  validateRequest({ body: RoleInputSchema }),
  async (req, res, next) => {
    try {
      const { teamId } = getNonNullUserWithTeam(req);
      const role = await createRole(teamId, req.body);
      res.json(serialize(role));
    } catch (e) {
      next(e);
    }
  },
);

router.patch(
  '/:id',
  requireAdmin(),
  validateRequest({
    body: RoleInputSchema,
    params: z.object({ id: objectIdSchema }),
  }),
  async (req, res, next) => {
    try {
      const { teamId } = getNonNullUserWithTeam(req);
      const role = await updateRole(teamId, req.params.id, req.body);
      res.json(serialize(role));
    } catch (e) {
      if (e instanceof RoleConflictError) {
        return res.status(409).json({ message: e.message });
      }
      next(e);
    }
  },
);

router.delete(
  '/:id',
  requireAdmin(),
  validateRequest({ params: z.object({ id: objectIdSchema }) }),
  async (req, res, next) => {
    try {
      const { teamId } = getNonNullUserWithTeam(req);
      await deleteRole(teamId, req.params.id);
      res.json({ message: 'Role deleted' });
    } catch (e) {
      if (e instanceof RoleConflictError) {
        return res.status(409).json({ message: e.message });
      }
      next(e);
    }
  },
);

export default router;
```

- [ ] **Step 4: Mount it and add member-role assignment**

In `packages/api/src/routers/api/team.ts`, add imports:

```ts
import { assignRole, RoleConflictError } from '@/controllers/role';
import rolesRouter from '@/routers/api/roles';
```

Mount before the other routes so `/team/roles` is not shadowed by `/team/:x`:

```ts
router.use('/roles', rolesRouter);
```

Add the assignment route:

```ts
router.patch(
  '/members/:id/role',
  requireAdmin(),
  validateRequest({
    body: z.object({ roleId: objectIdSchema }),
    params: z.object({ id: objectIdSchema }),
  }),
  async (req, res, next) => {
    try {
      const { teamId } = getNonNullUserWithTeam(req);
      await assignRole(teamId, req.params.id, req.body.roleId);
      res.json({ message: 'Role updated' });
    } catch (e) {
      if (e instanceof RoleConflictError) {
        return res.status(409).json({ message: e.message });
      }
      next(e);
    }
  },
);
```

Also guard member removal with the same invariant — in the existing
`DELETE /member/:id` handler, before `deleteTeamMember(...)`:

```ts
      if (await isLastAdmin(teamId, userIdToDelete)) {
        return res.status(409).json({
          message:
            "The last admin can't be removed. Promote someone else first.",
        });
      }
```

adding `isLastAdmin` to the `@/controllers/role` import.

- [ ] **Step 5: Run test to verify it passes**

```bash
cd /Users/dohaelsawy/hyperdx && make dev-int FILE=roles.int
```
Expected: PASS, 7 tests.

- [ ] **Step 6: Commit**

```bash
git add packages/api/src/routers/api/roles.ts packages/api/src/routers/api/team.ts \
        packages/api/src/routers/api/__tests__/roles.int.test.ts
git commit -m "feat(api): add role CRUD and member role assignment endpoints"
```

---

## Task 10: Seed roles on team creation

**Files:**
- Modify: `packages/api/src/routers/api/root.ts`
- Modify: `packages/api/src/setupDefaults.ts`
- Test: `packages/api/src/routers/api/__tests__/registrationRoles.int.test.ts`

**Interfaces:**
- Consumes: `seedSystemRoles`, `getAdminRole` (Task 3).
- Produces: a newly registered user holds the Admin role of a team with three seeded roles.

- [ ] **Step 1: Write the failing test**

Create `packages/api/src/routers/api/__tests__/registrationRoles.int.test.ts`:

```ts
import { getServer } from '@/fixtures';
import Role from '@/models/role';
import Team from '@/models/team';
import User from '@/models/user';

describe('registration seeds RBAC roles', () => {
  const server = getServer();

  beforeAll(async () => {
    await server.start();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('creates three system roles and makes the first user an admin', async () => {
    const agent = server.getAgent();

    await agent
      .post('/register/password')
      .send({
        email: 'founder@example.com',
        password: 'Str0ng!Password',
        confirmPassword: 'Str0ng!Password',
      })
      .expect(200);

    const team = await Team.findOne({});
    const roles = await Role.find({ team: team!._id }).sort({ name: 1 });
    expect(roles.map(r => r.name)).toEqual(['Admin', 'Member', 'ReadOnly']);

    const user = await User.findOne({ email: 'founder@example.com' }).populate(
      'role',
    );
    expect((user!.role as any).isAdmin).toBe(true);
  });
});
```

> If `server.getAgent()` is not the fixture's accessor, use `getAgent(server)`
> imported from `@/fixtures` — match whichever the other `*.int.test.ts` files
> in `routers/api/__tests__/` already use.

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/dohaelsawy/hyperdx && make dev-int FILE=registrationRoles.int
```
Expected: FAIL — `roles` is empty.

- [ ] **Step 3: Seed during registration**

In `packages/api/src/routers/api/root.ts`, inside the `register` callback, after
`user.team = team._id;` and before `await user.save();`:

```ts
          const [adminRole] = await seedSystemRoles(team._id).then(roles => [
            roles.find(r => r.isAdmin)!,
          ]);
          user.role = adminRole._id;
```

with the import:

```ts
import { seedSystemRoles } from '@/controllers/role';
```

- [ ] **Step 4: Seed in `setupTeamDefaults` for local mode**

In `packages/api/src/setupDefaults.ts`, inside `setupTeamDefaults(teamId)`, after
the existing `getTeam(teamId)` lookup succeeds:

```ts
  // Idempotent: safe to call on every boot in local/all-in-one mode.
  await seedSystemRoles(teamId);
```

with the import:

```ts
import { seedSystemRoles } from '@/controllers/role';
```

- [ ] **Step 5: Run test to verify it passes**

```bash
cd /Users/dohaelsawy/hyperdx && make dev-int FILE=registrationRoles.int
```
Expected: PASS, 1 test.

- [ ] **Step 6: Commit**

```bash
git add packages/api/src/routers/api/root.ts packages/api/src/setupDefaults.ts \
        packages/api/src/routers/api/__tests__/registrationRoles.int.test.ts
git commit -m "feat(api): seed system roles on team creation"
```

---

## Task 11: Backfill migration

**Files:**
- Create: `packages/api/migrations/mongo/20260802120000-add_rbac_roles.ts`
- Test: `packages/api/migrations/mongo/__tests__/addRbacRoles.int.test.ts`

**Interfaces:**
- Consumes: nothing (raw `mongodb` driver, per `migrate-mongo` convention).
- Produces: every existing user holds *their own team's* Admin role.

- [ ] **Step 1: Write the failing test**

Create `packages/api/migrations/mongo/__tests__/addRbacRoles.int.test.ts`:

```ts
import { Types } from 'mongoose';

import { getServer } from '@/fixtures';
import { mongooseConnection } from '@/models';

// eslint-disable-next-line @typescript-eslint/no-require-imports
const migration = require('../20260802120000-add_rbac_roles');

describe('add_rbac_roles migration', () => {
  const server = getServer();

  beforeAll(async () => {
    await server.start();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('gives each user their own team admin role, not another team’s', async () => {
    const db = mongooseConnection.db!;
    const teamA = new Types.ObjectId();
    const teamB = new Types.ObjectId();

    await db.collection('teams').insertMany([
      { _id: teamA, name: 'A' },
      { _id: teamB, name: 'B' },
    ]);
    await db.collection('users').insertMany([
      { email: 'a@x.com', team: teamA },
      { email: 'b@x.com', team: teamB },
    ]);

    await migration.up(db);

    const roles = await db.collection('roles').find({}).toArray();
    expect(roles).toHaveLength(6); // 3 per team

    const userA = await db.collection('users').findOne({ email: 'a@x.com' });
    const adminA = roles.find(
      r => r.isAdmin && r.team.toString() === teamA.toString(),
    );
    expect(userA!.role.toString()).toBe(adminA!._id.toString());

    const userB = await db.collection('users').findOne({ email: 'b@x.com' });
    const adminB = roles.find(
      r => r.isAdmin && r.team.toString() === teamB.toString(),
    );
    expect(userB!.role.toString()).toBe(adminB!._id.toString());
    expect(userB!.role.toString()).not.toBe(adminA!._id.toString());
  });

  it('down removes the field and the collection', async () => {
    const db = mongooseConnection.db!;
    const team = new Types.ObjectId();
    await db.collection('teams').insertOne({ _id: team, name: 'A' });
    await db.collection('users').insertOne({ email: 'a@x.com', team });

    await migration.up(db);
    await migration.down(db);

    const user = await db.collection('users').findOne({ email: 'a@x.com' });
    expect(user!.role).toBeUndefined();
    expect(
      await db.listCollections({ name: 'roles' }).toArray(),
    ).toHaveLength(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/dohaelsawy/hyperdx && make dev-int FILE=addRbacRoles.int
```
Expected: FAIL — cannot find the migration module.

- [ ] **Step 3: Write the migration**

Create `packages/api/migrations/mongo/20260802120000-add_rbac_roles.ts`:

```ts
import { Db, MongoClient } from 'mongodb';

// Permission matrices are duplicated here rather than imported from
// common-utils: a migration must keep describing the world as it was when it
// ran, even after the shared constants change.
const SYSTEM_ROLES = [
  {
    name: 'Admin',
    description: 'Full access, including roles and API key rotation',
    isAdmin: true,
    permissions: {
      dashboards: 'manage',
      savedSearches: 'manage',
      sources: 'manage',
      alerts: 'manage',
      webhooks: 'manage',
      connections: 'manage',
      users: 'read',
      team: 'manage',
    },
  },
  {
    name: 'Member',
    description: 'Build dashboards and alerts; read-only on sources',
    isAdmin: false,
    permissions: {
      dashboards: 'manage',
      savedSearches: 'manage',
      sources: 'read',
      alerts: 'manage',
      webhooks: 'read',
      connections: 'none',
      users: 'read',
      team: 'read',
    },
  },
  {
    name: 'ReadOnly',
    description: 'View dashboards, searches and alerts',
    isAdmin: false,
    permissions: {
      dashboards: 'read',
      savedSearches: 'read',
      sources: 'read',
      alerts: 'read',
      webhooks: 'none',
      connections: 'none',
      users: 'none',
      team: 'read',
    },
  },
];

module.exports = {
  async up(db: Db, _client?: MongoClient) {
    await db
      .collection('roles')
      .createIndex({ team: 1, name: 1 }, { unique: true });

    const teams = await db.collection('teams').find({}).toArray();
    const now = new Date();

    for (const team of teams) {
      const docs = SYSTEM_ROLES.map(role => ({
        team: team._id,
        name: role.name,
        description: role.description,
        isSystem: true,
        isAdmin: role.isAdmin,
        permissions: role.permissions,
        createdAt: now,
        updatedAt: now,
      }));

      await db.collection('roles').insertMany(docs);

      const admin = await db
        .collection('roles')
        .findOne({ team: team._id, isAdmin: true });

      // Every existing user becomes an Admin of their own team. Downgrading
      // people is then a deliberate act, rather than something an upgrade
      // does to them silently.
      await db
        .collection('users')
        .updateMany({ team: team._id }, { $set: { role: admin!._id } });
    }
  },

  async down(db: Db, _client?: MongoClient) {
    await db.collection('users').updateMany({}, { $unset: { role: '' } });
    const existing = await db.listCollections({ name: 'roles' }).toArray();
    if (existing.length > 0) {
      await db.collection('roles').drop();
    }
  },
};
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd /Users/dohaelsawy/hyperdx && make dev-int FILE=addRbacRoles.int
```
Expected: PASS, 2 tests.

- [ ] **Step 5: Run the migration against the dev database**

```bash
cd /Users/dohaelsawy/hyperdx && make dev-migrate-db
```
Expected: `MIGRATED UP: 20260802120000-add_rbac_roles`.

- [ ] **Step 6: Commit**

```bash
git add packages/api/migrations/mongo/
git commit -m "feat(api): backfill system roles and assign existing users to Admin"
```

---

## Task 12: App data layer — role hooks and useMyPermissions

**Files:**
- Modify: `packages/app/src/api.ts`
- Create: `packages/app/src/hooks/useMyPermissions.ts`
- Test: `packages/app/src/hooks/__tests__/useMyPermissions.test.tsx`

**Interfaces:**
- Consumes: `RolesApiResponse`, `hasPermission`, `Resource`, `PermissionLevel` (Task 1).
- Produces:
  - `api.useRoles()`, `api.useCreateRole()`, `api.useUpdateRole()`, `api.useDeleteRole()`, `api.useAssignMemberRole()`
  - `useMyPermissions(): { isAdmin: boolean; can: (r: Resource, l: PermissionLevel) => boolean; isLoading: boolean }`

- [ ] **Step 1: Write the failing test**

Create `packages/app/src/hooks/__tests__/useMyPermissions.test.tsx`:

```tsx
import { renderHook } from '@testing-library/react';

import { useMyPermissions } from '@/hooks/useMyPermissions';

const mockUseMe = jest.fn();
jest.mock('@/api', () => ({
  __esModule: true,
  default: { useMe: () => mockUseMe() },
}));

describe('useMyPermissions', () => {
  it('grants everything to an admin', () => {
    mockUseMe.mockReturnValue({
      data: { role: { isAdmin: true, permissions: { connections: 'none' } } },
      isLoading: false,
    });

    const { result } = renderHook(() => useMyPermissions());

    expect(result.current.isAdmin).toBe(true);
    expect(result.current.can('connections', 'manage')).toBe(true);
  });

  it('compares levels for a non-admin', () => {
    mockUseMe.mockReturnValue({
      data: {
        role: {
          isAdmin: false,
          permissions: { dashboards: 'read', alerts: 'manage' },
        },
      },
      isLoading: false,
    });

    const { result } = renderHook(() => useMyPermissions());

    expect(result.current.can('dashboards', 'read')).toBe(true);
    expect(result.current.can('dashboards', 'manage')).toBe(false);
    expect(result.current.can('alerts', 'manage')).toBe(true);
  });

  it('grants everything when there is no role, matching the server fail-open', () => {
    mockUseMe.mockReturnValue({ data: { role: null }, isLoading: false });

    const { result } = renderHook(() => useMyPermissions());

    expect(result.current.isAdmin).toBe(true);
    expect(result.current.can('connections', 'manage')).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd packages/app && yarn ci:unit src/hooks/__tests__/useMyPermissions.test.tsx
```
Expected: FAIL — cannot resolve `@/hooks/useMyPermissions`.

- [ ] **Step 3: Write the hook**

Create `packages/app/src/hooks/useMyPermissions.ts`:

```ts
import { useMemo } from 'react';
import {
  hasPermission,
  type PermissionLevel,
  type Resource,
} from '@hyperdx/common-utils/dist/types';

import api from '@/api';

/**
 * Client-side mirror of the server's resolution order. The server is always
 * authoritative; this exists only to decide what to render.
 */
export function useMyPermissions() {
  const { data: me, isLoading } = api.useMe();

  return useMemo(() => {
    const role = me?.role ?? null;
    // No role means the migration has not run; the server fails open as admin,
    // so the UI must agree or it would hide controls that actually work.
    const isAdmin = role == null || role.isAdmin === true;

    return {
      isAdmin,
      isLoading,
      can(resource: Resource, level: PermissionLevel) {
        if (isAdmin) return true;
        return hasPermission(role?.permissions?.[resource], level);
      },
    };
  }, [me, isLoading]);
}
```

- [ ] **Step 4: Add the API hooks**

In `packages/app/src/api.ts`, add alongside `useTeamMembers()`:

```ts
  useRoles() {
    return useQuery<RolesApiResponse>({
      queryKey: [`team/roles`],
      queryFn: () => hdxServer(`team/roles`).json<RolesApiResponse>(),
    });
  },
  useCreateRole() {
    return useMutation({
      mutationFn: async (role: RoleInput) =>
        hdxServer(`team/roles`, { method: 'POST', json: role }).json(),
    });
  },
  useUpdateRole() {
    return useMutation({
      mutationFn: async ({ id, ...role }: RoleInput & { id: string }) =>
        hdxServer(`team/roles/${id}`, { method: 'PATCH', json: role }).json(),
    });
  },
  useDeleteRole() {
    return useMutation({
      mutationFn: async (id: string) =>
        hdxServer(`team/roles/${id}`, { method: 'DELETE' }).json(),
    });
  },
  useAssignMemberRole() {
    return useMutation({
      mutationFn: async ({
        userId,
        roleId,
      }: {
        userId: string;
        roleId: string;
      }) =>
        hdxServer(`team/members/${userId}/role`, {
          method: 'PATCH',
          json: { roleId },
        }).json(),
    });
  },
```

with the type imports added to the existing `@hyperdx/common-utils/dist/types`
import in that file:

```ts
  type RoleInput,
  type RolesApiResponse,
```

- [ ] **Step 5: Run test to verify it passes**

```bash
cd packages/app && yarn ci:unit src/hooks/__tests__/useMyPermissions.test.tsx
```
Expected: PASS, 3 tests.

- [ ] **Step 6: Commit**

```bash
git add packages/app/src/api.ts packages/app/src/hooks/useMyPermissions.ts \
        packages/app/src/hooks/__tests__/useMyPermissions.test.tsx
git commit -m "feat(app): add role API hooks and useMyPermissions"
```

---

## Task 13: PermissionMatrix component

**Files:**
- Create: `packages/app/src/components/TeamSettings/PermissionMatrix.tsx`
- Test: `packages/app/src/components/TeamSettings/__tests__/PermissionMatrix.test.tsx`

**Interfaces:**
- Consumes: `RolePermissions`, `PermissionLevel` (Task 1).
- Produces: `<PermissionMatrix value={RolePermissions} onChange={(next: RolePermissions) => void} readOnly?: boolean />`

- [ ] **Step 1: Write the failing test**

Create `packages/app/src/components/TeamSettings/__tests__/PermissionMatrix.test.tsx`:

```tsx
import { SYSTEM_ROLE_PERMISSIONS } from '@hyperdx/common-utils/dist/types';
import { MantineProvider } from '@mantine/core';
import { fireEvent, render, screen } from '@testing-library/react';

import PermissionMatrix from '@/components/TeamSettings/PermissionMatrix';

function renderMatrix(props: Partial<React.ComponentProps<typeof PermissionMatrix>> = {}) {
  const onChange = jest.fn();
  render(
    <MantineProvider>
      <PermissionMatrix
        value={SYSTEM_ROLE_PERMISSIONS.Member}
        onChange={onChange}
        {...props}
      />
    </MantineProvider>,
  );
  return { onChange };
}

describe('PermissionMatrix', () => {
  it('renders a row for every permission key', () => {
    renderMatrix();

    expect(screen.getByText('Dashboards')).toBeInTheDocument();
    expect(screen.getByText('Saved searches')).toBeInTheDocument();
    expect(screen.getByText('Connections')).toBeInTheDocument();
    expect(screen.getByText('Users')).toBeInTheDocument();
    expect(screen.getByText('Team')).toBeInTheDocument();
  });

  it('emits the full matrix with one key changed', () => {
    const { onChange } = renderMatrix();

    fireEvent.click(screen.getByRole('radio', { name: 'sources-manage' }));

    expect(onChange).toHaveBeenCalledWith({
      ...SYSTEM_ROLE_PERMISSIONS.Member,
      sources: 'manage',
    });
  });

  it('does not emit changes in readOnly mode', () => {
    const { onChange } = renderMatrix({ readOnly: true });

    fireEvent.click(screen.getByRole('radio', { name: 'sources-manage' }));

    expect(onChange).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd packages/app && yarn ci:unit src/components/TeamSettings/__tests__/PermissionMatrix.test.tsx
```
Expected: FAIL — module not found.

- [ ] **Step 3: Write the component**

Create `packages/app/src/components/TeamSettings/PermissionMatrix.tsx`:

```tsx
import {
  type PermissionLevel,
  type RolePermissions,
} from '@hyperdx/common-utils/dist/types';
import { Divider, Group, SegmentedControl, Stack, Text } from '@mantine/core';

type Row = {
  key: keyof RolePermissions;
  label: string;
  levels: PermissionLevel[];
};

// `users` has no manage and `team` has no none: those levels do not exist in
// the vocabulary, so no role can hold them.
const RESOURCE_ROWS: Row[] = [
  { key: 'dashboards', label: 'Dashboards', levels: ['none', 'read', 'manage'] },
  { key: 'savedSearches', label: 'Saved searches', levels: ['none', 'read', 'manage'] },
  { key: 'sources', label: 'Sources', levels: ['none', 'read', 'manage'] },
  { key: 'alerts', label: 'Alerts', levels: ['none', 'read', 'manage'] },
  { key: 'webhooks', label: 'Webhooks', levels: ['none', 'read', 'manage'] },
  { key: 'connections', label: 'Connections', levels: ['none', 'read', 'manage'] },
];

const ADMIN_ROWS: Row[] = [
  { key: 'users', label: 'Users', levels: ['none', 'read'] },
  { key: 'team', label: 'Team', levels: ['read', 'manage'] },
];

const LEVEL_LABELS: Record<PermissionLevel, string> = {
  none: 'No access',
  read: 'Read',
  manage: 'Manage',
};

export default function PermissionMatrix({
  value,
  onChange,
  readOnly = false,
}: {
  value: RolePermissions;
  onChange: (next: RolePermissions) => void;
  readOnly?: boolean;
}) {
  const renderRow = (row: Row) => (
    <Group key={row.key} justify="space-between" wrap="nowrap" gap="md">
      <Text size="sm">{row.label}</Text>
      <SegmentedControl
        size="xs"
        disabled={readOnly}
        value={value[row.key]}
        onChange={next => {
          if (readOnly) return;
          onChange({ ...value, [row.key]: next as PermissionLevel });
        }}
        data={row.levels.map(level => ({
          value: level,
          label: (
            <span role="radio" aria-label={`${row.key}-${level}`} aria-checked={value[row.key] === level}>
              {LEVEL_LABELS[level]}
            </span>
          ),
        }))}
      />
    </Group>
  );

  return (
    <Stack gap="xs">
      <Text size="xs" c="dimmed" tt="uppercase" fw={500}>
        Resources
      </Text>
      {RESOURCE_ROWS.map(renderRow)}

      <Divider my="xs" />

      <Text size="xs" c="dimmed" tt="uppercase" fw={500}>
        Administration
      </Text>
      {ADMIN_ROWS.map(renderRow)}
    </Stack>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd packages/app && yarn ci:unit src/components/TeamSettings/__tests__/PermissionMatrix.test.tsx
```
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add packages/app/src/components/TeamSettings/PermissionMatrix.tsx \
        packages/app/src/components/TeamSettings/__tests__/PermissionMatrix.test.tsx
git commit -m "feat(app): add PermissionMatrix control"
```

---

## Task 14: RoleEditorModal and RbacRolesSection

**Files:**
- Create: `packages/app/src/components/TeamSettings/RoleEditorModal.tsx`
- Create: `packages/app/src/components/TeamSettings/RbacRolesSection.tsx`
- Modify: `packages/app/src/TeamPage.tsx`

**Interfaces:**
- Consumes: `PermissionMatrix` (Task 13), role hooks + `useMyPermissions` (Task 12).
- Produces: `<RoleEditorModal opened role onClose onSaved />`, `<RbacRolesSection />`.

- [ ] **Step 1: Write the modal**

Create `packages/app/src/components/TeamSettings/RoleEditorModal.tsx`:

```tsx
import { useEffect, useState } from 'react';
import {
  type Role,
  type RolePermissions,
  SYSTEM_ROLE_PERMISSIONS,
} from '@hyperdx/common-utils/dist/types';
import { Button, Group, Modal, Stack, Text, TextInput } from '@mantine/core';
import { notifications } from '@mantine/notifications';

import api from '@/api';
import PermissionMatrix from '@/components/TeamSettings/PermissionMatrix';

export default function RoleEditorModal({
  opened,
  role,
  onClose,
  onSaved,
}: {
  opened: boolean;
  /** null = create; a system role opens read-only. */
  role: Role | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  // `editing` tracks the save target separately from the `role` prop, so
  // "duplicate" can clear it and drop into create mode without closing.
  const [editing, setEditing] = useState<Role | null>(role);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [permissions, setPermissions] = useState<RolePermissions>(
    SYSTEM_ROLE_PERMISSIONS.Member,
  );

  const createRole = api.useCreateRole();
  const updateRole = api.useUpdateRole();

  const readOnly = editing?.isSystem === true;

  useEffect(() => {
    if (!opened) return;
    setEditing(role);
    setName(role?.name ?? '');
    setDescription(role?.description ?? '');
    setPermissions(role?.permissions ?? SYSTEM_ROLE_PERMISSIONS.Member);
  }, [opened, role]);

  const onError = (e: unknown) => {
    notifications.show({
      color: 'red',
      message:
        (e as any)?.message ?? 'Could not save the role. Please try again.',
    });
  };

  const onSuccess = (message: string) => {
    notifications.show({ color: 'green', message });
    onSaved();
    onClose();
  };

  const handleSave = () => {
    if (editing && !editing.isSystem) {
      updateRole.mutate(
        { id: editing.id, name, description, permissions },
        { onSuccess: () => onSuccess('Role updated'), onError },
      );
    } else {
      createRole.mutate(
        { name, description, permissions },
        { onSuccess: () => onSuccess('Role created'), onError },
      );
    }
  };

  /**
   * System roles are starting points. Clearing `editing` is what makes the
   * next save take the create branch — without it the save would target the
   * immutable system role and 409.
   */
  const handleDuplicate = () => {
    setName(`${editing?.name} copy`);
    setDescription(editing?.description ?? '');
    setEditing(null);
    // `permissions` already holds the system role's matrix.
  };

  const title =
    editing == null ? 'New role' : readOnly ? editing.name : 'Edit role';

  return (
    <Modal opened={opened} onClose={onClose} title={title} size="lg">
      <Stack gap="md">
        <TextInput
          label="Role name"
          value={name}
          disabled={readOnly}
          onChange={e => setName(e.currentTarget.value)}
        />
        <TextInput
          label="Description"
          placeholder="Optional"
          value={description}
          disabled={readOnly}
          onChange={e => setDescription(e.currentTarget.value)}
        />

        <PermissionMatrix
          value={permissions}
          onChange={setPermissions}
          readOnly={readOnly}
        />

        <Group justify="space-between">
          <Text size="xs" c="dimmed">
            Inviting and removing members stays with Admins.
          </Text>
          <Group gap="xs">
            <Button variant="secondary" onClick={onClose}>
              Cancel
            </Button>
            {readOnly ? (
              <Button variant="secondary" onClick={handleDuplicate}>
                Duplicate as custom role
              </Button>
            ) : (
              <Button
                variant="primary"
                disabled={name.trim().length === 0}
                loading={createRole.isPending || updateRole.isPending}
                onClick={handleSave}
              >
                {editing ? 'Save changes' : 'Create role'}
              </Button>
            )}
          </Group>
        </Group>
      </Stack>
    </Modal>
  );
}
```

- [ ] **Step 2: Write the section**

Create `packages/app/src/components/TeamSettings/RbacRolesSection.tsx`:

```tsx
import { useState } from 'react';
import { type Role } from '@hyperdx/common-utils/dist/types';
import { Badge, Button, Card, Group, Stack, Table, Text } from '@mantine/core';
import { notifications } from '@mantine/notifications';

import api from '@/api';
import { EmptyState } from '@/components/EmptyState';
import RoleEditorModal from '@/components/TeamSettings/RoleEditorModal';

export default function RbacRolesSection() {
  const { data, isLoading, refetch } = api.useRoles();
  const deleteRole = api.useDeleteRole();

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<Role | null>(null);

  const roles = data?.data ?? [];
  const customRoles = roles.filter(r => !r.isSystem);

  const openCreate = () => {
    setEditing(null);
    setEditorOpen(true);
  };

  const openRole = (role: Role) => {
    setEditing(role);
    setEditorOpen(true);
  };

  const onDelete = (role: Role) => {
    deleteRole.mutate(role.id, {
      onSuccess: () => {
        notifications.show({ color: 'green', message: 'Role deleted' });
        refetch();
      },
      onError: (e: any) => {
        notifications.show({
          color: 'red',
          message: e?.message ?? 'Could not delete the role.',
        });
      },
    });
  };

  return (
    <Card>
      <Stack gap="md">
        <Group justify="space-between" align="flex-start">
          <div>
            <Text fw={600}>Roles</Text>
            <Text size="sm" c="dimmed">
              Roles decide what members can see and change. Every member has
              exactly one.
            </Text>
          </div>
          <Button variant="primary" onClick={openCreate}>
            Add role
          </Button>
        </Group>

        {!isLoading && customRoles.length === 0 && (
          <EmptyState
            variant="card"
            title="Just the three built-in roles"
            description="Create a custom role when the built-ins don't fit — say, alerting access without dashboard editing."
          />
        )}

        <Table>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Role</Table.Th>
              <Table.Th>Members</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {roles.map(role => (
              <Table.Tr key={role.id}>
                <Table.Td>
                  <Group gap="xs">
                    <Text fw={500}>{role.name}</Text>
                    {role.isSystem && <Badge variant="default">System</Badge>}
                  </Group>
                  {role.description && (
                    <Text size="xs" c="dimmed">
                      {role.description}
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>{role.memberCount ?? 0}</Table.Td>
                <Table.Td align="right">
                  <Button variant="subtle" onClick={() => openRole(role)}>
                    {role.isSystem ? 'View' : 'Edit'}
                  </Button>
                  {!role.isSystem && (
                    <Button variant="danger" onClick={() => onDelete(role)}>
                      Delete
                    </Button>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      </Stack>

      <RoleEditorModal
        opened={editorOpen}
        role={editing}
        onClose={() => setEditorOpen(false)}
        onSaved={refetch}
      />
    </Card>
  );
}
```

> Check `packages/app/src/components/EmptyState.tsx` for its actual prop names
> before wiring — match them rather than the guesses above.

- [ ] **Step 3: Wire into TeamPage**

In `packages/app/src/TeamPage.tsx`:

Replace line 61:
```ts
  const hasAdminAccess = true;
```
with:
```ts
  const { isAdmin: hasAdminAccess } = useMyPermissions();
```
and import `import { useMyPermissions } from '@/hooks/useMyPermissions';`.

Replace the conditional Access tab (lines 117–134) so the tab always exists and
only Security Policies stays conditional:

```ts
    {
      value: 'access',
      label: 'Access',
      sections: [
        ...(hasAdminAccess
          ? [{ id: 'team-access-roles', content: <RbacRolesSection /> }]
          : []),
        ...(hasAllowedAuthMethods
          ? [
              {
                id: 'team-access-security-policies',
                content: (
                  <SecurityPoliciesSection
                    allowedAuthMethods={allowedAuthMethods}
                  />
                ),
              },
            ]
          : []),
      ],
    },
```
with `import RbacRolesSection from './components/TeamSettings/RbacRolesSection';`.

- [ ] **Step 4: Verify lint and types**

```bash
cd /Users/dohaelsawy/hyperdx && make ci-lint
```
Expected: clean. Fix any `variant=` violations — only `primary`/`secondary`/`danger`/`subtle`/`link` are allowed.

- [ ] **Step 5: Commit**

```bash
git add packages/app/src/components/TeamSettings/RoleEditorModal.tsx \
        packages/app/src/components/TeamSettings/RbacRolesSection.tsx \
        packages/app/src/TeamPage.tsx
git commit -m "feat(app): add role editor and roles section to Team Settings"
```

---

## Task 15: Members table role column

**Files:**
- Modify: `packages/app/src/components/TeamSettings/TeamMembersSection.tsx`
- Modify: `packages/api/src/routers/api/team.ts` (include role in `GET /team/members`)

**Interfaces:**
- Consumes: `api.useRoles`, `api.useAssignMemberRole`, `useMyPermissions`.
- Produces: role column with inline assignment.

- [ ] **Step 1: Return role data from the members endpoint**

In `packages/api/src/routers/api/team.ts`, the `GET /members` handler currently
maps `pick(user.toJSON(...), [...])`. Populate and include the role:

```ts
    const teamUsers = await findUsersByTeam(teamId);
    await User.populate(teamUsers, { path: 'role' });
    res.json({
      data: teamUsers.map(user => ({
        ...pick(user.toJSON({ virtuals: true }), [
          '_id',
          'email',
          'name',
          'hasPasswordAuth',
        ]),
        roleId: (user.role as any)?._id?.toString() ?? null,
        roleName: (user.role as any)?.name ?? null,
        isCurrentUser: user._id.equals(userId),
      })),
    });
```
adding `import User from '@/models/user';` if not already imported.

- [ ] **Step 2: Add the column**

In `packages/app/src/components/TeamSettings/TeamMembersSection.tsx`:

Replace `const hasAdminAccess = true;` with:
```ts
  const { isAdmin: hasAdminAccess } = useMyPermissions();
```

Add above the members table body:
```ts
  const { data: rolesData } = api.useRoles();
  const assignRole = api.useAssignMemberRole();

  const roleOptions = (rolesData?.data ?? []).map(r => ({
    value: r.id,
    label: r.name,
  }));

  const adminRoleIds = new Set(
    (rolesData?.data ?? []).filter(r => r.isAdmin).map(r => r.id),
  );
  const adminCount = (members?.data ?? []).filter(
    m => m.roleId != null && adminRoleIds.has(m.roleId),
  ).length;
```

Add a `Role` header cell, and per row:

```tsx
<Table.Td>
  <Select
    size="xs"
    data={roleOptions}
    value={member.roleId}
    disabled={
      !hasAdminAccess ||
      (adminCount === 1 &&
        member.roleId != null &&
        adminRoleIds.has(member.roleId))
    }
    onChange={roleId => {
      if (!roleId) return;
      assignRole.mutate(
        { userId: member._id, roleId },
        {
          onSuccess: () => {
            notifications.show({ color: 'green', message: 'Role updated' });
            refetchMembers();
          },
          onError: (e: any) => {
            notifications.show({
              color: 'red',
              message:
                e?.message ??
                "The last admin can't be changed. Promote someone else first.",
            });
          },
        },
      );
    }}
  />
</Table.Td>
```

with `Select` added to the `@mantine/core` import and
`import { useMyPermissions } from '@/hooks/useMyPermissions';`.

- [ ] **Step 3: Verify**

```bash
cd /Users/dohaelsawy/hyperdx && make ci-lint && cd packages/app && yarn ci:unit
```
Expected: clean, all tests pass.

- [ ] **Step 4: Commit**

```bash
git add packages/app/src/components/TeamSettings/TeamMembersSection.tsx \
        packages/api/src/routers/api/team.ts
git commit -m "feat(app): add role column and assignment to the members table"
```

---

## Task 16: E2E, full verification and changeset

**Files:**
- Create: `packages/app/tests/e2e/features/rbac.spec.ts`
- Create: `.changeset/rbac-slice-a.md`

- [ ] **Step 1: Write the E2E spec**

Create `packages/app/tests/e2e/features/rbac.spec.ts`:

```ts
import { expect, test } from '@playwright/test';

// Requires fullstack mode: real API + Mongo + ClickHouse.
test.describe('RBAC', () => {
  test('an admin can create a custom role and see it listed', async ({
    page,
  }) => {
    await page.goto('/team');
    await page.getByRole('tab', { name: 'Access' }).click();

    await expect(page.getByText('Roles')).toBeVisible();
    await expect(page.getByText('Admin')).toBeVisible();
    await expect(page.getByText('Member')).toBeVisible();
    await expect(page.getByText('ReadOnly')).toBeVisible();

    await page.getByRole('button', { name: 'Add role' }).click();
    await page.getByLabel('Role name').fill('On-call engineer');
    await page.getByRole('radio', { name: 'alerts-manage' }).click();
    await page.getByRole('button', { name: 'Create role' }).click();

    await expect(page.getByText('On-call engineer')).toBeVisible();
  });

  test('system roles cannot be edited', async ({ page }) => {
    await page.goto('/team');
    await page.getByRole('tab', { name: 'Access' }).click();

    await page
      .getByRole('row', { name: /Member/ })
      .getByRole('button', { name: 'View' })
      .click();

    await expect(page.getByLabel('Role name')).toBeDisabled();
    await expect(
      page.getByRole('button', { name: 'Duplicate as custom role' }),
    ).toBeVisible();
  });
});
```

- [ ] **Step 2: Run the E2E spec**

```bash
cd /Users/dohaelsawy/hyperdx && make dev-e2e FILE=rbac
```
Expected: 2 tests pass. If selectors miss, adjust to the rendered DOM rather than changing component markup to suit the test.

- [ ] **Step 3: Full verification sweep**

```bash
cd /Users/dohaelsawy/hyperdx
make ci-lint
make ci-unit
make dev-int FILE=rbac
make dev-int FILE=role
make dev-int FILE=roles
make dev-int FILE=teamRbac
make dev-int FILE=addRbacRoles
make dev-int FILE=registrationRoles
```
Expected: every command exits 0. Do not proceed with failures — report them.

- [ ] **Step 4: Write the changeset**

Create `.changeset/rbac-slice-a.md`:

```markdown
---
'@hyperdx/api': minor
'@hyperdx/app': minor
---

Add role-based access control. Teams now have three built-in roles (Admin,
Member, ReadOnly) and admins can create custom roles with per-resource
permissions from Team Settings → Access. All existing users are migrated to
Admin, so no one loses access on upgrade.

Note: source permissions currently govern the interface, not the underlying
data — a user can still query ClickHouse directly through the query proxy.
Gating the query path is tracked as follow-up work.
```

- [ ] **Step 5: Commit**

```bash
git add packages/app/tests/e2e/features/rbac.spec.ts .changeset/rbac-slice-a.md
git commit -m "test(app): add RBAC e2e coverage and changeset"
```

---

## Self-Review

**Spec coverage** — every section maps to a task:

| Spec § | Task |
|---|---|
| §4.1 Role collection | 2 |
| §4.2 `User.role` | 2 |
| §4.3 `isAdmin` rationale | 2, 3, 5 |
| §5 Taxonomy + level semantics | 1 |
| §6 System roles | 1, 3 |
| §7.1 Three declarations | 5 |
| §7.2 Resolution order | 5 |
| §7.3 Boot assertion | 8 |
| §8 All 65 routes | 6 (38), 7 (27) |
| §9.1 New routes | 9 |
| §9.2 Invariants | 3, 9 |
| §9.3 IDOR rider | 7 |
| §10.1 New components | 12, 13, 14 |
| §10.2 Modified | 14, 15 |
| §10.3 Gating rules | 14, 15 |
| §11.1 Migration | 11 |
| §11.2 Seeding on creation | 10 |
| §11.3 Fail-open | 5, 12 |
| §12 Testing | every task + 16 |

**Gap found and closed:** §9.2's "last admin cannot be *removed*" was only
covered for demotion. Added `isLastAdmin` to Task 3 and the `DELETE /member/:id`
guard to Task 9 Step 4.

**Placeholder scan:** no TBD/TODO. Two steps flag verification against real code
rather than asserting it — Task 10 Step 1 (fixture accessor name) and Task 14
Step 2 (`EmptyState` props) — because inventing those names would be worse than
saying "check".

**Type consistency:** `RolePermissions`, `RoleInput`, `Resource`,
`PermissionLevel`, `hasPermission`, `SYSTEM_ROLE_PERMISSIONS` used identically
across Tasks 1→15. `RoleConflictError` thrown in Task 3, caught in Task 9.
`getRbacDeclaration` produced in Task 5, consumed in Task 8.

**Fixed during review:** Task 14's `RoleEditorModal` originally read the `role`
prop directly, so "Duplicate as custom role" prefilled the form while still
targeting the immutable system role — the save would have 409'd. The modal now
tracks `editing` in local state and clears it on duplicate.
