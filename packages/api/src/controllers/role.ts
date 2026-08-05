import {
  type RoleInput,
  SYSTEM_ROLE_DESCRIPTIONS,
  SYSTEM_ROLE_NAMES,
  SYSTEM_ROLE_PERMISSIONS,
} from '@hyperdx/common-utils/dist/types';
import mongoose from 'mongoose';

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

/**
 * Mongoose builds indexes in the background, so the {team, name} unique index
 * may not exist yet during the first registration on a fresh database — the
 * exact window BUG-4 reproduced, where 12 parallel seeds produced duplicate
 * Admin roles in 7 of 20 trials. Once duplicates exist the index can never
 * build, which also wedges the migration's own createIndex.
 *
 * Memoised: only the first caller in the process waits.
 */
let roleIndexesReady: Promise<unknown> | null = null;
function ensureRoleIndexes(): Promise<unknown> {
  roleIndexesReady ??= Role.init();
  return roleIndexesReady;
}

export async function seedSystemRoles(
  teamId: string | ObjectId,
): Promise<RoleDocument[]> {
  await ensureRoleIndexes();

  const created: RoleDocument[] = [];

  for (const name of SYSTEM_ROLE_NAMES) {
    let role: RoleDocument | null;
    try {
      role = await Role.findOneAndUpdate(
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
    } catch (e) {
      // Two upserts racing a *present* index both attempt the insert and the
      // loser gets E11000. The document exists either way, so re-read rather
      // than fail the caller's registration. The index barrier above prevents
      // duplicate documents; this prevents a duplicate request failing.
      if (!isDuplicateKey(e)) throw e;
      role = await Role.findOne({ team: teamId, name });
      if (!role) throw e;
    }

    // Non-null by construction: the try branch's overload resolves to a
    // non-null ResultDoc (upsert+new), and the catch branch throws above
    // when the re-read comes back empty. TS can't merge that narrowing
    // across the try/catch boundary.
    created.push(role!);
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

  // $match does no type coercion, so a string teamId would match nothing and
  // silently report every count as zero.
  const teamObjectId =
    typeof teamId === 'string' ? new mongoose.Types.ObjectId(teamId) : teamId;

  const counts = await User.aggregate<{ _id: ObjectId | null; count: number }>([
    { $match: { team: teamObjectId } },
    { $group: { _id: '$role', count: { $sum: 1 } } },
  ]);

  const byRole = new Map(counts.map(c => [c._id?.toString(), c.count]));

  return roles.map(role => ({
    ...(role.toObject() as IRole),
    memberCount: byRole.get(role._id.toString()) ?? 0,
  }));
}

/** Mongo duplicate-key. The {team, name} unique index is the only one here. */
function isDuplicateKey(e: unknown): boolean {
  return (e as { code?: number })?.code === 11000;
}

export async function createRole(
  teamId: string | ObjectId,
  input: RoleInput,
): Promise<RoleDocument> {
  try {
    // isSystem/isAdmin are never taken from input — that is the escalation
    // guard. Do NOT refactor to `...input`: RoleInputSchema is validated but
    // not stripped from req.body, so a spread would let those keys through.
    return await Role.create({
      team: teamId,
      name: input.name,
      description: input.description,
      permissions: input.permissions,
      isSystem: false,
      isAdmin: false,
    });
  } catch (e) {
    if (isDuplicateKey(e)) {
      throw new RoleConflictError(
        `A role named "${input.name}" already exists.`,
      );
    }
    throw e;
  }
}

async function getAdminRoleIds(teamId: string | ObjectId): Promise<ObjectId[]> {
  const roles = await Role.find({ team: teamId, isAdmin: true })
    .select('_id')
    .lean();
  return roles.map(r => r._id);
}

/**
 * Users holding an `isAdmin` role.
 *
 * BUG-1: this deliberately does NOT count role-less users. They pass
 * `requireAdmin` via the session fail-open, so counting them made the guard
 * fall silent whenever any un-migrated user existed — the same demotion
 * returning 200 or 409 depending on invisible state. The guard's callers
 * instead check that the *target* holds an admin role, which keeps
 * un-migrated teams usable without weakening the invariant.
 */
async function countAdminRoleHolders(
  teamId: string | ObjectId,
  excludeUserId?: ObjectId | string,
): Promise<number> {
  const adminRoleIds = await getAdminRoleIds(teamId);
  if (adminRoleIds.length === 0) return 0;

  return User.countDocuments({
    team: teamId,
    role: { $in: adminRoleIds },
    ...(excludeUserId ? { _id: { $ne: excludeUserId } } : {}),
  });
}

/** Whether this user currently holds one of the team's isAdmin roles. */
async function holdsAdminRole(
  teamId: string | ObjectId,
  user: { role?: ObjectId | null },
): Promise<boolean> {
  if (user.role == null) return false;
  const adminRoleIds = await getAdminRoleIds(teamId);
  return adminRoleIds.some(id => id.toString() === user.role!.toString());
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
  try {
    await role.save();
  } catch (e) {
    if (isDuplicateKey(e)) {
      throw new RoleConflictError(
        `A role named "${input.name}" already exists.`,
      );
    }
    throw e;
  }

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

  // Repair sweep. The in-use check above is check-then-act, so an assignment
  // racing this delete can leave a user pointing at a deleted role. A dangling
  // ref populates to null, which the middleware reads as "no role" and fails
  // OPEN as admin — a delete silently granting privilege. Clear any stragglers.
  await User.updateMany(
    { team: teamId, role: roleId },
    { $unset: { role: '' } },
  );
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

  const previousRoleId = user.role;
  // Captured before the write: the rollback below must know whether this user
  // was an admin, and the answer changes once the write lands.
  const wasAdmin = await holdsAdminRole(teamId, user);

  // Last-admin protection. §9.2: the last user *holding* an isAdmin role
  // cannot be demoted. A user who holds no admin role cannot be the last one,
  // so the guard does not fire for them — which is what keeps an un-migrated
  // team (nobody holds an admin role) from becoming unmanageable.
  if (!nextRole.isAdmin && wasAdmin) {
    const remaining = await countAdminRoleHolders(teamId, user._id);
    if (remaining === 0) {
      throw new RoleConflictError(
        'This is the last Admin. Promote someone else to Admin first.',
      );
    }
  }

  user.role = nextRole._id;
  await user.save();

  // Re-check after the write. Two concurrent demotions can each observe one
  // other admin remaining and both commit, leaving zero — an unrecoverable
  // state. Roll this one back if that happened.
  if (
    !nextRole.isAdmin &&
    wasAdmin &&
    (await countAdminRoleHolders(teamId)) === 0
  ) {
    user.role = previousRoleId;
    await user.save();
    throw new RoleConflictError(
      'This is the last Admin. Promote someone else to Admin first.',
    );
  }
}

/**
 * True when removing this user would leave the team with no admin-role holder.
 *
 * Only ever true for a user who currently holds an `isAdmin` role — see
 * `countAdminRoleHolders` for why role-less users are not counted.
 */
export async function isLastAdmin(
  teamId: string | ObjectId,
  userId: string | ObjectId,
): Promise<boolean> {
  const user = await User.findOne({ _id: userId, team: teamId });
  if (!user) return false;
  if (!(await holdsAdminRole(teamId, user))) return false;

  return (await countAdminRoleHolders(teamId, userId)) === 0;
}
