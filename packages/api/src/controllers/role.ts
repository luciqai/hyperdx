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

/**
 * Users who can currently reach `requireAdmin`.
 *
 * Deliberately counts role-less users: the middleware fails open as admin for
 * them (see spec §11.3), so they ARE effective admins. Counting only holders
 * of an isAdmin role would let an operator assign roles one-by-one on an
 * un-migrated team and silently reach zero real admins — an unrecoverable
 * lockout, since every admin route then 403s for everyone.
 */
async function countEffectiveAdmins(
  teamId: string | ObjectId,
  excludeUserId?: ObjectId | string,
): Promise<number> {
  const adminRoleIds = (
    await Role.find({ team: teamId, isAdmin: true }).select('_id').lean()
  ).map(r => r._id);

  return User.countDocuments({
    team: teamId,
    ...(excludeUserId ? { _id: { $ne: excludeUserId } } : {}),
    $or: [
      { role: { $in: adminRoleIds } },
      { role: null },
      { role: { $exists: false } },
    ],
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

  // Last-admin protection. The user being demoted counts as an effective admin
  // if they hold an isAdmin role OR have no role at all (fail-open), so this
  // must run for role-less users too — not just holders of an admin role.
  if (!nextRole.isAdmin) {
    const remaining = await countEffectiveAdmins(teamId, user._id);
    if (remaining === 0) {
      throw new RoleConflictError(
        "The last admin can't be changed. Promote someone else first.",
      );
    }
  }

  user.role = nextRole._id;
  await user.save();

  // Re-check after the write. Two concurrent demotions can each observe one
  // other admin remaining and both commit, leaving zero — an unrecoverable
  // state. Roll this one back if that happened.
  if (!nextRole.isAdmin && (await countEffectiveAdmins(teamId)) === 0) {
    user.role = previousRoleId;
    await user.save();
    throw new RoleConflictError(
      "The last admin can't be changed. Promote someone else first.",
    );
  }
}

/**
 * True when removing this user would leave the team with no effective admin.
 *
 * Counts role-less users as admins for the same reason as
 * `countEffectiveAdmins` — they pass `requireAdmin` via the fail-open.
 */
export async function isLastAdmin(
  teamId: string | ObjectId,
  userId: string | ObjectId,
): Promise<boolean> {
  const user = await User.findOne({ _id: userId, team: teamId });
  if (!user) return false;

  return (await countEffectiveAdmins(teamId, userId)) === 0;
}
