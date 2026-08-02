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
