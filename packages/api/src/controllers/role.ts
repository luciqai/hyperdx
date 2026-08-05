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
import { getCounter } from '@/utils/instrumentation';
import logger from '@/utils/logger';

/** Thrown when an invariant blocks the write. Surfaces as HTTP 409. */
export class RoleConflictError extends Error {
  statusCode = 409;
  constructor(message: string) {
    super(message);
    this.name = 'RoleConflictError';
  }
}

const roleIndexBuildFailedCounter = getCounter(
  'hyperdx.rbac.role_index_build_failed',
  {
    description:
      'Failures to build the roles {team, name} unique index. Non-zero means duplicate roles already exist and must be cleaned up by hand.',
  },
);

/**
 * Mongoose builds indexes in the background, so the {team, name} unique index
 * may not exist yet during the first registration on a fresh database — the
 * exact window BUG-4 reproduced, where 12 parallel seeds produced duplicate
 * Admin roles in 7 of 20 trials. Once duplicates exist the index can never
 * build, which also wedges the migration's own createIndex.
 *
 * Memoised on SUCCESS only: the first caller in the process waits, the rest
 * ride its promise.
 *
 * A rejection is deliberately neither propagated nor memoised. `Role.init()`
 * rejects precisely on a deployment that already has duplicate {team, name}
 * roles — the population this barrier exists to help. Propagating would make
 * registration and invite acceptance start failing where they previously
 * succeeded, and caching the rejection would keep them failing even after an
 * operator cleaned the duplicates up, until the process was restarted. The
 * E11000 catch in `seedSystemRoles` already handles the racing-insert case
 * this barrier is an optimisation for, so degrading to that is safe.
 */
let roleIndexesReady: Promise<void> | null = null;
function ensureRoleIndexes(): Promise<void> {
  roleIndexesReady ??= Role.init().then(
    () => undefined,
    err => {
      // Clear the memo so a later call retries — the operator's duplicate
      // cleanup should take effect without a restart.
      roleIndexesReady = null;
      roleIndexBuildFailedCounter.add(1);
      logger.warn(
        { err },
        'RBAC: could not build the roles {team, name} unique index; continuing without the seed barrier. Duplicate roles likely exist and must be removed by hand.',
      );
    },
  );
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
 *
 * Role-less users are counted separately by `countRoleLessUsers`, for the
 * independent admin-less invariant. See that function for why.
 *
 * Takes `adminRoleIds` rather than looking them up so a caller making several
 * checks in one operation issues one `Role.find` instead of one per check.
 */
async function countAdminRoleHolders(
  teamId: string | ObjectId,
  adminRoleIds: ObjectId[],
  excludeUserId?: ObjectId | string,
): Promise<number> {
  if (adminRoleIds.length === 0) return 0;

  return User.countDocuments({
    team: teamId,
    role: { $in: adminRoleIds },
    ...(excludeUserId ? { _id: { $ne: excludeUserId } } : {}),
  });
}

/**
 * Users holding no role at all.
 *
 * These are the *other* population that passes `requireAdmin`: `resolveVerdict`
 * fails open for a role-less session user, so on an un-migrated team they are
 * the team's only admin access. `countAdminRoleHolders` cannot see them, and
 * must not — but something has to, because a team with zero admin-role holders
 * AND zero role-less users has nobody who can pass `requireAdmin` at all.
 * Every route that could repair that (`POST /team/roles`,
 * `PATCH /team/roles/:id`, `PATCH /team/members/:id/role`) is itself
 * `requireAdmin()`, so the state is unrecoverable through the API — only
 * direct Mongo surgery gets the team back.
 */
async function countRoleLessUsers(
  teamId: string | ObjectId,
  excludeUserId?: ObjectId | string,
): Promise<number> {
  return User.countDocuments({
    team: teamId,
    // `role` is absent rather than null on users written before the field
    // existed; `$in: [null, undefined]` matches both. Same filter the RBAC
    // migration uses to find the users it needs to backfill.
    role: { $in: [null, undefined] },
    ...(excludeUserId ? { _id: { $ne: excludeUserId } } : {}),
  });
}

/** Whether this user currently holds one of the team's isAdmin roles. */
function holdsAdminRole(
  adminRoleIds: ObjectId[],
  user: { role?: ObjectId | null },
): boolean {
  if (user.role == null) return false;
  return adminRoleIds.some(id => id.toString() === user.role!.toString());
}

/**
 * The two blocking conditions, each phrased for the action being attempted —
 * a 2x2 matrix of {last-admin, no-admin-role} x {changing, removing}.
 *
 * The two conditions stay distinct on purpose: they are different states and
 * the operator's next action differs. "Promote someone else to Admin" is
 * meaningless advice on a team where nobody holds the Admin role in the first
 * place — what they have to do is assign it. The *action* axis, by contrast,
 * only ever varied the wording, so it is a parameter rather than a second
 * constant.
 */
type BlockedAction = 'changing' | 'removing';

/** The last user holding an isAdmin role cannot be demoted or removed. */
const lastAdminMessage = (action: BlockedAction) =>
  'This is the last Admin. Promote someone else to Admin before ' +
  `${action} this user.`;

const noAdminRoleMessage = (action: BlockedAction) =>
  'This team has no Admin role assigned. Give someone the Admin role before ' +
  `${action} this user.`;

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
  // One Role.find for the whole call, including the rollback path below.
  const adminRoleIds = await getAdminRoleIds(teamId);
  // Captured before the write: the rollback below must know whether this user
  // was an admin, and the answer changes once the write lands.
  const wasAdmin = holdsAdminRole(adminRoleIds, user);

  // Both guards below are phrased as "what the team looks like *after* this
  // write". `nextRole` is always a real role, so the target is never role-less
  // afterwards, and an isAdmin `nextRole` can never reduce either population —
  // hence the single `!nextRole.isAdmin` gate.
  if (!nextRole.isAdmin) {
    const remainingAdmins = await countAdminRoleHolders(
      teamId,
      adminRoleIds,
      user._id,
    );

    if (remainingAdmins === 0) {
      // Guard 1 — last-admin protection. §9.2: the last user *holding* an
      // isAdmin role cannot be demoted. A user who holds no admin role cannot
      // be the last one, so this does not fire for them — which is what keeps
      // an un-migrated team (nobody holds an admin role) manageable.
      if (wasAdmin) {
        throw new RoleConflictError(lastAdminMessage('changing'));
      }

      // Guard 2 — admin-less protection, independent of guard 1. Guard 1
      // protects only holders of an isAdmin role; role-less users are the
      // other population that passes `requireAdmin` (session fail-open), and
      // nothing preserved them. Demoting them one by one on a team that holds
      // no Admin role walks it to zero callers who can pass `requireAdmin`,
      // which no API route can undo. Only the terminal write is refused, so
      // un-migrated teams stay usable right up to that point.
      if ((await countRoleLessUsers(teamId, user._id)) === 0) {
        throw new RoleConflictError(noAdminRoleMessage('changing'));
      }
    }
  }

  user.role = nextRole._id;
  await user.save();

  // Re-check after the write. Two concurrent demotions can each observe one
  // survivor and both commit, leaving zero — an unrecoverable state. That race
  // exists for the role-less population too, so the recheck mirrors both
  // guards above rather than only the last-admin one. Roll this one back if it
  // happened.
  if (!nextRole.isAdmin) {
    const admins = await countAdminRoleHolders(teamId, adminRoleIds);
    if (admins === 0) {
      const rollback = async (message: string) => {
        user.role = previousRoleId;
        await user.save();
        throw new RoleConflictError(message);
      };

      if (wasAdmin) await rollback(lastAdminMessage('changing'));
      if ((await countRoleLessUsers(teamId)) === 0) {
        await rollback(noAdminRoleMessage('changing'));
      }
    }
  }
}

/**
 * Why this user cannot be removed from the team, or `null` if they can be.
 *
 * Returns a message rather than a boolean because two different invariants can
 * block a removal and the operator's next action differs between them:
 *
 *  1. They are the last holder of an `isAdmin` role.
 *  2. Nobody holds an `isAdmin` role and they are the last role-less user, who
 *     passes `requireAdmin` through the session fail-open. Removing them
 *     strands the team with no caller who can pass `requireAdmin` at all —
 *     see `countRoleLessUsers`.
 */
export async function getMemberRemovalConflict(
  teamId: string | ObjectId,
  userId: string | ObjectId,
): Promise<string | null> {
  const user = await User.findOne({ _id: userId, team: teamId });
  if (!user) return null;

  const adminRoleIds = await getAdminRoleIds(teamId);
  if ((await countAdminRoleHolders(teamId, adminRoleIds, userId)) > 0) {
    return null;
  }

  if (holdsAdminRole(adminRoleIds, user)) return lastAdminMessage('removing');

  return (await countRoleLessUsers(teamId, userId)) === 0
    ? noAdminRoleMessage('removing')
    : null;
}
