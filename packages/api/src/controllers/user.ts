import type { OnboardingTaskId } from '@hyperdx/common-utils/dist/types';
import { isPersistableUserId as isPersistableUserIdHex } from '@hyperdx/common-utils/dist/types';
import opentelemetry from '@opentelemetry/api';
import crypto from 'crypto';
import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid';

import { seedSystemRoles } from '@/controllers/role';
import type { ObjectId } from '@/models';
import Alert from '@/models/alert';
import User, { type IUser } from '@/models/user';
import { isDuplicateKeyError } from '@/utils/errors';
import { getCounter } from '@/utils/instrumentation';
import logger from '@/utils/logger';

export const NOT_VIRTUAL = { isVirtual: { $ne: true } };

export const ORG_API_KEY_PREFIX = 'hdx_org_';

// Virtual users with no createdBy (such as EE's role and CHC actor accounts)
// are not org keys, so they never authenticate as one or show up in key management.
export const ACTIVE_ORG_API_KEY = {
  isVirtual: true,
  createdBy: { $ne: null },
  revokedAt: null,
} as const;

export function hashOrgApiKey(key: string) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

// `role` is populated on both branches for the same reason as findUserById:
// RBAC reads req.user.role. Without it the Bearer path (MCP + External API v2)
// always saw a missing role.
export function findUserByAccessKey(accessKey: string, now = new Date()) {
  // Org keys are stored hashed; only the prefixed plaintext reaches a service
  // account, so presenting the stored hash itself never authenticates.
  if (accessKey.startsWith(ORG_API_KEY_PREFIX)) {
    return User.findOne({
      accessKey: hashOrgApiKey(accessKey),
      ...ACTIVE_ORG_API_KEY,
      $or: [{ expiresAt: null }, { expiresAt: { $gt: now } }],
    }).populate('role');
  }
  return User.findOne({ accessKey, ...NOT_VIRTUAL }).populate('role');
}

/**
 * Rotates a user's personal access key, immediately revoking the previous one.
 *
 * There is exactly one key per user and no grace period: findUserByAccessKey
 * above is hit uncached on every bearer request (see validateUserAccessKey), so
 * requests presenting the old key start 401ing the instant this returns.
 */
export function rotateUserAccessKey(userId: string | ObjectId) {
  return User.findByIdAndUpdate(userId, { accessKey: uuidv4() }, { new: true });
}

// Populated on every session request via passport's deserializeUser, so RBAC
// middleware can read req.user.role without an extra round trip.
export function findUserById(id: string) {
  return User.findById(id).populate('role');
}

export function createVirtualUser({
  name,
  accessKey,
  teamId,
  ...fields
}: {
  name: string;
  accessKey?: string;
  teamId: string | ObjectId;
} & Pick<IUser, 'email' | 'expiresAt' | 'createdBy'>) {
  return User.create({
    name,
    team: teamId,
    isVirtual: true,
    accessKey,
    ...fields,
  });
}

export function findUserByEmail(email: string) {
  // Case-insensitive email search - lowercase the email since User model stores emails in lowercase
  return User.findOne({ email: email.toLowerCase() });
}

export function findUserByGoogleId(googleId: string) {
  return User.findOne({ googleId });
}

/**
 * Creates a user provisioned by Google SSO, at the lowest privilege.
 *
 * Returns null when the team has no ReadOnly role, which the caller must
 * treat as a failed login. Creating the user anyway would be worse than
 * refusing: `computeVerdict` fails OPEN for a role-less user on the session
 * path, so a self-service SSO signup would land with admin-equivalent
 * access. Roles are seeded here rather than assumed for the same reason the
 * invite path seeds them — a team created before RBAC shipped has none.
 */
export async function createGoogleUser({
  email,
  teamId,
  googleId,
}: {
  email: string;
  teamId: string | ObjectId;
  googleId: string;
}) {
  const roles = await seedSystemRoles(teamId);
  const readOnlyRole = roles.find(r => r.name === 'ReadOnly');
  if (!readOnlyRole) {
    return null;
  }

  const user = new User({
    email,
    name: email,
    team: teamId,
    googleId,
    role: readOnlyRole._id,
  });
  await user.save();
  return user;
}

export function findUsersByTeam(team: string | ObjectId) {
  // `+salt` re-selects the passport-local-mongoose salt field, which the
  // plugin marks `select: false` by default. The `hasPasswordAuth` virtual
  // reads `this.salt`, so without this projection every user in the result
  // would report `hasPasswordAuth: false` regardless of whether they
  // actually have a password. Do not remove this "unused" projection.
  return User.find({ team, ...NOT_VIRTUAL })
    .select('+salt')
    .sort({ createdAt: 1 });
}

// Type-guard wrapper over the shared 24-hex check; rejects the synthetic
// `_local_user_` id injected in IS_LOCAL_APP_MODE (see isPersistableUserIdHex).
function isPersistableUserId(
  userId: string | ObjectId | undefined | null,
): userId is string | ObjectId {
  return userId != null && isPersistableUserIdHex(String(userId));
}

// Returns null for a non-persistable user so the route reports unchanged
// default state rather than a write that silently matched nothing.
export function completeOnboardingTask(
  userId: string | ObjectId,
  taskId: OnboardingTaskId,
) {
  if (!isPersistableUserId(userId)) {
    return null;
  }
  return User.findByIdAndUpdate(
    userId,
    { $addToSet: { 'onboardingData.completedTasks': taskId } },
    { new: true },
  );
}

export function setOnboardingDismissed(
  userId: string | ObjectId,
  isDismissed: boolean,
) {
  if (!isPersistableUserId(userId)) {
    return null;
  }
  return User.findByIdAndUpdate(
    userId,
    { $set: { 'onboardingData.isDismissed': isDismissed } },
    { new: true },
  );
}

// Fire-and-forget recording from an unrelated write path (alert/dashboard save,
// MCP tool call): must never fail or delay the triggering operation, so errors
// are swallowed. The $ne skips the write once already recorded — these fire on
// every save / tool call, so it avoids write amplification on hot paths.
export function recordOnboardingTaskCompletion(
  userId: string | ObjectId | undefined | null,
  taskId: OnboardingTaskId,
) {
  if (!isPersistableUserId(userId)) {
    return;
  }
  void User.updateOne(
    {
      _id: userId,
      ...NOT_VIRTUAL,
      'onboardingData.completedTasks': { $ne: taskId },
    },
    { $addToSet: { 'onboardingData.completedTasks': taskId } },
  ).catch(err => {
    logger.warn(
      { error: err, userId: userId.toString(), taskId },
      'Failed to record onboarding task completion',
    );
  });
}

/**
 * Never removes the last person, so someone can always sign in to revoke the
 * team's org API keys. Mongo here has no transactions, so delete first and put
 * the member back if a concurrent removal emptied the team.
 */
export async function deleteTeamMember(
  teamId: string | ObjectId,
  userIdToDelete: string,
  userIdRequestingDelete: string | ObjectId,
): Promise<'deleted' | 'not_found' | 'last_member'> {
  const countPeople = () =>
    User.countDocuments({ team: teamId, ...NOT_VIRTUAL });
  const target = { team: teamId, _id: userIdToDelete, ...NOT_VIRTUAL };
  if ((await User.exists(target)) == null) {
    return 'not_found';
  }
  // Checked first so the usual case never deletes; the restore below only
  // covers two removals racing past this check.
  if ((await countPeople()) <= 1) {
    return 'last_member';
  }
  const deletedUser = await User.findOneAndDelete(target)
    .select('+hash +salt')
    .lean();
  if (deletedUser == null) {
    return 'not_found';
  }
  let isTeamEmpty = true;
  try {
    isTeamEmpty = (await countPeople()) === 0;
  } finally {
    // Also runs if the count throws, so a failed check can't lose the member.
    if (isTeamEmpty) {
      await restoreTeamMember(deletedUser);
    }
  }
  if (isTeamEmpty) {
    return 'last_member';
  }
  await Alert.updateMany(
    { createdBy: deletedUser._id, team: teamId },
    {
      $set: { createdBy: new mongoose.Types.ObjectId(userIdRequestingDelete) },
    },
  );
  return 'deleted';
}

const memberRestoreFailures = getCounter(
  'hyperdx.team.member_restore_failures',
  {
    description:
      'Removed team members that could not be put back after the team emptied.',
  },
);

const RESTORE_ATTEMPTS = 3;
const RESTORE_RETRY_DELAY_MS = 100;

async function restoreTeamMember(user: IUser) {
  for (let attempt = 1; ; attempt++) {
    try {
      await User.collection.insertOne(user);
      return;
    } catch (err) {
      const isDuplicate = isDuplicateKeyError(err);
      const keyPattern =
        typeof err === 'object' && err != null && 'keyPattern' in err
          ? err.keyPattern
          : undefined;
      // A duplicate _id means an earlier attempt already landed.
      if (
        isDuplicate &&
        typeof keyPattern === 'object' &&
        keyPattern != null &&
        '_id' in keyPattern
      ) {
        return;
      }
      // Any other duplicate (the email was taken meanwhile) can't succeed.
      if (!isDuplicate && attempt < RESTORE_ATTEMPTS) {
        await new Promise(r => setTimeout(r, RESTORE_RETRY_DELAY_MS * attempt));
        continue;
      }
      memberRestoreFailures.add(1);
      opentelemetry.trace
        .getActiveSpan()
        ?.recordException(err instanceof Error ? err : new Error(String(err)));
      logger.error(
        {
          error: err,
          userId: user._id.toString(),
          teamId: user.team.toString(),
        },
        'Failed to restore a removed team member',
      );
      throw err;
    }
  }
}
