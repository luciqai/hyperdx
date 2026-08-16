import mongoose from 'mongoose';

import { seedSystemRoles } from '@/controllers/role';
import type { ObjectId } from '@/models';
import Alert from '@/models/alert';
import User from '@/models/user';
// Populated for the same reason as findUserById: RBAC reads req.user.role.
// Without this the Bearer path (MCP + External API v2) always saw a missing
// role, which the resolver would treat as fail-open admin.
export function findUserByAccessKey(accessKey: string) {
  return User.findOne({ accessKey }).populate('role');
}

// Populated on every session request via passport's deserializeUser, so RBAC
// middleware can read req.user.role without an extra round trip.
export function findUserById(id: string) {
  return User.findById(id).populate('role');
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
  return User.find({ team }).select('+salt').sort({ createdAt: 1 });
}

export async function deleteTeamMember(
  teamId: string | ObjectId,
  userIdToDelete: string,
  userIdRequestingDelete: string | ObjectId,
) {
  const [, deletedUser] = await Promise.all([
    Alert.updateMany(
      { createdBy: new mongoose.Types.ObjectId(userIdToDelete), team: teamId },
      {
        $set: {
          createdBy: new mongoose.Types.ObjectId(userIdRequestingDelete),
        },
      },
    ),
    User.findOneAndDelete({
      team: teamId,
      _id: userIdToDelete,
    }),
  ]);

  return deletedUser;
}
