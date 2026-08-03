import mongoose from 'mongoose';

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

export function findUsersByTeam(team: string | ObjectId) {
  return User.find({ team }).sort({ createdAt: 1 });
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
