import mongoose from 'mongoose';

import type { ObjectId } from '@/models';
import Alert from '@/models/alert';
import User from '@/models/user';
export function findUserByAccessKey(accessKey: string) {
  return User.findOne({ accessKey });
}

export function findUserById(id: string) {
  return User.findById(id);
}

export function findUserByEmail(email: string) {
  // Case-insensitive email search - lowercase the email since User model stores emails in lowercase
  return User.findOne({ email: email.toLowerCase() });
}

export function findUserByGoogleId(googleId: string) {
  return User.findOne({ googleId });
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
