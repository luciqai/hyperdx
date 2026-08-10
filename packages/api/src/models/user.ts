// @ts-ignore don't install the @types for this package, as it conflicts with mongoose
import passportLocalMongoose from '@hyperdx/passport-local-mongoose';
import mongoose, { Schema } from 'mongoose';
import { v4 as uuidv4 } from 'uuid';

type ObjectId = mongoose.Types.ObjectId;

export interface IUser {
  _id: ObjectId;
  accessKey: string;
  createdAt: Date;
  email: string;
  googleId?: string;
  name: string;
  team: ObjectId;
}

export type UserDocument = mongoose.HydratedDocument<IUser>;

const UserSchema = new Schema(
  {
    name: String,
    email: {
      type: String,
      required: true,
    },
    googleId: {
      type: String,
      required: false,
    },
    team: { type: mongoose.Schema.Types.ObjectId, ref: 'Team' },
    accessKey: {
      type: String,
      default: function genUUID() {
        return uuidv4();
      },
    },
  },
  {
    timestamps: true,
  },
);

// Depends on passport-local-mongoose's default `saltField` ('salt') and on
// callers `.select('+salt')`-ing it, since the plugin marks the field
// `select: false`. If the plugin config or a query's projection changes,
// `this.salt` silently becomes `undefined` and this virtual goes stale-false.
UserSchema.virtual('hasPasswordAuth').get(function (this: { salt?: string }) {
  return this.salt != null;
});

UserSchema.plugin(passportLocalMongoose, {
  usernameField: 'email',
  usernameLowerCase: true,
  usernameCaseInsensitive: true,
});

UserSchema.index({ email: 1 }, { unique: true });
UserSchema.index({ accessKey: 1 }, { unique: true });
UserSchema.index({ googleId: 1 }, { unique: true, sparse: true });

export default mongoose.model<IUser>('User', UserSchema);
