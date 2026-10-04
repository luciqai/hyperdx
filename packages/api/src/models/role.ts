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
