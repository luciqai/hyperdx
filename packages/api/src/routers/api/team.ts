import type {
  RotateApiKeyApiResponse,
  TeamApiResponse,
  TeamInvitationsApiResponse,
  TeamMembersApiResponse,
  TeamTagsApiResponse,
  UpdateClickHouseSettingsApiResponse,
} from '@hyperdx/common-utils/dist/types';
import { TeamClickHouseSettingsUpdateSchema } from '@hyperdx/common-utils/dist/types';
import crypto from 'crypto';
import express from 'express';
import pick from 'lodash/pick';
import { z } from 'zod';
import { processRequest, validateRequest } from 'zod-express-middleware';

import { assignRole, isLastAdmin, RoleConflictError } from '@/controllers/role';
import {
  getTags,
  getTeam,
  getTeamInviteUrl,
  rotateTeamApiKey,
  setTeamName,
  updateTeamClickhouseSettings,
} from '@/controllers/team';
import {
  deleteTeamMember,
  findUserByEmail,
  findUsersByTeam,
} from '@/controllers/user';
import { getNonNullUserWithTeam } from '@/middleware/auth';
import { requireAdmin, requirePermission } from '@/middleware/rbac';
import TeamInvite from '@/models/teamInvite';
import User from '@/models/user';
import rolesRouter from '@/routers/api/roles';
import { sendJson } from '@/utils/serialization';
import { objectIdSchema } from '@/utils/zod';

const router = express.Router();

// Mounted first so `/team/roles` is never shadowed by a sibling `/:param`
// route. The sub-router carries its own RBAC declarations.
router.use('/roles', rolesRouter);

type TeamApiExpRes = express.Response<TeamApiResponse>;
router.get(
  '/',
  requirePermission('team', 'read'),
  async (req, res: TeamApiExpRes, next) => {
    try {
      const teamId = req.user?.team;
      const userId = req.user?._id;

      if (teamId == null) {
        throw new Error(`User ${req.user?._id} not associated with a team`);
      }
      if (userId == null) {
        throw new Error(`User has no id`);
      }

      const fields = [
        '_id',
        'allowedAuthMethods',
        'apiKey',
        'name',
        'createdAt',
      ] as const;
      const team = await getTeam(teamId, fields);
      if (team == null) {
        throw new Error(`Team ${teamId} not found for user ${userId}`);
      }

      sendJson(res, team);
    } catch (e) {
      next(e);
    }
  },
);

type RotateApiKeyExpRes = express.Response<RotateApiKeyApiResponse>;
// Hard capability: rotating the ingestion key breaks every running collector,
// so it is admin-only and deliberately not expressible as a permission.
router.patch(
  '/apiKey',
  requireAdmin(),
  async (req, res: RotateApiKeyExpRes, next) => {
    try {
      const teamId = req.user?.team;
      if (teamId == null) {
        throw new Error(`User ${req.user?._id} not associated with a team`);
      }
      const team = await rotateTeamApiKey(teamId);
      if (team?.apiKey == null) {
        throw new Error(`Failed to rotate API key for team ${teamId}`);
      }
      res.json({ newApiKey: team.apiKey });
    } catch (e) {
      next(e);
    }
  },
);

router.patch(
  '/name',
  requirePermission('team', 'manage'),
  validateRequest({
    body: z.object({
      name: z.string().min(1).max(100),
    }),
  }),
  async (req, res, next) => {
    try {
      const teamId = req.user?.team;
      if (teamId == null) {
        throw new Error(`User ${req.user?._id} not associated with a team`);
      }
      const { name } = req.body;
      const team = await setTeamName(teamId, name);
      res.json({ name: team?.name });
    } catch (e) {
      next(e);
    }
  },
);

router.patch(
  '/clickhouse-settings',
  requirePermission('team', 'manage'),
  processRequest({
    body: TeamClickHouseSettingsUpdateSchema,
  }),
  async (
    req,
    res: express.Response<UpdateClickHouseSettingsApiResponse>,
    next,
  ) => {
    try {
      const teamId = req.user?.team;
      if (teamId == null) {
        throw new Error(`User ${req.user?._id} not associated with a team`);
      }

      if (Object.keys(req.body).length === 0) {
        return res.json({});
      }

      const team = await updateTeamClickhouseSettings(teamId, req.body);

      res.json(pick(team, Object.keys(req.body)));
    } catch (e) {
      next(e);
    }
  },
);

router.post(
  '/invitation',
  requireAdmin(),
  validateRequest({
    body: z.object({
      email: z.string().email(),
      name: z.string().optional(),
    }),
  }),
  async (req, res, next) => {
    try {
      const { email: toEmail, name } = req.body;
      const teamId = req.user?.team;
      const fromEmail = req.user?.email;

      if (teamId == null) {
        throw new Error(`User ${req.user?._id} not associated with a team`);
      }

      if (fromEmail == null) {
        throw new Error(`User ${req.user?._id} doesnt have email`);
      }

      const toUser = await findUserByEmail(toEmail);
      if (toUser) {
        return res.status(400).json({
          message:
            'User already exists. Please contact HyperDX team for support',
        });
      }

      // Normalize email to lowercase for consistency
      const normalizedEmail = toEmail.toLowerCase();

      // Check for existing invitation with normalized email
      let teamInvite = await TeamInvite.findOne({
        teamId,
        email: normalizedEmail,
      });

      if (!teamInvite) {
        teamInvite = await new TeamInvite({
          teamId,
          name,
          email: normalizedEmail,
          token: crypto.randomBytes(32).toString('hex'),
        }).save();
      }

      res.json({
        url: getTeamInviteUrl(teamInvite.token),
      });
    } catch (e) {
      next(e);
    }
  },
);

type TeamInviteExpressRes = express.Response<TeamInvitationsApiResponse>;
router.get(
  '/invitations',
  requirePermission('users', 'read'),
  async (req, res: TeamInviteExpressRes, next) => {
    try {
      const teamId = req.user?.team;
      if (teamId == null) {
        throw new Error(`User ${req.user?._id} not associated with a team`);
      }
      const teamInvites = await TeamInvite.find(
        { teamId },
        {
          createdAt: 1,
          email: 1,
          name: 1,
          token: 1,
        },
      );
      res.json({
        data: teamInvites.map(ti => ({
          _id: ti._id.toString(),
          createdAt: ti.createdAt.toISOString(),
          email: ti.email,
          name: ti.name,
          url: getTeamInviteUrl(ti.token),
        })),
      });
    } catch (e) {
      next(e);
    }
  },
);

router.delete(
  '/invitation/:id',
  requireAdmin(),
  validateRequest({
    params: z.object({
      id: objectIdSchema,
    }),
  }),
  async (req, res, next) => {
    try {
      const id = req.params.id;
      const teamId = req.user?.team;
      if (teamId == null) {
        throw new Error(`User ${req.user?._id} not associated with a team`);
      }

      // Scoped by team: deleting by _id alone let any authenticated user of
      // any team remove another team's pending invite.
      const deleted = await TeamInvite.findOneAndDelete({ _id: id, teamId });
      if (!deleted) {
        return res.status(404).json({ message: 'TeamInvite not found' });
      }

      return res.json({ message: 'TeamInvite deleted' });
    } catch (e) {
      next(e);
    }
  },
);

type TeamMembersExpRes = express.Response<TeamMembersApiResponse>;
router.get(
  '/members',
  requirePermission('users', 'read'),
  async (req, res: TeamMembersExpRes, next) => {
    try {
      const teamId = req.user?.team;
      const userId = req.user?._id;
      if (teamId == null) {
        throw new Error(`User ${req.user?._id} not associated with a team`);
      }
      if (userId == null) {
        throw new Error(`User has no id`);
      }
      const teamUsers = await findUsersByTeam(teamId);
      await User.populate(teamUsers, { path: 'role' });
      res.json({
        data: teamUsers.map(user => ({
          ...pick(user.toJSON({ virtuals: true }), [
            '_id',
            'email',
            'name',
            'hasPasswordAuth',
          ]),
          roleId: (user.role as any)?._id?.toString() ?? null,
          roleName: (user.role as any)?.name ?? null,
          isCurrentUser: user._id.equals(userId),
        })),
      });
    } catch (e) {
      next(e);
    }
  },
);

// Hard capability: assigning roles is admin-only, so no custom role can grant
// the ability to hand out privileges.
router.patch(
  '/members/:id/role',
  requireAdmin(),
  validateRequest({
    body: z.object({ roleId: objectIdSchema }),
    params: z.object({ id: objectIdSchema }),
  }),
  async (req, res, next) => {
    try {
      const { teamId } = getNonNullUserWithTeam(req);
      await assignRole(teamId, req.params.id, req.body.roleId);
      res.json({ message: 'Role updated' });
    } catch (e) {
      if (e instanceof RoleConflictError) {
        return res.status(409).json({ message: e.message });
      }
      next(e);
    }
  },
);

router.delete(
  '/member/:id',
  requireAdmin(),
  validateRequest({
    params: z.object({
      id: objectIdSchema,
    }),
  }),
  async (req, res, next) => {
    try {
      const userIdToDelete = req.params.id;
      const teamId = req.user?.team;
      if (teamId == null) {
        throw new Error(`User ${req.user?._id} not associated with a team`);
      }

      const userIdRequestingDelete = req.user?._id;
      if (!userIdRequestingDelete) {
        throw new Error(`Requesting user has no id`);
      }

      // Same invariant as role reassignment: a team must always keep one admin.
      if (await isLastAdmin(teamId, userIdToDelete)) {
        return res.status(409).json({
          message:
            "The last admin can't be removed. Promote someone else first.",
        });
      }

      await deleteTeamMember(teamId, userIdToDelete, userIdRequestingDelete);

      res.json({ message: 'User deleted' });
    } catch (e) {
      next(e);
    }
  },
);

type TeamTagsExpRes = express.Response<TeamTagsApiResponse>;
router.get(
  '/tags',
  requirePermission('team', 'read'),
  async (req, res: TeamTagsExpRes, next) => {
    try {
      const teamId = req.user?.team;
      if (teamId == null) {
        throw new Error(`User ${req.user?._id} not associated with a team`);
      }
      const tags = await getTags(teamId);
      return res.json({ data: tags });
    } catch (e) {
      next(e);
    }
  },
);

export default router;
