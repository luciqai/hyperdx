import type { MeApiResponse } from '@hyperdx/common-utils/dist/types';
import express from 'express';

import { AI_API_KEY, ANTHROPIC_API_KEY, USAGE_STATS_ENABLED } from '@/config';
import { getTeam } from '@/controllers/team';
import { noPermissionRequired } from '@/middleware/rbac';
import { Api404Error } from '@/utils/errors';
import { sendJson } from '@/utils/serialization';

const router = express.Router();

// Personal state. Gating this would deny every non-admin their own access key,
// and with it all CLI and MCP access.
router.get(
  '/',
  noPermissionRequired('personal-state'),
  async (req, res: express.Response<MeApiResponse>, next) => {
    try {
      if (req.user == null) {
        throw new Api404Error('Request without user found');
      }

      const {
        _id: id,
        accessKey,
        createdAt,
        email,
        name,
        team: teamId,
      } = req.user;

      const team = await getTeam(teamId);
      if (team == null) {
        throw new Api404Error(`Team not found for user ${id}`);
      }

      // Populated by findUserById in passport's deserializeUser. Null until the
      // RBAC migration has run — the server fails open as admin in that case.
      const role = (req.user as any)?.role;

      return sendJson(res, {
        accessKey,
        createdAt,
        email,
        id,
        name,
        role: role
          ? {
              id: role._id.toString(),
              name: role.name,
              description: role.description,
              isSystem: role.isSystem,
              isAdmin: role.isAdmin,
              permissions: role.permissions,
            }
          : null,
        team,
        usageStatsEnabled: USAGE_STATS_ENABLED,
        aiAssistantEnabled: !!(AI_API_KEY || ANTHROPIC_API_KEY),
      });
    } catch (e) {
      next(e);
    }
  },
);

export default router;
