import { RoleInputSchema } from '@hyperdx/common-utils/dist/types';
import express from 'express';
import { z } from 'zod';
import { validateRequest } from 'zod-express-middleware';

import {
  createRole,
  deleteRole,
  getRolesWithCounts,
  RoleConflictError,
  updateRole,
} from '@/controllers/role';
import { getNonNullUserWithTeam } from '@/middleware/auth';
import { requireAdmin, requirePermission } from '@/middleware/rbac';
import { objectIdSchema } from '@/utils/zod';

const router = express.Router();

function serialize(role: any) {
  return {
    id: role._id.toString(),
    name: role.name,
    description: role.description,
    isSystem: role.isSystem,
    isAdmin: role.isAdmin,
    permissions: role.permissions,
    ...(role.memberCount != null ? { memberCount: role.memberCount } : {}),
  };
}

router.get('/', requirePermission('team', 'read'), async (req, res, next) => {
  try {
    const { teamId } = getNonNullUserWithTeam(req);
    const roles = await getRolesWithCounts(teamId);
    res.json({ data: roles.map(serialize) });
  } catch (e) {
    next(e);
  }
});

router.post(
  '/',
  requireAdmin(),
  // RoleInputSchema has no isAdmin/isSystem keys, so Zod drops them.
  validateRequest({ body: RoleInputSchema }),
  async (req, res, next) => {
    try {
      const { teamId } = getNonNullUserWithTeam(req);
      const role = await createRole(teamId, req.body);
      res.json(serialize(role));
    } catch (e) {
      if (e instanceof RoleConflictError) {
        return res.status(409).json({ message: e.message });
      }
      next(e);
    }
  },
);

router.patch(
  '/:id',
  requireAdmin(),
  validateRequest({
    body: RoleInputSchema,
    params: z.object({ id: objectIdSchema }),
  }),
  async (req, res, next) => {
    try {
      const { teamId } = getNonNullUserWithTeam(req);
      const role = await updateRole(teamId, req.params.id, req.body);
      res.json(serialize(role));
    } catch (e) {
      if (e instanceof RoleConflictError) {
        return res.status(409).json({ message: e.message });
      }
      next(e);
    }
  },
);

router.delete(
  '/:id',
  requireAdmin(),
  validateRequest({ params: z.object({ id: objectIdSchema }) }),
  async (req, res, next) => {
    try {
      const { teamId } = getNonNullUserWithTeam(req);
      await deleteRole(teamId, req.params.id);
      res.json({ message: 'Role deleted' });
    } catch (e) {
      if (e instanceof RoleConflictError) {
        return res.status(409).json({ message: e.message });
      }
      next(e);
    }
  },
);

export default router;
