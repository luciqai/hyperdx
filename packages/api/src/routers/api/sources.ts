import {
  SourceSchema,
  SourceSchemaNoId,
} from '@hyperdx/common-utils/dist/types';
import express from 'express';
import { z } from 'zod';
import { validateRequest } from 'zod-express-middleware';

import {
  getConnectionsByTeam,
  validateConnectionId,
} from '@/controllers/connection';
import {
  createSource,
  deleteSource,
  getSources,
  updateSource,
} from '@/controllers/sources';
import { getNonNullUserWithTeam } from '@/middleware/auth';
import { requirePermission } from '@/middleware/rbac';
import { objectIdSchema } from '@/utils/zod';

const router = express.Router();

router.get(
  '/',
  requirePermission('sources', 'read'),
  async (req, res, next) => {
    try {
      const { teamId } = getNonNullUserWithTeam(req);

      // BUG-5. The list view previously fetched /connections itself just to
      // render a name, which requires connections:read — `none` for Member and
      // ReadOnly, so a sources:read grant produced a permanent 403 banner.
      // Resolving the name here keeps the section's data need inside its own
      // gate.
      const [sources, connections] = await Promise.all([
        getSources(teamId.toString()),
        getConnectionsByTeam(teamId.toString()),
      ]);

      const connectionNameById = new Map(
        connections.map(c => [c._id.toString(), c.name]),
      );

      return res.json(
        sources.map(source => ({
          // @ts-expect-error source.toJSON has incompatible type signatures but is actually a safe operation
          ...source.toJSON({ getters: true }),
          connectionName:
            connectionNameById.get(source.connection?.toString()) ?? null,
        })),
      );
    } catch (e) {
      next(e);
    }
  },
);

router.post(
  '/',
  requirePermission('sources', 'manage'),
  validateRequest({
    body: SourceSchemaNoId,
  }),
  async (req, res, next) => {
    try {
      const { teamId } = getNonNullUserWithTeam(req);

      const connectionCheck = await validateConnectionId(
        req.body.connection,
        teamId,
      );
      if (!connectionCheck.ok) {
        return res
          .status(connectionCheck.status)
          .json({ message: connectionCheck.message });
      }

      const source = await createSource(teamId.toString(), {
        ...req.body,
        team: teamId.toString(),
      });

      res.json(source);
    } catch (e) {
      next(e);
    }
  },
);

router.put(
  '/:id',
  requirePermission('sources', 'manage'),
  validateRequest({
    body: SourceSchema,
    params: z.object({
      id: objectIdSchema,
    }),
  }),
  async (req, res, next) => {
    try {
      const { teamId } = getNonNullUserWithTeam(req);

      const connectionCheck = await validateConnectionId(
        req.body.connection,
        teamId,
      );
      if (!connectionCheck.ok) {
        return res
          .status(connectionCheck.status)
          .json({ message: connectionCheck.message });
      }

      const source = await updateSource(teamId.toString(), req.params.id, {
        ...req.body,
        team: teamId.toString(),
      });

      if (!source) {
        res.status(404).send('Source not found');
        return;
      }

      return res.status(200).send();
    } catch (e) {
      next(e);
    }
  },
);

router.delete(
  '/:id',
  requirePermission('sources', 'manage'),
  validateRequest({
    params: z.object({
      id: objectIdSchema,
    }),
  }),
  async (req, res, next) => {
    try {
      const { teamId } = getNonNullUserWithTeam(req);

      await deleteSource(teamId.toString(), req.params.id);

      return res.status(200).send();
    } catch (e) {
      next(e);
    }
  },
);

export default router;
