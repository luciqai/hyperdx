import type { InstallationApiResponse } from '@hyperdx/common-utils/dist/types';
import express from 'express';
import { serializeError } from 'serialize-error';
import { z } from 'zod';
import { validateRequest } from 'zod-express-middleware';

import * as config from '@/config';
import {
  generateAlertSilenceToken,
  silenceAlertByToken,
} from '@/controllers/alerts';
import { seedSystemRoles } from '@/controllers/role';
import { createTeam, isTeamExisting } from '@/controllers/team';
import { handleAuthError, redirectToDashboard } from '@/middleware/auth';
import { noPermissionRequired } from '@/middleware/rbac';
import TeamInvite from '@/models/teamInvite';
import User from '@/models/user'; // TODO -> do not import model directly
import { setupTeamDefaults } from '@/setupDefaults';
import logger from '@/utils/logger';
import passport from '@/utils/passport';
import { passwordSchema, validatePassword } from '@/utils/validators';

const registrationSchema = z
  .object({
    email: z.string().email(),
    password: passwordSchema,
    confirmPassword: z.string(),
  })
  .refine(data => data.password === data.confirmPassword, {
    message: "Passwords don't match",
    path: ['confirmPassword'],
  });

const router = express.Router();

router.get('/health', noPermissionRequired('public'), async (req, res) => {
  res.send({
    data: 'OK',
    version: config.CODE_VERSION,
    ip: req.ip,
    env: config.NODE_ENV,
  });
});

type InstallationEspRes = express.Response<InstallationApiResponse>;
router.get(
  '/installation',
  noPermissionRequired('public'),
  async (_, res: InstallationEspRes, next) => {
    try {
      const _isTeamExisting = await isTeamExisting();
      return res.json({
        isTeamExisting: _isTeamExisting,
      });
    } catch (e) {
      next(e);
    }
  },
);

router.post(
  '/login/password',
  noPermissionRequired('public'),
  passport.authenticate('local', {
    failWithError: true,
    failureMessage: true,
  }),
  redirectToDashboard,
  handleAuthError,
);

router.post(
  '/register/password',
  noPermissionRequired('public'),
  validateRequest({ body: registrationSchema }),
  async (req, res, next) => {
    try {
      const { email, password } = req.body;

      if (await isTeamExisting()) {
        return res.status(409).json({ error: 'teamAlreadyExists' });
      }

      (User as any).register(
        new User({ email }),
        password,
        async (err: Error, user: any) => {
          if (err) {
            logger.error(
              { err: serializeError(err) },
              'User registration error',
            );
            return res.status(400).json({ error: 'invalid' });
          }

          const team = await createTeam({
            name: `${email}'s Team`,
            collectorAuthenticationEnforced: true,
          });
          user.team = team._id;
          user.name = email;

          // The founder of a team is its first admin. Seeding here (rather
          // than in setupTeamDefaults) keeps the role assignment on the same
          // save as the team association, so a user can never exist without a
          // role on a freshly created team.
          const roles = await seedSystemRoles(team._id);
          const adminRole = roles.find(r => r.isAdmin);
          if (adminRole) {
            user.role = adminRole._id;
          }

          await user.save();

          // Set up default connections and sources for this new team
          try {
            await setupTeamDefaults(team._id.toString());
          } catch (error) {
            logger.error(
              { err: serializeError(error) },
              'Failed to setup team defaults',
            );
            // Continue with registration even if setup defaults fails
          }

          return passport.authenticate('local')(req, res, () => {
            if (req?.user?.team) {
              return res.status(200).json({ status: 'success' });
            }

            logger.error(
              { userId: req?.user?._id },
              'Password login for user failed, user or team not found',
            );
            return res.status(400).json({ error: 'invalid' });
          });
        },
      );
    } catch (e) {
      next(e);
    }
  },
);

router.get('/logout', noPermissionRequired('public'), (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect(`${config.FRONTEND_REDIRECT_BASE}/login`);
  });
});

// TODO: rename this ?
router.post(
  '/team/setup/:token',
  noPermissionRequired('public'),
  async (req, res, next) => {
    try {
      const { password } = req.body;
      const { token } = req.params;

      if (!validatePassword(password)) {
        return res.redirect(
          `${config.FRONTEND_REDIRECT_BASE}/join-team?err=invalid&token=${token}`,
        );
      }

      const teamInvite = await TeamInvite.findOne({
        token: req.params.token,
      });
      if (!teamInvite) {
        return res.status(401).send('Invalid token');
      }

      // Roles are seeded at team creation, but seed defensively: a team
      // created before RBAC shipped has none, and a user saved without a role
      // would fail OPEN as admin (see spec §11.3) — silently making every
      // invited member a full administrator.
      const inviteRoles = await seedSystemRoles(teamInvite.teamId);
      const memberRole = inviteRoles.find(r => r.name === 'Member');
      if (!memberRole) {
        logger.error(
          { teamId: teamInvite.teamId?.toString() },
          'Team setup aborted: could not resolve the Member role',
        );
        return res.redirect(
          `${config.FRONTEND_REDIRECT_BASE}/join-team?token=${token}&err=500`,
        );
      }

      (User as any).register(
        new User({
          email: teamInvite.email,
          name: teamInvite.email,
          team: teamInvite.teamId,
          role: memberRole._id,
        }),
        password,
        async (err: Error, user: any) => {
          if (err) {
            logger.error({ err: serializeError(err) }, 'Team setup error');
            return res.redirect(
              `${config.FRONTEND_REDIRECT_BASE}/join-team?token=${token}&err=500`,
            );
          }

          await TeamInvite.findByIdAndRemove(teamInvite._id);

          req.login(user, err => {
            if (err) {
              return next(err);
            }
            redirectToDashboard(req, res);
          });
        },
      );
    } catch (e) {
      next(e);
    }
  },
);

router.get(
  '/ext/silence-alert/:token',
  noPermissionRequired('public'),
  async (req, res) => {
    let isError = false;

    try {
      const token = req.params.token;
      await silenceAlertByToken(token);
    } catch (e) {
      isError = true;
      logger.error({ err: e }, 'Failed to silence alert');
    }

    // TODO: Create a template for utility pages
    return res.send(`
  <html>
    <head>
      <title>HyperDX</title>
      <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.classless.min.css" />
    </head>
    <body>
      <header>
        <img src="https://www.hyperdx.io/Icon32.png" />
      </header>
      <main>
        ${
          isError
            ? '<p><strong>Link is invalid or expired.</strong> Please try again.</p>'
            : '<p><strong>Alert silenced.</strong> You can close this window now.</p>'
        }
        <a href="${config.FRONTEND_URL}">Back to HyperDX</a>
      </main>
    </body>
  </html>`);
  },
);

export default router;
