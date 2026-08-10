import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as LocalStrategy } from 'passport-local';

import * as config from '@/config';
import { getSoleTeam } from '@/controllers/team';
import {
  findUserByEmail,
  findUserByGoogleId,
  findUserById,
} from '@/controllers/user';
import type { UserDocument } from '@/models/user';
import User from '@/models/user';
import { evaluateGoogleProfile } from '@/utils/googleAuth';

import logger from './logger';

passport.serializeUser(function (user, done) {
  done(null, (user as any)._id);
});

passport.deserializeUser(function (id: string, done) {
  findUserById(id)
    .then(user => {
      if (user == null) {
        return done(new Error('User not found'));
      }
      done(null, user as UserDocument);
    })
    .catch(done);
});

// Use local passport strategy via passport-local-mongoose plugin
const passportLocalMongooseAuthenticate = (User as any).authenticate();

passport.use(
  new LocalStrategy(
    {
      usernameField: 'email',
    },
    async function (username, password, done) {
      try {
        const { user, error } = await passportLocalMongooseAuthenticate(
          username,
          password,
        );
        if (error) {
          logger.info({
            message: `Login for "${username}" failed, ${error}"`,
            type: 'user_login',
            authType: 'password',
          });
        }
        return done(null, user, error);
      } catch (err) {
        logger.error({ err, username }, 'Login failed with error');
        return done(err);
      }
    },
  ),
);

if (config.IS_GOOGLE_AUTH_ENABLED) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: config.GOOGLE_CLIENT_ID,
        clientSecret: config.GOOGLE_CLIENT_SECRET,
        callbackURL: config.GOOGLE_REDIRECT_URI,
        scope: ['openid', 'email', 'profile'],
        // Session-backed CSRF state. The session middleware is already
        // installed ahead of passport in api-app.ts.
        state: true,
      },
      async function (_accessToken, _refreshToken, profile, done) {
        try {
          const claims = profile._json as {
            email?: string;
            email_verified?: boolean;
          };
          const email = claims.email ?? profile.emails?.[0]?.value;
          const emailVerified = claims.email_verified === true;

          const byGoogleId = await findUserByGoogleId(profile.id);
          const byEmail =
            byGoogleId == null && email != null
              ? await findUserByEmail(email)
              : null;

          const existingUser = byGoogleId
            ? ({ user: byGoogleId, matchedBy: 'googleId' } as const)
            : byEmail
              ? ({ user: byEmail, matchedBy: 'email' } as const)
              : null;

          const decision = evaluateGoogleProfile(
            { googleId: profile.id, email, emailVerified },
            {
              allowedDomains: config.GOOGLE_ALLOWED_DOMAINS,
              existingUser,
              soleTeam: existingUser ? null : await getSoleTeam(),
            },
          );

          if (decision.action === 'reject') {
            logger.info({
              message: `Google login for "${email}" rejected: ${decision.code}`,
              type: 'user_login',
              authType: 'google',
            });
            return done(null, false, { message: decision.code });
          }

          if (decision.action === 'provision') {
            const created = new User({
              email: decision.email,
              name: decision.email,
              team: decision.team._id,
              googleId: profile.id,
            });
            await created.save();
            logger.info({
              message: `Provisioned user "${decision.email}" via Google`,
              type: 'user_login',
              authType: 'google',
            });
            return done(null, created);
          }

          if (decision.stampGoogleId) {
            decision.user.googleId = profile.id;
            await decision.user.save();
          }
          return done(null, decision.user);
        } catch (err) {
          logger.error({ err }, 'Google login failed with error');
          return done(err as Error);
        }
      },
    ),
  );
}

export default passport;
