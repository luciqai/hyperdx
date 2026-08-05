import express from 'express';

import { validateUserAccessKey } from '@/middleware/auth';
import { noPermissionRequired } from '@/middleware/rbac';
import alertsRouter from '@/routers/external-api/v2/alerts';
import chartsRouter from '@/routers/external-api/v2/charts';
import connectionsRouter from '@/routers/external-api/v2/connections';
import dashboardRouter from '@/routers/external-api/v2/dashboards';
import savedSearchesRouter from '@/routers/external-api/v2/savedSearches';
import searchRouter from '@/routers/external-api/v2/search';
import sourcesRouter from '@/routers/external-api/v2/sources';
import teamRouter from '@/routers/external-api/v2/team';
import webhooksRouter from '@/routers/external-api/v2/webhooks';
import rateLimiter, {
  ipOnlyKeyGenerator,
  rateLimiterKeyGenerator,
} from '@/utils/rateLimiter';

const router = express.Router();

// Runs AFTER validateUserAccessKey so it can key on the authenticated user.
const defaultRateLimiter = rateLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // Limit each user to 100 requests per `window`
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  keyGenerator: rateLimiterKeyGenerator,
});

// Runs BEFORE authentication, so failed key guesses from one origin share a
// bucket (BUG-8). Generous enough not to bite a legitimate multi-user NAT.
const authAttemptRateLimiter = rateLimiter({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: ipOnlyKeyGenerator,
});

router.get(
  '/',
  authAttemptRateLimiter,
  validateUserAccessKey,
  defaultRateLimiter,
  // Identity check: returns the caller's own user record.
  noPermissionRequired('personal-state'),
  (req, res) => {
    res.json({
      version: 'v2',
      user: req.user?.toJSON(),
    });
  },
);

router.use(
  '/alerts',
  authAttemptRateLimiter,
  validateUserAccessKey,
  defaultRateLimiter,
  alertsRouter,
);

router.use(
  '/charts',
  authAttemptRateLimiter,
  validateUserAccessKey,
  defaultRateLimiter,
  chartsRouter,
);

router.use(
  '/connections',
  authAttemptRateLimiter,
  validateUserAccessKey,
  defaultRateLimiter,
  connectionsRouter,
);

router.use(
  '/dashboards',
  authAttemptRateLimiter,
  validateUserAccessKey,
  defaultRateLimiter,
  dashboardRouter,
);

router.use(
  '/sources',
  authAttemptRateLimiter,
  validateUserAccessKey,
  defaultRateLimiter,
  sourcesRouter,
);

router.use(
  '/saved-searches',
  authAttemptRateLimiter,
  validateUserAccessKey,
  defaultRateLimiter,
  savedSearchesRouter,
);

router.use(
  '/search',
  authAttemptRateLimiter,
  validateUserAccessKey,
  defaultRateLimiter,
  searchRouter,
);

router.use(
  '/webhooks',
  authAttemptRateLimiter,
  validateUserAccessKey,
  defaultRateLimiter,
  webhooksRouter,
);

router.use(
  '/team',
  authAttemptRateLimiter,
  validateUserAccessKey,
  defaultRateLimiter,
  teamRouter,
);

export default router;
