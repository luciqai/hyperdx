import express from 'express';

import { validateUserAccessKey } from '@/middleware/auth';
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
// bucket (BUG-8).
//
// `skipSuccessfulRequests` is what makes this a *failed-attempt* meter rather
// than a second traffic limiter. Without it, a shared origin — one NAT, one
// corporate proxy, one CI runner — spends this budget on legitimate
// authenticated traffic, and four users each staying inside their own 100/min
// `defaultRateLimiter` allowance would 429 the whole /api/v2 surface for
// everyone behind that IP. Throughput is governed per-user, behind auth.
//
// Because the budget counts *only failures*, 30/min is generous rather than
// tight: a legitimate client essentially never fails authentication — a failed
// bearer means a wrong or revoked key — so legitimate traffic never touches
// this bucket at all. The ceiling therefore has to sit far below any plausible
// guessing volume, not near normal request volume. BUG-8's reported
// reproduction was 105 distinct garbage bearers in one window; a limit above
// that still returns zero 429s no matter how correct the keying is.
const authAttemptRateLimiter = rateLimiter({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: ipOnlyKeyGenerator,
});

/**
 * The entry stack every /api/v2 mount shares. The order is security
 * load-bearing and is the reason this is one array rather than nine
 * hand-written copies:
 *
 *  1. `authAttemptRateLimiter` must sit in FRONT of authentication — it meters
 *     failed key guesses, which never reach a later middleware (BUG-8).
 *  2. `validateUserAccessKey` establishes `req.user`.
 *  3. `defaultRateLimiter` keys on that authenticated user, so it must follow.
 *
 * Express flattens an array of handlers, so this mounts identically to listing
 * the three inline.
 */
const authenticatedV2 = [
  authAttemptRateLimiter,
  validateUserAccessKey,
  defaultRateLimiter,
];

router.get('/', authenticatedV2, (req, res) => {
  res.json({
    version: 'v2',
    user: req.user?.toJSON(),
  });
});

router.use('/alerts', authenticatedV2, alertsRouter);

router.use('/charts', authenticatedV2, chartsRouter);

router.use('/connections', authenticatedV2, connectionsRouter);

router.use('/dashboards', authenticatedV2, dashboardRouter);

router.use('/sources', authenticatedV2, sourcesRouter);

router.use('/saved-searches', authenticatedV2, savedSearchesRouter);

router.use('/search', authenticatedV2, searchRouter);

router.use('/webhooks', authenticatedV2, webhooksRouter);

router.use('/team', authenticatedV2, teamRouter);

export default router;
