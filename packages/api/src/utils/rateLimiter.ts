import express from 'express';
import rateLimit, { Options } from 'express-rate-limit';

/**
 * Buckets authenticated traffic per user.
 *
 * BUG-8: this previously returned `req.headers.authorization`, which gives
 * every *guessed* key its own bucket — 105 distinct garbage bearers from one
 * origin produced zero 429s. Never key a limiter on the credential it is meant
 * to protect. Callers must place this AFTER authentication so `req.user` is
 * populated; before it, every request collapses to the origin bucket.
 *
 * express-rate-limit is pinned at 6.x, which has no `ipKeyGenerator` helper,
 * so IPv6 addresses are bucketed exactly rather than by subnet.
 */
export const rateLimiterKeyGenerator = (req: express.Request): string => {
  const userId = (req.user as any)?._id?.toString();
  if (userId) return `user:${userId}`;
  return `ip:${req.ip ?? 'unknown'}`;
};

/**
 * Buckets by origin regardless of identity, for limiters that sit in FRONT of
 * authentication so failed key guesses are metered.
 */
export const ipOnlyKeyGenerator = (req: express.Request): string =>
  `ip:${req.ip ?? 'unknown'}`;

export default (config?: Partial<Options>) => {
  return rateLimit({
    ...config,
  });
};
