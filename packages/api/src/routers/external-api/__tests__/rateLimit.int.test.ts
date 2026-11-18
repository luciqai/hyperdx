import request from 'supertest';

import { getServer } from '@/fixtures';

/**
 * BUG-8's acceptance test, taken verbatim from the reported reproduction
 * (design spec §8.3): 105 distinct garbage bearer tokens from one origin must
 * produce at least one 429.
 *
 * The original defect was the *keying* — `rateLimiterKeyGenerator` returned the
 * Authorization header, so each guess got its own bucket and 105 attempts hit
 * zero 429s. But keying is only half of it: with a shared bucket and a 300/min
 * ceiling the same reproduction still returns zero 429s, because 105 < 300. The
 * mechanism and the threshold have to be right together, so this asserts on the
 * reproduction rather than on the key generator (which
 * `utils/__tests__/rateLimiter.test.ts` covers directly).
 *
 * `GET /api/v2` is the route the report called a validity oracle, and is the
 * cheapest failing request on the surface.
 */
describe('external API v2 auth-attempt rate limiting', () => {
  const server = getServer();

  beforeAll(async () => {
    await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('429s a burst of 105 distinct garbage bearers from one origin', async () => {
    const http = server.getHttpServer();
    const statuses: number[] = [];

    // Sequential, not parallel: the limiter counts requests, and a burst that
    // races the store could in principle let attempts overlap. Sequential is
    // also the shape the report used.
    for (let i = 0; i < 105; i++) {
      const res = await request(http)
        .get('/api/v2')
        .set('Authorization', `Bearer garbage-access-key-${i}`);
      statuses.push(res.status);
    }

    // The headline assertion, stated exactly as the report did.
    expect(statuses).toContain(429);

    // Every attempt must genuinely have failed auth — a 200 anywhere here would
    // mean the fixture accidentally minted a matching key and the 429s proved
    // nothing about guessing.
    expect(statuses.every(s => s === 401 || s === 429)).toBe(true);

    // The budget counts only failures (`skipSuccessfulRequests`), so the number
    // of attempts that got as far as auth is the ceiling itself. Asserting the
    // shape — not just "a 429 happened somewhere" — keeps this honest if the
    // ceiling is ever raised back above the reproduction volume.
    const rejected = statuses.filter(s => s === 429).length;
    expect(rejected).toBeGreaterThanOrEqual(105 - 30);
    expect(statuses.slice(0, 30)).not.toContain(429);
  }, 60_000);
});
