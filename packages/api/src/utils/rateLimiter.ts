import express from 'express';
import rateLimit, { MemoryStore, Options } from 'express-rate-limit';

/** Matches an IPv4-mapped IPv6 address (`::ffff:1.2.3.4`). */
// Written out rather than `(?:\.\d{1,3}){3}` — a nested quantifier here is
// harmless but trips the ReDoS lint, and the flat form is no less readable.
const IPV4_MAPPED_PATTERN = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i;

/** A single IPv6 hextet: one to four hex digits. */
const HEXTET_PATTERN = /^[0-9a-f]{1,4}$/i;

/**
 * Expands an IPv6 address to its eight groups, or null if it does not parse.
 *
 * Only the first four groups are load-bearing for `/64` bucketing, but the
 * whole address has to be expanded first: `::` elides a variable number of
 * groups, so `2001:db8::1` and `2001:db8:1:2:3:4:5:6` do not line up
 * positionally until the elision is filled in.
 */
function expandIpv6(ip: string): string[] | null {
  const halves = ip.split('::');
  if (halves.length > 2) return null; // `::` may appear at most once

  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];

  let groups: string[];
  if (halves.length === 1) {
    if (head.length !== 8) return null;
    groups = head;
  } else {
    const elided = 8 - head.length - tail.length;
    if (elided < 0) return null;
    groups = [...head, ...Array<string>(elided).fill('0'), ...tail];
  }

  // Only the /64 prefix is used, so only those groups need to be well formed.
  // A trailing embedded IPv4 literal (`64:ff9b::1.2.3.4`) is left alone: it
  // can never fall inside the first four groups.
  const prefix = groups.slice(0, 4);
  if (!prefix.every(g => HEXTET_PATTERN.test(g))) return null;
  return prefix.map(g => g.replace(/^0+(?=.)/, '').toLowerCase());
}

/**
 * Normalises an origin to the unit a rate limiter should meter.
 *
 * IPv4 addresses are left alone: one address is one host. IPv6 is not — a
 * single host is routinely handed an entire /64, so keying on the full address
 * hands an attacker 2^64 free buckets and reproduces BUG-8's "one bucket per
 * attempt" shape at the network layer instead of the header. Bucketing on the
 * /64 prefix makes the whole allocation share one budget.
 *
 * express-rate-limit is pinned at 6.x, whose `ipKeyGenerator` helper does not
 * exist yet (it arrived in v7), hence the local implementation.
 *
 * Exported for direct unit testing.
 */
export function ipBucket(rawIp: string | undefined): string {
  if (!rawIp) return 'unknown';

  // `req.ip` can carry an RFC 4007 zone index on link-local addresses, and
  // bracketed literals show up when an address round-trips through a URL.
  const ip = rawIp.replace(/^\[/, '').replace(/\]$/, '').split('%')[0];
  if (!ip) return 'unknown';

  // Node reports IPv4 peers on a dual-stack socket as `::ffff:1.2.3.4`. That is
  // an IPv4 host; bucketing it as a /64 would collapse every IPv4 client on the
  // internet into one bucket.
  const mapped = IPV4_MAPPED_PATTERN.exec(ip);
  if (mapped) return mapped[1];

  if (!ip.includes(':')) return ip; // IPv4, or anything else opaque

  const prefix = expandIpv6(ip);
  // Unparseable: fall back to exact keying rather than inventing a bucket. That
  // is the pre-existing behaviour, so it is no worse than today.
  if (!prefix) return ip;
  return `${prefix.join(':')}::/64`;
}

/**
 * Buckets authenticated traffic per user.
 *
 * BUG-8: this previously returned `req.headers.authorization`, which gives
 * every *guessed* key its own bucket — 105 distinct garbage bearers from one
 * origin produced zero 429s. Never key a limiter on the credential it is meant
 * to protect. Callers must place this AFTER authentication so `req.user` is
 * populated; before it, every request collapses to the origin bucket.
 */
export const rateLimiterKeyGenerator = (req: express.Request): string => {
  const userId = (req.user as any)?._id?.toString();
  if (userId) return `user:${userId}`;
  return `ip:${ipBucket(req.ip)}`;
};

/**
 * Buckets by origin regardless of identity, for limiters that sit in FRONT of
 * authentication so failed key guesses are metered. IPv6 origins are bucketed
 * by /64 — see `ipBucket`.
 */
export const ipOnlyKeyGenerator = (req: express.Request): string =>
  `ip:${ipBucket(req.ip)}`;

/**
 * Every store handed out below, so tests can clear them. Holding the reference
 * is the only reason the store is constructed here rather than left to
 * express-rate-limit, which would build the identical MemoryStore internally.
 */
const stores: MemoryStore[] = [];

export default (config?: Partial<Options>) => {
  const store = new MemoryStore();
  stores.push(store);
  return rateLimit({
    store,
    ...config,
  });
};

/**
 * Test-only. Clears every limiter's counters.
 *
 * Limiter counters are process-global and keyed by origin, and every request in
 * a test run comes from 127.0.0.1 — so one suite is one bucket. The pre-auth
 * limiters meter *failed* requests, and integration suites deliberately assert
 * dozens of 4xx responses, which means a production-realistic failed-attempt
 * budget is exhausted partway through a long file and unrelated cases start
 * seeing 429. Reset between tests, alongside the databases. Called from
 * `jest.setup.ts`; a test that is *about* the limiter keeps its whole burst
 * inside a single `it`.
 */
export const resetRateLimitersForTests = async () => {
  await Promise.all(stores.map(store => store.resetAll()));
};
