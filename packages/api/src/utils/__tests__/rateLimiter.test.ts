import {
  ipBucket,
  ipOnlyKeyGenerator,
  rateLimiterKeyGenerator,
} from '@/utils/rateLimiter';

const req = (over: any = {}) =>
  ({ ip: '203.0.113.9', headers: {}, ...over }) as any;

describe('rateLimiterKeyGenerator', () => {
  // BUG-8. Keying on the Authorization header gave every guessed key its own
  // bucket: 105 distinct garbage bearers from one origin produced zero 429s.
  it('never keys on the credential', () => {
    const a = rateLimiterKeyGenerator(
      req({ headers: { authorization: 'Bearer aaa' } }),
    );
    const b = rateLimiterKeyGenerator(
      req({ headers: { authorization: 'Bearer bbb' } }),
    );

    expect(a).not.toContain('aaa');
    expect(b).not.toContain('bbb');
    expect(a).toBe(b);
  });

  it('buckets an authenticated caller per user', () => {
    const key = rateLimiterKeyGenerator(
      req({ user: { _id: 'user-1' }, headers: { authorization: 'Bearer x' } }),
    );
    expect(key).toBe('user:user-1');
  });

  it('gives two users distinct buckets', () => {
    expect(rateLimiterKeyGenerator(req({ user: { _id: 'a' } }))).not.toBe(
      rateLimiterKeyGenerator(req({ user: { _id: 'b' } })),
    );
  });

  it('falls back to origin when unauthenticated', () => {
    expect(rateLimiterKeyGenerator(req())).toBe('ip:203.0.113.9');
  });
});

describe('ipOnlyKeyGenerator', () => {
  it('ignores identity entirely so failed guesses share one bucket', () => {
    expect(ipOnlyKeyGenerator(req({ user: { _id: 'a' } }))).toBe(
      ipOnlyKeyGenerator(req({ headers: { authorization: 'Bearer zzz' } })),
    );
  });

  it('collapses an IPv6 /64 to one bucket', () => {
    expect(ipOnlyKeyGenerator(req({ ip: '2001:db8:1:2::1' }))).toBe(
      ipOnlyKeyGenerator(req({ ip: '2001:db8:1:2:ffff:ffff:ffff:ffff' })),
    );
  });
});

// A /64 is a normal single-host IPv6 allocation. Keying on the full address
// gives one attacker 2^64 free buckets — BUG-8's "one bucket per attempt"
// shape, relocated from the Authorization header to the source address.
describe('ipBucket', () => {
  it('leaves IPv4 addresses untouched', () => {
    expect(ipBucket('203.0.113.9')).toBe('203.0.113.9');
    expect(ipBucket('10.0.0.1')).toBe('10.0.0.1');
  });

  it('collapses two addresses in the same /64 to one key', () => {
    expect(ipBucket('2001:db8:1:2::1')).toBe(
      ipBucket('2001:db8:1:2:ffff:ffff:ffff:ffff'),
    );
    expect(ipBucket('2001:db8:1:2::1')).toBe('2001:db8:1:2::/64');
  });

  it('keeps two distinct /64s in distinct keys', () => {
    expect(ipBucket('2001:db8:1:2::1')).not.toBe(ipBucket('2001:db8:1:3::1'));
    expect(ipBucket('2001:db8:1:2::1')).not.toBe(ipBucket('2001:db8::1'));
  });

  it('normalises equivalent spellings of the same prefix', () => {
    // Leading zeros, case, and `::` elision are all cosmetic; two spellings of
    // one prefix must not buy two buckets.
    expect(ipBucket('2001:0DB8:0001:0002::1')).toBe(
      ipBucket('2001:db8:1:2::9'),
    );
    expect(ipBucket('2001:db8:0:0:0:0:0:1')).toBe(ipBucket('2001:db8::2'));
  });

  it('treats an IPv4-mapped IPv6 address as its IPv4 host', () => {
    // Node reports IPv4 peers on a dual-stack socket this way. Bucketing it as
    // a /64 would collapse every IPv4 client into a single bucket.
    expect(ipBucket('::ffff:203.0.113.9')).toBe('203.0.113.9');
    expect(ipBucket('::ffff:203.0.113.9')).toBe(ipBucket('203.0.113.9'));
    expect(ipBucket('::ffff:203.0.113.9')).not.toBe(
      ipBucket('::ffff:198.51.100.4'),
    );
  });

  it('handles a zone index and a bracketed literal', () => {
    expect(ipBucket('fe80::1%eth0')).toBe('fe80:0:0:0::/64');
    expect(ipBucket('[2001:db8:1:2::1]')).toBe('2001:db8:1:2::/64');
  });

  it('handles a missing req.ip without throwing', () => {
    expect(ipBucket(undefined)).toBe('unknown');
    expect(ipBucket('')).toBe('unknown');
  });

  it('falls back to exact keying on an unparseable address', () => {
    // No worse than the pre-fix behaviour, and never invents a shared bucket
    // that a valid address could also land in.
    expect(ipBucket('2001:db8::nonsense::1')).toBe('2001:db8::nonsense::1');
    expect(ipBucket('2001:db8:1:2:3:4:5')).toBe('2001:db8:1:2:3:4:5');
  });
});
