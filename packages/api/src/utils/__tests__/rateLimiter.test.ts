import {
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
});
