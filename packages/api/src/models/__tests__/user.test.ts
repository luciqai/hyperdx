import User from '@/models/user';

describe('User model', () => {
  describe('hasPasswordAuth virtual', () => {
    it('is false for a user with no password salt (Google-only)', () => {
      const user = new User({ email: 'ada@luciq.ai', name: 'ada@luciq.ai' });
      expect(user.get('hasPasswordAuth')).toBe(false);
    });

    it('is true once a password salt is present', () => {
      const user = new User({ email: 'ada@luciq.ai', name: 'ada@luciq.ai' });
      user.set('salt', 'some-salt');
      expect(user.get('hasPasswordAuth')).toBe(true);
    });
  });

  describe('googleId', () => {
    it('is undefined by default', () => {
      const user = new User({ email: 'ada@luciq.ai' });
      expect(user.get('googleId')).toBeUndefined();
    });

    it('round-trips a value', () => {
      const user = new User({ email: 'ada@luciq.ai', googleId: 'sub-1' });
      expect(user.get('googleId')).toBe('sub-1');
    });
  });
});
