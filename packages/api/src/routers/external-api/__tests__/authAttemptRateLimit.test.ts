import express from 'express';
import request from 'supertest';

import { findUserByAccessKey } from '@/controllers/user';
import externalRoutersV2 from '@/routers/external-api/v2';

jest.mock('@/controllers/user', () => ({
  ...jest.requireActual('@/controllers/user'),
  findUserByAccessKey: jest.fn(),
}));

const mockFindUserByAccessKey = findUserByAccessKey as unknown as jest.Mock;

// The pre-auth limiter is keyed on origin, and behind a VPN or NAT every caller
// shares one. A caller whose key was accepted must not spend the budget that
// meters guessed keys.
describe('external API v2 auth-attempt rate limiting', () => {
  const app = express();
  app.use('/api/v2', externalRoutersV2);

  const VALID_KEY = 'valid-access-key';
  // No role: RBAC denies every permissioned route on the access-key path, so
  // this caller is authenticated and still collects 403s.
  const user = {
    _id: 'user-1',
    team: 'team-1',
    email: 'u@example.com',
    toJSON: () => ({ _id: 'user-1' }),
  };

  beforeEach(() => {
    mockFindUserByAccessKey.mockImplementation(async (key: string) =>
      key === VALID_KEY ? user : null,
    );
  });

  const authed = (url: string) =>
    request(app).get(url).set('Authorization', `Bearer ${VALID_KEY}`);

  it('does not count failures of an authenticated caller', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 31; i++) {
      statuses.push((await authed('/api/v2/dashboards')).status);
    }
    expect(statuses.every(s => s === 403)).toBe(true);

    expect((await authed('/api/v2')).status).toBe(200);
  });

  it('still 429s a burst of rejected keys from one origin', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 31; i++) {
      const res = await request(app)
        .get('/api/v2')
        .set('Authorization', `Bearer garbage-${i}`);
      statuses.push(res.status);
    }
    expect(statuses.slice(0, 30).every(s => s === 401)).toBe(true);
    expect(statuses[30]).toBe(429);
  });
});
