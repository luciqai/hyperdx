import express from 'express';
import request from 'supertest';

import { findUserByAccessKey } from '@/controllers/user';
import mcpRouter from '@/mcp/app';

jest.mock('@/controllers/user', () => ({
  ...jest.requireActual('@/controllers/user'),
  findUserByAccessKey: jest.fn(),
}));

const mockFindUserByAccessKey = findUserByAccessKey as unknown as jest.Mock;

// The MCP transport is stateless, so GET (standalone SSE stream) and DELETE
// (session termination) are not offered and must return 405 so spec-compliant
// SDK clients continue connecting rather than aborting. See issue #2686.
describe('mcp app transport methods', () => {
  const app = express();
  app.use('/mcp', mcpRouter);

  it('returns 405 with Allow: POST for GET', async () => {
    const res = await request(app).get('/mcp');
    expect(res.status).toBe(405);
    expect(res.headers.allow).toBe('POST');
  });

  it('returns 405 with Allow: POST for DELETE', async () => {
    const res = await request(app).delete('/mcp');
    expect(res.status).toBe(405);
    expect(res.headers.allow).toBe('POST');
  });
});

// The pre-auth limiter is keyed on origin, and behind a VPN or NAT every client
// shares one. Only a rejected key may spend its budget, or clients with valid
// keys lock each other out.
describe('mcp app auth-attempt rate limiting', () => {
  const app = express();
  app.use('/mcp', mcpRouter);

  const VALID_KEY = 'valid-access-key';

  beforeEach(() => {
    mockFindUserByAccessKey.mockImplementation(async (key: string) =>
      key === VALID_KEY
        ? { _id: 'user-1', team: 'team-1', email: 'u@example.com' }
        : null,
    );
  });

  const initialize = (key?: string) => {
    const req = request(app)
      .post('/mcp')
      .set('Accept', 'application/json, text/event-stream')
      .send({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-03-26',
          capabilities: {},
          clientInfo: { name: 'test', version: '0.0.0' },
        },
      });
    return key ? req.set('Authorization', `Bearer ${key}`) : req;
  };

  // Every SDK client sends this GET once per connection, so 31 of them is 31
  // clients connecting, not 31 guesses.
  it('does not count the 405 SSE probe as a failed attempt', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 31; i++) {
      statuses.push((await request(app).get('/mcp')).status);
    }
    expect(statuses.every(s => s === 405)).toBe(true);

    expect((await initialize(VALID_KEY)).status).toBe(200);
  });

  it('still 429s a burst of rejected keys from one origin', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 31; i++) {
      statuses.push((await initialize(`garbage-${i}`)).status);
    }
    expect(statuses.slice(0, 30).every(s => s === 401)).toBe(true);
    expect(statuses[30]).toBe(429);
  });
});
