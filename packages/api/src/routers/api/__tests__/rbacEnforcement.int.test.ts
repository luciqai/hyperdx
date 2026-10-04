import {
  SourceKind,
  SYSTEM_ROLE_PERMISSIONS,
  TSource,
} from '@hyperdx/common-utils/dist/types';
import { Types } from 'mongoose';

import { getLoggedInAgent, getServer } from '@/fixtures';
import Role from '@/models/role';
import { Source } from '@/models/source';
import User from '@/models/user';

const MOCK_SOURCE: Omit<Extract<TSource, { kind: 'log' }>, 'id'> = {
  kind: SourceKind.Log,
  name: 'Test Source',
  connection: new Types.ObjectId().toString(),
  from: { databaseName: 'test_db', tableName: 'test_table' },
  timestampValueExpression: 'timestamp',
  defaultTableSelectExpression: 'body',
};

/**
 * Re-point the logged-in user at a freshly created role.
 *
 * `getLoggedInAgent` creates a user with no role at all, and the RBAC
 * middleware deliberately fails open as admin in that case — so every
 * assertion below is meaningless unless this runs first.
 */
async function withRole(
  teamId: string,
  userId: string,
  permissions = SYSTEM_ROLE_PERMISSIONS.ReadOnly,
) {
  const role = await Role.create({
    team: teamId,
    name: `test-${Math.random().toString(36).slice(2)}`,
    permissions,
    isSystem: false,
    isAdmin: false,
  });
  await User.findByIdAndUpdate(userId, { role: role._id });
  return role;
}

describe('RBAC route enforcement', () => {
  const server = getServer();

  beforeAll(async () => {
    await server.start();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('allows a read-level role to list dashboards', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await withRole(team._id.toString(), user._id.toString());

    await agent.get('/dashboards').expect(200);
  });

  it('denies a read-level role creating a dashboard', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await withRole(team._id.toString(), user._id.toString());

    const res = await agent.post('/dashboards').send({ name: 'x', tiles: [] });

    expect(res.status).toBe(403);
    expect(res.body.required).toEqual({
      resource: 'dashboards',
      level: 'manage',
    });
  });

  it('denies connections entirely at none', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await withRole(team._id.toString(), user._id.toString());

    const res = await agent.get('/connections');

    expect(res.status).toBe(403);
    expect(res.body.required).toEqual({
      resource: 'connections',
      level: 'read',
    });
  });

  it('denies webhooks entirely at none', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await withRole(team._id.toString(), user._id.toString());

    // Denied before validateRequest, so the missing `service` query param
    // never turns this into a 400.
    const res = await agent.get('/webhooks');

    expect(res.status).toBe(403);
    expect(res.body.required).toEqual({ resource: 'webhooks', level: 'read' });
  });

  it('allows a manage-level role to reach webhook validation', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await withRole(team._id.toString(), user._id.toString(), {
      ...SYSTEM_ROLE_PERMISSIONS.ReadOnly,
      webhooks: 'manage',
    });

    // 400 (not 403): RBAC passed and the request reached validateRequest.
    await agent.post('/webhooks').send({}).expect(400);
  });

  it('treats pinned filters as shared team config, not personal state', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await withRole(team._id.toString(), user._id.toString());

    const source = await Source.create({ ...MOCK_SOURCE, team: team._id });
    const sourceId = source._id.toString();

    // ReadOnly holds sources:read, so GET passes and PUT does not.
    await agent.get(`/pinned-filters?source=${sourceId}`).expect(200);

    const res = await agent
      .put('/pinned-filters')
      .send({ source: sourceId, fields: [], filters: {} });

    expect(res.status).toBe(403);
    expect(res.body.required).toEqual({ resource: 'sources', level: 'manage' });
  });

  it('leaves personal state ungated', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await withRole(team._id.toString(), user._id.toString());

    await agent.get('/me').expect(200);
    await agent.get('/favorites').expect(200);
  });
});
