import { SYSTEM_ROLE_PERMISSIONS } from '@hyperdx/common-utils/dist/types';

import { seedSystemRoles } from '@/controllers/role';
import { getLoggedInAgent, getServer } from '@/fixtures';
import Role from '@/models/role';
import User from '@/models/user';

describe('/team/roles', () => {
  const server = getServer();

  beforeAll(async () => {
    await server.start();
    // Unique {team,name} index is built asynchronously by Mongoose.
    await Role.init();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  /**
   * Registration already seeds roles and makes the founder an admin; this
   * re-asserts it explicitly so the tests do not depend on that side effect,
   * and so the middleware never falls back to its no-role fail-open path.
   */
  async function asAdmin() {
    const ctx = await getLoggedInAgent(server);
    await seedSystemRoles(ctx.team._id);
    const admin = await Role.findOne({ team: ctx.team._id, isAdmin: true });
    await User.findByIdAndUpdate(ctx.user._id, { role: admin!._id });
    return ctx;
  }

  async function asNonAdmin() {
    const ctx = await getLoggedInAgent(server);
    await seedSystemRoles(ctx.team._id);
    const member = await Role.findOne({ team: ctx.team._id, name: 'Member' });
    await User.findByIdAndUpdate(ctx.user._id, { role: member!._id });
    return ctx;
  }

  it('lists roles with member counts', async () => {
    const { agent } = await asAdmin();

    const res = await agent.get('/team/roles').expect(200);

    expect(res.body.data.map((r: any) => r.name).sort()).toEqual([
      'Admin',
      'Member',
      'ReadOnly',
    ]);
    expect(res.body.data.find((r: any) => r.isAdmin).memberCount).toBe(1);
  });

  it('creates a custom role', async () => {
    const { agent } = await asAdmin();

    const res = await agent
      .post('/team/roles')
      .send({
        name: 'On-call engineer',
        description: 'Alerts and webhooks',
        permissions: SYSTEM_ROLE_PERMISSIONS.Member,
      })
      .expect(200);

    expect(res.body.isSystem).toBe(false);
    expect(res.body.isAdmin).toBe(false);
  });

  it('strips isAdmin from the request body', async () => {
    const { agent } = await asAdmin();

    const res = await agent
      .post('/team/roles')
      .send({
        name: 'Escalation attempt',
        permissions: SYSTEM_ROLE_PERMISSIONS.Member,
        isAdmin: true,
        isSystem: true,
      })
      .expect(200);

    expect(res.body.isAdmin).toBe(false);
    expect(res.body.isSystem).toBe(false);
  });

  it('rejects manage on users', async () => {
    const { agent } = await asAdmin();

    await agent
      .post('/team/roles')
      .send({
        name: 'Invalid',
        permissions: { ...SYSTEM_ROLE_PERMISSIONS.Member, users: 'manage' },
      })
      .expect(400);
  });

  it('409s editing a system role', async () => {
    const { agent, team } = await asAdmin();
    const member = await Role.findOne({ team: team._id, name: 'Member' });

    await agent
      .patch(`/team/roles/${member!._id}`)
      .send({ name: 'Renamed', permissions: SYSTEM_ROLE_PERMISSIONS.Member })
      .expect(409);
  });

  it('409s deleting a role that is in use', async () => {
    const { agent, team } = await asAdmin();
    const role = await Role.create({
      team: team._id,
      name: 'Busy',
      permissions: SYSTEM_ROLE_PERMISSIONS.Member,
    });
    // Assign the role to a DIFFERENT user. Assigning it to the caller would
    // strip their admin capability, so requireAdmin() would 403 before the
    // in-use guard ever ran — testing the wrong thing.
    await User.create({
      email: 'occupant@example.com',
      team: team._id,
      role: role._id,
    });

    await agent.delete(`/team/roles/${role._id}`).expect(409);
  });

  it('409s demoting the last admin', async () => {
    const { agent, team, user } = await asAdmin();
    const member = await Role.findOne({ team: team._id, name: 'Member' });

    await agent
      .patch(`/team/members/${user._id}/role`)
      .send({ roleId: member!._id.toString() })
      .expect(409);
  });

  it('assigns a role when another admin remains', async () => {
    const { agent, team, user } = await asAdmin();
    const admin = await Role.findOne({ team: team._id, isAdmin: true });
    const member = await Role.findOne({ team: team._id, name: 'Member' });
    await User.create({
      email: 'second-admin@example.com',
      team: team._id,
      role: admin!._id,
    });

    await agent
      .patch(`/team/members/${user._id}/role`)
      .send({ roleId: member!._id.toString() })
      .expect(200);

    const reloaded = await User.findById(user._id);
    expect(reloaded!.role!.toString()).toBe(member!._id.toString());
  });

  it('403s role CRUD for a non-admin', async () => {
    const { agent } = await asNonAdmin();

    // team:read is enough to list roles for the members-table dropdown...
    await agent.get('/team/roles').expect(200);

    // ...but authoring them is a hard admin capability.
    await agent
      .post('/team/roles')
      .send({ name: 'Nope', permissions: SYSTEM_ROLE_PERMISSIONS.Member })
      .expect(403);
  });

  it('cannot read or edit another team roles', async () => {
    const { agent, team } = await asAdmin();
    const foreign = await Role.create({
      team: '000000000000000000000001',
      name: 'Foreign',
      permissions: SYSTEM_ROLE_PERMISSIONS.Member,
    });

    await agent
      .patch(`/team/roles/${foreign._id}`)
      .send({ name: 'Hijacked', permissions: SYSTEM_ROLE_PERMISSIONS.Member })
      .expect(409);

    const list = await agent.get('/team/roles').expect(200);
    expect(list.body.data.some((r: any) => r.name === 'Foreign')).toBe(false);
    expect(team._id).toBeDefined();
  });
});
