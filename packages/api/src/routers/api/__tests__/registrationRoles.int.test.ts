import { getAgent, getServer } from '@/fixtures';
import Role from '@/models/role';
import Team from '@/models/team';
import User from '@/models/user';

describe('registration seeds RBAC roles', () => {
  const server = getServer();

  beforeAll(async () => {
    await server.start();
    // Seeding upserts on {team, name}; the unique index backing that has to be
    // built before the first registration runs.
    await Role.init();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('creates three system roles and makes the first user an admin', async () => {
    const agent = getAgent(server);

    await agent
      .post('/register/password')
      .send({
        email: 'founder@example.com',
        password: 'Str0ng!Password',
        confirmPassword: 'Str0ng!Password',
      })
      .expect(200);

    const team = await Team.findOne({});
    const roles = await Role.find({ team: team!._id }).sort({ name: 1 });
    expect(roles.map(r => r.name)).toEqual(['Admin', 'Member', 'ReadOnly']);
    expect(roles.every(r => r.isSystem)).toBe(true);
    expect(roles.filter(r => r.isAdmin)).toHaveLength(1);

    const user = await User.findOne({ email: 'founder@example.com' }).populate(
      'role',
    );
    expect((user!.role as any).isAdmin).toBe(true);
    expect((user!.role as any).name).toBe('Admin');
  });

  it('reports the seeded role on /me and /team/members', async () => {
    const agent = getAgent(server);

    await agent
      .post('/register/password')
      .send({
        email: 'founder2@example.com',
        password: 'Str0ng!Password',
        confirmPassword: 'Str0ng!Password',
      })
      .expect(200);

    await agent
      .post('/login/password')
      .send({ email: 'founder2@example.com', password: 'Str0ng!Password' })
      .expect(303);

    const me = await agent.get('/me').expect(200);
    expect(me.body.role.name).toBe('Admin');
    expect(me.body.role.isAdmin).toBe(true);

    const members = await agent.get('/team/members').expect(200);
    expect(members.body.data[0].roleName).toBe('Admin');
    expect(members.body.data[0].roleId).toEqual(expect.any(String));
  });
});
