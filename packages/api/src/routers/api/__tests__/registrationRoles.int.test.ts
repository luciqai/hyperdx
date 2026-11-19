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

describe('invite acceptance assigns a real role', () => {
  const server = getServer();

  beforeAll(async () => {
    await server.start();
    await Role.init();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  // Regression: the invited user was created with no role at all. Combined
  // with the middleware's deliberate fail-open, that silently made every
  // invited member a full administrator on a fully-migrated deployment.
  it('gives an invited user the Member role, not admin-by-fail-open', async () => {
    const founder = getAgent(server);
    await founder
      .post('/register/password')
      .send({
        email: 'owner@example.com',
        password: 'Str0ng!Password',
        confirmPassword: 'Str0ng!Password',
      })
      .expect(200);

    const team = await Team.findOne({});
    const invite = await founder
      .post('/team/invitation')
      .send({ email: 'invitee@example.com' })
      .expect(200);

    const token = new URL(invite.body.url).searchParams.get('token');
    expect(token).toBeTruthy();

    const joiner = getAgent(server);
    await joiner.post(`/team/setup/${token}`).send({
      password: 'Str0ng!Password',
    });

    const invited = await User.findOne({
      email: 'invitee@example.com',
    }).populate('role');
    expect(invited).not.toBeNull();
    expect(invited!.role).not.toBeNull();
    expect((invited!.role as any).name).toBe('Member');
    expect((invited!.role as any).isAdmin).toBe(false);
    expect((invited!.role as any).team.toString()).toBe(team!._id.toString());
  });

  it('an invited user cannot reach admin-only routes', async () => {
    const founder = getAgent(server);
    await founder
      .post('/register/password')
      .send({
        email: 'owner2@example.com',
        password: 'Str0ng!Password',
        confirmPassword: 'Str0ng!Password',
      })
      .expect(200);

    const invite = await founder
      .post('/team/invitation')
      .send({ email: 'invitee2@example.com' })
      .expect(200);
    const token = new URL(invite.body.url).searchParams.get('token');

    const joiner = getAgent(server);
    await joiner
      .post(`/team/setup/${token}`)
      .send({ password: 'Str0ng!Password' });

    // Rotating the ingestion key is requireAdmin(). Before the fix this
    // returned 200 for an invited user.
    await joiner.patch('/team/apiKey').expect(403);
    await joiner.post('/team/roles').send({}).expect(403);
  });
});
