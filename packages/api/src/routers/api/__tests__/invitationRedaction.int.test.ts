import { SuperAgentTest } from 'supertest';

import { getAgent, getLoggedInAgent, getServer } from '@/fixtures';
import Role from '@/models/role';
import TeamInvite from '@/models/teamInvite';
import User from '@/models/user';

/**
 * BUG-7, at the route level.
 *
 * The `url` on a pending invitation embeds an accept-capable token: anyone
 * holding it can join the team. `users: read` is held by Member, so before
 * this fix every Member of every team could read a working join link for every
 * outstanding invite. The redaction is one of the release's three breaking
 * changes, and the only test for it covered `isEffectiveAdmin` in isolation —
 * which proves nothing about the Mongo projection actually dropping `token`,
 * nor about the helper being wired into the handler at all.
 *
 * So this drives the real routes. Both of them: the internal session-authed
 * `GET /team/invitations` and the access-key-authed
 * `GET /api/v2/team/invitations` are separate handlers with separate
 * projections, and a fix to one does not fix the other.
 */
describe('invitation URL redaction', () => {
  const server = getServer();

  const MEMBER_EMAIL = 'invited-member@deploysentinel.com';
  const MEMBER_PASSWORD = 'TestPassword123!';
  const PENDING_EMAIL = 'still-pending@deploysentinel.com';

  beforeAll(async () => {
    await server.start();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  /**
   * Real Admin + real Member, both created the way production creates them:
   * the founder of a team is seeded Admin at registration, and an invitee who
   * completes `/team/setup/:token` is seeded Member. Assigning roles by hand
   * would test the assertion rather than the wiring.
   */
  async function twoActors() {
    const { agent: adminAgent, user: adminUser } =
      await getLoggedInAgent(server);

    // One invite to consume (it creates the Member), one to leave pending so
    // both actors have something to list.
    await adminAgent
      .post('/team/invitation')
      .send({ email: MEMBER_EMAIL, name: 'Invited Member' })
      .expect(200);
    await adminAgent
      .post('/team/invitation')
      .send({ email: PENDING_EMAIL, name: 'Still Pending' })
      .expect(200);

    const invite = await TeamInvite.findOne({ email: MEMBER_EMAIL });
    const memberAgent: SuperAgentTest = getAgent(server);
    await memberAgent
      .post(`/team/setup/${invite!.token}`)
      .send({ password: MEMBER_PASSWORD });

    const memberUser = await User.findOne({ email: MEMBER_EMAIL });
    expect(memberUser).not.toBeNull();

    // Guard the premise: a Member that somehow came out admin, or role-less
    // (which fails OPEN as admin on the session path), would make every
    // assertion below vacuous.
    const memberRole = await Role.findById(memberUser!.role);
    expect(memberRole?.name).toBe('Member');
    expect(memberRole?.isAdmin).toBe(false);

    return { adminAgent, adminUser, memberAgent, memberUser: memberUser! };
  }

  const pendingRow = (body: any) =>
    body.data.find((i: { email: string }) => i.email === PENDING_EMAIL);

  describe('GET /team/invitations', () => {
    it('returns the accept-capable url to an admin', async () => {
      const { adminAgent } = await twoActors();

      const res = await adminAgent.get('/team/invitations').expect(200);
      const row = pendingRow(res.body);

      expect(row).toBeTruthy();
      expect(row.url).toContain('/join-team?token=');
    });

    it('lists the invitation for a non-admin but without url or token', async () => {
      const { memberAgent } = await twoActors();

      const res = await memberAgent.get('/team/invitations').expect(200);
      const row = pendingRow(res.body);

      // The list itself is unchanged — only the credential is withheld.
      expect(row).toBeTruthy();
      expect(row.email).toBe(PENDING_EMAIL);
      expect(row.url).toBeUndefined();
      // The token must not be projected out of Mongo at all, so it can never
      // leak through some other field or a future serialiser change.
      expect(row.token).toBeUndefined();
      expect(JSON.stringify(res.body)).not.toContain('join-team?token=');
    });
  });

  describe('GET /api/v2/team/invitations', () => {
    const listAs = (agent: SuperAgentTest, accessKey: string) =>
      agent
        .get('/api/v2/team/invitations')
        .set('Authorization', `Bearer ${accessKey}`);

    it('returns the accept-capable url to an admin', async () => {
      const { adminAgent, adminUser } = await twoActors();

      const res = await listAs(adminAgent, adminUser.accessKey).expect(200);
      const row = pendingRow(res.body);

      expect(row).toBeTruthy();
      expect(row.url).toContain('/join-team?token=');
    });

    it('lists the invitation for a non-admin but without url or token', async () => {
      const { memberAgent, memberUser } = await twoActors();

      const res = await listAs(memberAgent, memberUser.accessKey).expect(200);
      const row = pendingRow(res.body);

      expect(row).toBeTruthy();
      expect(row.email).toBe(PENDING_EMAIL);
      expect(row.url).toBeUndefined();
      expect(row.token).toBeUndefined();
      expect(JSON.stringify(res.body)).not.toContain('join-team?token=');
    });
  });
});
