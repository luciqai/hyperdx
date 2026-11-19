import { SYSTEM_ROLE_PERMISSIONS } from '@hyperdx/common-utils/dist/types';
import { Types } from 'mongoose';

import { getLoggedInAgent, getServer } from '@/fixtures';
import Role from '@/models/role';
import TeamInvite from '@/models/teamInvite';
import User from '@/models/user';

/**
 * Registration seeds the founder as Admin, and the middleware fails open when
 * a user has no role at all — so every 403 assertion has to explicitly move
 * the user onto a non-admin role first.
 */
async function demote(teamId: string, userId: string) {
  const role = await Role.create({
    team: teamId,
    name: 'demoted',
    permissions: SYSTEM_ROLE_PERMISSIONS.Member,
    isSystem: false,
    isAdmin: false,
  });
  await User.findByIdAndUpdate(userId, { role: role._id });
  return role;
}

describe('team router RBAC', () => {
  const server = getServer();

  beforeAll(async () => {
    await server.start();
    // Mongoose builds indexes asynchronously; the unique {team,name} index has
    // to exist before any test relies on role uniqueness.
    await Role.init();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('blocks a non-admin from rotating the ingestion key', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await demote(team._id.toString(), user._id.toString());

    await agent.patch('/team/apiKey').expect(403);
  });

  it('blocks a non-admin from inviting a member', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await demote(team._id.toString(), user._id.toString());

    await agent
      .post('/team/invitation')
      .send({ email: 'new@example.com' })
      .expect(403);
  });

  it('blocks a non-admin from deleting an invitation', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    const invite = await TeamInvite.create({
      teamId: team._id,
      email: 'pending@example.com',
      token: 'pending-token',
    });
    await demote(team._id.toString(), user._id.toString());

    await agent.delete(`/team/invitation/${invite._id}`).expect(403);

    expect(await TeamInvite.findById(invite._id)).not.toBeNull();
  });

  it('allows a member-level role to read team settings', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await demote(team._id.toString(), user._id.toString());

    await agent.get('/team').expect(200);
  });

  it('allows a member-level role to read the member list', async () => {
    const { agent, team, user } = await getLoggedInAgent(server);
    await demote(team._id.toString(), user._id.toString());

    const res = await agent.get('/team/members').expect(200);
    expect(res.body.data[0].roleName).toBe('demoted');
  });

  // Regression: DELETE /team/invitation/:id previously used
  // TeamInvite.findByIdAndDelete(id) with no team filter — a cross-tenant IDOR.
  it('cannot delete another team invitation', async () => {
    const { agent } = await getLoggedInAgent(server);

    const foreignInvite = await TeamInvite.create({
      teamId: new Types.ObjectId(),
      email: 'victim@other-team.com',
      token: 'foreign-token',
    });

    await agent.delete(`/team/invitation/${foreignInvite._id}`).expect(404);

    expect(await TeamInvite.findById(foreignInvite._id)).not.toBeNull();
  });

  it('still deletes an invitation belonging to the caller team', async () => {
    const { agent, team } = await getLoggedInAgent(server);

    const invite = await TeamInvite.create({
      teamId: team._id,
      email: 'mine@example.com',
      token: 'own-token',
    });

    await agent.delete(`/team/invitation/${invite._id}`).expect(200);

    expect(await TeamInvite.findById(invite._id)).toBeNull();
  });

  it('refuses to remove the last admin', async () => {
    const { agent, user } = await getLoggedInAgent(server);

    // Registration made this user the only admin of the team.
    await agent.delete(`/team/member/${user._id}`).expect(409);

    expect(await User.findById(user._id)).not.toBeNull();
  });
});
