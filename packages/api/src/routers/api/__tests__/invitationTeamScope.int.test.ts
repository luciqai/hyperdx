import { Types } from 'mongoose';

import { getLoggedInAgent, getServer } from '@/fixtures';
import TeamInvite from '@/models/teamInvite';

describe('DELETE /team/invitation/:id team scoping', () => {
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

  // Regression: the handler used TeamInvite.findByIdAndDelete(id) with no team
  // filter, so any authenticated user could remove another team's pending
  // invite by id alone — a cross-tenant IDOR.
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
});
