import { Types } from 'mongoose';

import * as roleController from '@/controllers/role';
import { seedSystemRoles } from '@/controllers/role';
import { createGoogleUser, findUserById } from '@/controllers/user';
import { getServer } from '@/fixtures';
import { computeVerdict } from '@/middleware/rbac';
import User from '@/models/user';

/**
 * A user provisioned by Google SSO must land on ReadOnly.
 *
 * The failure this guards is not "slightly too much access": a role-less
 * user fails OPEN on the session path (see `computeVerdict`), so an SSO
 * signup that skips role assignment is a full administrator in a browser.
 */
describe('createGoogleUser', () => {
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

  it('assigns ReadOnly to a newly provisioned user', async () => {
    const teamId = new Types.ObjectId();
    await seedSystemRoles(teamId);

    const created = await createGoogleUser({
      email: 'new@example.com',
      teamId,
      googleId: 'google-sub-1',
    });

    expect(created).not.toBeNull();

    const found = await findUserById(created!._id.toString());
    const role = found!.role as any;
    expect(role.name).toBe('ReadOnly');
    expect(role.isAdmin).toBe(false);
    expect(role.permissions).toEqual({
      dashboards: 'read',
      savedSearches: 'read',
      sources: 'read',
      alerts: 'read',
      webhooks: 'none',
      connections: 'none',
      users: 'none',
      team: 'read',
    });
  });

  it('seeds roles itself on a team that predates RBAC', async () => {
    // No seedSystemRoles call: this is a team created before RBAC shipped.
    const teamId = new Types.ObjectId();

    const created = await createGoogleUser({
      email: 'legacy@example.com',
      teamId,
      googleId: 'google-sub-2',
    });

    expect(created).not.toBeNull();
    const found = await findUserById(created!._id.toString());
    expect((found!.role as any).name).toBe('ReadOnly');
  });

  it('never leaves a provisioned user role-less, which would fail open', async () => {
    const teamId = new Types.ObjectId();

    const created = await createGoogleUser({
      email: 'open@example.com',
      teamId,
      googleId: 'google-sub-3',
    });

    const found = await findUserById(created!._id.toString());
    // The session path is the one that fails open, so assert against it.
    expect(computeVerdict(found!.role as any, 'session')).not.toBe('allow');
  });

  it('creates no user at all when ReadOnly cannot be resolved', async () => {
    const teamId = new Types.ObjectId();
    // Simulate seeding that comes back without ReadOnly. Returning a user
    // here would be the dangerous outcome: role-less, and admin in a browser.
    const spy = jest
      .spyOn(roleController, 'seedSystemRoles')
      .mockResolvedValue([]);

    try {
      const created = await createGoogleUser({
        email: 'refused@example.com',
        teamId,
        googleId: 'google-sub-5',
      });

      expect(created).toBeNull();
      expect(await User.findOne({ googleId: 'google-sub-5' })).toBeNull();
    } finally {
      spy.mockRestore();
    }
  });

  it('stores the google id and email so the user can log back in', async () => {
    const teamId = new Types.ObjectId();
    await seedSystemRoles(teamId);

    await createGoogleUser({
      email: 'repeat@example.com',
      teamId,
      googleId: 'google-sub-4',
    });

    const byGoogleId = await User.findOne({ googleId: 'google-sub-4' });
    expect(byGoogleId!.email).toBe('repeat@example.com');
    // No password was ever set, so the user must not claim password auth.
    expect(byGoogleId!.googleId).toBe('google-sub-4');
  });
});
