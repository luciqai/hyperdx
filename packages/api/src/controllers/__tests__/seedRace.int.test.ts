import { Types } from 'mongoose';

import { seedSystemRoles } from '@/controllers/role';
import { getServer } from '@/fixtures';
import Role from '@/models/role';

describe('seedSystemRoles concurrency', () => {
  const server = getServer();

  // BUG-4. Deliberately NO `await Role.init()` in this beforeAll, unlike
  // role.int.test.ts. That barrier in the *tests* is exactly what hid the
  // defect — the application had none. The barrier must come from
  // seedSystemRoles itself or this suite is meaningless.
  beforeAll(async () => {
    await server.start();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('produces exactly 3 roles and 1 admin under parallel calls', async () => {
    const teamId = new Types.ObjectId().toString();
    await Promise.all(
      Array.from({ length: 12 }, () => seedSystemRoles(teamId)),
    );

    const roles = await Role.find({ team: teamId });
    expect(roles).toHaveLength(3);
    expect(roles.filter(r => r.isAdmin)).toHaveLength(1);
  });

  it('returns all three roles to every caller', async () => {
    const teamId = new Types.ObjectId().toString();
    const results = await Promise.all(
      Array.from({ length: 6 }, () => seedSystemRoles(teamId)),
    );

    for (const created of results) {
      expect(created).toHaveLength(3);
      expect(created.every(r => r != null)).toBe(true);
    }
  });
});
