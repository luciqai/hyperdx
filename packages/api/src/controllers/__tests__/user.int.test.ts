import { Types } from 'mongoose';

import { seedSystemRoles } from '@/controllers/role';
import { findUserById } from '@/controllers/user';
import { getServer } from '@/fixtures';
import Role from '@/models/role';
import User from '@/models/user';

describe('findUserById', () => {
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

  it('populates the role document', async () => {
    const teamId = new Types.ObjectId();
    await seedSystemRoles(teamId);
    const admin = await Role.findOne({ team: teamId, isAdmin: true });
    const user = await User.create({
      email: 'p@example.com',
      team: teamId,
      role: admin!._id,
    });

    const found = await findUserById(user._id.toString());

    expect((found!.role as any).name).toBe('Admin');
    expect((found!.role as any).isAdmin).toBe(true);
  });

  it('returns a user with no role without throwing', async () => {
    const user = await User.create({
      email: 'norole@example.com',
      team: new Types.ObjectId(),
    });

    const found = await findUserById(user._id.toString());
    expect(found!.role).toBeUndefined();
  });
});
