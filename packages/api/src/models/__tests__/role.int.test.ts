import { SYSTEM_ROLE_PERMISSIONS } from '@hyperdx/common-utils/dist/types';
import { Types } from 'mongoose';

import { getServer } from '@/fixtures';
import Role from '@/models/role';

describe('Role model', () => {
  const server = getServer();

  beforeAll(async () => {
    await server.start();
    // Mongoose builds indexes in the background, so a create() issued before
    // the build finishes is not uniqueness-checked. Await init() once so the
    // { team, name } unique index is guaranteed live before any assertion.
    await Role.init();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('defaults isSystem and isAdmin to false', async () => {
    const role = await Role.create({
      team: new Types.ObjectId(),
      name: 'On-call engineer',
      permissions: SYSTEM_ROLE_PERMISSIONS.Member,
    });

    expect(role.isSystem).toBe(false);
    expect(role.isAdmin).toBe(false);
  });

  it('enforces unique name per team', async () => {
    const team = new Types.ObjectId();
    await Role.create({
      team,
      name: 'Duplicate',
      permissions: SYSTEM_ROLE_PERMISSIONS.Member,
    });

    await expect(
      Role.create({
        team,
        name: 'Duplicate',
        permissions: SYSTEM_ROLE_PERMISSIONS.Member,
      }),
    ).rejects.toThrow();
  });

  it('allows the same name in a different team', async () => {
    await Role.create({
      team: new Types.ObjectId(),
      name: 'Shared',
      permissions: SYSTEM_ROLE_PERMISSIONS.Member,
    });

    await expect(
      Role.create({
        team: new Types.ObjectId(),
        name: 'Shared',
        permissions: SYSTEM_ROLE_PERMISSIONS.Member,
      }),
    ).resolves.toBeDefined();
  });
});
