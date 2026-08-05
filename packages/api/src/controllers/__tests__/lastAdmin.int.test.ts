import { Types } from 'mongoose';

import {
  assignRole,
  isLastAdmin,
  RoleConflictError,
  seedSystemRoles,
} from '@/controllers/role';
import { getServer } from '@/fixtures';
import Role from '@/models/role';
import User from '@/models/user';

describe('last-admin invariant', () => {
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

  async function team(): Promise<string> {
    const teamId = new Types.ObjectId().toString();
    await seedSystemRoles(teamId);
    return teamId;
  }

  const roleId = async (teamId: string, name: string) =>
    (await Role.findOne({ team: teamId, name }))!._id;

  let seq = 0;
  const user = async (teamId: string, role: any) =>
    User.create({
      team: teamId,
      email: `u${seq++}@x.test`,
      name: 'u',
      role,
    });

  // BUG-1, the exact A/B the manual test ran: same request, different outcome
  // depending on whether a role-less user happened to exist.
  it('blocks demoting the last Admin even when a role-less user exists', async () => {
    const t = await team();
    const admin = await user(t, await roleId(t, 'Admin'));
    await user(t, undefined); // role-less: previously made the guard silent

    await expect(
      assignRole(
        t,
        admin._id.toString(),
        (await roleId(t, 'Member')).toString(),
      ),
    ).rejects.toThrow(RoleConflictError);

    const reread = await User.findById(admin._id);
    expect(reread!.role!.toString()).toBe(
      (await roleId(t, 'Admin')).toString(),
    );
  });

  it('allows demoting an Admin while another Admin remains', async () => {
    const t = await team();
    const a1 = await user(t, await roleId(t, 'Admin'));
    await user(t, await roleId(t, 'Admin'));

    await assignRole(
      t,
      a1._id.toString(),
      (await roleId(t, 'Member')).toString(),
    );

    const reread = await User.findById(a1._id);
    expect(reread!.role!.toString()).toBe(
      (await roleId(t, 'Member')).toString(),
    );
  });

  // The clause that keeps un-migrated teams usable: nobody there holds an
  // isAdmin role, so the guard must not fire at all.
  it('does not fire for a role-less user on an un-migrated team', async () => {
    const t = await team();
    const u = await user(t, undefined);

    await assignRole(
      t,
      u._id.toString(),
      (await roleId(t, 'Member')).toString(),
    );

    const reread = await User.findById(u._id);
    expect(reread!.role!.toString()).toBe(
      (await roleId(t, 'Member')).toString(),
    );
  });

  it('reports isLastAdmin only for a holder of an isAdmin role', async () => {
    const t = await team();
    const admin = await user(t, await roleId(t, 'Admin'));
    const roleless = await user(t, undefined);

    expect(await isLastAdmin(t, admin._id.toString())).toBe(true);
    expect(await isLastAdmin(t, roleless._id.toString())).toBe(false);
  });
});
