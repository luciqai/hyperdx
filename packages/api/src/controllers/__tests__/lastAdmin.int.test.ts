import { Types } from 'mongoose';

import {
  assignRole,
  getMemberRemovalConflict,
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
  // isAdmin role, so the last-admin guard must not fire at all. A second
  // role-less user remains, so this is not the terminal write that the
  // admin-less guard below blocks.
  it('does not fire for a role-less user on an un-migrated team', async () => {
    const t = await team();
    const u = await user(t, undefined);
    await user(t, undefined);

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

  it('reports a removal conflict only for a holder of an isAdmin role', async () => {
    const t = await team();
    const admin = await user(t, await roleId(t, 'Admin'));
    const roleless = await user(t, undefined);

    expect(await getMemberRemovalConflict(t, admin._id.toString())).toMatch(
      /last admin/i,
    );
    expect(await getMemberRemovalConflict(t, roleless._id.toString())).toBe(
      null,
    );
  });

  // ---------------------------------------------------------------------
  // The admin-less lockout. Role-less users pass `requireAdmin` through the
  // session fail-open, so on an un-migrated team they ARE the team's admin
  // access. Draining them to zero while nobody holds an isAdmin role leaves
  // nobody who can pass `requireAdmin`, and every route that could repair it
  // (POST /team/roles, PATCH /team/roles/:id, PATCH /team/members/:id/role)
  // is itself requireAdmin() — so the state is unrecoverable through the API.
  // ---------------------------------------------------------------------
  describe('admin-less lockout', () => {
    // The exact four-step sequence from the review: un-migrated team, an
    // invite acceptance defensively seeds the system roles (held by nobody),
    // then a role-less user demotes every other role-less user in turn. The
    // last of those writes is the one that strands the team.
    it('refuses the assignment that would leave zero admins and zero role-less users', async () => {
      const t = await team(); // roles exist, held by nobody
      const u1 = await user(t, undefined);
      const u2 = await user(t, undefined);
      const member = (await roleId(t, 'Member')).toString();

      // Not terminal: u2 is still role-less, so the team stays manageable.
      await assignRole(t, u1._id.toString(), member);

      await expect(assignRole(t, u2._id.toString(), member)).rejects.toThrow(
        RoleConflictError,
      );

      const reread = await User.findById(u2._id);
      expect(reread!.role ?? null).toBe(null);
    });

    it('tells the operator to assign the Admin role, not to promote another admin', async () => {
      const t = await team();
      const u = await user(t, undefined);

      await expect(
        assignRole(t, u._id.toString(), (await roleId(t, 'Member')).toString()),
      ).rejects.toThrow(/no Admin role assigned/i);
    });

    it('allows the same write once someone holds the Admin role', async () => {
      const t = await team();
      await user(t, await roleId(t, 'Admin'));
      const u = await user(t, undefined);
      const member = (await roleId(t, 'Member')).toString();

      await assignRole(t, u._id.toString(), member);

      const reread = await User.findById(u._id);
      expect(reread!.role!.toString()).toBe(member);
    });

    it('allows promoting the last role-less user straight to Admin', async () => {
      const t = await team();
      const u = await user(t, undefined);
      const admin = (await roleId(t, 'Admin')).toString();

      await assignRole(t, u._id.toString(), admin);

      const reread = await User.findById(u._id);
      expect(reread!.role!.toString()).toBe(admin);
    });

    it('refuses to remove the last role-less user off an admin-less team', async () => {
      const t = await team();
      const u = await user(t, undefined);

      expect(await getMemberRemovalConflict(t, u._id.toString())).toMatch(
        /no Admin role assigned/i,
      );
    });

    it('allows removing a role-less user while another role-less user remains', async () => {
      const t = await team();
      const u = await user(t, undefined);
      await user(t, undefined);

      expect(await getMemberRemovalConflict(t, u._id.toString())).toBe(null);
    });
  });
});
