import { SYSTEM_ROLE_PERMISSIONS } from '@hyperdx/common-utils/dist/types';
import { Types } from 'mongoose';

import {
  assignRole,
  createRole,
  deleteRole,
  getAdminRole,
  getRolesWithCounts,
  RoleConflictError,
  seedSystemRoles,
  updateRole,
} from '@/controllers/role';
import { getServer } from '@/fixtures';
import Role from '@/models/role';
import User from '@/models/user';

describe('role controller', () => {
  const server = getServer();
  const teamId = new Types.ObjectId();

  beforeAll(async () => {
    await server.start();
    // Mongoose builds indexes in the background; awaiting init() guarantees the
    // { team, name } unique index is live before seeding relies on it.
    await Role.init();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('seeds exactly three system roles, one of them admin', async () => {
    await seedSystemRoles(teamId);

    const roles = await Role.find({ team: teamId }).sort({ name: 1 });
    expect(roles.map(r => r.name)).toEqual(['Admin', 'Member', 'ReadOnly']);
    expect(roles.filter(r => r.isAdmin)).toHaveLength(1);
    expect(roles.every(r => r.isSystem)).toBe(true);
  });

  it('is idempotent', async () => {
    await seedSystemRoles(teamId);
    await seedSystemRoles(teamId);

    expect(await Role.countDocuments({ team: teamId })).toBe(3);
  });

  it('strips isAdmin and isSystem from created roles', async () => {
    const role = await createRole(teamId, {
      name: 'Sneaky',
      permissions: SYSTEM_ROLE_PERMISSIONS.Member,
      // @ts-expect-error deliberately passing fields the type forbids
      isAdmin: true,
      isSystem: true,
    });

    expect(role.isAdmin).toBe(false);
    expect(role.isSystem).toBe(false);
  });

  it('refuses to update a system role', async () => {
    await seedSystemRoles(teamId);
    const member = await Role.findOne({ team: teamId, name: 'Member' });

    await expect(
      updateRole(teamId, member!._id.toString(), {
        name: 'Renamed',
        permissions: SYSTEM_ROLE_PERMISSIONS.Member,
      }),
    ).rejects.toBeInstanceOf(RoleConflictError);
  });

  it('refuses to delete a role that is assigned', async () => {
    const role = await createRole(teamId, {
      name: 'In use',
      permissions: SYSTEM_ROLE_PERMISSIONS.Member,
    });
    await User.create({
      email: 'a@example.com',
      team: teamId,
      role: role._id,
    });

    await expect(
      deleteRole(teamId, role._id.toString()),
    ).rejects.toBeInstanceOf(RoleConflictError);
  });

  it('refuses to demote the last admin', async () => {
    await seedSystemRoles(teamId);
    const admin = await getAdminRole(teamId);
    const member = await Role.findOne({ team: teamId, name: 'Member' });
    const user = await User.create({
      email: 'solo@example.com',
      team: teamId,
      role: admin!._id,
    });

    await expect(
      assignRole(teamId, user._id.toString(), member!._id.toString()),
    ).rejects.toBeInstanceOf(RoleConflictError);
  });

  it('allows demoting an admin when another remains', async () => {
    await seedSystemRoles(teamId);
    const admin = await getAdminRole(teamId);
    const member = await Role.findOne({ team: teamId, name: 'Member' });
    const first = await User.create({
      email: 'one@example.com',
      team: teamId,
      role: admin!._id,
    });
    await User.create({
      email: 'two@example.com',
      team: teamId,
      role: admin!._id,
    });

    await assignRole(teamId, first._id.toString(), member!._id.toString());

    const reloaded = await User.findById(first._id);
    expect(reloaded!.role!.toString()).toBe(member!._id.toString());
  });

  it('reports member counts per role', async () => {
    await seedSystemRoles(teamId);
    const admin = await getAdminRole(teamId);
    await User.create({
      email: 'c@example.com',
      team: teamId,
      role: admin!._id,
    });

    const roles = await getRolesWithCounts(teamId);
    const adminRow = roles.find(r => r.name === 'Admin');
    expect(adminRow!.memberCount).toBe(1);
    expect(roles.find(r => r.name === 'Member')!.memberCount).toBe(0);
  });

  it('counts members when the team id arrives as a string', async () => {
    await seedSystemRoles(teamId);
    const admin = await getAdminRole(teamId);
    await User.create({
      email: 'str@example.com',
      team: teamId,
      role: admin!._id,
    });

    const roles = await getRolesWithCounts(teamId.toString());
    expect(roles.find(r => r.name === 'Admin')!.memberCount).toBe(1);
  });

  // BUG-1 fix: the guard now counts holders of an isAdmin role only, and only
  // fires when the *target* holds one. A role-less sole user cannot be the
  // last admin-role holder (there isn't one), so this un-migrated team stays
  // manageable instead of getting permanently stuck. See
  // lastAdmin.int.test.ts for the full invariant coverage.
  it('does not block demoting a role-less user on an un-migrated team', async () => {
    await seedSystemRoles(teamId);
    const member = await Role.findOne({ team: teamId, name: 'Member' });
    const first = await User.create({
      email: 'roleless@example.com',
      team: teamId,
    });
    // A second role-less user remains, so this is not the terminal write that
    // the admin-less guard refuses — see lastAdmin.int.test.ts.
    await User.create({ email: 'roleless2@example.com', team: teamId });

    await assignRole(teamId, first._id.toString(), member!._id.toString());

    const reloaded = await User.findById(first._id);
    expect(reloaded!.role!.toString()).toBe(member!._id.toString());
  });

  // The second, independent invariant: the fail-open population is real admin
  // access, and draining it to zero while nobody holds an Admin role cannot be
  // undone through the API.
  it('blocks the write that would leave no admin holder and no role-less user', async () => {
    await seedSystemRoles(teamId);
    const member = await Role.findOne({ team: teamId, name: 'Member' });
    const soleUser = await User.create({
      email: 'sole@example.com',
      team: teamId,
    });

    await expect(
      assignRole(teamId, soleUser._id.toString(), member!._id.toString()),
    ).rejects.toBeInstanceOf(RoleConflictError);
  });

  // BUG-1 fix: a role-less user is no longer counted as an admin, so it can no
  // longer stand in for a "remaining admin" that lets the last real
  // isAdmin-role holder be demoted. Previously this silently succeeded and
  // left the team with zero admin-role holders.
  it('refuses to demote the last isAdmin-role holder even when a role-less user exists', async () => {
    await seedSystemRoles(teamId);
    const admin = await getAdminRole(teamId);
    const member = await Role.findOne({ team: teamId, name: 'Member' });
    const held = await User.create({
      email: 'held@example.com',
      team: teamId,
      role: admin!._id,
    });
    await User.create({ email: 'other@example.com', team: teamId });

    await expect(
      assignRole(teamId, held._id.toString(), member!._id.toString()),
    ).rejects.toBeInstanceOf(RoleConflictError);
  });

  it('rejects a duplicate role name with a conflict, not a raw driver error', async () => {
    await createRole(teamId, {
      name: 'Duplicated',
      permissions: SYSTEM_ROLE_PERMISSIONS.Member,
    });

    await expect(
      createRole(teamId, {
        name: 'Duplicated',
        permissions: SYSTEM_ROLE_PERMISSIONS.Member,
      }),
    ).rejects.toBeInstanceOf(RoleConflictError);
  });

  it('clears dangling role references when a role is deleted', async () => {
    const role = await createRole(teamId, {
      name: 'Doomed',
      permissions: SYSTEM_ROLE_PERMISSIONS.Member,
    });
    await deleteRole(teamId, role._id.toString());

    // Simulate the delete/assign race: a user written after the in-use check.
    const stray = await User.create({
      email: 'stray@example.com',
      team: teamId,
      role: role._id,
    });
    const again = await createRole(teamId, {
      name: 'Doomed2',
      permissions: SYSTEM_ROLE_PERMISSIONS.Member,
    });
    await User.findByIdAndUpdate(stray._id, { role: again._id });
    await expect(
      deleteRole(teamId, again._id.toString()),
    ).rejects.toBeInstanceOf(RoleConflictError);
  });
});
