import { getServer } from '@/fixtures';
import Role from '@/models/role';
import Team from '@/models/team';
import User from '@/models/user';
import { bootstrapRbacRoles } from '@/utils/rbacStartup';

/**
 * The upgrade path the RBAC rollout never covered.
 *
 * `seedSystemRoles` is only reachable from registration, invite acceptance,
 * Google user creation and the local-app-mode boot. A team that already
 * existed when RBAC shipped gets its roles from the migrate-mongo migration —
 * which no Docker entrypoint runs. The result on every upgraded install is an
 * empty `roles` collection, role-less users riding the session fail-open, and
 * no API route that can ever mint an `isAdmin` role to repair it.
 */
describe('bootstrapRbacRoles', () => {
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

  const makeUser = (teamId: any, email: string, createdAt: Date) =>
    User.create({ email, name: email, team: teamId, createdAt });

  it('seeds the three system roles for a team that predates RBAC', async () => {
    const team = await Team.create({ name: 'Legacy Team' });

    const report = await bootstrapRbacRoles();

    const roles = await Role.find({ team: team._id }).sort({ name: 1 });
    expect(roles.map(r => r.name)).toEqual(['Admin', 'Member', 'ReadOnly']);
    expect(roles.every(r => r.isSystem)).toBe(true);
    expect(roles.filter(r => r.isAdmin)).toHaveLength(1);
    expect(report.teamsSeeded).toBe(1);
  });

  it('backfills role-less users onto the Admin role', async () => {
    const team = await Team.create({ name: 'Legacy Team' });
    await makeUser(team._id, 'founder@example.com', new Date('2024-01-01'));
    await makeUser(team._id, 'later@example.com', new Date('2024-06-01'));

    const report = await bootstrapRbacRoles();

    const users = await User.find({ team: team._id }).populate('role');
    expect(users).toHaveLength(2);
    for (const user of users) {
      expect((user.role as any)?.isAdmin).toBe(true);
    }
    expect(report.usersBackfilled).toBe(2);
  });

  /**
   * The reported lockout. The operator rode the fail-open, created a custom
   * role with every `manage` permission, assigned it to themselves — and lost
   * admin, because `createRole` hard-codes `isAdmin: false` and `requireAdmin`
   * never consults permissions. Nothing role-less is left to backfill, so the
   * team has zero callers who can pass `requireAdmin` and no route can undo it.
   */
  it('repairs a team stranded with no admin-role holder', async () => {
    const team = await Team.create({ name: 'Stranded Team' });
    const custom = await Role.create({
      team: team._id,
      name: 'Custom Admin',
      isSystem: false,
      isAdmin: false,
      permissions: {
        dashboards: 'manage',
        savedSearches: 'manage',
        sources: 'manage',
        alerts: 'manage',
        webhooks: 'manage',
        connections: 'manage',
        users: 'read',
        team: 'manage',
      },
    });

    const founder = await makeUser(
      team._id,
      'founder@example.com',
      new Date('2024-01-01'),
    );
    const later = await makeUser(
      team._id,
      'later@example.com',
      new Date('2024-06-01'),
    );
    await User.updateMany({ team: team._id }, { $set: { role: custom._id } });

    const report = await bootstrapRbacRoles();

    // The founder — the team's oldest user — is the one promoted, matching
    // "the founder of a team is its first admin" at registration.
    const repaired = await User.findById(founder._id).populate('role');
    expect((repaired!.role as any).isAdmin).toBe(true);
    expect((repaired!.role as any).name).toBe('Admin');

    // Nobody else is touched: repair is the minimum write that unwedges.
    const untouched = await User.findById(later._id).populate('role');
    expect((untouched!.role as any).name).toBe('Custom Admin');

    expect(report.teamsRepaired).toBe(1);
  });

  it('leaves a healthy team untouched and is idempotent', async () => {
    const team = await Team.create({ name: 'Healthy Team' });
    await makeUser(team._id, 'founder@example.com', new Date('2024-01-01'));

    await bootstrapRbacRoles();
    const second = await bootstrapRbacRoles();

    expect(second.usersBackfilled).toBe(0);
    expect(second.teamsRepaired).toBe(0);
    expect(await Role.countDocuments({ team: team._id })).toBe(3);
  });

  /**
   * A team with no users at all cannot be repaired and must not be reported
   * as repaired — there is nobody to promote.
   */
  it('does not report a repair for a team with no users', async () => {
    await Team.create({ name: 'Empty Team' });

    const report = await bootstrapRbacRoles();

    expect(report.teamsRepaired).toBe(0);
  });

  it('never throws, so a bootstrap failure cannot block startup', async () => {
    const spy = jest.spyOn(Team, 'find').mockImplementation((() => {
      throw new Error('mongo is down');
    }) as any);

    await expect(bootstrapRbacRoles()).resolves.toEqual(
      expect.objectContaining({ teamsSeeded: 0 }),
    );

    spy.mockRestore();
  });
});
