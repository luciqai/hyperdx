import { seedSystemRoles } from '@/controllers/role';
import type { ObjectId } from '@/models';
import Role from '@/models/role';
import Team from '@/models/team';
import User from '@/models/user';
import { getCounter } from '@/utils/instrumentation';
import logger from '@/utils/logger';

const roleLessAtBootCounter = getCounter(
  'hyperdx.rbac.users_without_role_at_boot',
  {
    description:
      'Users with no role assigned, counted once at startup. Non-zero means the RBAC migration has not run and those users resolve as admin via the session fail-open.',
  },
);

const teamsSeededCounter = getCounter('hyperdx.rbac.teams_seeded_at_boot', {
  description:
    'Teams that gained their system roles during the boot-time RBAC bootstrap. Non-zero on the first boot after upgrading an install that predates RBAC.',
});

const usersBackfilledCounter = getCounter(
  'hyperdx.rbac.users_backfilled_at_boot',
  {
    description:
      'Role-less users assigned the Admin role by the boot-time RBAC bootstrap.',
  },
);

const teamsRepairedCounter = getCounter('hyperdx.rbac.teams_repaired_at_boot', {
  description:
    'Teams that had zero callers able to pass requireAdmin and were repaired at boot by promoting their oldest user to Admin.',
});

const bootstrapFailedCounter = getCounter('hyperdx.rbac.bootstrap_failed', {
  description:
    'Boot-time RBAC bootstrap failures. Non-zero means system roles may be missing and admin routes unreachable.',
});

export type RbacBootstrapReport = {
  teamsSeeded: number;
  usersBackfilled: number;
  teamsRepaired: number;
};

/**
 * Boot-time half of §11.3's "loud, never silent" guarantee.
 *
 * BUG-6: the only boot-time RBAC output was the coverage line. The fail-open's
 * entire safety case rests on being noticed, and a per-request WARN that
 * accrues 128 lines an hour is noise, not signal. Returns the count so callers
 * and tests can assert on it.
 */
export async function warnOnRoleLessUsers(): Promise<number> {
  try {
    const count = await User.countDocuments({
      role: { $in: [null, undefined] },
    });

    // A clean boot stays clean — logging zero would train operators to skim.
    if (count === 0) return 0;

    roleLessAtBootCounter.add(count);
    logger.warn(
      { roleLessUserCount: count },
      'RBAC: users have no role assigned and will resolve as admin (fail-open). ' +
        'Run the RBAC migration to assign roles.',
    );

    return count;
  } catch (e) {
    // Never let a startup diagnostic prevent startup.
    logger.error({ err: e }, 'RBAC: failed to count users without a role');
    return 0;
  }
}

/**
 * Bring every team up to the RBAC baseline, idempotently, on every boot.
 *
 * `seedSystemRoles` is only reachable from password registration, invite
 * acceptance, Google user creation, and the `IS_LOCAL_APP_MODE` boot. A team
 * that already existed when RBAC shipped is covered by none of them: its only
 * seeding path is the `add_rbac_roles` migrate-mongo migration, and no Docker
 * entrypoint runs migrate-mongo — `make dev-migrate-db` is the sole invocation
 * in the repo. Every upgraded install therefore boots with an empty `roles`
 * collection, role-less users riding the session fail-open, and a Team Settings
 * page that lists no roles at all.
 *
 * That state is a trap rather than merely a gap, because it is one assignment
 * away from being unrecoverable. `createRole` hard-codes `isAdmin: false` and
 * `requireAdmin` never consults the permission map, so an operator who creates
 * a custom "admin" role and assigns it to themselves trades the fail-open for a
 * role that can never pass `requireAdmin` — losing key rotation, role
 * assignment, invitations and role creation with no API route left to undo it.
 *
 * Doing this at boot rather than in the migration is deliberate: it is
 * idempotent by construction, needs no changelog collection, and cannot leave a
 * half-applied state behind if it is interrupted. It mirrors `setupTeamDefaults`
 * calling `seedSystemRoles` unconditionally for the same reason.
 *
 * Fails soft in every branch. A bootstrap that cannot run must degrade to the
 * old fail-open behaviour, not refuse to start the API.
 */
export async function bootstrapRbacRoles(): Promise<RbacBootstrapReport> {
  const report: RbacBootstrapReport = {
    teamsSeeded: 0,
    usersBackfilled: 0,
    teamsRepaired: 0,
  };

  let teams: { _id: ObjectId }[];
  try {
    teams = await Team.find({}).select('_id').lean();
  } catch (e) {
    bootstrapFailedCounter.add(1);
    logger.error(
      { err: e },
      'RBAC: could not list teams for the boot-time bootstrap; system roles may be missing.',
    );
    return report;
  }

  for (const team of teams) {
    try {
      await bootstrapTeam(team._id, report);
    } catch (e) {
      // One wedged team must not stop the others from being repaired.
      bootstrapFailedCounter.add(1);
      logger.error(
        { err: e, teamId: team._id.toString() },
        'RBAC: boot-time bootstrap failed for this team; its admin routes may be unreachable.',
      );
    }
  }

  if (report.teamsSeeded > 0) teamsSeededCounter.add(report.teamsSeeded);
  if (report.usersBackfilled > 0) {
    usersBackfilledCounter.add(report.usersBackfilled);
  }
  if (report.teamsRepaired > 0) teamsRepairedCounter.add(report.teamsRepaired);

  return report;
}

async function bootstrapTeam(
  teamId: ObjectId,
  report: RbacBootstrapReport,
): Promise<void> {
  const rolesBefore = await Role.countDocuments({ team: teamId });

  // Idempotent: `$setOnInsert` upserts on {team, name}, so an already-seeded
  // team is left exactly as it is — including any edits to a system role made
  // by direct Mongo access.
  const roles = await seedSystemRoles(teamId);
  if (rolesBefore === 0) {
    report.teamsSeeded += 1;
    logger.info(
      { teamId: teamId.toString() },
      'RBAC: seeded system roles for a team that had none. This install predates RBAC or never ran the migration.',
    );
  }

  const adminRole = roles.find(r => r.isAdmin);
  if (!adminRole) {
    // seedSystemRoles always upserts an isAdmin Admin role, so reaching here
    // means a non-system role already occupies the name "Admin" — the exact
    // collision the migration's pre-flight aborts on. Say so rather than
    // silently skipping the backfill.
    throw new Error(
      'no isAdmin role after seeding; a non-system role is likely named "Admin"',
    );
  }

  // Every pre-RBAC user becomes an Admin of their own team, matching the
  // migration. Downgrading people is then a deliberate act rather than
  // something an upgrade does to them silently. Scoped to users with no role
  // so a re-run never clobbers assignments an admin has since made.
  const backfilled = await User.updateMany(
    { team: teamId, role: { $in: [null, undefined] } },
    { $set: { role: adminRole._id } },
  );
  if (backfilled.modifiedCount > 0) {
    report.usersBackfilled += backfilled.modifiedCount;
    logger.warn(
      { teamId: teamId.toString(), userCount: backfilled.modifiedCount },
      'RBAC: assigned the Admin role to users who had none. They were previously resolving as admin through the session fail-open.',
    );
  }

  await repairAdminLessTeam(teamId, adminRole._id, report);
}

/**
 * The lockout repair.
 *
 * After the backfill above, a team with nobody holding an `isAdmin` role has
 * nobody who can pass `requireAdmin` at all — the fail-open only covers
 * role-less users, and there are none left. `controllers/role.ts` guards
 * against *reaching* this state through the API and describes it as
 * recoverable "only [by] direct Mongo surgery"; those guards cannot help a team
 * that arrived here through the un-migrated upgrade path instead.
 *
 * The oldest user is promoted because that is the team's founder, and
 * registration already establishes "the founder of a team is its first admin".
 * Deterministic beats arbitrary: a rerun promotes the same person. Only that
 * one user is touched — the minimum write that unwedges the team, leaving every
 * other role assignment for the restored admin to review.
 */
async function repairAdminLessTeam(
  teamId: ObjectId,
  adminRoleId: ObjectId,
  report: RbacBootstrapReport,
): Promise<void> {
  const adminRoleIds = (
    await Role.find({ team: teamId, isAdmin: true }).select('_id').lean()
  ).map(r => r._id);

  const adminHolders = await User.countDocuments({
    team: teamId,
    role: { $in: adminRoleIds },
  });
  if (adminHolders > 0) return;

  // Nothing to promote. An empty team is not wedged — the next user to join it
  // gets a role from the registration or invite path.
  const founder = await User.findOne({ team: teamId })
    .sort({ createdAt: 1, _id: 1 })
    .select('_id email');
  if (!founder) return;

  await User.updateOne({ _id: founder._id }, { $set: { role: adminRoleId } });

  report.teamsRepaired += 1;
  logger.warn(
    { teamId: teamId.toString(), userId: founder._id.toString() },
    'RBAC: this team had no member able to pass requireAdmin — key rotation, role assignment and invitations were all unreachable. ' +
      "Promoted its earliest member to the Admin role to restore access. Review the team's role assignments.",
  );
}
