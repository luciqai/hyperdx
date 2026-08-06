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
