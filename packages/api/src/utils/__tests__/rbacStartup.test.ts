import User from '@/models/user';
import logger from '@/utils/logger';
import { warnOnRoleLessUsers } from '@/utils/rbacStartup';

jest.mock('@/models/user', () => ({ countDocuments: jest.fn() }));
jest.mock('@/utils/logger', () => ({ warn: jest.fn(), error: jest.fn() }));

describe('warnOnRoleLessUsers', () => {
  beforeEach(() => jest.clearAllMocks());

  // BUG-6. §11.3 rests the entire safety case for the fail-open on it being
  // "loud, never silent", but the only boot-time RBAC output was the coverage
  // line — nothing counted or warned about users with role == null.
  it('warns with the count when role-less users exist', async () => {
    (User.countDocuments as jest.Mock).mockResolvedValue(7);

    const count = await warnOnRoleLessUsers();

    expect(count).toBe(7);
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ roleLessUserCount: 7 }),
      expect.stringContaining('RBAC migration'),
    );
  });

  it('stays silent on a clean boot', async () => {
    (User.countDocuments as jest.Mock).mockResolvedValue(0);

    const count = await warnOnRoleLessUsers();

    expect(count).toBe(0);
    expect(logger.warn).not.toHaveBeenCalled();
  });

  // Startup diagnostics must never be able to prevent startup.
  it('does not throw when the count query fails', async () => {
    (User.countDocuments as jest.Mock).mockRejectedValue(new Error('no db'));

    await expect(warnOnRoleLessUsers()).resolves.toBe(0);
  });
});
