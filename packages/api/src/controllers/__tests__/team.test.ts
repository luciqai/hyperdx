import { getSoleTeam } from '@/controllers/team';
import Team from '@/models/team';

// Mongoose models can be constructed/queried against a mocked query chain
// without a real database connection, so this is a plain unit test.
describe('getSoleTeam', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  function mockTeamsFound(teams: unknown[]) {
    const mockLimit = jest.fn().mockResolvedValue(teams);
    jest.spyOn(Team, 'find').mockReturnValue({ limit: mockLimit } as any);
    return mockLimit;
  }

  it('returns null when there are no teams (fresh install)', async () => {
    mockTeamsFound([]);
    expect(await getSoleTeam()).toBeNull();
  });

  it('returns the team when there is exactly one', async () => {
    const soleTeam = { _id: 'team-1', name: 'Solo Team' };
    mockTeamsFound([soleTeam]);
    expect(await getSoleTeam()).toBe(soleTeam);
  });

  it('returns null when there is more than one team (ambiguous)', async () => {
    mockTeamsFound([{ _id: 'team-1' }, { _id: 'team-2' }]);
    expect(await getSoleTeam()).toBeNull();
  });

  it('queries all teams with a limit of 2', async () => {
    const mockLimit = mockTeamsFound([]);
    await getSoleTeam();
    expect(Team.find).toHaveBeenCalledWith({});
    expect(mockLimit).toHaveBeenCalledWith(2);
  });
});
