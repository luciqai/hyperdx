// --- mocks (hoisted; names must be prefixed with `mock`) ---
const mockCounterAdd = jest.fn();
const mockLogger = { warn: jest.fn() };

jest.mock('@/config', () => ({ IS_LOCAL_APP_MODE: false }));
jest.mock('@/utils/instrumentation', () => ({
  getCounter: () => ({ add: (...args: unknown[]) => mockCounterAdd(...args) }),
}));
jest.mock('@/utils/logger', () => ({
  __esModule: true,
  default: mockLogger,
}));

import { resolveVerdict } from '@/middleware/rbac';

// `warnedMissingRole` is a process-lifetime Set inside rbac.ts, shared across
// every test in this file. Each test below uses actorIds no other test here
// uses, so the dedupe guard never leaks between cases.
describe('resolveVerdict missing-role split (counter vs. log)', () => {
  beforeEach(() => jest.clearAllMocks());

  it('counts every request but logs only once per actor+authPath', () => {
    resolveVerdict(null, 'session', 'split-user-1');
    resolveVerdict(null, 'session', 'split-user-1');

    expect(mockLogger.warn).toHaveBeenCalledTimes(1);
    expect(mockCounterAdd).toHaveBeenCalledTimes(2);
  });

  it('warns independently for different actors (dedupe is per-user, not global)', () => {
    resolveVerdict(null, 'session', 'split-user-2');
    resolveVerdict(null, 'session', 'split-user-3');

    expect(mockLogger.warn).toHaveBeenCalledTimes(2);
    expect(mockCounterAdd).toHaveBeenCalledTimes(2);
  });

  it('warns independently per auth path for the same actor', () => {
    resolveVerdict(null, 'session', 'split-user-4');
    resolveVerdict(null, 'access-key', 'split-user-4');

    expect(mockLogger.warn).toHaveBeenCalledTimes(2);
    expect(mockCounterAdd).toHaveBeenCalledTimes(2);
  });
});
