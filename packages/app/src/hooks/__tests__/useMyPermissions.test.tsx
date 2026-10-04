import { renderHook } from '@testing-library/react';

import { useMyPermissions } from '@/hooks/useMyPermissions';

const mockUseMe = jest.fn();
jest.mock('@/api', () => ({
  __esModule: true,
  // This is a mock of the api.useMe hook, so it must keep the `use` prefix.
  default: { useMe: () => mockUseMe() },
}));

describe('useMyPermissions', () => {
  it('grants everything to an admin', () => {
    mockUseMe.mockReturnValue({
      data: { role: { isAdmin: true, permissions: { connections: 'none' } } },
      isLoading: false,
    });

    const { result } = renderHook(() => useMyPermissions());

    expect(result.current.isAdmin).toBe(true);
    expect(result.current.can('connections', 'manage')).toBe(true);
  });

  it('compares levels for a non-admin', () => {
    mockUseMe.mockReturnValue({
      data: {
        role: {
          isAdmin: false,
          permissions: { dashboards: 'read', alerts: 'manage' },
        },
      },
      isLoading: false,
    });

    const { result } = renderHook(() => useMyPermissions());

    expect(result.current.can('dashboards', 'read')).toBe(true);
    expect(result.current.can('dashboards', 'manage')).toBe(false);
    expect(result.current.can('alerts', 'manage')).toBe(true);
  });

  it('grants everything when there is no role, matching the server fail-open', () => {
    mockUseMe.mockReturnValue({ data: { role: null }, isLoading: false });

    const { result } = renderHook(() => useMyPermissions());

    expect(result.current.isAdmin).toBe(true);
    expect(result.current.can('connections', 'manage')).toBe(true);
  });

  // Regression: `me` is undefined while /me is in flight, which made `role`
  // null and therefore isAdmin true — flashing the full admin UI to every
  // non-admin on load and letting them click controls that then 403.
  it('grants nothing while /me is still loading', () => {
    mockUseMe.mockReturnValue({ data: undefined, isLoading: true });

    const { result } = renderHook(() => useMyPermissions());

    expect(result.current.isLoading).toBe(true);
    expect(result.current.isAdmin).toBe(false);
    expect(result.current.can('dashboards', 'read')).toBe(false);
  });
});
