import { screen } from '@testing-library/react';

import { SourcesList } from '@/components/Sources/SourcesList';
import { useMyPermissions } from '@/hooks/useMyPermissions';
import { useSources } from '@/source';

jest.mock('@/hooks/useMyPermissions');
jest.mock('@/source', () => ({ useSources: jest.fn() }));

// The form is what makes these controls a lie for a role without
// `connections: manage` — it calls `useConnections()`. Stubbed so the test
// exercises the gating rather than the form's own data fetching.
jest.mock('@/components/Sources/SourceForm', () => ({
  TableSourceForm: () => <div data-testid="source-form" />,
}));

jest.mock('next/router', () => ({
  useRouter: () => ({
    isReady: true,
    pathname: '/team',
    query: {},
    replace: jest.fn(),
  }),
}));

// eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion
const asMock = (fn: unknown) => fn as jest.Mock;

const perms = (sources: 'none' | 'read' | 'manage') =>
  asMock(useMyPermissions).mockReturnValue({
    isAdmin: false,
    isLoading: false,
    can: (resource: string, level: string) =>
      resource === 'sources' &&
      (sources === 'manage' || (sources === 'read' && level === 'read')),
  });

beforeEach(() => {
  jest.clearAllMocks();
  asMock(useSources).mockReturnValue({
    data: [
      {
        id: 'src1',
        name: 'Logs',
        kind: 'log',
        connectionName: 'Default',
        from: { databaseName: 'default', tableName: 'otel_logs' },
      },
    ],
    isLoading: false,
    error: null,
    refetch: jest.fn(),
  });
});

// The sources LIST needs only `sources: read`, but every control that opens
// `TableSourceForm` needs `sources: manage` — the form reads connections, which
// Member and ReadOnly hold as `connections: none`, and saving from it 403s.
// §10.3: absent, not disabled.
describe('SourcesList permission gating', () => {
  it('lists sources for a role holding only sources: read', () => {
    perms('read');
    renderWithMantine(<SourcesList />);
    expect(screen.getByText('Logs')).toBeInTheDocument();
  });

  it('hides the expand chevron from a role holding only sources: read', () => {
    perms('read');
    renderWithMantine(<SourcesList />);
    expect(screen.queryByTestId('expand-source-src1')).toBeNull();
  });

  it('hides Add source from a role holding only sources: read', () => {
    perms('read');
    renderWithMantine(<SourcesList />);
    expect(screen.queryByTestId('add-source-button')).toBeNull();
  });

  it('shows both controls to a role holding sources: manage', () => {
    perms('manage');
    renderWithMantine(<SourcesList />);
    expect(screen.getByTestId('expand-source-src1')).toBeInTheDocument();
    expect(screen.getByTestId('add-source-button')).toBeInTheDocument();
  });
});
