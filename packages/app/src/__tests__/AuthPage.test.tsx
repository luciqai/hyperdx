import AuthPage from '@/AuthPage';

// AuthPage marks its error notification with `data-test-id` (hyphenated),
// not the `data-testid` attribute `getByTestId` looks for by default, so
// queries below go through this helper instead.
const getAuthErrorMessage = (container: HTMLElement) =>
  container.querySelector('[data-test-id="auth-error-msg"]');

// AuthPage resolves `err` query-param codes against a plain object literal
// (AUTH_ERROR_MESSAGES). This suite guards the `typeof resolvedAuthError ===
// 'string'` check in AuthPage.tsx: without it, inherited Object.prototype
// members (`__proto__`, `toString`, `constructor`, ...) leak through and
// either crash React ("Objects are not valid as a React child") or render
// nothing, blanking the whole login page.

let mockQuery: Record<string, string | undefined> = {};

jest.mock('next/router', () => ({
  useRouter: () => ({
    query: mockQuery,
    push: jest.fn(),
  }),
}));

jest.mock('next-seo', () => ({
  NextSeo: () => null,
}));

jest.mock('@/LandingHeader', () => ({
  __esModule: true,
  default: () => <div data-testid="landing-header" />,
}));

jest.mock('@/theme/ThemeProvider', () => ({
  __esModule: true,
  useBrandDisplayName: () => 'HyperDX',
}));

jest.mock('@/api', () => ({
  __esModule: true,
  default: {
    useTeam: () => ({ data: null, isLoading: false }),
    useInstallation: () => ({ data: { authProviders: [] } }),
    useRegisterPassword: () => ({ mutate: jest.fn() }),
  },
}));

describe('AuthPage error message rendering', () => {
  beforeEach(() => {
    mockQuery = {};
  });

  it('does not throw and shows the default message for err=__proto__', () => {
    mockQuery = { err: '__proto__' };

    let container: HTMLElement;
    expect(() => {
      container = renderWithMantine(<AuthPage action="login" />).container;
    }).not.toThrow();

    expect(getAuthErrorMessage(container!)).toHaveTextContent(
      'Unknown error occurred, please try again later.',
    );
  });

  it('does not throw and shows the default message for err=toString', () => {
    mockQuery = { err: 'toString' };

    let container: HTMLElement;
    expect(() => {
      container = renderWithMantine(<AuthPage action="login" />).container;
    }).not.toThrow();

    expect(getAuthErrorMessage(container!)).toHaveTextContent(
      'Unknown error occurred, please try again later.',
    );
  });

  it('shows the specific message for a known error code', () => {
    mockQuery = { err: 'googleDomainNotAllowed' };

    const { container } = renderWithMantine(<AuthPage action="login" />);

    expect(getAuthErrorMessage(container)).toHaveTextContent(
      'This Google account is not permitted to sign in. Contact your admin.',
    );
  });

  it('shows the default message for an unknown error code', () => {
    mockQuery = { err: 'nonsense' };

    const { container } = renderWithMantine(<AuthPage action="login" />);

    expect(getAuthErrorMessage(container)).toHaveTextContent(
      'Unknown error occurred, please try again later.',
    );
  });
});
