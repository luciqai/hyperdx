import {
  getApiErrorMessage,
  showApiErrorNotification,
} from '@/utils/errorNotification';

jest.mock('@mantine/notifications', () => ({
  notifications: { show: jest.fn() },
}));

const shown = () =>
  (jest.requireMock('@mantine/notifications') as any).notifications.show;

describe('getApiErrorMessage', () => {
  beforeEach(() => shown().mockClear());

  // The regression this exists for: RBAC answers 403 with `message`, and
  // handlers that looked for `error` fell through to a fallback that blamed
  // the host and credentials for what was really a permissions problem.
  it('reads an RBAC denial body', async () => {
    const err = {
      response: {
        json: async () => ({
          message: 'You do not have permission to perform this action.',
          required: { resource: 'connections', level: 'manage' },
        }),
      },
    };

    await expect(getApiErrorMessage(err, 'FALLBACK')).resolves.toBe(
      'You do not have permission to perform this action.',
    );
  });

  it('falls back when the body uses a different key', async () => {
    const err = { response: { json: async () => ({ error: 'legacy shape' }) } };
    await expect(getApiErrorMessage(err, 'FALLBACK')).resolves.toBe('FALLBACK');
  });

  it('falls back on an empty message rather than showing a blank toast', async () => {
    const err = { response: { json: async () => ({ message: '' }) } };
    await expect(getApiErrorMessage(err, 'FALLBACK')).resolves.toBe('FALLBACK');
  });

  it('falls back when there is no response at all (network failure)', async () => {
    await expect(
      getApiErrorMessage(new Error('offline'), 'FALLBACK'),
    ).resolves.toBe('FALLBACK');
  });

  it('falls back when the body is not JSON', async () => {
    const err = {
      response: {
        json: async () => {
          throw new Error('Unexpected token < in JSON');
        },
      },
    };
    await expect(getApiErrorMessage(err, 'FALLBACK')).resolves.toBe('FALLBACK');
  });

  it('falls back on null and non-object bodies', async () => {
    await expect(
      getApiErrorMessage({ response: { json: async () => null } }, 'FALLBACK'),
    ).resolves.toBe('FALLBACK');
    await expect(
      getApiErrorMessage(
        { response: { json: async () => 'nope' } },
        'FALLBACK',
      ),
    ).resolves.toBe('FALLBACK');
  });
});

describe('showApiErrorNotification', () => {
  beforeEach(() => shown().mockClear());

  it('shows the server message in red', async () => {
    await showApiErrorNotification(
      { response: { json: async () => ({ message: 'DENIED' }) } },
      'FALLBACK',
    );

    expect(shown()).toHaveBeenCalledWith(
      expect.objectContaining({ color: 'red', message: 'DENIED' }),
    );
  });

  it('shows the fallback when nothing usable is available', async () => {
    await showApiErrorNotification(new Error('boom'), 'FALLBACK');

    expect(shown()).toHaveBeenCalledWith(
      expect.objectContaining({ color: 'red', message: 'FALLBACK' }),
    );
  });
});
