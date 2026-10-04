import React from 'react';
import { Connection } from '@hyperdx/common-utils/dist/types';
import { fireEvent, screen, waitFor } from '@testing-library/react';

import { ConnectionForm } from '@/components/ConnectionForm';

import '@testing-library/jest-dom';

// --- Mocks ---
const mockCreateMutate = jest.fn();
const mockUpdateMutate = jest.fn();
jest.mock('@/connection', () => ({
  ...jest.requireActual('@/connection'),
  useCreateConnection: () => ({
    mutate: mockCreateMutate,
    isPending: false,
  }),
  useUpdateConnection: () => ({
    mutate: mockUpdateMutate,
    isPending: false,
  }),

  useDeleteConnection: () => ({
    mutate: jest.fn(),
    isPending: false,
  }),
}));

jest.mock('@mantine/notifications', () => ({
  notifications: {
    show: jest.fn(),
  },
}));

const mockTestConnectionMutateAsync = jest.fn();
jest.mock('@/api', () => ({
  ...(jest.requireActual('@/api') ?? {}),
  useTestConnection: () => ({
    // Default behaviour is set in beforeEach, not here: calling
    // mockResolvedValue() inside the factory re-applied it on every render and
    // silently reverted any per-test override.
    mutateAsync: mockTestConnectionMutateAsync,
  }),
}));

// --- Test Suite ---

describe('ConnectionForm', () => {
  const baseConnection: Connection = {
    id: '',
    name: 'Test Connection',
    host: 'http://localhost:8123',
    username: 'default',
    password: '',
  };

  beforeEach(() => {
    mockCreateMutate.mockClear();
    mockUpdateMutate.mockClear();
    mockTestConnectionMutateAsync.mockReset();
    mockTestConnectionMutateAsync.mockResolvedValue({ success: true });
    (
      jest.requireMock('@mantine/notifications') as any
    ).notifications.show.mockClear();
  });

  it('should save connection with trailing slash removed from host when creating', async () => {
    renderWithMantine(
      <ConnectionForm connection={baseConnection} isNew={true} />,
    );

    // Wait for form validation to complete
    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /Create/i }),
      ).toBeInTheDocument();
    });

    const hostInput = screen.getByPlaceholderText('http://localhost:8123');
    const nameInput = screen.getByPlaceholderText('My Clickhouse Server');
    const submitButton = screen.getByRole('button', { name: /Create/i });

    await fireEvent.change(nameInput, { target: { value: 'Test Name' } });
    await fireEvent.change(hostInput, {
      target: { value: 'http://example.com:8123/' },
    }); // Host with trailing slash

    fireEvent.click(submitButton);

    await waitFor(() => {
      expect(mockCreateMutate).toHaveBeenCalledTimes(1);
    });

    // Check the arguments passed to the mutate function
    expect(mockCreateMutate).toHaveBeenCalledWith(
      expect.objectContaining({
        connection: expect.objectContaining({
          host: 'http://example.com:8123',
          name: 'Test Name',
        }),
      }),
      expect.anything(),
    );
  });

  it('should save connection with trailing slash removed from host when updating', async () => {
    const existingConnection = {
      ...baseConnection,
      id: 'existing-id',
      host: 'http://old.com/',
    };
    renderWithMantine(
      <ConnectionForm connection={existingConnection} isNew={false} />,
    );

    // Wait for form validation to complete
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Save/i })).toBeInTheDocument();
    });

    const hostInput = screen.getByPlaceholderText('http://localhost:8123');
    const submitButton = screen.getByRole('button', { name: /Save/i });

    // Update host
    await fireEvent.change(hostInput, {
      target: { value: 'http://updated.com:8123/' },
    });

    fireEvent.click(submitButton);

    // Wait for mutate to be called and assert
    await waitFor(() => {
      expect(mockUpdateMutate).toHaveBeenCalledTimes(1);
    });

    // Check the arguments passed to the mutate function
    expect(mockUpdateMutate).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 'existing-id',
        connection: expect.objectContaining({
          host: 'http://updated.com:8123',
        }),
      }),
      expect.anything(),
    );
  });

  it('should use stripped host for test connection', async () => {
    renderWithMantine(
      <ConnectionForm connection={baseConnection} isNew={true} />,
    );

    // Wait for form validation to complete
    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: 'Test Connection' }),
      ).toBeInTheDocument();
    });

    const hostInput = screen.getByPlaceholderText('http://localhost:8123');
    const nameInput = screen.getByPlaceholderText('My Clickhouse Server');
    const testButton = screen.getByRole('button', { name: 'Test Connection' });

    await fireEvent.change(nameInput, { target: { value: 'Test Name' } });
    await fireEvent.change(hostInput, {
      target: { value: 'http://test.com:8123/' },
    });

    // Ensure form state is valid before clicking test
    await waitFor(() => expect(testButton).not.toBeDisabled());

    fireEvent.click(testButton);

    await waitFor(() =>
      expect(mockTestConnectionMutateAsync).toHaveBeenCalled(),
    );

    // Assert that the mock API call received the stripped host
    expect(mockTestConnectionMutateAsync).toHaveBeenCalledTimes(1);
    expect(mockTestConnectionMutateAsync).toHaveBeenCalledWith(
      expect.objectContaining({
        host: 'http://test.com:8123',
      }),
    );
  });

  it('should include hyperdxSettingPrefix when creating connection', async () => {
    renderWithMantine(
      <ConnectionForm connection={baseConnection} isNew={true} />,
    );

    // Wait for form validation to complete
    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /Create/i }),
      ).toBeInTheDocument();
    });

    const nameInput = screen.getByPlaceholderText('My Clickhouse Server');
    const hostInput = screen.getByPlaceholderText('http://localhost:8123');
    const submitButton = screen.getByRole('button', { name: /Create/i });

    // Click "Advanced Settings" to reveal the setting prefix input
    const advancedSettingsLink = screen.getByText('Advanced Settings');
    fireEvent.click(advancedSettingsLink);

    const settingPrefixInput = screen.getByPlaceholderText('hyperdx');

    await fireEvent.change(nameInput, { target: { value: 'Test Name' } });
    await fireEvent.change(hostInput, {
      target: { value: 'http://example.com:8123' },
    });
    await fireEvent.change(settingPrefixInput, {
      target: { value: 'myprefix' },
    });

    fireEvent.click(submitButton);

    await waitFor(() => {
      expect(mockCreateMutate).toHaveBeenCalledWith(
        expect.objectContaining({
          connection: expect.objectContaining({
            hyperdxSettingPrefix: 'myprefix',
          }),
        }),
        expect.anything(),
      );
    });
  });

  it('should convert empty hyperdxSettingPrefix to null when updating', async () => {
    const existingConnection = {
      ...baseConnection,
      id: 'existing-id',
      hyperdxSettingPrefix: 'oldprefix',
    };
    renderWithMantine(
      <ConnectionForm connection={existingConnection} isNew={false} />,
    );

    // Wait for form validation to complete
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Save/i })).toBeInTheDocument();
    });

    // Click "Advanced Settings" to reveal the setting prefix input
    const advancedSettingsLink = screen.getByText('Advanced Settings');
    fireEvent.click(advancedSettingsLink);

    const settingPrefixInput = screen.getByPlaceholderText('hyperdx');
    const submitButton = screen.getByRole('button', { name: /Save/i });

    // Clear the setting prefix
    await fireEvent.change(settingPrefixInput, {
      target: { value: '' },
    });

    fireEvent.click(submitButton);

    await waitFor(() => {
      expect(mockUpdateMutate).toHaveBeenCalledWith(
        expect.objectContaining({
          connection: expect.objectContaining({
            hyperdxSettingPrefix: null,
          }),
        }),
        expect.anything(),
      );
    });
  });

  // --- RBAC: a 403 must not masquerade as bad credentials ---

  /** Shape the API actually returns for an RBAC denial. */
  const permissionDenied = () => ({
    response: {
      json: async () => ({
        message: 'You do not have permission to perform this action.',
        required: { resource: 'connections', level: 'manage' },
      }),
    },
  });

  const shownMessages = () =>
    (
      jest.requireMock('@mantine/notifications') as any
    ).notifications.show.mock.calls.map((c: any[]) => c[0]?.message);

  it('surfaces the permission message when creating is denied', async () => {
    // The server returns 403 { message, required }. Before the fix onError took
    // no argument at all, so this rendered "check the host and credentials",
    // blaming the user's input for a permissions problem.
    mockCreateMutate.mockImplementation((_vars: unknown, opts: any) => {
      opts?.onError?.(permissionDenied());
    });

    renderWithMantine(
      <ConnectionForm connection={baseConnection} isNew={true} />,
    );
    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /Create/i }),
      ).toBeInTheDocument();
    });
    fireEvent.change(screen.getByPlaceholderText('My Clickhouse Server'), {
      target: { value: 'Test Name' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Create/i }));

    await waitFor(() => {
      expect(shownMessages()).toContain(
        'You do not have permission to perform this action.',
      );
    });
    expect(shownMessages().join(' ')).not.toContain(
      'check the host and credentials',
    );
  });

  it('surfaces the permission message when updating is denied', async () => {
    mockUpdateMutate.mockImplementation((_vars: unknown, opts: any) => {
      opts?.onError?.(permissionDenied());
    });

    renderWithMantine(
      <ConnectionForm
        connection={{ ...baseConnection, id: 'existing-id' }}
        isNew={false}
      />,
    );
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Save/i })).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole('button', { name: /Save/i }));

    await waitFor(() => {
      expect(shownMessages()).toContain(
        'You do not have permission to perform this action.',
      );
    });
    expect(shownMessages().join(' ')).not.toContain(
      'check the host and credentials',
    );
  });

  // The test-connection path is asserted in
  // src/utils/__tests__/errorNotification.test.ts rather than here: this
  // component reaches its hook via the default export (api.useTestConnection)
  // while this file mocks a named export, so the mock is not what runs. The
  // logic under test is the message extraction, which lives in the helper.
});
