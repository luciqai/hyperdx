import { useState } from 'react';
import { type HTTPError } from 'ky';
import {
  type Role,
  type RolePermissions,
  SYSTEM_ROLE_PERMISSIONS,
} from '@hyperdx/common-utils/dist/types';
import { Button, Group, Modal, Stack, Text, TextInput } from '@mantine/core';
import { notifications } from '@mantine/notifications';

import api from '@/api';
import PermissionMatrix from '@/components/TeamSettings/PermissionMatrix';

/**
 * The API answers role conflicts (duplicate name, system role, role still in
 * use) with a message in the JSON body — surface that rather than ky's generic
 * "Request failed with status code 409".
 */
export async function showRoleErrorNotification(
  error: HTTPError,
  fallback: string,
) {
  let message = fallback;
  try {
    // Network failures reject with something that has no `response` at all,
    // even though the mutation types the error as HTTPError.
    const body: unknown = await error?.response?.json();
    if (
      body != null &&
      typeof body === 'object' &&
      'message' in body &&
      typeof body.message === 'string' &&
      body.message.length > 0
    ) {
      message = body.message;
    }
  } catch {
    // Body was not JSON — the fallback already says something useful.
  }
  notifications.show({ color: 'red', message, autoClose: 5000 });
}

export default function RoleEditorModal({
  opened,
  role,
  onClose,
  onSaved,
}: {
  opened: boolean;
  /** null = create; a system role opens read-only. */
  role: Role | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  // `editing` tracks the save target separately from the `role` prop, so
  // "duplicate" can clear it and drop into create mode without closing.
  //
  // These initialisers only run on mount: the parent mounts this component
  // when the editor opens and keys it by role, so every open starts from a
  // fresh copy of the props without an effect syncing state back down.
  const [editing, setEditing] = useState<Role | null>(role);
  const [name, setName] = useState(role?.name ?? '');
  const [description, setDescription] = useState(role?.description ?? '');
  const [permissions, setPermissions] = useState<RolePermissions>(
    role?.permissions ?? SYSTEM_ROLE_PERMISSIONS.Member,
  );

  const createRole = api.useCreateRole();
  const updateRole = api.useUpdateRole();

  const readOnly = editing?.isSystem === true;

  const onError = (error: HTTPError) => {
    void showRoleErrorNotification(
      error,
      'Could not save the role. Please try again.',
    );
  };

  const onSuccess = (message: string) => {
    notifications.show({ color: 'green', message });
    onSaved();
    onClose();
  };

  const handleSave = () => {
    const input = { name: name.trim(), description, permissions };
    if (editing && !editing.isSystem) {
      updateRole.mutate(
        { id: editing.id, ...input },
        { onSuccess: () => onSuccess('Role updated'), onError },
      );
    } else {
      createRole.mutate(input, {
        onSuccess: () => onSuccess('Role created'),
        onError,
      });
    }
  };

  /**
   * System roles are starting points. Clearing `editing` is what makes the
   * next save take the create branch — without it the save would target the
   * immutable system role and 409.
   */
  const handleDuplicate = () => {
    setName(`${editing?.name ?? 'Role'} copy`);
    setDescription(editing?.description ?? '');
    setEditing(null);
    // `permissions` already holds the system role's matrix.
  };

  const title =
    editing == null ? 'New role' : readOnly ? editing.name : 'Edit role';

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title={title}
      size="lg"
      data-testid="role-editor-modal"
    >
      <Stack gap="md">
        <TextInput
          label="Role name"
          value={name}
          disabled={readOnly}
          maxLength={64}
          onChange={e => setName(e.currentTarget.value)}
        />
        <TextInput
          label="Description"
          placeholder="Optional"
          value={description}
          disabled={readOnly}
          maxLength={256}
          onChange={e => setDescription(e.currentTarget.value)}
        />

        <PermissionMatrix
          value={permissions}
          onChange={setPermissions}
          readOnly={readOnly}
        />

        <Group justify="space-between" gap="md">
          <Text size="xs" c="dimmed">
            Inviting and removing members stays with Admins.
          </Text>
          <Group gap="xs">
            <Button variant="secondary" onClick={onClose}>
              Cancel
            </Button>
            {readOnly ? (
              <Button variant="secondary" onClick={handleDuplicate}>
                Duplicate as custom role
              </Button>
            ) : (
              <Button
                variant="primary"
                disabled={name.trim().length === 0}
                loading={createRole.isPending || updateRole.isPending}
                onClick={handleSave}
              >
                {editing ? 'Save changes' : 'Create role'}
              </Button>
            )}
          </Group>
        </Group>
      </Stack>
    </Modal>
  );
}
