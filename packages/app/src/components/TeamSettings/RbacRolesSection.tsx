import { useState } from 'react';
import { type Role } from '@hyperdx/common-utils/dist/types';
import {
  Badge,
  Button,
  Card,
  Center,
  Group,
  Loader,
  Stack,
  Table,
  Text,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconPlus } from '@tabler/icons-react';

import api from '@/api';
import EmptyState from '@/components/EmptyState';
import RoleEditorModal, {
  showRoleErrorNotification,
} from '@/components/TeamSettings/RoleEditorModal';
import { useConfirm } from '@/useConfirm';

/**
 * The roles list. Rendered only for admins — role CRUD is a hard capability,
 * so non-admins get no disabled version of this card, they get no card.
 */
export default function RbacRolesSection() {
  const confirm = useConfirm();
  const { data, isLoading, refetch } = api.useRoles();
  const deleteRole = api.useDeleteRole();

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<Role | null>(null);

  const roles = data?.data ?? [];
  const hasCustomRoles = roles.some(role => !role.isSystem);

  const openCreate = () => {
    setEditing(null);
    setEditorOpen(true);
  };

  const openRole = (role: Role) => {
    setEditing(role);
    setEditorOpen(true);
  };

  const onDelete = async (role: Role) => {
    const confirmed = await confirm(
      `Are you sure you want to delete the "${role.name}" role?`,
      'Delete',
      { variant: 'danger' },
    );
    if (!confirmed) {
      return;
    }

    deleteRole.mutate(role.id, {
      onSuccess: () => {
        notifications.show({ color: 'green', message: 'Role deleted' });
        refetch();
      },
      onError: error => {
        // A role still assigned to members answers 409 with the count — that
        // message is more useful than anything we could write here.
        void showRoleErrorNotification(error, 'Could not delete the role.');
      },
    });
  };

  return (
    <Card id="team_roles" data-testid="rbac-roles-section">
      <Card.Section withBorder py="sm" px="lg">
        <Group align="flex-start" justify="space-between">
          <div>
            <Text fw={600}>Roles</Text>
            <Text size="sm" c="dimmed">
              Roles decide what members can see and change. Every member has
              exactly one.
            </Text>
          </div>
          <Button
            data-testid="add-role-button"
            variant="primary"
            leftSection={<IconPlus size={16} />}
            onClick={openCreate}
          >
            Add role
          </Button>
        </Group>
      </Card.Section>

      <Card.Section>
        {isLoading ? (
          <Center py="xl">
            <Loader color="dimmed" />
          </Center>
        ) : (
          <Stack gap="md" pb={hasCustomRoles ? undefined : 'lg'}>
            <Table horizontalSpacing="lg" verticalSpacing="xs">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Role</Table.Th>
                  <Table.Th>Members</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {roles.map(role => (
                  <Table.Tr key={role.id}>
                    <Table.Td>
                      <Group gap="xs">
                        <Text fw={500} size="sm">
                          {role.name}
                        </Text>
                        {role.isSystem && (
                          <Badge variant="light" color="gray" tt="none">
                            System
                          </Badge>
                        )}
                      </Group>
                      {role.description && (
                        <Text size="xs" c="dimmed">
                          {role.description}
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>{role.memberCount ?? 0}</Table.Td>
                    <Table.Td style={{ textAlign: 'right' }}>
                      <Group justify="flex-end" gap="8" wrap="nowrap">
                        <Button
                          size="compact-sm"
                          variant="subtle"
                          onClick={() => openRole(role)}
                        >
                          {role.isSystem ? 'View' : 'Edit'}
                        </Button>
                        {!role.isSystem && (
                          <Button
                            size="compact-sm"
                            variant="danger"
                            loading={
                              deleteRole.isPending &&
                              deleteRole.variables === role.id
                            }
                            onClick={() => void onDelete(role)}
                          >
                            Delete
                          </Button>
                        )}
                      </Group>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>

            {!hasCustomRoles && (
              <EmptyState
                title="Just the three built-in roles"
                description="Create a custom role when the built-ins don't fit — say, alerting access without dashboard editing."
              />
            )}
          </Stack>
        )}
      </Card.Section>

      {/*
        Mounted only while open, and keyed by the role being edited, so the
        editor always starts from a fresh copy of the role instead of syncing
        props into state after the fact.
      */}
      {editorOpen && (
        <RoleEditorModal
          key={editing?.id ?? 'new-role'}
          opened
          role={editing}
          onClose={() => setEditorOpen(false)}
          onSaved={refetch}
        />
      )}
    </Card>
  );
}
