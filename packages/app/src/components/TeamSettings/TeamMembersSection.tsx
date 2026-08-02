import { useState } from 'react';
import { HTTPError } from 'ky';
import CopyToClipboard from 'react-copy-to-clipboard';
import {
  Badge,
  Box,
  Button,
  Card,
  Divider,
  Group,
  Modal,
  Select,
  Stack,
  Table,
  Text,
  TextInput,
  Tooltip,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconLock, IconUserPlus } from '@tabler/icons-react';

import api from '@/api';
import { showRoleErrorNotification } from '@/components/TeamSettings/RoleEditorModal';
import { useMyPermissions } from '@/hooks/useMyPermissions';
import { useBrandDisplayName } from '@/theme/ThemeProvider';

/**
 * A team always needs someone who can hand out roles, so the last admin is
 * frozen. The server enforces this too (409) — disabling here just avoids
 * offering an action that is guaranteed to fail.
 */
const LAST_ADMIN_MESSAGE =
  "The last admin can't be changed. Promote someone else first.";

export default function TeamMembersSection() {
  const brandName = useBrandDisplayName();
  const { isAdmin: hasAdminAccess } = useMyPermissions();

  const {
    data: members,
    isLoading: isLoadingMembers,
    refetch: refetchMembers,
  } = api.useTeamMembers();

  const {
    data: invitations,
    isLoading: isLoadingInvitations,
    refetch: refetchInvitations,
  } = api.useTeamInvitations();

  const { data: rolesData } = api.useRoles();
  const assignRole = api.useAssignMemberRole();

  const roles = rolesData?.data ?? [];
  const roleOptions = roles.map(role => ({ value: role.id, label: role.name }));

  const adminRoleIds = new Set(
    roles.filter(role => role.isAdmin).map(role => role.id),
  );
  const holdsAdminRole = (roleId?: string | null) =>
    roleId != null && adminRoleIds.has(roleId);
  const adminCount = (members?.data ?? []).filter(member =>
    holdsAdminRole(member.roleId),
  ).length;

  const assignRoleAction = (userId: string, roleId: string | null) => {
    if (!roleId) {
      return;
    }
    assignRole.mutate(
      { userId, roleId },
      {
        onSuccess: () => {
          notifications.show({ color: 'green', message: 'Role updated' });
          refetchMembers();
        },
        onError: error => {
          // The server explains itself better than we can here — the last-admin
          // guard answers 409 with its own message.
          void showRoleErrorNotification(error, 'Could not update the role.');
        },
      },
    );
  };

  const onSubmitTeamInviteForm = ({ email }: { email: string }) => {
    sendTeamInviteAction(email);
    setTeamInviteModalShow(false);
  };

  const [
    deleteTeamMemberConfirmationModalData,
    setDeleteTeamMemberConfirmationModalData,
  ] = useState<{
    mode: 'team' | 'teamInvite' | null;
    id: string | null;
    email: string | null;
  }>({
    mode: null,
    id: null,
    email: null,
  });
  const [teamInviteModalShow, setTeamInviteModalShow] = useState(false);

  const saveTeamInvitation = api.useSaveTeamInvitation();
  const deleteTeamMember = api.useDeleteTeamMember();
  const deleteTeamInvitation = api.useDeleteTeamInvitation();

  const sendTeamInviteAction = (email: string) => {
    if (email) {
      saveTeamInvitation.mutate(
        { email },
        {
          onSuccess: () => {
            notifications.show({
              color: 'green',
              message:
                'Click "Copy URL" and share the URL with your team member',
            });
            refetchInvitations();
          },
          onError: e => {
            if (e instanceof HTTPError) {
              e.response
                .json()
                .then(res => {
                  notifications.show({
                    color: 'red',
                    message: res.message,
                    autoClose: 5000,
                  });
                })
                .catch(() => {
                  notifications.show({
                    color: 'red',
                    message: `Something went wrong. Please contact ${brandName} team.`,

                    autoClose: 5000,
                  });
                });
            } else {
              notifications.show({
                color: 'red',
                message: `Something went wrong. Please contact ${brandName} team.`,
                autoClose: 5000,
              });
            }
          },
        },
      );
    }
  };

  const onConfirmDeleteTeamMember = (id: string) => {
    if (deleteTeamMemberConfirmationModalData.mode === 'team') {
      deleteTeamMemberAction(id);
    } else if (deleteTeamMemberConfirmationModalData.mode === 'teamInvite') {
      deleteTeamInviteAction(id);
    }
    setDeleteTeamMemberConfirmationModalData({
      mode: null,
      id: null,
      email: null,
    });
  };

  const deleteTeamInviteAction = (id: string) => {
    if (id) {
      deleteTeamInvitation.mutate(
        { id: encodeURIComponent(id) },
        {
          onSuccess: () => {
            notifications.show({
              color: 'green',
              message: 'Deleted team invite',
            });
            refetchInvitations();
          },
          onError: e => {
            if (e instanceof HTTPError) {
              e.response
                .json()
                .then(res => {
                  notifications.show({
                    color: 'red',
                    message: res.message,
                    autoClose: 5000,
                  });
                })
                .catch(() => {
                  notifications.show({
                    color: 'red',
                    message: `Something went wrong. Please contact ${brandName} team.`,

                    autoClose: 5000,
                  });
                });
            } else {
              notifications.show({
                color: 'red',
                message: `Something went wrong. Please contact ${brandName} team.`,
                autoClose: 5000,
              });
            }
          },
        },
      );
    }
  };
  const deleteTeamMemberAction = (id: string) => {
    if (id) {
      deleteTeamMember.mutate(
        { userId: encodeURIComponent(id) },
        {
          onSuccess: () => {
            notifications.show({
              color: 'green',
              message: 'Deleted team member',
            });
            refetchMembers();
          },
          onError: e => {
            if (e instanceof HTTPError) {
              e.response
                .json()
                .then(res => {
                  notifications.show({
                    color: 'red',
                    message: res.message,
                    autoClose: 5000,
                  });
                })
                .catch(() => {
                  notifications.show({
                    color: 'red',
                    message: `Something went wrong. Please contact ${brandName} team.`,
                    autoClose: 5000,
                  });
                });
            } else {
              notifications.show({
                color: 'red',
                message: `Something went wrong. Please contact ${brandName} team.`,
                autoClose: 5000,
              });
            }
          },
        },
      );
    }
  };

  return (
    <Box id="team_members" data-testid="team-members-section">
      <Text size="md">Team Members</Text>
      <Divider my="md" />
      <Card>
        <Card.Section withBorder py="sm" px="lg">
          <Group align="center" justify="space-between">
            <div className="fs-7">Team Members</div>
            <Button
              data-testid="invite-member-button"
              variant="primary"
              leftSection={<IconUserPlus size={16} />}
              onClick={() => setTeamInviteModalShow(true)}
            >
              Invite Team Member
            </Button>
          </Group>
        </Card.Section>
        <Card.Section>
          <Table horizontalSpacing="lg" verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Member</Table.Th>
                <Table.Th />
                <Table.Th>Role</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {!isLoadingMembers &&
                Array.isArray(members?.data) &&
                members?.data.map(member => {
                  const isLastAdmin =
                    adminCount === 1 && holdsAdminRole(member.roleId);

                  return (
                    <Table.Tr key={member.email}>
                      <Table.Td>
                        <div>
                          {member.isCurrentUser && (
                            <Badge variant="light" mr="xs" tt="none">
                              You
                            </Badge>
                          )}
                          <span className="text-white fw-bold fs-7">
                            {member.name}
                          </span>
                        </div>
                        <Group mt={4} fz="xs">
                          <div>{member.email}</div>
                          {member.hasPasswordAuth && (
                            <div>
                              <IconLock size={14} /> Password Auth
                            </div>
                          )}
                        </Group>
                      </Table.Td>
                      <Table.Td>
                        {member.groupName && (
                          <Badge
                            variant="light"
                            color="green"
                            fw="normal"
                            tt="none"
                          >
                            {member.groupName}
                          </Badge>
                        )}
                      </Table.Td>
                      <Table.Td>
                        {/*
                          Disabled inputs swallow pointer events, so the tooltip
                          hangs off a wrapper rather than the Select itself.
                        */}
                        <Tooltip
                          label={LAST_ADMIN_MESSAGE}
                          disabled={!isLastAdmin}
                          multiline
                          w={240}
                          withArrow
                        >
                          <Box w={180}>
                            <Select
                              data-testid={`member-role-${member.email}`}
                              aria-label={`Role for ${member.email}`}
                              size="xs"
                              allowDeselect={false}
                              comboboxProps={{ withinPortal: true }}
                              data={roleOptions}
                              value={member.roleId ?? null}
                              placeholder={member.roleName ?? 'No role'}
                              disabled={!hasAdminAccess || isLastAdmin}
                              onChange={roleId =>
                                assignRoleAction(member._id, roleId)
                              }
                            />
                          </Box>
                        </Tooltip>
                      </Table.Td>
                      <Table.Td style={{ textAlign: 'right' }}>
                        {!member.isCurrentUser && hasAdminAccess && (
                          <Group justify="flex-end" gap="8">
                            <Tooltip
                              label={LAST_ADMIN_MESSAGE}
                              disabled={!isLastAdmin}
                              multiline
                              w={240}
                              withArrow
                            >
                              <Box>
                                <Button
                                  size="compact-sm"
                                  variant="danger"
                                  disabled={isLastAdmin}
                                  onClick={() =>
                                    setDeleteTeamMemberConfirmationModalData({
                                      mode: 'team',
                                      id: member._id,
                                      email: member.email,
                                    })
                                  }
                                >
                                  Remove
                                </Button>
                              </Box>
                            </Tooltip>
                          </Group>
                        )}
                      </Table.Td>
                    </Table.Tr>
                  );
                })}
              {!isLoadingInvitations &&
                Array.isArray(invitations?.data) &&
                invitations.data.map(invitation => (
                  <Table.Tr key={invitation.email} className="mt-2">
                    <Table.Td>
                      <span className="text-white fw-bold fs-7">
                        {invitation.email}
                      </span>
                    </Table.Td>
                    <Table.Td>
                      <Badge variant="dot" color="gray" fw="normal" tt="none">
                        Pending Invite
                      </Badge>
                      <CopyToClipboard text={invitation.url}>
                        <Button size="compact-xs" variant="secondary" ml="xs">
                          📋 Copy URL
                        </Button>
                      </CopyToClipboard>
                    </Table.Td>
                    {/* Role is assigned once the invite is accepted. */}
                    <Table.Td />
                    <Table.Td style={{ textAlign: 'right' }}>
                      {hasAdminAccess && (
                        <Group justify="flex-end" gap="8">
                          <Button
                            size="compact-sm"
                            variant="danger"
                            onClick={() =>
                              setDeleteTeamMemberConfirmationModalData({
                                mode: 'teamInvite',
                                id: invitation._id,
                                email: invitation.email,
                              })
                            }
                          >
                            Delete
                          </Button>
                        </Group>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
            </Table.Tbody>
          </Table>
        </Card.Section>
      </Card>

      <Modal
        centered
        onClose={() => setTeamInviteModalShow(false)}
        opened={teamInviteModalShow}
        title="Invite Team Member"
      >
        <InviteTeamMemberForm
          onSubmit={onSubmitTeamInviteForm}
          isSubmitting={saveTeamInvitation.isPending}
        />
      </Modal>

      <Modal
        centered
        onClose={() =>
          setDeleteTeamMemberConfirmationModalData({
            mode: null,
            id: null,
            email: null,
          })
        }
        opened={deleteTeamMemberConfirmationModalData.id != null}
        size="lg"
        title="Delete Team Member"
      >
        <Stack>
          <Text>
            Deleting this team member (
            {deleteTeamMemberConfirmationModalData.email}) will revoke their
            access to the team&apos;s resources and services. This action is not
            reversible.
          </Text>
          <Group justify="flex-end" gap="xs">
            <Button
              data-testid="cancel-delete-member"
              variant="secondary"
              onClick={() =>
                setDeleteTeamMemberConfirmationModalData({
                  mode: null,
                  id: null,
                  email: null,
                })
              }
            >
              Cancel
            </Button>
            <Button
              data-testid="confirm-delete-member"
              variant="danger"
              onClick={() =>
                deleteTeamMemberConfirmationModalData.id &&
                onConfirmDeleteTeamMember(
                  deleteTeamMemberConfirmationModalData.id,
                )
              }
            >
              Confirm
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Box>
  );
}

function InviteTeamMemberForm({
  isSubmitting,
  onSubmit,
}: {
  isSubmitting?: boolean;
  onSubmit: (arg0: { email: string }) => void;
}) {
  const [email, setEmail] = useState<string>('');

  return (
    <form
      onSubmit={e => {
        onSubmit({ email });
        e.preventDefault();
      }}
    >
      <Stack>
        <TextInput
          data-testid="invite-email-input"
          label="Email"
          name="email"
          type="email"
          value={email}
          onChange={e => setEmail(e.target.value)}
          required
          placeholder="you@company.com"
          withAsterisk={false}
        />
        <div className="fs-8">
          The invite link will automatically expire after 30 days.
        </div>
        <Button
          data-testid="send-invite-button"
          variant="primary"
          type="submit"
          disabled={!email || isSubmitting}
        >
          Send Invite
        </Button>
      </Stack>
    </form>
  );
}
