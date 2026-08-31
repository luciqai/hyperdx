import { screen } from '@testing-library/react';

import api from '@/api';
import ApiKeysSection from '@/components/TeamSettings/ApiKeysSection';
import TeamMembersSection from '@/components/TeamSettings/TeamMembersSection';
import WebhooksSection from '@/components/TeamSettings/WebhooksSection';
import { useMyPermissions } from '@/hooks/useMyPermissions';

jest.mock('@/hooks/useMyPermissions');

// The real ConfirmProvider lives in pages/_app.tsx and pulls in next/router.
// These tests only assert which controls render, never that a dialog opens.
jest.mock('@/useConfirm', () => ({ useConfirm: () => jest.fn() }));

jest.mock('@/api', () => ({
  __esModule: true,
  default: {
    useTeam: jest.fn(),
    useMe: jest.fn(),
    useRotateTeamApiKey: jest.fn(),
    useRotatePersonalAccessKey: jest.fn(),
    useWebhooks: jest.fn(),
    useDeleteWebhook: jest.fn(),
    useTeamMembers: jest.fn(),
    useTeamInvitations: jest.fn(),
    useRoles: jest.fn(),
    useAssignMemberRole: jest.fn(),
    useSaveTeamInvitation: jest.fn(),
    useDeleteTeamMember: jest.fn(),
    useDeleteTeamInvitation: jest.fn(),
  },
  hdxServer: jest.fn(),
}));

// eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion
const asMock = (fn: unknown) => fn as jest.Mock;

const perms = (isAdmin: boolean, granted: Record<string, string> = {}) =>
  asMock(useMyPermissions).mockReturnValue({
    isAdmin,
    isLoading: false,
    can: (resource: string, level: string) =>
      isAdmin || granted[resource] === level || granted[resource] === 'manage',
  });

beforeEach(() => {
  jest.clearAllMocks();

  asMock(api.useTeam).mockReturnValue({
    data: { apiKey: 'team-api-key' },
    refetch: jest.fn(),
  });
  asMock(api.useMe).mockReturnValue({
    data: { accessKey: 'personal-api-key' },
    isLoading: false,
  });
  asMock(api.useRotateTeamApiKey).mockReturnValue({
    mutate: jest.fn(),
    isPending: false,
  });
  asMock(api.useRotatePersonalAccessKey).mockReturnValue({
    mutate: jest.fn(),
    isPending: false,
  });

  asMock(api.useWebhooks).mockReturnValue({
    data: { data: [] },
    refetch: jest.fn(),
  });
  asMock(api.useDeleteWebhook).mockReturnValue({
    mutate: jest.fn(),
    mutateAsync: jest.fn(),
    isPending: false,
  });

  asMock(api.useTeamMembers).mockReturnValue({
    data: { data: [] },
    isLoading: false,
    refetch: jest.fn(),
  });
  asMock(api.useTeamInvitations).mockReturnValue({
    data: { data: [] },
    isLoading: false,
    refetch: jest.fn(),
  });
  asMock(api.useRoles).mockReturnValue({ data: { data: [] } });
  asMock(api.useAssignMemberRole).mockReturnValue({ mutate: jest.fn() });
  asMock(api.useSaveTeamInvitation).mockReturnValue({
    mutate: jest.fn(),
    isPending: false,
  });
  asMock(api.useDeleteTeamMember).mockReturnValue({ mutate: jest.fn() });
  asMock(api.useDeleteTeamInvitation).mockReturnValue({ mutate: jest.fn() });
});

// BUG-2 §10.3: whole sections a role cannot reach are absent, not disabled —
// the UI must never advertise something the server will reject.
describe('Team Settings permission gating', () => {
  it('hides Rotate API Key from a non-admin', () => {
    perms(false, { team: 'read' });
    renderWithMantine(<ApiKeysSection />);
    expect(screen.queryByTestId('rotate-api-key-button')).toBeNull();
  });

  it('shows Rotate API Key to an admin', () => {
    perms(true);
    renderWithMantine(<ApiKeysSection />);
    expect(screen.getByTestId('rotate-api-key-button')).toBeInTheDocument();
  });

  it('hides Add Webhook from a role holding only webhooks: read', () => {
    perms(false, { webhooks: 'read' });
    renderWithMantine(<WebhooksSection />);
    expect(screen.queryByTestId('add-webhook-section-button')).toBeNull();
  });

  it('shows Add Webhook to a role holding webhooks: manage', () => {
    perms(false, { webhooks: 'manage' });
    renderWithMantine(<WebhooksSection />);
    expect(
      screen.getByTestId('add-webhook-section-button'),
    ).toBeInTheDocument();
  });
});

// An earlier task made the invitation `url` field admin-only (it embeds an
// accept-capable token); `TeamMembersSection` guards its Copy URL control on
// `invitation.url &&`, but nothing exercised that conditional.
describe('TeamMembersSection invitation Copy URL gating', () => {
  it('hides Copy URL when a non-admin views an invitation with no url', () => {
    perms(false, { team: 'read' });
    asMock(api.useTeamInvitations).mockReturnValue({
      data: { data: [{ _id: 'inv1', email: 'invitee@example.com' }] },
      isLoading: false,
      refetch: jest.fn(),
    });

    renderWithMantine(<TeamMembersSection />);

    expect(screen.queryByText(/Copy URL/)).toBeNull();
  });

  it('shows Copy URL when an admin views an invitation with a url', () => {
    perms(true);
    asMock(api.useTeamInvitations).mockReturnValue({
      data: {
        data: [
          {
            _id: 'inv1',
            email: 'invitee@example.com',
            url: 'https://app.example.com/join-team/token123',
          },
        ],
      },
      isLoading: false,
      refetch: jest.fn(),
    });

    renderWithMantine(<TeamMembersSection />);

    expect(screen.getByText(/Copy URL/)).toBeInTheDocument();
  });
});
