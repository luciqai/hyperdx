import { ReactNode, useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import { useRouter } from 'next/router';
import { SubmitHandler, useForm } from 'react-hook-form';
import {
  Box,
  Button,
  Center,
  Container,
  Group,
  Loader,
  Stack,
  Tabs,
  TextInput,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconPencil } from '@tabler/icons-react';

import { useMyPermissions } from '@/hooks/useMyPermissions';

import { PageHeader } from './components/PageHeader';
import ApiKeysSection from './components/TeamSettings/ApiKeysSection';
import ConnectionsSection from './components/TeamSettings/ConnectionsSection';
import IntegrationsSection from './components/TeamSettings/IntegrationsSection';
import McpServerSection from './components/TeamSettings/McpServerSection';
import RbacRolesSection from './components/TeamSettings/RbacRolesSection';
import SecurityPoliciesSection from './components/TeamSettings/SecurityPoliciesSection';
import SourcesSection from './components/TeamSettings/SourcesSection';
import TeamMembersSection from './components/TeamSettings/TeamMembersSection';
import TeamQueryConfigSection from './components/TeamSettings/TeamQueryConfigSection';
import { useBrandDisplayName } from './theme/ThemeProvider';
import api from './api';
import { withAppNav } from './layout';

type TeamTab = {
  value: string;
  label: string;
  sections: {
    id: string;
    content: ReactNode;
  }[];
};

function TeamTabContent({ sections }: { sections: TeamTab['sections'] }) {
  return (
    <Stack gap="lg" pt="lg">
      {sections.map(section => (
        <Box key={section.id} id={section.id}>
          {section.content}
        </Box>
      ))}
    </Stack>
  );
}

export default function TeamPage() {
  const brandName = useBrandDisplayName();
  const router = useRouter();
  const { data: team, refetch: refetchTeam, isLoading } = api.useTeam();
  const setTeamName = api.useSetTeamName();
  const allowedAuthMethods = team?.allowedAuthMethods ?? [];
  const hasAllowedAuthMethods = allowedAuthMethods.length > 0;

  // Gate each section on the permission its own data needs. A section whose
  // read permission is missing would otherwise render and 403 on load, which
  // is worse than not offering it: `connections: none` is the default for both
  // Member and ReadOnly, so that was every non-admin's Team Settings.
  const {
    isAdmin: hasAdminAccess,
    can,
    isLoading: isLoadingPermissions,
  } = useMyPermissions();
  const [isEditingTeamName, setIsEditingTeamName] = useState(false);
  const form = useForm<{ name: string }>({
    defaultValues: { name: team?.name },
  });

  const onSubmitTeamName: SubmitHandler<{ name: string }> = useCallback(
    async values => {
      setTeamName.mutate(
        { name: values.name },
        {
          onError: () => {
            notifications.show({
              color: 'red',
              message: 'Failed to update team name',
            });
          },
          onSuccess: () => {
            notifications.show({
              color: 'green',
              message: 'Updated team name',
            });
            refetchTeam();
            setIsEditingTeamName(false);
          },
        },
      );
    },
    [refetchTeam, setTeamName],
  );

  const accessSections: TeamTab['sections'] = [
    ...(hasAdminAccess
      ? [{ id: 'team-access-roles', content: <RbacRolesSection /> }]
      : []),
    ...(hasAllowedAuthMethods
      ? [
          {
            id: 'team-access-security-policies',
            content: (
              <SecurityPoliciesSection
                allowedAuthMethods={allowedAuthMethods}
              />
            ),
          },
        ]
      : []),
  ];

  const dataSections: TeamTab['sections'] = [
    ...(can('sources', 'read')
      ? [{ id: 'team-data-sources', content: <SourcesSection /> }]
      : []),
    ...(can('connections', 'read')
      ? [{ id: 'team-data-connections', content: <ConnectionsSection /> }]
      : []),
  ];

  const tabs: TeamTab[] = [
    ...(dataSections.length > 0
      ? [{ value: 'data', label: 'Data', sections: dataSections }]
      : []),
    // GET /team/members requires users:read, which ReadOnly does not have.
    ...(can('users', 'read')
      ? [
          {
            value: 'team',
            label: 'Members',
            sections: [{ id: 'team-members', content: <TeamMembersSection /> }],
          },
        ]
      : []),
    // The Access tab appears whenever it has something to show. Roles are
    // admin-only and Security Policies needs configured auth methods, so a
    // non-admin on a team without them would otherwise land on a blank tab —
    // the "advertises something you can't have" failure the design forbids.
    ...(accessSections.length > 0
      ? [{ value: 'access', label: 'Access', sections: accessSections }]
      : []),
    // Both sections read the team document (team:read), which every role has.
    {
      value: 'api-agents',
      label: 'API & Agents',
      sections: [
        {
          id: 'team-api-agents-api-keys',
          content: <ApiKeysSection />,
        },
        {
          id: 'team-api-agents-mcp-server',
          content: <McpServerSection />,
        },
      ],
    },
    // GET /webhooks requires webhooks:read; ReadOnly has webhooks: none.
    ...(can('webhooks', 'read')
      ? [
          {
            value: 'integrations',
            label: 'Integrations',
            sections: [
              {
                id: 'team-integrations-webhooks',
                content: <IntegrationsSection />,
              },
            ],
          },
        ]
      : []),
    {
      value: 'advanced',
      label: 'Query Settings',
      sections: [
        {
          id: 'team-advanced-query-settings',
          content: <TeamQueryConfigSection />,
        },
      ],
    },
  ];

  const queryTab =
    typeof router.query.tab === 'string' ? router.query.tab : null;
  const activeTab = tabs.some(tab => tab.value === queryTab)
    ? queryTab
    : tabs[0]?.value;

  useEffect(() => {
    if (!router.isReady || !activeTab || queryTab === activeTab) {
      return;
    }

    // Preserve any hash (e.g. `#source-<id>` deep links consumed by
    // SourcesList) — this replace only normalizes the `tab` param and
    // must not strip other parts of the URL.
    const hash = window.location.hash.slice(1);
    void router.replace(
      {
        pathname: router.pathname,
        query: {
          ...router.query,
          tab: activeTab,
        },
        hash: hash || undefined,
      },
      undefined,
      {
        shallow: true,
        scroll: false,
      },
    );
  }, [activeTab, queryTab, router]);

  const handleTabChange = useCallback(
    (value: string | null) => {
      if (!value || value === activeTab) {
        return;
      }

      document.getElementById('app-content-scroll-container')?.scrollTo({
        top: 0,
      });

      void router.replace(
        {
          pathname: router.pathname,
          query: {
            ...router.query,
            tab: value,
          },
        },
        undefined,
        {
          shallow: true,
          scroll: false,
        },
      );
    },
    [activeTab, router],
  );

  return (
    <div className="TeamPage" data-testid="team-page">
      <Head>
        <title>My Team - {brandName}</title>
      </Head>
      <PageHeader>
        <div data-testid="team-name-section">
          {isEditingTeamName ? (
            <form onSubmit={form.handleSubmit(onSubmitTeamName)}>
              <Group gap="xs">
                <TextInput
                  data-testid="team-name-input"
                  size="xs"
                  placeholder="My Team"
                  required
                  error={form.formState.errors.name?.message}
                  {...form.register('name', { required: true })}
                  miw={300}
                  maxLength={100}
                  autoFocus
                  onKeyDown={e => {
                    if (e.key === 'Escape') {
                      setIsEditingTeamName(false);
                    }
                  }}
                />
                <Button
                  data-testid="team-name-save-button"
                  type="submit"
                  size="xs"
                  variant="primary"
                  loading={setTeamName.isPending}
                >
                  Save
                </Button>
                <Button
                  data-testid="team-name-cancel-button"
                  type="button"
                  size="xs"
                  variant="secondary"
                  disabled={setTeamName.isPending}
                  onClick={() => setIsEditingTeamName(false)}
                >
                  Cancel
                </Button>
              </Group>
            </form>
          ) : (
            <Group gap="sm">
              <span data-testid="team-name-display">
                {team?.name || 'My team'}
              </span>
              {/* PATCH /team/name is team:manage, which Member and ReadOnly
                  do not hold — gate on the actual permission, not on admin. */}
              {can('team', 'manage') && (
                <Button
                  data-testid="team-name-change-button"
                  size="xs"
                  variant="subtle"
                  px={4}
                  aria-label="Edit team name"
                  onClick={() => {
                    form.reset({ name: team?.name });
                    setIsEditingTeamName(true);
                  }}
                >
                  <IconPencil size={16} />
                </Button>
              )}
            </Group>
          )}
        </div>
      </PageHeader>
      <div>
        <Container size="lg" py="md">
          {(isLoading || isLoadingPermissions) && (
            <Center mt="xl">
              <Loader color="dimmed" />
            </Center>
          )}
          {!isLoading && !isLoadingPermissions && team != null && (
            <Tabs value={activeTab} onChange={handleTabChange}>
              <Tabs.List>
                {tabs.map(tab => (
                  <Tabs.Tab key={tab.value} value={tab.value}>
                    {tab.label}
                  </Tabs.Tab>
                ))}
              </Tabs.List>
              {tabs.map(tab => (
                <Tabs.Panel key={tab.value} value={tab.value}>
                  <TeamTabContent sections={tab.sections} />
                </Tabs.Panel>
              ))}
            </Tabs>
          )}
        </Container>
      </div>
    </div>
  );
}

TeamPage.getLayout = withAppNav;
