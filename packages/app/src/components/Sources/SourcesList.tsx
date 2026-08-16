import React, { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/router';
import { SourceKind } from '@hyperdx/common-utils/dist/types';
import {
  ActionIcon,
  Alert,
  Badge,
  Box,
  Button,
  Card,
  Divider,
  Flex,
  Group,
  Loader,
  Stack,
  Text,
  Title,
} from '@mantine/core';
import {
  IconAlertCircle,
  IconChevronDown,
  IconChevronUp,
  IconFolder,
  IconPlus,
  IconRefresh,
  IconServer,
  IconStack,
} from '@tabler/icons-react';

import { IS_LOCAL_MODE } from '@/config';
import { useMyPermissions } from '@/hooks/useMyPermissions';
import { useSources } from '@/source';
import { capitalizeFirstLetter } from '@/utils';

import { TableSourceForm } from './SourceForm';

import styles from './Sources.module.scss';

export interface SourcesListProps {
  /** Callback when add source button is clicked */
  onAddSource?: () => void;
  /** Whether to wrap content in a Card component (default: true) */
  withCard?: boolean;
  /** Whether the card has a border (default: true) */
  withBorder?: boolean;
  /** Custom className for the card */
  cardClassName?: string;
  /** Visual variant: 'compact' for smaller text, 'default' for standard sizing */
  variant?: 'compact' | 'default';
  /** Whether to show empty state UI (default: true) */
  showEmptyState?: boolean;
}

export function SourcesList({
  onAddSource,
  withCard = true,
  withBorder = true,
  cardClassName,
  variant = 'compact',
  showEmptyState = true,
}: SourcesListProps) {
  const {
    data: sources,
    isLoading,
    error,
    refetch: refetchSources,
  } = useSources();

  const [editedSourceId, setEditedSourceId] = useState<string | null>(null);
  const [isCreatingSource, setIsCreatingSource] = useState(false);

  /**
   * The list itself needs only `sources: read`, but both controls that reveal
   * `TableSourceForm` need more than that: the form calls `useConnections()`,
   * which Member and ReadOnly hold as `connections: none`, and saving from it
   * 403s. Absent, not disabled — §10.3: the UI must never advertise an action
   * the server will reject.
   */
  const { can } = useMyPermissions();
  const canManageSources = can('sources', 'manage');

  // Expand and scroll to the relevant source when the URL includes a
  // `#source-<id>` anchor.
  const router = useRouter();
  const expandedFromHashRef = useRef<string | null>(null);

  useEffect(() => {
    if (!router.isReady || isLoading || error) return;

    const hash = window.location.hash;
    const sourceId = hash?.startsWith('#source-')
      ? hash.slice('#source-'.length)
      : undefined;

    if (!sourceId || expandedFromHashRef.current === sourceId) return;
    if (!sources?.some(s => s.id === sourceId)) return;
    expandedFromHashRef.current = sourceId;

    // Expand the source
    setEditedSourceId(sourceId);

    // Scroll the source into view.
    requestAnimationFrame(() => {
      document
        .getElementById(`source-${sourceId}`)
        ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });

    // Drop the hash (keeping the query, e.g. `?tab=`) so later commits
    // don't re-trigger Next's scrollToHash.
    void router.replace(
      { pathname: router.pathname, query: router.query },
      undefined,
      { shallow: true },
    );
  }, [router, sources, isLoading, error]);

  const handleRetry = () => {
    refetchSources();
  };

  // Sizing based on variant
  const textSize = variant === 'compact' ? 'sm' : 'md';
  const subtextSize = variant === 'compact' ? 'xs' : 'sm';
  const iconSize = variant === 'compact' ? 11 : 14;
  const buttonSize = variant === 'compact' ? 'xs' : 'sm';

  const Wrapper = withCard ? Card : React.Fragment;
  const wrapperProps = withCard
    ? {
        withBorder,
        p: 'md',
        radius: 'sm',
        className: cardClassName ?? styles.sourcesCard,
      }
    : {};

  if (isLoading) {
    return (
      <Wrapper {...wrapperProps}>
        <Flex justify="center" align="center" py="xl">
          <Loader size="sm" />
          <Text size="sm" c="dimmed" ml="sm">
            Loading sources...
          </Text>
        </Flex>
      </Wrapper>
    );
  }

  if (error) {
    return (
      <Wrapper {...wrapperProps}>
        <Alert
          icon={<IconAlertCircle size={16} />}
          title="Failed to load sources"
          color="red"
          variant="light"
        >
          <Text size="sm" mb="sm">
            {error instanceof Error
              ? error.message
              : 'An error occurred while loading data sources.'}
          </Text>
          <Button
            size="xs"
            variant="danger"
            leftSection={<IconRefresh size={14} />}
            onClick={handleRetry}
          >
            Retry
          </Button>
        </Alert>
      </Wrapper>
    );
  }

  const isEmpty = !sources || sources.length === 0;

  return (
    <Wrapper {...wrapperProps}>
      <Stack gap="md">
        {isEmpty && !isCreatingSource && showEmptyState && (
          <Flex direction="column" align="center" py="xl" gap="sm">
            <IconStack size={32} color="var(--color-text-muted)" />
            <Title size="sm" ta="center" c="var(--color-text-muted)">
              No data sources configured yet.
            </Title>
            <Text size="xs" ta="center" c="var(--color-text-muted)">
              Add a source to start querying your data.
            </Text>
          </Flex>
        )}

        {sources?.map((s, index) => (
          <React.Fragment key={s.id}>
            <Flex justify="space-between" align="center" id={`source-${s.id}`}>
              <div
                style={{
                  flex: 1,
                  opacity: s.disabled ? 0.5 : 1,
                  transition: 'opacity 0.2s ease',
                }}
              >
                <Group gap="xs" align="center">
                  <Text size={textSize} fw={500}>
                    {s.name}
                  </Text>
                  {s.disabled && (
                    <Badge size="xs" variant="light" color="gray">
                      Disabled
                    </Badge>
                  )}
                </Group>
                <Text size={subtextSize} c="dimmed" mt={4}>
                  <Group gap="xs">
                    {capitalizeFirstLetter(s.kind)}
                    {s.section && (
                      <Group gap={4}>
                        <IconFolder size={iconSize} />
                        {s.section}
                      </Group>
                    )}
                    <Group gap={4}>
                      <IconServer size={iconSize} />
                      {s.connectionName}
                    </Group>
                    <Group gap={4}>
                      {s.from && (
                        <>
                          <IconStack size={iconSize} />
                          {s.from.databaseName}
                          {s.kind === SourceKind.Metric ? '' : '.'}
                          {s.from.tableName}
                        </>
                      )}
                    </Group>
                  </Group>
                </Text>
              </div>
              {canManageSources && (
                <ActionIcon
                  variant="secondary"
                  size={buttonSize}
                  data-testid={`expand-source-${s.id}`}
                  onClick={() =>
                    setEditedSourceId(editedSourceId === s.id ? null : s.id)
                  }
                >
                  {editedSourceId === s.id ? (
                    <IconChevronUp size={iconSize + 2} />
                  ) : (
                    <IconChevronDown size={iconSize + 2} />
                  )}
                </ActionIcon>
              )}
            </Flex>
            {/* Also gated: the `#source-<id>` deep link above expands without
                going through the chevron. */}
            {canManageSources && editedSourceId === s.id && (
              <Box mt="xs">
                <TableSourceForm
                  sourceId={s.id}
                  onSave={() => setEditedSourceId(null)}
                />
              </Box>
            )}
            {index < (sources?.length ?? 0) - 1 && <Divider />}
          </React.Fragment>
        ))}

        {isCreatingSource && (
          <>
            {sources && sources.length > 0 && <Divider />}
            <TableSourceForm
              isNew
              onCreate={() => setIsCreatingSource(false)}
              onCancel={() => setIsCreatingSource(false)}
            />
          </>
        )}

        {!IS_LOCAL_MODE && !isCreatingSource && canManageSources && (
          <Flex
            justify="flex-end"
            pt={sources && sources.length > 0 ? 'md' : 0}
          >
            <Button
              variant="secondary"
              size={buttonSize}
              data-testid="add-source-button"
              leftSection={<IconPlus size={14} />}
              onClick={() => {
                setIsCreatingSource(true);
                onAddSource?.();
              }}
            >
              Add source
            </Button>
          </Flex>
        )}
      </Stack>
    </Wrapper>
  );
}
