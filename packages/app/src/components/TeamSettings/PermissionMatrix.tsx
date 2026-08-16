import {
  type PermissionLevel,
  type RolePermissions,
} from '@hyperdx/common-utils/dist/types';
import { Divider, Group, SegmentedControl, Stack, Text } from '@mantine/core';

const ALL_LEVELS: PermissionLevel[] = ['none', 'read', 'manage'];

type Row = {
  key: keyof RolePermissions;
  label: string;
  levels: PermissionLevel[];
};

// `users` has no manage and `team` has no none: those levels do not exist in
// the vocabulary, so no role can hold them. The cells are still rendered, but
// disabled — greyed means "absent", not "forbidden", and keeping the column
// count constant is what lets a role's posture read down the page.
const RESOURCE_ROWS: Row[] = [
  { key: 'dashboards', label: 'Dashboards', levels: ALL_LEVELS },
  { key: 'savedSearches', label: 'Saved searches', levels: ALL_LEVELS },
  { key: 'sources', label: 'Sources', levels: ALL_LEVELS },
  { key: 'alerts', label: 'Alerts', levels: ALL_LEVELS },
  { key: 'webhooks', label: 'Webhooks', levels: ALL_LEVELS },
  { key: 'connections', label: 'Connections', levels: ALL_LEVELS },
];

const ADMIN_ROWS: Row[] = [
  { key: 'users', label: 'Users', levels: ['none', 'read'] },
  { key: 'team', label: 'Team', levels: ['read', 'manage'] },
];

const LEVEL_LABELS: Record<PermissionLevel, string> = {
  none: 'No access',
  read: 'Read',
  manage: 'Manage',
};

export default function PermissionMatrix({
  value,
  onChange,
  readOnly = false,
}: {
  value: RolePermissions;
  onChange: (next: RolePermissions) => void;
  readOnly?: boolean;
}) {
  const renderRow = (row: Row) => (
    <Group key={row.key} justify="space-between" wrap="nowrap" gap="md">
      <Text size="sm">{row.label}</Text>
      <SegmentedControl
        size="xs"
        disabled={readOnly}
        value={value[row.key]}
        onChange={next => {
          if (readOnly) return;
          onChange({ ...value, [row.key]: next as PermissionLevel });
        }}
        data={ALL_LEVELS.map(level => {
          const available = row.levels.includes(level);
          return {
            value: level,
            disabled: !available,
            // SegmentedControl already renders a real `input[type=radio]` per
            // item; the aria-label here names that input (`dashboards-read`)
            // so rows stay distinguishable to assistive tech and to tests.
            // Adding role="radio" to this span would double every radio.
            label: (
              <span aria-label={`${row.key}-${level}`}>
                {LEVEL_LABELS[level]}
              </span>
            ),
          };
        })}
      />
    </Group>
  );

  return (
    <Stack gap="xs">
      <Text size="xs" c="dimmed" tt="uppercase" fw={500}>
        Resources
      </Text>
      {RESOURCE_ROWS.map(renderRow)}

      <Divider my="xs" />

      <Text size="xs" c="dimmed" tt="uppercase" fw={500}>
        Administration
      </Text>
      {ADMIN_ROWS.map(renderRow)}
    </Stack>
  );
}
