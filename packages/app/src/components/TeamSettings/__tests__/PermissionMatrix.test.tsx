import { SYSTEM_ROLE_PERMISSIONS } from '@hyperdx/common-utils/dist/types';
import { MantineProvider } from '@mantine/core';
import { fireEvent, render, screen } from '@testing-library/react';

import PermissionMatrix from '@/components/TeamSettings/PermissionMatrix';

function renderMatrix(
  props: Partial<React.ComponentProps<typeof PermissionMatrix>> = {},
) {
  const onChange = jest.fn();
  render(
    <MantineProvider>
      <PermissionMatrix
        value={SYSTEM_ROLE_PERMISSIONS.Member}
        onChange={onChange}
        {...props}
      />
    </MantineProvider>,
  );
  return { onChange };
}

describe('PermissionMatrix', () => {
  it('renders a row for every permission key', () => {
    renderMatrix();

    expect(screen.getByText('Dashboards')).toBeInTheDocument();
    expect(screen.getByText('Saved searches')).toBeInTheDocument();
    expect(screen.getByText('Connections')).toBeInTheDocument();
    expect(screen.getByText('Users')).toBeInTheDocument();
    expect(screen.getByText('Team')).toBeInTheDocument();
  });

  it('emits the full matrix with one key changed', () => {
    const { onChange } = renderMatrix();

    fireEvent.click(screen.getByRole('radio', { name: 'sources-manage' }));

    expect(onChange).toHaveBeenCalledWith({
      ...SYSTEM_ROLE_PERMISSIONS.Member,
      sources: 'manage',
    });
  });

  it('does not emit changes in readOnly mode', () => {
    const { onChange } = renderMatrix({ readOnly: true });

    fireEvent.click(screen.getByRole('radio', { name: 'sources-manage' }));

    expect(onChange).not.toHaveBeenCalled();
  });
});
