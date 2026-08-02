import { useMemo } from 'react';
import {
  hasPermission,
  type PermissionLevel,
  type Resource,
} from '@hyperdx/common-utils/dist/types';

import api from '@/api';

/**
 * Client-side mirror of the server's resolution order. The server is always
 * authoritative; this exists only to decide what to render.
 */
export function useMyPermissions() {
  const { data: me, isLoading } = api.useMe();

  return useMemo(() => {
    const role = me?.role ?? null;
    // No role means the migration has not run; the server fails open as admin,
    // so the UI must agree or it would hide controls that actually work.
    const isAdmin = role == null || role.isAdmin === true;

    return {
      isAdmin,
      isLoading,
      can(resource: Resource, level: PermissionLevel) {
        if (isAdmin) return true;
        return hasPermission(role?.permissions?.[resource], level);
      },
    };
  }, [me, isLoading]);
}
