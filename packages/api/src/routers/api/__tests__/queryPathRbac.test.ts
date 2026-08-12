import { getRbacDeclaration } from '@/middleware/rbac';

// SEC-2: a role holding sources:none and connections:none was denied
// GET /sources, GET /connections and MCP list_sources, then reached
// POST /clickhouse-proxy and ran arbitrary read SQL against the cluster.
// These routes must declare a permission, not an exemption.
describe('query path RBAC declarations', () => {
  const layersOf = (router: any) =>
    router.stack
      .filter((l: any) => l.route)
      .flatMap((l: any) =>
        l.route.stack.map((s: any) => ({
          path: l.route.path,
          declaration: getRbacDeclaration(s.handle),
        })),
      )
      .filter((e: any) => e.declaration);

  it('gates the clickhouse proxy passthrough on sources: read', () => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports, n/no-missing-require
    const router = require('@/routers/api/clickhouseProxy').default;
    const passthrough = layersOf(router).filter((e: any) => e.path === '/*');

    expect(passthrough.length).toBeGreaterThan(0);
    for (const entry of passthrough) {
      expect(entry.declaration).toEqual({
        kind: 'permission',
        resource: 'sources',
        level: 'read',
      });
    }
  });

  it('gates every prometheus route on sources: read', () => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports, n/no-missing-require
    const router = require('@/routers/api/prometheus').default;
    const entries = layersOf(router);

    expect(entries.length).toBe(5);
    for (const entry of entries) {
      expect(entry.declaration).toEqual({
        kind: 'permission',
        resource: 'sources',
        level: 'read',
      });
    }
  });

  it('leaves no route claiming the retired query-path exemption', () => {
    for (const mod of ['clickhouseProxy', 'prometheus']) {
      // eslint-disable-next-line @typescript-eslint/no-require-imports, security/detect-non-literal-require
      const router = require(`@/routers/api/${mod}`).default;
      for (const entry of layersOf(router)) {
        expect(entry.declaration.kind).not.toBe('exempt');
      }
    }
  });
});
