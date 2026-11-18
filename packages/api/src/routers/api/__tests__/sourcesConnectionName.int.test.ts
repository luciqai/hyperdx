import { SourceKind } from '@hyperdx/common-utils/dist/types';
import { Types } from 'mongoose';

import { createConnection } from '@/controllers/connection';
import { createSource } from '@/controllers/sources';
import { getLoggedInAgent, getServer } from '@/fixtures';

describe('GET /sources', () => {
  const server = getServer();

  beforeAll(async () => {
    await server.start();
  });

  afterEach(async () => {
    await server.clearDBs();
  });

  afterAll(async () => {
    await server.stop();
  });

  // BUG-5: TeamPage gated the section on sources:read, but SourcesList also
  // called GET /connections (connections:read — `none` for Member and
  // ReadOnly), so the section rendered and then permanently 403'd.
  it('inlines the connection name so the view needs no connections:read', async () => {
    const { agent, team } = await getLoggedInAgent(server);
    const connection = await createConnection(team._id.toString(), {
      team: team._id,
      name: 'Local CH',
      host: 'http://localhost:8123',
      username: 'default',
      password: '',
    });
    await createSource(team._id.toString(), {
      team: team._id.toString(),
      kind: SourceKind.Log,
      name: 'Logs',
      connection: connection._id.toString(),
      from: { databaseName: 'default', tableName: 'otel_logs' },
      timestampValueExpression: 'Timestamp',
      defaultTableSelectExpression: 'Body',
    });

    const res = await agent.get('/sources').expect(200);

    expect(res.body).toHaveLength(1);
    expect(res.body[0].connectionName).toBe('Local CH');
  });

  it('returns null rather than failing when the connection is missing', async () => {
    const { agent, team } = await getLoggedInAgent(server);
    await createSource(team._id.toString(), {
      team: team._id.toString(),
      kind: SourceKind.Log,
      name: 'Orphan',
      connection: new Types.ObjectId().toString(),
      from: { databaseName: 'default', tableName: 'otel_logs' },
      timestampValueExpression: 'Timestamp',
      defaultTableSelectExpression: 'Body',
    });

    const res = await agent.get('/sources').expect(200);

    expect(res.body[0].connectionName).toBeNull();
  });
});
