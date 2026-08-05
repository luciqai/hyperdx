import { Types } from 'mongoose';

import { getServer } from '@/fixtures';
import { mongooseConnection } from '@/models';

// eslint-disable-next-line @typescript-eslint/no-require-imports
const migration = require('../20260802120000-add_rbac_roles');

describe('add_rbac_roles migration', () => {
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

  it('gives each user their own team admin role, not another team’s', async () => {
    const db = mongooseConnection.db!;
    const teamA = new Types.ObjectId();
    const teamB = new Types.ObjectId();

    await db.collection('teams').insertMany([
      { _id: teamA, name: 'A' },
      { _id: teamB, name: 'B' },
    ]);
    // accessKey carries a unique index and the raw driver bypasses Mongoose's
    // UUID default, so inserted users need distinct keys or they collide on null.
    await db.collection('users').insertMany([
      { email: 'a@x.com', team: teamA, accessKey: 'key-a' },
      { email: 'b@x.com', team: teamB, accessKey: 'key-b' },
    ]);

    await migration.up(db);

    const roles = await db.collection('roles').find({}).toArray();
    expect(roles).toHaveLength(6); // 3 per team

    const userA = await db.collection('users').findOne({ email: 'a@x.com' });
    const adminA = roles.find(
      r => r.isAdmin && r.team.toString() === teamA.toString(),
    );
    expect(userA!.role.toString()).toBe(adminA!._id.toString());

    const userB = await db.collection('users').findOne({ email: 'b@x.com' });
    const adminB = roles.find(
      r => r.isAdmin && r.team.toString() === teamB.toString(),
    );
    expect(userB!.role.toString()).toBe(adminB!._id.toString());
    expect(userB!.role.toString()).not.toBe(adminA!._id.toString());
  });

  it('down removes the field and the collection', async () => {
    const db = mongooseConnection.db!;
    const team = new Types.ObjectId();
    await db.collection('teams').insertOne({ _id: team, name: 'A' });
    await db
      .collection('users')
      .insertOne({ email: 'a@x.com', team, accessKey: 'key-down' });

    await migration.up(db);
    await migration.down(db);

    const user = await db.collection('users').findOne({ email: 'a@x.com' });
    expect(user!.role).toBeUndefined();
    expect(await db.listCollections({ name: 'roles' }).toArray()).toHaveLength(
      0,
    );
  });

  // Regression: `up` used insertMany, so a re-run after a partial failure —
  // or after the API booted first and seeded roles itself — threw E11000 and
  // left the operator with a migration that could never advance.
  it('is idempotent: a second up() is a no-op and preserves assignments', async () => {
    const db = mongooseConnection.db!;
    const team = new Types.ObjectId();
    await db.collection('teams').insertOne({ _id: team, name: 'A' });
    await db
      .collection('users')
      .insertOne({ email: 'a@x.com', team, accessKey: 'key-idem' });

    await migration.up(db);

    const roles = await db.collection('roles').find({ team }).toArray();
    expect(roles).toHaveLength(3);

    // An admin then demotes the user to ReadOnly.
    const readOnly = roles.find(r => r.name === 'ReadOnly');
    await db
      .collection('users')
      .updateOne({ email: 'a@x.com' }, { $set: { role: readOnly!._id } });

    await expect(migration.up(db)).resolves.not.toThrow();

    expect(await db.collection('roles').countDocuments({ team })).toBe(3);
    const user = await db.collection('users').findOne({ email: 'a@x.com' });
    // Must NOT be clobbered back to Admin.
    expect(user!.role.toString()).toBe(readOnly!._id.toString());
  });

  // BUG-3: the $setOnInsert upsert matched the existing role by {team,name}
  // and inserted nothing, so findOne({isAdmin:true}) returned null and
  // admin!._id threw — leaving Member + ReadOnly seeded, no admin role, no
  // user assigned, and no migrate-mongo changelog entry.
  it('aborts before any write when a non-system role uses a reserved name', async () => {
    const db = mongooseConnection.db!;
    const teamId = new Types.ObjectId();
    await db.collection('teams').insertOne({ _id: teamId, name: 'T' });
    await db.collection('roles').insertOne({
      team: teamId,
      name: 'Admin',
      isSystem: false,
      isAdmin: false,
      permissions: {},
    });

    await expect(migration.up(db)).rejects.toThrow(/aborted before any write/);

    // Nothing was seeded — the operator repairs from a clean state.
    const roles = await db.collection('roles').find({ team: teamId }).toArray();
    expect(roles).toHaveLength(1);
    expect(roles[0].name).toBe('Admin');
    expect(roles[0].isSystem).toBe(false);
  });

  it('names the offending team and role in the error', async () => {
    const db = mongooseConnection.db!;
    const teamId = new Types.ObjectId();
    await db.collection('teams').insertOne({ _id: teamId, name: 'T' });
    await db
      .collection('roles')
      .insertOne({
        team: teamId,
        name: 'ReadOnly',
        isSystem: false,
        permissions: {},
      });

    await expect(migration.up(db)).rejects.toThrow(
      new RegExp(`${teamId.toString()}[\\s\\S]*ReadOnly`),
    );
  });

  it('seeds normally when no reserved name is taken', async () => {
    const db = mongooseConnection.db!;
    const teamId = new Types.ObjectId();
    await db.collection('teams').insertOne({ _id: teamId, name: 'T' });
    await db.collection('users').insertOne({ team: teamId, email: 'a@x.test' });

    await migration.up(db);

    const roles = await db.collection('roles').find({ team: teamId }).toArray();
    expect(roles).toHaveLength(3);
    const admin = roles.find((r: any) => r.isAdmin === true);
    expect(admin).toBeDefined();

    const user = await db.collection('users').findOne({ team: teamId });
    expect(user!.role.toString()).toBe(admin!._id.toString());
  });
});
