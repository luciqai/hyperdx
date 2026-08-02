import { Db, MongoClient } from 'mongodb';

// Permission matrices are duplicated here rather than imported from
// common-utils: a migration must keep describing the world as it was when it
// ran, even after the shared constants change.
const SYSTEM_ROLES = [
  {
    name: 'Admin',
    description: 'Full access, including roles and API key rotation',
    isAdmin: true,
    permissions: {
      dashboards: 'manage',
      savedSearches: 'manage',
      sources: 'manage',
      alerts: 'manage',
      webhooks: 'manage',
      connections: 'manage',
      users: 'read',
      team: 'manage',
    },
  },
  {
    name: 'Member',
    description: 'Build dashboards and alerts; read-only on sources',
    isAdmin: false,
    permissions: {
      dashboards: 'manage',
      savedSearches: 'manage',
      sources: 'read',
      alerts: 'manage',
      webhooks: 'read',
      connections: 'none',
      users: 'read',
      team: 'read',
    },
  },
  {
    name: 'ReadOnly',
    description: 'View dashboards, searches and alerts',
    isAdmin: false,
    permissions: {
      dashboards: 'read',
      savedSearches: 'read',
      sources: 'read',
      alerts: 'read',
      webhooks: 'none',
      connections: 'none',
      users: 'none',
      team: 'read',
    },
  },
];

module.exports = {
  async up(db: Db, _client?: MongoClient) {
    await db
      .collection('roles')
      .createIndex({ team: 1, name: 1 }, { unique: true });

    const teams = await db.collection('teams').find({}).toArray();
    const now = new Date();

    for (const team of teams) {
      const docs = SYSTEM_ROLES.map(role => ({
        team: team._id,
        name: role.name,
        description: role.description,
        isSystem: true,
        isAdmin: role.isAdmin,
        permissions: role.permissions,
        createdAt: now,
        updatedAt: now,
      }));

      await db.collection('roles').insertMany(docs);

      const admin = await db
        .collection('roles')
        .findOne({ team: team._id, isAdmin: true });

      // Every existing user becomes an Admin of their own team. Downgrading
      // people is then a deliberate act, rather than something an upgrade
      // does to them silently.
      await db
        .collection('users')
        .updateMany({ team: team._id }, { $set: { role: admin!._id } });
    }
  },

  async down(db: Db, _client?: MongoClient) {
    await db.collection('users').updateMany({}, { $unset: { role: '' } });
    const existing = await db.listCollections({ name: 'roles' }).toArray();
    if (existing.length > 0) {
      await db.collection('roles').drop();
    }
  },
};
