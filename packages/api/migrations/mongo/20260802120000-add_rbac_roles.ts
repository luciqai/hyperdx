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

const SYSTEM_ROLE_NAMES = SYSTEM_ROLES.map(r => r.name);

module.exports = {
  async up(db: Db, _client?: MongoClient) {
    // BUG-3. The roles API is live pre-migration (the session path fails open
    // as admin), so an operator can create a custom role named "Admin" first.
    // The $setOnInsert upsert below would then match it, insert nothing, and
    // leave the team with Member + ReadOnly and no admin role — and because
    // the throw happens mid-loop, migrate-mongo records no changelog entry, so
    // the operator must hand-repair before the migration can advance.
    //
    // Check every team before touching anything, so the failure mode is
    // "nothing happened, here is what to rename".
    const conflicts = await db
      .collection('roles')
      .find({ name: { $in: SYSTEM_ROLE_NAMES }, isSystem: { $ne: true } })
      .toArray();

    if (conflicts.length > 0) {
      const lines = conflicts
        .map(r => `  team ${r.team}: role "${r.name}" (_id ${r._id})`)
        .join('\n');
      throw new Error(
        'RBAC migration aborted before any write.\n\n' +
          `${conflicts.length} non-system role(s) use a reserved system role name:\n${lines}\n\n` +
          'Each would collide with the {team, name} unique index and leave its ' +
          'team seeded without an admin role. Rename them, then re-run the ' +
          'migration.',
      );
    }

    await db
      .collection('roles')
      .createIndex({ team: 1, name: 1 }, { unique: true });

    const teams = await db.collection('teams').find({}).toArray();
    const now = new Date();

    for (const team of teams) {
      // Upsert rather than insertMany. insertMany would throw E11000 against
      // the unique {team, name} index whenever roles already exist — which
      // happens on a re-run after a partial failure (migrate-mongo records no
      // changelog entry, so the operator is stuck), and whenever the API booted
      // first and setupTeamDefaults already seeded them.
      await db.collection('roles').bulkWrite(
        SYSTEM_ROLES.map(role => ({
          updateOne: {
            filter: { team: team._id, name: role.name },
            update: {
              $setOnInsert: {
                team: team._id,
                name: role.name,
                description: role.description,
                isSystem: true,
                isAdmin: role.isAdmin,
                permissions: role.permissions,
                createdAt: now,
                updatedAt: now,
              },
            },
            upsert: true,
          },
        })),
      );

      const admin = await db
        .collection('roles')
        .findOne({ team: team._id, isAdmin: true });

      // Belt and braces behind the pre-flight: never dereference this blind.
      // Reaching here means something created a colliding role between the
      // check and now.
      if (!admin) {
        throw new Error(
          `RBAC migration: team ${team._id} has no isAdmin role after seeding. ` +
            'Inspect the roles collection for this team before re-running.',
        );
      }

      // Every existing user becomes an Admin of their own team. Downgrading
      // people is then a deliberate act, rather than something an upgrade
      // does to them silently.
      //
      // Only users who have no role yet: on a re-run this must not clobber
      // assignments an admin has already made since the first run.
      await db
        .collection('users')
        .updateMany(
          { team: team._id, role: { $in: [null, undefined] } },
          { $set: { role: admin._id } },
        );
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
