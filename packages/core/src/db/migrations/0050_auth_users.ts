import type { Migration } from './types.js';

/**
 * Credentials managed at runtime through the dashboard API, alongside the
 * fixed AIOSTREAMS_AUTH list. The password is stored encrypted with SECRET_KEY
 * rather than hashed: the built-in proxy and `/proxy/generate` need the
 * plaintext to build credentialed URLs. `permissions` is a `|`-joined list.
 */
const ddl = (int: string) => `
      CREATE TABLE IF NOT EXISTS auth_users (
        username           TEXT PRIMARY KEY,
        encrypted_password TEXT NOT NULL,
        permissions        TEXT NOT NULL,
        note               TEXT,
        created_at         ${int} NOT NULL,
        updated_at         ${int} NOT NULL
      );
`;

export const authUsers: Migration = {
  id: 50,
  name: 'auth_users',
  up: { sqlite: ddl('INTEGER'), postgres: ddl('BIGINT') },
};
