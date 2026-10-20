/**
 * Credentials managed at runtime (dashboard API) alongside AIOSTREAMS_AUTH.
 * Every check is synchronous, so the whole table is mirrored into memory via
 * `setManagedAuthUsers`: after each write here, and by the `auth-users-sync`
 * task on every replica.
 */
import { createLogger } from '../../logging/logger.js';
import { setManagedAuthUsers, type ManagedAuthUser } from '../../utils/auth.js';
import { decryptString, encryptString } from '../../utils/crypto.js';
import { isPermission, type Permission } from '../../utils/permissions.js';
import { getDb } from '../db.js';
import { sql } from '../sql.js';

const logger = createLogger('auth');

export interface AuthUserListItem {
  username: string;
  permissions: Permission[];
  note: string | null;
  /** Own concurrent-stream cap; null defers to `streams.connectionLimits`. */
  connectionLimit: number | null;
  createdAt: number;
  updatedAt: number;
}

interface Row {
  username: string;
  encrypted_password: string;
  permissions: string;
  note: string | null;
  connection_limit: number | string | null;
  created_at: number | string;
  updated_at: number | string;
  [k: string]: unknown;
}

export const AuthUserRepository = {
  async list(): Promise<AuthUserListItem[]> {
    const rows = await getDb().query<Row>(
      sql`SELECT username, permissions, note, connection_limit, created_at, updated_at
          FROM auth_users ORDER BY username`
    );
    return rows.map((r) => ({
      username: r.username,
      permissions: r.permissions.split('|').filter(isPermission),
      note: r.note,
      connectionLimit: toLimit(r.connection_limit),
      createdAt: Number(r.created_at),
      updatedAt: Number(r.updated_at),
    }));
  },

  /**
   * Create or replace a credential. Returns whether it was newly created. The
   * in-memory set is refreshed before returning, so the credential works on
   * this replica immediately.
   */
  async upsert(input: {
    username: string;
    password: string;
    permissions: Permission[];
    note?: string | null;
    connectionLimit?: number | null;
  }): Promise<{ created: boolean }> {
    const { success, data: encrypted, error } = encryptString(input.password);
    if (!success || !encrypted) {
      throw new Error(`Failed to encrypt password: ${error}`);
    }
    const db = getDb();
    const now = Date.now();
    const existing = await db.maybeOne(
      sql`SELECT 1 AS one FROM auth_users WHERE username = ${input.username}`
    );
    await db.exec(
      sql`INSERT INTO auth_users
            (username, encrypted_password, permissions, note, connection_limit,
             created_at, updated_at)
          VALUES (${input.username}, ${encrypted}, ${input.permissions.join('|')},
                  ${input.note ?? null}, ${input.connectionLimit ?? null},
                  ${now}, ${now})
          ON CONFLICT (username) DO UPDATE SET
            encrypted_password = EXCLUDED.encrypted_password,
            permissions = EXCLUDED.permissions,
            note = EXCLUDED.note,
            connection_limit = EXCLUDED.connection_limit,
            updated_at = EXCLUDED.updated_at`
    );
    await AuthUserRepository.reload();
    return { created: !existing };
  },

  /** Delete a credential. Returns whether it existed. */
  async remove(username: string): Promise<boolean> {
    const { rowCount } = await getDb().exec(
      sql`DELETE FROM auth_users WHERE username = ${username}`
    );
    await AuthUserRepository.reload();
    return rowCount > 0;
  },

  /** Mirror the table into the in-memory credential set. */
  async reload(): Promise<number> {
    const rows = await getDb().query<Row>(
      sql`SELECT username, encrypted_password, permissions, connection_limit
          FROM auth_users`
    );
    const users = new Map<string, ManagedAuthUser>();
    for (const r of rows) {
      const { success, data: password } = decryptString(r.encrypted_password);
      if (!success || !password) {
        // SECRET_KEY changed since it was written: unusable, so leave it out
        // rather than fail every other credential.
        logger.warn(
          { username: r.username },
          'skipping managed auth user whose password cannot be decrypted'
        );
        continue;
      }
      users.set(r.username, {
        password,
        permissions: new Set(r.permissions.split('|').filter(isPermission)),
        connectionLimit: toLimit(r.connection_limit),
      });
    }
    setManagedAuthUsers(users);
    return users.size;
  },
};

/** Postgres may return integers as strings; NULL stays null. */
function toLimit(value: number | string | null): number | null {
  return value === null || value === undefined ? null : Number(value);
}
