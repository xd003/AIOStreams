import type { Migration } from './types.js';

/**
 * A managed credential's own concurrent-stream cap. NULL defers to
 * `streams.connectionLimits` (its `*` entry); `0`/`-1` mean unlimited.
 */
export const authUsersConnectionLimit: Migration = {
  id: 49,
  name: 'auth_users_connection_limit',
  up: {
    sqlite: `
      ALTER TABLE auth_users ADD COLUMN connection_limit INTEGER;
`,
    postgres: `
      ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS connection_limit INTEGER;
`,
  },
};
