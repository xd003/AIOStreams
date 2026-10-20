import { Router } from 'express';
import type { Request, Response } from 'express';
import { z } from 'zod';
import {
  AuthUserRepository,
  config as appConfig,
  createLogger,
  formatZodError,
  PERMISSION_NAMES,
  stopUserStreams,
  type Permission,
} from '@aiostreams/core';
import { createResponse } from '../../../utils/responses.js';

const router: Router = Router();
const logger = createLogger('dashboard:auth-users');

// No `:` (the credential separator) or `,`/`=`/`|` (the env grammars), so a
// managed name can always be moved into AIOSTREAMS_AUTH verbatim.
const USERNAME = /^[A-Za-z0-9._@-]{1,64}$/;

const UpsertSchema = z.object({
  password: z.string().min(8).max(256),
  permissions: z
    .array(z.enum(PERMISSION_NAMES as [Permission, ...Permission[]]))
    .max(PERMISSION_NAMES.length),
  note: z.string().max(200).nullish(),
});

function fail(res: Response, status: number, code: string, message: string) {
  return res
    .status(status)
    .json(createResponse({ success: false, error: { code, message } }));
}

/** Validates `:username`; answers and returns null when it is unusable. */
function target(req: Request, res: Response): string | null {
  const name = String(req.params.username);
  if (!USERNAME.test(name)) {
    fail(res, 400, 'BAD_REQUEST', 'username must match [A-Za-z0-9._@-]{1,64}');
    return null;
  }
  if (appConfig.bootstrap.auth?.has(name)) {
    fail(
      res,
      409,
      'ENV_MANAGED',
      'this username is defined in AIOSTREAMS_AUTH; change it there'
    );
    return null;
  }
  return name;
}

// GET /dashboard/auth-users: every managed credential, passwords omitted.
router.get('/', async (_req, res, next) => {
  try {
    res.json(
      createResponse({ success: true, data: await AuthUserRepository.list() })
    );
  } catch (err) {
    next(err);
  }
});

// PUT /dashboard/auth-users/:username: create or replace. Effective at once.
router.put('/:username', async (req, res, next) => {
  try {
    const username = target(req, res);
    if (!username) return;
    const parsed = UpsertSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return fail(res, 400, 'BAD_REQUEST', formatZodError(parsed.error));
    }
    const { created } = await AuthUserRepository.upsert({
      username,
      ...parsed.data,
    });
    logger.info(
      { username, permissions: parsed.data.permissions, created },
      created ? 'managed auth user created' : 'managed auth user updated'
    );
    res
      .status(created ? 201 : 200)
      .json(createResponse({ success: true, data: { username, created } }));
  } catch (err) {
    next(err);
  }
});

// DELETE /dashboard/auth-users/:username: remove and stop its live streams.
// The credential stops authenticating immediately; an already-open proxied
// response would otherwise keep playing until it ends.
router.delete('/:username', async (req, res, next) => {
  try {
    const username = target(req, res);
    if (!username) return;
    const removed = await AuthUserRepository.remove(username);
    const stopped = removed ? await stopUserStreams(username) : 0;
    if (removed) {
      logger.info({ username, stopped }, 'managed auth user removed');
    }
    res.json(createResponse({ success: true, data: { removed, stopped } }));
  } catch (err) {
    next(err);
  }
});

export default router;
