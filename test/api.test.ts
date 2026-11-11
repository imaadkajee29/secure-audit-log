import { afterEach, describe, expect, it } from 'vitest';
import { SignJWT } from 'jose';
import { bearer, sampleEvent, setup } from './helpers.js';

type Ctx = Awaited<ReturnType<typeof setup>>;
let ctx: Ctx | undefined;

afterEach(async () => {
  await ctx?.app.close();
  ctx = undefined;
});

async function start(overrides?: Parameters<typeof setup>[0]) {
  ctx = await setup(overrides);
  return ctx;
}

describe('health', () => {
  it('serves liveness and readiness', async () => {
    const { app } = await start();
    expect((await app.inject('/health')).json()).toEqual({ status: 'ok' });
    expect((await app.inject('/ready')).json()).toEqual({ status: 'ready' });
  });

  it('reports not ready when the database is unavailable', async () => {
    const { app, store } = await start();
    store.db.close();
    const res = await app.inject('/ready');
    expect(res.statusCode).toBe(503);
    // reopen-free teardown: avoid double close in onClose
    store.close = () => undefined;
  });
});

describe('security headers', () => {
  it('sets helmet headers, request id and no-store', async () => {
    const { app } = await start();
    const res = await app.inject('/health');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['content-security-policy']).toContain("default-src 'self'");
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('ignores client-supplied request ids', async () => {
    const { app } = await start();
    const res = await app.inject({ url: '/health', headers: { 'request-id': 'evil\ninjected' } });
    expect(res.headers['x-request-id']).not.toContain('evil');
  });
});

describe('authentication and authorization', () => {
  it('rejects requests without a token', async () => {
    const { app } = await start();
    const res = await app.inject({ method: 'GET', url: '/v1/events' });
    expect(res.statusCode).toBe(401);
    expect(res.headers['www-authenticate']).toBe('Bearer');
    expect(res.json()).toMatchObject({ error: 'Unauthorized', message: 'missing bearer token' });
  });

  it('rejects malformed authorization headers', async () => {
    const { app } = await start();
    const res = await app.inject({ url: '/v1/events', headers: { authorization: 'Basic abc' } });
    expect(res.statusCode).toBe(401);
  });

  it('rejects a token signed with another key', async () => {
    const { app, config } = await start();
    const forged = await new SignJWT({ roles: ['auditor'] })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('mallory')
      .setIssuer(config.jwtIssuer)
      .setAudience(config.jwtAudience)
      .setExpirationTime('1h')
      .sign(new TextEncoder().encode('x'.repeat(48)));
    const res = await app.inject({ url: '/v1/events', headers: bearer(forged) });
    expect(res.statusCode).toBe(401);
    expect(res.json().message).toBe('invalid token');
  });

  it('rejects alg=none tokens', async () => {
    const { app } = await start();
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const none = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: 'x', roles: ['auditor'], exp: 9999999999 })}.`;
    const res = await app.inject({ url: '/v1/events', headers: bearer(none) });
    expect(res.statusCode).toBe(401);
  });

  it('rejects expired tokens with a clear reason', async () => {
    const { app, auth } = await start();
    const expired = await auth.signToken('alice', ['auditor'], '-1s');
    const res = await app.inject({ url: '/v1/events', headers: bearer(expired) });
    expect(res.statusCode).toBe(401);
    expect(res.json().message).toBe('token expired');
  });

  it('rejects tokens for the wrong audience', async () => {
    const { app, config } = await start();
    const wrongAud = await new SignJWT({ roles: ['auditor'] })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('alice')
      .setIssuer(config.jwtIssuer)
      .setAudience('some-other-api')
      .setExpirationTime('1h')
      .sign(new TextEncoder().encode(config.jwtSecret));
    expect((await app.inject({ url: '/v1/events', headers: bearer(wrongAud) })).statusCode).toBe(
      401,
    );
  });

  it('enforces roles: writers cannot read, auditors cannot write', async () => {
    const { app, tokens } = await start();
    const read = await app.inject({ url: '/v1/events', headers: bearer(tokens.writer) });
    expect(read.statusCode).toBe(403);
    const write = await app.inject({
      method: 'POST',
      url: '/v1/events',
      headers: bearer(tokens.auditor),
      payload: sampleEvent,
    });
    expect(write.statusCode).toBe(403);
    expect(write.json().message).toBe('requires role "writer"');
  });

  it('ignores unknown roles in the token', async () => {
    const { app, auth } = await start();
    const t = await auth.signToken('alice', ['superadmin' as never]);
    expect((await app.inject({ url: '/v1/verify', headers: bearer(t) })).statusCode).toBe(403);
  });
});

describe('POST /v1/events', () => {
  it('appends an event with the actor taken from the token', async () => {
    const { app, tokens } = await start();
    const res = await app.inject({
      method: 'POST',
      url: '/v1/events',
      headers: bearer(tokens.writer),
      payload: { ...sampleEvent, actor: 'someone-else' },
    });
    // additionalProperties: false rejects attempts to set the actor
    expect(res.statusCode).toBe(400);

    const ok = await app.inject({
      method: 'POST',
      url: '/v1/events',
      headers: bearer(tokens.writer),
      payload: sampleEvent,
    });
    expect(ok.statusCode).toBe(201);
    expect(ok.json()).toMatchObject({ seq: 1, actor: 'svc-payments', ...sampleEvent });
  });

  it.each([
    [{ ...sampleEvent, action: '' }],
    [{ ...sampleEvent, action: 'bad action\nFAKE LOG LINE' }],
    [{ ...sampleEvent, outcome: 'maybe' }],
    [{ action: 'x', resource: 'y' }],
  ])('rejects invalid payload %#', async (payload) => {
    const { app, tokens } = await start();
    const res = await app.inject({
      method: 'POST',
      url: '/v1/events',
      headers: bearer(tokens.writer),
      payload,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toHaveProperty('requestId');
  });

  it('rejects oversized metadata', async () => {
    const { app, tokens } = await start();
    const res = await app.inject({
      method: 'POST',
      url: '/v1/events',
      headers: bearer(tokens.writer),
      payload: { ...sampleEvent, metadata: { blob: 'a'.repeat(9000) } },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().message).toMatch(/metadata must be at most/);
  });

  it('rejects bodies over the global limit', async () => {
    const { app, tokens } = await start();
    const res = await app.inject({
      method: 'POST',
      url: '/v1/events',
      headers: { ...bearer(tokens.writer), 'content-type': 'application/json' },
      payload: JSON.stringify({ ...sampleEvent, metadata: { blob: 'a'.repeat(20000) } }),
    });
    expect(res.statusCode).toBe(413);
  });
});

describe('reading and verifying', () => {
  async function seeded(n: number) {
    const c = await start();
    for (let i = 0; i < n; i++) {
      await c.app.inject({
        method: 'POST',
        url: '/v1/events',
        headers: bearer(c.tokens.writer),
        payload: { ...sampleEvent, resource: `account/${i}` },
      });
    }
    return c;
  }

  it('lists events with cursor pagination', async () => {
    const { app, tokens } = await seeded(5);
    const p1 = (
      await app.inject({ url: '/v1/events?limit=2', headers: bearer(tokens.auditor) })
    ).json();
    expect(p1.events.map((e: { seq: number }) => e.seq)).toEqual([1, 2]);
    expect(p1.nextAfterSeq).toBe(2);
    const p3 = (
      await app.inject({ url: '/v1/events?limit=2&afterSeq=4', headers: bearer(tokens.auditor) })
    ).json();
    expect(p3.events).toHaveLength(1);
    expect(p3.nextAfterSeq).toBeNull();
  });

  it('rejects unknown query params and out-of-range limits', async () => {
    const { app, tokens } = await start();
    for (const q of ['limit=0', 'limit=501', 'foo=bar']) {
      const res = await app.inject({ url: `/v1/events?${q}`, headers: bearer(tokens.auditor) });
      expect(res.statusCode).toBe(400);
    }
  });

  it('fetches a single event or 404s', async () => {
    const { app, tokens } = await seeded(1);
    expect(
      (await app.inject({ url: '/v1/events/1', headers: bearer(tokens.auditor) })).statusCode,
    ).toBe(200);
    const missing = await app.inject({ url: '/v1/events/42', headers: bearer(tokens.auditor) });
    expect(missing.statusCode).toBe(404);
  });

  it('verifies an intact chain', async () => {
    const { app, tokens } = await seeded(3);
    const res = await app.inject({ url: '/v1/verify', headers: bearer(tokens.auditor) });
    expect(res.json()).toMatchObject({ valid: true, checked: 3, headSeq: 3 });
  });

  it('reports tampering through the API', async () => {
    const { app, tokens, store } = await seeded(3);
    store.db.exec('DROP TRIGGER audit_events_no_update');
    store.db.exec(`UPDATE audit_events SET metadata = '{"amount":1}' WHERE seq = 2`);
    const res = await app.inject({ url: '/v1/verify', headers: bearer(tokens.auditor) });
    expect(res.json()).toMatchObject({ valid: false, brokenAt: 2 });
  });
});

describe('errors, limits and docs', () => {
  it('returns JSON 404 for unknown routes', async () => {
    const { app } = await start();
    const res = await app.inject('/nope');
    expect(res.statusCode).toBe(404);
    expect(res.json()).toMatchObject({ error: 'Not Found' });
  });

  it('hides internal errors from clients', async () => {
    const { app, tokens, store } = await start();
    store.append = () => {
      throw new Error('SQLITE_CORRUPT: secret internals');
    };
    const res = await app.inject({
      method: 'POST',
      url: '/v1/events',
      headers: bearer(tokens.writer),
      payload: sampleEvent,
    });
    expect(res.statusCode).toBe(500);
    expect(res.body).not.toContain('SQLITE');
  });

  it('rate limits clients', async () => {
    const { app, tokens } = await start({ rateLimitMax: 3 });
    const codes: number[] = [];
    for (let i = 0; i < 5; i++) {
      codes.push(
        (await app.inject({ url: '/v1/verify', headers: bearer(tokens.auditor) })).statusCode,
      );
    }
    expect(codes).toEqual([200, 200, 200, 429, 429]);
    // probes stay exempt so orchestrators never kill a busy pod
    expect((await app.inject('/health')).statusCode).toBe(200);
  });

  it('serves the OpenAPI spec when docs are enabled', async () => {
    const { app } = await start();
    const spec = (await app.inject('/docs/json')).json();
    expect(spec.info.title).toBe('Secure Audit Log API');
    expect(spec.paths).toHaveProperty('/v1/verify');
  });

  it('does not expose docs when disabled', async () => {
    const { app } = await start({ enableDocs: false });
    expect((await app.inject('/docs/json')).statusCode).toBe(404);
  });
});
