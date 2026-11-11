import type { FastifyPluginAsync } from 'fastify';
import type { AuditStore } from '../store.js';

export const healthRoutes: FastifyPluginAsync<{ store: AuditStore }> = async (app, { store }) => {
  const noLimit = { rateLimit: false };

  app.get(
    '/health',
    { config: noLimit, schema: { summary: 'Liveness probe', tags: ['ops'] } },
    async () => ({ status: 'ok' }),
  );

  app.get(
    '/ready',
    {
      config: noLimit,
      schema: { summary: 'Readiness probe (checks the database)', tags: ['ops'] },
    },
    async (_req, reply) => {
      try {
        if (store.ping()) return { status: 'ready' };
      } catch {
        // fall through
      }
      return reply.code(503).send({ status: 'unavailable' });
    },
  );
};
