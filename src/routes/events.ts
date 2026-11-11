import type { FastifyPluginAsync } from 'fastify';
import type { TypeBoxTypeProvider } from '@fastify/type-provider-typebox';
import type { Auth } from '../auth.js';
import type { JsonValue } from '../chain.js';
import type { AuditStore } from '../store.js';
import {
  AuditEventSchema,
  ErrorResponse,
  ListQuerySchema,
  ListResponse,
  NewEventBody,
  SeqParams,
  VerifyResponse,
} from '../schemas.js';

const MAX_METADATA_BYTES = 8 * 1024;
const secured = [{ bearerAuth: [] }];

export interface EventRoutesOptions {
  store: AuditStore;
  auth: Auth;
}

export const eventRoutes: FastifyPluginAsync<EventRoutesOptions> = async (fastify, opts) => {
  const app = fastify.withTypeProvider<TypeBoxTypeProvider>();
  const { store, auth } = opts;

  app.post(
    '/events',
    {
      preHandler: auth.requireRole('writer'),
      schema: {
        summary: 'Append an audit event',
        description:
          'The actor is taken from the verified JWT subject, never from the request body, ' +
          'so callers cannot write events on behalf of someone else.',
        tags: ['events'],
        security: secured,
        body: NewEventBody,
        response: {
          201: AuditEventSchema,
          400: ErrorResponse,
          401: ErrorResponse,
          403: ErrorResponse,
        },
      },
    },
    async (req, reply) => {
      const metadata = (req.body.metadata ?? {}) as Record<string, JsonValue>;
      if (Buffer.byteLength(JSON.stringify(metadata)) > MAX_METADATA_BYTES) {
        return reply.code(400).send({
          error: 'Bad Request',
          message: `metadata must be at most ${MAX_METADATA_BYTES} bytes`,
          requestId: req.id,
        });
      }
      // principal is guaranteed by the preHandler
      const actor = req.principal?.sub ?? 'unknown';
      const event = store.append({
        actor,
        action: req.body.action,
        resource: req.body.resource,
        outcome: req.body.outcome,
        metadata,
      });
      req.log.info({ seq: event.seq, action: event.action }, 'audit event appended');
      return reply.code(201).send(event);
    },
  );

  app.get(
    '/events',
    {
      preHandler: auth.requireRole('auditor'),
      schema: {
        summary: 'List audit events (cursor-paginated, oldest first)',
        tags: ['events'],
        security: secured,
        querystring: ListQuerySchema,
        response: { 200: ListResponse, 401: ErrorResponse, 403: ErrorResponse },
      },
    },
    async (req) => {
      const events = store.list(req.query);
      const last = events.at(-1);
      return {
        events,
        nextAfterSeq: events.length === req.query.limit && last ? last.seq : null,
      };
    },
  );

  app.get(
    '/events/:seq',
    {
      preHandler: auth.requireRole('auditor'),
      schema: {
        summary: 'Get a single audit event',
        tags: ['events'],
        security: secured,
        params: SeqParams,
        response: { 200: AuditEventSchema, 404: ErrorResponse },
      },
    },
    async (req, reply) => {
      const event = store.get(req.params.seq);
      if (!event) {
        return reply
          .code(404)
          .send({ error: 'Not Found', message: 'event not found', requestId: req.id });
      }
      return event;
    },
  );

  app.get(
    '/verify',
    {
      preHandler: auth.requireRole('auditor'),
      schema: {
        summary: 'Verify the integrity of the entire chain',
        description:
          'Recomputes every HMAC and checks sequence and prevHash links. ' +
          'Store headHash externally (e.g. in a ticket or another system) to detect a full rewrite.',
        tags: ['integrity'],
        security: secured,
        response: { 200: VerifyResponse },
      },
    },
    async (req) => {
      const result = store.verify();
      if (!result.valid) {
        req.log.error(result, 'AUDIT CHAIN INTEGRITY FAILURE');
      }
      return result;
    },
  );
};
