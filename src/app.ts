import { randomUUID } from 'node:crypto';
import Fastify, { type FastifyError, type FastifyInstance } from 'fastify';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { AuthError, createAuth, type Auth } from './auth.js';
import type { Config } from './config.js';
import { eventRoutes } from './routes/events.js';
import { healthRoutes } from './routes/health.js';
import { AuditStore } from './store.js';

export interface BuildOptions {
  config: Config;
  store?: AuditStore;
  logger?: boolean;
}

export interface BuiltApp {
  app: FastifyInstance;
  store: AuditStore;
  auth: Auth;
}

export async function buildApp({ config, store, logger = true }: BuildOptions): Promise<BuiltApp> {
  const app = Fastify({
    bodyLimit: 16 * 1024,
    genReqId: () => randomUUID(),
    requestIdHeader: false, // never trust a client-supplied request ID
    trustProxy: config.trustProxy,
    // Reject unknown fields instead of silently stripping them: an audit API should fail loudly.
    ajv: { customOptions: { removeAdditional: false } },
    logger: logger
      ? {
          level: config.logLevel,
          redact: {
            paths: ['req.headers.authorization', 'req.headers.cookie'],
            censor: '[REDACTED]',
          },
        }
      : false,
  });

  const auditStore = store ?? new AuditStore(config.dbPath, config.hmacKey);
  const auth = createAuth({
    secret: config.jwtSecret,
    issuer: config.jwtIssuer,
    audience: config.jwtAudience,
  });

  app.decorateRequest('principal', null);

  app.addHook('onSend', async (req, reply) => {
    void reply.header('x-request-id', req.id);
    void reply.header('cache-control', 'no-store');
  });

  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
      },
    },
  });

  await app.register(rateLimit, {
    global: true,
    max: config.rateLimitMax,
    timeWindow: config.rateLimitWindow,
  });

  if (config.enableDocs) {
    await app.register(swagger, {
      openapi: {
        info: {
          title: 'Secure Audit Log API',
          description: 'Tamper-evident, append-only audit logging with HMAC hash chaining.',
          version: '1.0.0',
        },
        components: {
          securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } },
        },
      },
    });
    await app.register(swaggerUi, { routePrefix: '/docs' });
  }

  app.setErrorHandler((err: FastifyError, req, reply) => {
    if (err instanceof AuthError) {
      return reply.code(err.statusCode).send({
        error: err.statusCode === 401 ? 'Unauthorized' : 'Forbidden',
        message: err.message,
        requestId: req.id,
      });
    }
    if (err.validation) {
      return reply
        .code(400)
        .send({ error: 'Bad Request', message: err.message, requestId: req.id });
    }
    const status = err.statusCode ?? 500;
    if (status >= 500) {
      req.log.error({ err }, 'unhandled error');
      // Never leak internals (stack traces, SQL) to the client.
      return reply
        .code(500)
        .send({ error: 'Internal Server Error', message: 'unexpected error', requestId: req.id });
    }
    return reply.code(status).send({ error: err.name, message: err.message, requestId: req.id });
  });

  app.setNotFoundHandler((req, reply) =>
    reply.code(404).send({ error: 'Not Found', message: 'route not found', requestId: req.id }),
  );

  await app.register(healthRoutes, { store: auditStore });
  await app.register(eventRoutes, { prefix: '/v1', store: auditStore, auth });

  app.addHook('onClose', () => {
    auditStore.close();
  });

  return { app, store: auditStore, auth };
}
