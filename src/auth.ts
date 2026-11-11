import type { FastifyReply, FastifyRequest } from 'fastify';
import { errors as joseErrors, jwtVerify, SignJWT } from 'jose';

export const ROLES = ['writer', 'auditor'] as const;
export type Role = (typeof ROLES)[number];

export interface Principal {
  sub: string;
  roles: Role[];
}

declare module 'fastify' {
  interface FastifyRequest {
    principal: Principal | null;
  }
}

export interface AuthOptions {
  secret: string;
  issuer: string;
  audience: string;
}

function isRole(value: unknown): value is Role {
  return typeof value === 'string' && (ROLES as readonly string[]).includes(value);
}

export class AuthError extends Error {
  constructor(
    public readonly statusCode: 401 | 403,
    message: string,
  ) {
    super(message);
    this.name = 'AuthError';
  }
}

export function createAuth(opts: AuthOptions) {
  const key = new TextEncoder().encode(opts.secret);

  async function verifyToken(token: string): Promise<Principal> {
    try {
      const { payload } = await jwtVerify(token, key, {
        issuer: opts.issuer,
        audience: opts.audience,
        algorithms: ['HS256'], // pin the algorithm: blocks alg=none / alg-confusion
        requiredClaims: ['sub', 'exp'],
      });
      const roles = Array.isArray(payload.roles) ? payload.roles.filter(isRole) : [];
      return { sub: payload.sub as string, roles };
    } catch (err) {
      const reason = err instanceof joseErrors.JWTExpired ? 'token expired' : 'invalid token';
      throw new AuthError(401, reason);
    }
  }

  /** Fastify preHandler: authenticates the bearer token and enforces a role. */
  function requireRole(role: Role) {
    return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
      const header = req.headers.authorization;
      const match = header ? /^Bearer\s+(\S+)$/i.exec(header) : null;
      if (!match?.[1]) {
        void reply.header('WWW-Authenticate', 'Bearer');
        throw new AuthError(401, 'missing bearer token');
      }
      const principal = await verifyToken(match[1]);
      if (!principal.roles.includes(role)) {
        req.log.warn({ sub: principal.sub, required: role }, 'authorization denied');
        throw new AuthError(403, `requires role "${role}"`);
      }
      req.principal = principal;
    };
  }

  async function signToken(sub: string, roles: Role[], ttl = '1h'): Promise<string> {
    return new SignJWT({ roles })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setSubject(sub)
      .setIssuer(opts.issuer)
      .setAudience(opts.audience)
      .setIssuedAt()
      .setExpirationTime(ttl)
      .sign(key);
  }

  return { verifyToken, requireRole, signToken };
}

export type Auth = ReturnType<typeof createAuth>;
