export interface Config {
  env: 'development' | 'test' | 'production';
  host: string;
  port: number;
  logLevel: string;
  dbPath: string;
  jwtSecret: string;
  jwtIssuer: string;
  jwtAudience: string;
  hmacKey: string;
  rateLimitMax: number;
  rateLimitWindow: string;
  enableDocs: boolean;
  trustProxy: boolean;
}

export class ConfigError extends Error {
  constructor(public readonly problems: string[]) {
    super(`Invalid configuration:\n  - ${problems.join('\n  - ')}`);
    this.name = 'ConfigError';
  }
}

const MIN_SECRET_LENGTH = 32;

/**
 * Builds a validated config from environment variables.
 * Fails fast on anything unsafe, so a misconfigured container never starts.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const problems: string[] = [];

  const nodeEnv = env.NODE_ENV ?? 'development';
  if (!['development', 'test', 'production'].includes(nodeEnv)) {
    problems.push(`NODE_ENV must be development, test or production (got "${nodeEnv}")`);
  }

  const port = Number(env.PORT ?? 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    problems.push('PORT must be an integer between 1 and 65535');
  }

  const rateLimitMax = Number(env.RATE_LIMIT_MAX ?? 100);
  if (!Number.isInteger(rateLimitMax) || rateLimitMax < 1) {
    problems.push('RATE_LIMIT_MAX must be a positive integer');
  }

  const jwtSecret = env.JWT_SECRET ?? '';
  const hmacKey = env.AUDIT_HMAC_KEY ?? '';
  for (const [name, value] of [
    ['JWT_SECRET', jwtSecret],
    ['AUDIT_HMAC_KEY', hmacKey],
  ] as const) {
    if (value.length < MIN_SECRET_LENGTH) {
      problems.push(`${name} must be set and at least ${MIN_SECRET_LENGTH} characters`);
    } else if (value.startsWith('change-me')) {
      problems.push(`${name} is still the placeholder value from .env.example`);
    }
  }
  if (jwtSecret && jwtSecret === hmacKey) {
    problems.push('JWT_SECRET and AUDIT_HMAC_KEY must be different (key separation)');
  }

  if (problems.length > 0) throw new ConfigError(problems);

  return {
    env: nodeEnv as Config['env'],
    host: env.HOST ?? '0.0.0.0',
    port,
    logLevel: env.LOG_LEVEL ?? 'info',
    dbPath: env.DB_PATH ?? './data/audit.db',
    jwtSecret,
    jwtIssuer: env.JWT_ISSUER ?? 'secure-audit-log',
    jwtAudience: env.JWT_AUDIENCE ?? 'secure-audit-log-api',
    hmacKey,
    rateLimitMax,
    rateLimitWindow: env.RATE_LIMIT_WINDOW ?? '1 minute',
    // Only enable behind a proxy you control, or clients can spoof X-Forwarded-For.
    trustProxy: env.TRUST_PROXY === 'true',
    enableDocs: (env.ENABLE_DOCS ?? (nodeEnv === 'production' ? 'false' : 'true')) === 'true',
  };
}
