/**
 * Dev helper: mints a signed JWT for local testing.
 *   npm run token -- --sub alice --roles writer,auditor --ttl 1h
 * Reads JWT_SECRET / JWT_ISSUER / JWT_AUDIENCE from the environment (or .env via --env-file).
 */
import { parseArgs } from 'node:util';
import { ROLES, createAuth, type Role } from '../src/auth.js';

const { values } = parseArgs({
  options: {
    sub: { type: 'string', default: 'dev-user' },
    roles: { type: 'string', default: 'writer,auditor' },
    ttl: { type: 'string', default: '1h' },
  },
});

const secret = process.env.JWT_SECRET;
if (!secret || secret.length < 32) {
  console.error('JWT_SECRET must be set (32+ chars). Try: npm run token --env-file=.env');
  process.exit(1);
}

const roles = values.roles.split(',').map((r) => r.trim());
const invalid = roles.filter((r) => !(ROLES as readonly string[]).includes(r));
if (invalid.length > 0) {
  console.error(`Unknown role(s): ${invalid.join(', ')}. Valid: ${ROLES.join(', ')}`);
  process.exit(1);
}

const auth = createAuth({
  secret,
  issuer: process.env.JWT_ISSUER ?? 'secure-audit-log',
  audience: process.env.JWT_AUDIENCE ?? 'secure-audit-log-api',
});

console.log(await auth.signToken(values.sub, roles as Role[], values.ttl));
