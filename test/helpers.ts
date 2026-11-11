import { randomBytes } from 'node:crypto';
import { buildApp } from '../src/app.js';
import { loadConfig, type Config } from '../src/config.js';

export const secret = () => randomBytes(48).toString('base64url');

export function testConfig(overrides: Partial<Config> = {}): Config {
  return {
    ...loadConfig({
      NODE_ENV: 'test',
      JWT_SECRET: secret(),
      AUDIT_HMAC_KEY: secret(),
      DB_PATH: ':memory:',
      ENABLE_DOCS: 'true',
    }),
    ...overrides,
  };
}

export async function setup(overrides: Partial<Config> = {}) {
  const config = testConfig(overrides);
  const built = await buildApp({ config, logger: false });
  const writer = await built.auth.signToken('svc-payments', ['writer']);
  const auditor = await built.auth.signToken('auditor-jane', ['auditor']);
  const admin = await built.auth.signToken('admin', ['writer', 'auditor']);
  return { ...built, config, tokens: { writer, auditor, admin } };
}

export const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

export const sampleEvent = {
  action: 'payment.approve',
  resource: 'account/12345',
  outcome: 'success' as const,
  metadata: { amount: 1500, currency: 'ZAR', channel: 'mobile' },
};
