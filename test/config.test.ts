import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from '../src/config.js';
import { secret } from './helpers.js';

const valid = () => ({ JWT_SECRET: secret(), AUDIT_HMAC_KEY: secret() });

describe('loadConfig', () => {
  it('applies safe defaults', () => {
    const c = loadConfig(valid());
    expect(c).toMatchObject({
      env: 'development',
      port: 3000,
      rateLimitMax: 100,
      enableDocs: true,
      trustProxy: false,
    });
  });

  it('disables docs by default in production', () => {
    expect(loadConfig({ ...valid(), NODE_ENV: 'production' }).enableDocs).toBe(false);
  });

  it('rejects missing or short secrets', () => {
    expect(() => loadConfig({})).toThrow(ConfigError);
    expect(() => loadConfig({ JWT_SECRET: 'short', AUDIT_HMAC_KEY: secret() })).toThrow(
      /JWT_SECRET must be set/,
    );
  });

  it('rejects the placeholder values from .env.example', () => {
    expect(() =>
      loadConfig({ JWT_SECRET: 'change-me'.padEnd(40, 'x'), AUDIT_HMAC_KEY: secret() }),
    ).toThrow(/placeholder/);
  });

  it('requires key separation between JWT and HMAC secrets', () => {
    const s = secret();
    expect(() => loadConfig({ JWT_SECRET: s, AUDIT_HMAC_KEY: s })).toThrow(/must be different/);
  });

  it('collects every problem in one error', () => {
    try {
      loadConfig({ NODE_ENV: 'staging', PORT: '99999', RATE_LIMIT_MAX: '0' });
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigError);
      expect((err as ConfigError).problems.length).toBeGreaterThanOrEqual(5);
    }
  });
});
