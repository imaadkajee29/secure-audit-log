import { describe, expect, it } from 'vitest';
import {
  GENESIS_HASH,
  canonicalize,
  computeHash,
  verifyChain,
  type AuditEvent,
  type EventPayload,
} from '../src/chain.js';

const KEY = 'k'.repeat(48);

function buildChain(n: number, key = KEY): AuditEvent[] {
  const events: AuditEvent[] = [];
  let prev = GENESIS_HASH;
  for (let i = 1; i <= n; i++) {
    const payload: EventPayload = {
      seq: i,
      timestamp: new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString(),
      actor: 'alice',
      action: 'login',
      resource: `user/${i}`,
      outcome: 'success',
      metadata: { i },
      prevHash: prev,
    };
    const hash = computeHash(payload, key);
    events.push({ ...payload, hash });
    prev = hash;
  }
  return events;
}

describe('canonicalize', () => {
  it('sorts keys recursively so key order never changes the hash', () => {
    expect(canonicalize({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: null } })).toBe(
      '{"a":{"c":null,"d":[3,{"y":2,"z":1}]},"b":1}',
    );
    expect(canonicalize({ x: 1, y: 2 })).toBe(canonicalize({ y: 2, x: 1 }));
  });

  it('handles primitives and escapes strings', () => {
    expect(canonicalize('he said "hi"')).toBe('"he said \\"hi\\""');
    expect(canonicalize(true)).toBe('true');
    expect(canonicalize([])).toBe('[]');
  });

  it('rejects non-finite numbers', () => {
    expect(() => canonicalize(Number.NaN)).toThrow(TypeError);
    expect(() => canonicalize({ a: Number.POSITIVE_INFINITY })).toThrow(TypeError);
  });
});

describe('computeHash', () => {
  it('is deterministic and key-dependent', () => {
    const [e] = buildChain(1);
    const { hash, ...payload } = e!;
    expect(computeHash(payload, KEY)).toBe(hash);
    expect(computeHash(payload, 'x'.repeat(48))).not.toBe(hash);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('verifyChain', () => {
  it('accepts an empty chain', () => {
    expect(verifyChain([], KEY)).toEqual({
      valid: true,
      checked: 0,
      headSeq: null,
      headHash: null,
    });
  });

  it('accepts an intact chain and reports the head', () => {
    const chain = buildChain(5);
    const result = verifyChain(chain, KEY);
    expect(result).toMatchObject({ valid: true, checked: 5, headSeq: 5, headHash: chain[4]!.hash });
  });

  it('detects an edited field', () => {
    const chain = buildChain(5);
    chain[2] = { ...chain[2]!, outcome: 'failure' };
    expect(verifyChain(chain, KEY)).toMatchObject({
      valid: false,
      checked: 2,
      brokenAt: 3,
      reason: 'event content does not match its hash',
    });
  });

  it('detects edited metadata', () => {
    const chain = buildChain(3);
    chain[0] = { ...chain[0]!, metadata: { i: 999 } };
    expect(verifyChain(chain, KEY)).toMatchObject({ valid: false, brokenAt: 1 });
  });

  it('detects a deleted event (sequence gap)', () => {
    const chain = buildChain(5);
    chain.splice(2, 1);
    expect(verifyChain(chain, KEY)).toMatchObject({ valid: false, brokenAt: 4 });
    expect(verifyChain(chain, KEY).reason).toMatch(/sequence gap/);
  });

  it('detects a broken prevHash link even if the event hash is re-signed', () => {
    const chain = buildChain(3);
    const forged: EventPayload = { ...chain[1]!, prevHash: 'f'.repeat(64) };
    chain[1] = { ...forged, hash: computeHash(forged, KEY) };
    expect(verifyChain(chain, KEY)).toMatchObject({
      valid: false,
      brokenAt: 2,
      reason: 'prevHash does not match the previous event hash',
    });
  });

  it('detects a chain rewritten without the HMAC key', () => {
    const forged = buildChain(3, 'attacker-key'.padEnd(48, '!'));
    expect(verifyChain(forged, KEY)).toMatchObject({ valid: false, brokenAt: 1 });
  });

  it('rejects malformed hashes without throwing', () => {
    const chain = buildChain(1);
    chain[0] = { ...chain[0]!, hash: 'not-hex' };
    expect(verifyChain(chain, KEY).valid).toBe(false);
  });
});
