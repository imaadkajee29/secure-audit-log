import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { GENESIS_HASH } from '../src/chain.js';
import { AuditStore } from '../src/store.js';

const KEY = 'h'.repeat(48);
const ev = (i: number, actor = 'alice') => ({
  actor,
  action: i % 2 ? 'login' : 'logout',
  resource: `user/${actor}`,
  outcome: 'success' as const,
  metadata: { i },
});

const stores: AuditStore[] = [];
const dirs: string[] = [];
function memStore() {
  const s = new AuditStore(':memory:', KEY);
  stores.push(s);
  return s;
}

afterEach(() => {
  for (const s of stores.splice(0)) {
    try {
      s.close();
    } catch {
      /* already closed */
    }
  }
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe('AuditStore', () => {
  it('links each event to the previous one', () => {
    const s = memStore();
    const a = s.append(ev(1));
    const b = s.append(ev(2));
    expect(a.seq).toBe(1);
    expect(a.prevHash).toBe(GENESIS_HASH);
    expect(b.seq).toBe(2);
    expect(b.prevHash).toBe(a.hash);
    expect(s.verify()).toMatchObject({ valid: true, checked: 2, headHash: b.hash });
  });

  it('round-trips events exactly (including nested metadata)', () => {
    const s = memStore();
    const written = s.append({ ...ev(1), metadata: { z: [1, { b: 2, a: 1 }], ok: true } });
    expect(s.get(1)).toEqual(written);
    expect(s.get(99)).toBeUndefined();
  });

  it('defaults metadata to an empty object', () => {
    const s = memStore();
    const { actor, action, resource, outcome } = ev(1);
    expect(s.append({ actor, action, resource, outcome }).metadata).toEqual({});
  });

  it('filters and paginates', () => {
    const s = memStore();
    for (let i = 1; i <= 6; i++) s.append(ev(i, i <= 3 ? 'alice' : 'bob'));
    expect(s.list({ limit: 2 }).map((e) => e.seq)).toEqual([1, 2]);
    expect(s.list({ limit: 2, afterSeq: 2 }).map((e) => e.seq)).toEqual([3, 4]);
    expect(s.list({ limit: 10, actor: 'bob' }).map((e) => e.seq)).toEqual([4, 5, 6]);
    expect(s.list({ limit: 10, action: 'logout', actor: 'alice' }).map((e) => e.seq)).toEqual([2]);
  });

  it('blocks UPDATE and DELETE at the database level', () => {
    const s = memStore();
    s.append(ev(1));
    expect(() => {
      s.db.exec("UPDATE audit_events SET actor = 'mallory'");
    }).toThrow(/append-only/);
    expect(() => {
      s.db.exec('DELETE FROM audit_events');
    }).toThrow(/append-only/);
    expect(s.verify().valid).toBe(true);
  });

  it('detects tampering by someone who bypasses the triggers', () => {
    const s = memStore();
    for (let i = 1; i <= 4; i++) s.append(ev(i));
    // Simulate an attacker with raw DB access.
    s.db.exec('DROP TRIGGER audit_events_no_update');
    s.db.exec("UPDATE audit_events SET outcome = 'failure' WHERE seq = 3");
    expect(s.verify()).toMatchObject({ valid: false, brokenAt: 3, checked: 2 });
  });

  it('detects deleted rows', () => {
    const s = memStore();
    for (let i = 1; i <= 4; i++) s.append(ev(i));
    s.db.exec('DROP TRIGGER audit_events_no_delete');
    s.db.exec('DELETE FROM audit_events WHERE seq = 2');
    expect(s.verify()).toMatchObject({ valid: false, brokenAt: 3 });
  });

  it('rolls back a failed append and leaves the chain intact', () => {
    const s = memStore();
    s.append(ev(1));
    expect(() => s.append({ ...ev(2), outcome: 'maybe' as never })).toThrow();
    const next = s.append(ev(3));
    expect(next.seq).toBe(2);
    expect(s.verify()).toMatchObject({ valid: true, checked: 2 });
  });

  it('persists to disk and verifies after reopening', () => {
    const dir = mkdtempSync(join(tmpdir(), 'audit-'));
    dirs.push(dir);
    const path = join(dir, 'nested', 'audit.db');
    const s1 = new AuditStore(path, KEY);
    for (let i = 1; i <= 3; i++) s1.append(ev(i));
    s1.close();

    const s2 = new AuditStore(path, KEY);
    stores.push(s2);
    expect(s2.verify()).toMatchObject({ valid: true, checked: 3 });
    expect(s2.append(ev(4)).seq).toBe(4);

    const wrongKey = new AuditStore(path, 'w'.repeat(48));
    stores.push(wrongKey);
    expect(wrongKey.verify().valid).toBe(false);
  });

  it('uses the injected clock', () => {
    const fixed = new Date('2026-03-01T08:00:00.000Z');
    const s = new AuditStore(':memory:', KEY, () => fixed);
    stores.push(s);
    expect(s.append(ev(1)).timestamp).toBe(fixed.toISOString());
  });

  it('answers ping', () => {
    expect(memStore().ping()).toBe(true);
  });
});
