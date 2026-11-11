import { createHmac, timingSafeEqual } from 'node:crypto';

/** prevHash of the first event in the chain. */
export const GENESIS_HASH = '0'.repeat(64);

export type Outcome = 'success' | 'failure';

export type JsonValue =
  string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

/** The fields covered by an event's hash. Changing any of them breaks the chain. */
export interface EventPayload {
  seq: number;
  timestamp: string;
  actor: string;
  action: string;
  resource: string;
  outcome: Outcome;
  metadata: Record<string, JsonValue>;
  prevHash: string;
}

export interface AuditEvent extends EventPayload {
  hash: string;
}

/**
 * Deterministic JSON: object keys sorted recursively, no whitespace.
 * The same logical event always produces the same bytes, so the same hash.
 */
export function canonicalize(value: JsonValue): string {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) {
      throw new TypeError('Non-finite numbers cannot be canonicalized');
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  const parts = keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k] as JsonValue)}`);
  return `{${parts.join(',')}}`;
}

/**
 * HMAC-SHA256 over the canonical payload.
 * A plain SHA-256 chain can be fully recomputed by anyone with DB write access;
 * keying it means an attacker also needs the HMAC key (held outside the DB).
 */
export function computeHash(payload: EventPayload, key: string): string {
  const body = canonicalize(payload as unknown as JsonValue);
  return createHmac('sha256', key).update(body).digest('hex');
}

function safeEqualHex(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  return ba.length === bb.length && ba.length > 0 && timingSafeEqual(ba, bb);
}

export interface VerifyResult {
  valid: boolean;
  checked: number;
  headSeq: number | null;
  headHash: string | null;
  brokenAt?: number;
  reason?: string;
}

/**
 * Walks events in order and checks three things per event:
 *  1. sequence numbers are contiguous (detects deleted rows)
 *  2. prevHash links to the previous event's hash (detects reordering/insertion)
 *  3. the stored hash matches a fresh HMAC of the payload (detects edits)
 */
export function verifyChain(events: Iterable<AuditEvent>, key: string): VerifyResult {
  let expectedPrev = GENESIS_HASH;
  let expectedSeq = 1;
  let checked = 0;
  let last: AuditEvent | null = null;

  for (const event of events) {
    const fail = (reason: string): VerifyResult => ({
      valid: false,
      checked,
      headSeq: last?.seq ?? null,
      headHash: last?.hash ?? null,
      brokenAt: event.seq,
      reason,
    });

    if (event.seq !== expectedSeq) {
      return fail(`sequence gap: expected seq ${expectedSeq}, found ${event.seq}`);
    }
    if (event.prevHash !== expectedPrev) {
      return fail('prevHash does not match the previous event hash');
    }
    const { hash, ...payload } = event;
    if (!safeEqualHex(hash, computeHash(payload, key))) {
      return fail('event content does not match its hash');
    }

    checked++;
    expectedPrev = hash;
    expectedSeq++;
    last = event;
  }

  return { valid: true, checked, headSeq: last?.seq ?? null, headHash: last?.hash ?? null };
}
