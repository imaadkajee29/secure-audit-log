import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  GENESIS_HASH,
  canonicalize,
  computeHash,
  verifyChain,
  type AuditEvent,
  type EventPayload,
  type JsonValue,
  type Outcome,
  type VerifyResult,
} from './chain.js';

export interface NewEvent {
  actor: string;
  action: string;
  resource: string;
  outcome: Outcome;
  metadata?: Record<string, JsonValue>;
}

export interface ListQuery {
  limit: number;
  afterSeq?: number;
  actor?: string;
  action?: string;
}

interface Row {
  seq: number;
  timestamp: string;
  actor: string;
  action: string;
  resource: string;
  outcome: Outcome;
  metadata: string;
  prev_hash: string;
  hash: string;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS audit_events (
  seq        INTEGER PRIMARY KEY,
  timestamp  TEXT NOT NULL,
  actor      TEXT NOT NULL,
  action     TEXT NOT NULL,
  resource   TEXT NOT NULL,
  outcome    TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
  metadata   TEXT NOT NULL,
  prev_hash  TEXT NOT NULL,
  hash       TEXT NOT NULL UNIQUE
) STRICT;

CREATE INDEX IF NOT EXISTS idx_audit_actor  ON audit_events (actor, seq);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events (action, seq);

-- Defence in depth: the table is append-only at the database level too.
CREATE TRIGGER IF NOT EXISTS audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;

CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
`;

function toEvent(row: Row): AuditEvent {
  return {
    seq: row.seq,
    timestamp: row.timestamp,
    actor: row.actor,
    action: row.action,
    resource: row.resource,
    outcome: row.outcome,
    metadata: JSON.parse(row.metadata) as Record<string, JsonValue>,
    prevHash: row.prev_hash,
    hash: row.hash,
  };
}

export class AuditStore {
  /** Exposed for operational tooling and tamper-detection tests only. */
  readonly db: DatabaseSync;

  constructor(
    path: string,
    private readonly hmacKey: string,
    private readonly now: () => Date = () => new Date(),
  ) {
    if (path !== ':memory:') {
      mkdirSync(dirname(path), { recursive: true });
    }
    this.db = new DatabaseSync(path);
    this.db.exec('PRAGMA busy_timeout = 5000;');
    if (path !== ':memory:') this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec(SCHEMA);
  }

  /**
   * Appends an event atomically. BEGIN IMMEDIATE takes the write lock before
   * reading the chain head, so two writers can never link to the same prevHash.
   */
  append(input: NewEvent): AuditEvent {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const head = this.db
        .prepare('SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1')
        .get() as { seq: number; hash: string } | undefined;

      const payload: EventPayload = {
        seq: (head?.seq ?? 0) + 1,
        timestamp: this.now().toISOString(),
        actor: input.actor,
        action: input.action,
        resource: input.resource,
        outcome: input.outcome,
        metadata: input.metadata ?? {},
        prevHash: head?.hash ?? GENESIS_HASH,
      };
      const hash = computeHash(payload, this.hmacKey);

      this.db
        .prepare(
          `INSERT INTO audit_events
             (seq, timestamp, actor, action, resource, outcome, metadata, prev_hash, hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          payload.seq,
          payload.timestamp,
          payload.actor,
          payload.action,
          payload.resource,
          payload.outcome,
          canonicalize(payload.metadata),
          payload.prevHash,
          hash,
        );

      this.db.exec('COMMIT');
      return { ...payload, hash };
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  get(seq: number): AuditEvent | undefined {
    const row = this.db.prepare('SELECT * FROM audit_events WHERE seq = ?').get(seq) as
      Row | undefined;
    return row ? toEvent(row) : undefined;
  }

  list(query: ListQuery): AuditEvent[] {
    const where: string[] = ['seq > ?'];
    const params: (string | number)[] = [query.afterSeq ?? 0];
    if (query.actor !== undefined) {
      where.push('actor = ?');
      params.push(query.actor);
    }
    if (query.action !== undefined) {
      where.push('action = ?');
      params.push(query.action);
    }
    params.push(query.limit);

    const rows = this.db
      .prepare(`SELECT * FROM audit_events WHERE ${where.join(' AND ')} ORDER BY seq ASC LIMIT ?`)
      .all(...params) as unknown as Row[];
    return rows.map(toEvent);
  }

  /** Streams the whole chain so verification stays O(1) in memory. */
  *iterateAll(): Generator<AuditEvent> {
    const stmt = this.db.prepare('SELECT * FROM audit_events ORDER BY seq ASC');
    for (const row of stmt.iterate()) {
      yield toEvent(row as unknown as Row);
    }
  }

  verify(): VerifyResult {
    return verifyChain(this.iterateAll(), this.hmacKey);
  }

  ping(): boolean {
    const row = this.db.prepare('SELECT 1 AS ok').get() as { ok: number } | undefined;
    return row?.ok === 1;
  }

  close(): void {
    this.db.close();
  }
}
