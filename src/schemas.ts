import { Type, type Static } from 'typebox';

// Identifiers are restricted to a safe character set: keeps logs clean and
// stops control characters / log-injection payloads entering the audit trail.
const Identifier = (description: string) =>
  Type.String({ minLength: 1, maxLength: 128, pattern: '^[A-Za-z0-9._:/@-]+$', description });

export const NewEventBody = Type.Object(
  {
    action: Identifier('What happened, e.g. "payment.approve"'),
    resource: Identifier('What it happened to, e.g. "account/12345"'),
    outcome: Type.Union([Type.Literal('success'), Type.Literal('failure')]),
    metadata: Type.Optional(
      Type.Record(Type.String({ maxLength: 64 }), Type.Unknown(), {
        maxProperties: 32,
        description: 'Extra context (max 32 keys, 8 KB serialized)',
      }),
    ),
  },
  { additionalProperties: false },
);
export type NewEventBody = Static<typeof NewEventBody>;

export const AuditEventSchema = Type.Object({
  seq: Type.Integer(),
  timestamp: Type.String({ format: 'date-time' }),
  actor: Type.String(),
  action: Type.String(),
  resource: Type.String(),
  outcome: Type.Union([Type.Literal('success'), Type.Literal('failure')]),
  metadata: Type.Record(Type.String(), Type.Unknown()),
  prevHash: Type.String(),
  hash: Type.String(),
});

export const ListQuerySchema = Type.Object(
  {
    limit: Type.Integer({ minimum: 1, maximum: 500, default: 100 }),
    afterSeq: Type.Optional(Type.Integer({ minimum: 0 })),
    actor: Type.Optional(Type.String({ maxLength: 128 })),
    action: Type.Optional(Type.String({ maxLength: 128 })),
  },
  { additionalProperties: false },
);

export const SeqParams = Type.Object({ seq: Type.Integer({ minimum: 1 }) });

export const ListResponse = Type.Object({
  events: Type.Array(AuditEventSchema),
  nextAfterSeq: Type.Union([Type.Integer(), Type.Null()]),
});

export const VerifyResponse = Type.Object({
  valid: Type.Boolean(),
  checked: Type.Integer(),
  headSeq: Type.Union([Type.Integer(), Type.Null()]),
  headHash: Type.Union([Type.String(), Type.Null()]),
  brokenAt: Type.Optional(Type.Integer()),
  reason: Type.Optional(Type.String()),
});

export const ErrorResponse = Type.Object({
  error: Type.String(),
  message: Type.String(),
  requestId: Type.String(),
});
