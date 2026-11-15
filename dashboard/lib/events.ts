import type { AuditEvent } from "./api";

export type EventBatch = {
  events: AuditEvent[];
  cursor: number;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function parseSequence(value: unknown): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : undefined;
}

function toAuditEvent(value: unknown, sequenceFromId?: number): AuditEvent | undefined {
  if (!isRecord(value)) return undefined;
  const sequence = parseSequence(value.sequence) ?? sequenceFromId;
  if (
    sequence === undefined
    || typeof value.action !== "string"
    || typeof value.decision !== "string"
    || typeof value.target !== "string"
    || typeof value.occurred_at !== "string"
    || !isRecord(value.metadata)
  ) {
    return undefined;
  }
  return {
    sequence,
    action: value.action,
    decision: value.decision,
    target: value.target,
    occurred_at: value.occurred_at,
    metadata: value.metadata,
  };
}

/** Parse one finite SSE response and return its replay cursor. */
export function parseEventStream(text: string, after = 0): EventBatch {
  const events: AuditEvent[] = [];
  let cursor = after;

  for (const block of text.split(/\r?\n\r?\n/)) {
    let id: number | undefined;
    const data: string[] = [];
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith("id:")) {
        const candidate = Number.parseInt(line.slice(3).trim(), 10);
        id = Number.isInteger(candidate) && candidate >= 0 ? candidate : undefined;
      } else if (line.startsWith("data:")) {
        data.push(line.slice(5).trimStart());
      }
    }
    if (data.length === 0) continue;

    try {
      const event = toAuditEvent(JSON.parse(data.join("\n")) as unknown, id);
      if (!event) continue;
      cursor = Math.max(cursor, event.sequence);
      if (event.sequence > after) events.push(event);
    } catch {
      // Ignore a malformed event so the next reconnect can resume at the last valid cursor.
    }
  }

  return { events: mergeEvents([], events), cursor };
}

export function mergeEvents(existing: AuditEvent[], incoming: AuditEvent[]): AuditEvent[] {
  const bySequence = new Map<number, AuditEvent>();
  for (const event of [...existing, ...incoming]) bySequence.set(event.sequence, event);
  return [...bySequence.values()].sort((left, right) => left.sequence - right.sequence);
}

/** Exponential backoff for finite snapshot reconnects, capped for offline clients. */
export function reconnectDelay(attempt: number, base = 1_000, maximum = 30_000): number {
  const safeAttempt = Math.max(0, Math.floor(attempt));
  return Math.min(maximum, base * (2 ** safeAttempt));
}
