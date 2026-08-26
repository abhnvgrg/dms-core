"use client";

import { ApiError, transferAsset } from "./api";

/**
 * Custody transfers prepared while offline.
 *
 * Each queued transfer is already signed and carries the custody status the
 * officer believed the item was in. That is what makes a late sync safe: if
 * someone else moved the item first, the backend rejects this one with 409 and
 * records the conflict, instead of quietly applying a second handover.
 */

const QUEUE_KEY = "dms_offline_transfers";

export interface QueuedTransfer {
  id: string;
  assetId: string;
  itemName: string;
  qrUuid: string;
  expected_prior_custody_status: string;
  new_custody_status: string;
  receiving_officer_badge_number: string;
  client_signature: string;
  mfaCode: string;
  queuedAt: string;
  lastError?: string;
  conflict?: boolean;
}

export function readQueue(): QueuedTransfer[] {
  if (typeof window === "undefined") return [];
  try {
    return JSON.parse(localStorage.getItem(QUEUE_KEY) ?? "[]") as QueuedTransfer[];
  } catch {
    return [];
  }
}

function writeQueue(items: QueuedTransfer[]) {
  localStorage.setItem(QUEUE_KEY, JSON.stringify(items));
}

export function enqueue(item: Omit<QueuedTransfer, "id" | "queuedAt">): QueuedTransfer {
  const entry: QueuedTransfer = {
    ...item,
    id: crypto.randomUUID(),
    queuedAt: new Date().toISOString(),
  };
  writeQueue([...readQueue(), entry]);
  return entry;
}

export function remove(id: string) {
  writeQueue(readQueue().filter((item) => item.id !== id));
}

function update(id: string, changes: Partial<QueuedTransfer>) {
  writeQueue(readQueue().map((item) => (item.id === id ? { ...item, ...changes } : item)));
}

export interface SyncOutcome {
  applied: number;
  conflicts: number;
  failed: number;
}

/**
 * Try to apply everything queued. Conflicts stay in the queue, flagged, so the
 * officer sees that their handover did not happen and why.
 */
export async function syncQueue(): Promise<SyncOutcome> {
  const outcome: SyncOutcome = { applied: 0, conflicts: 0, failed: 0 };

  for (const item of readQueue()) {
    if (item.conflict) {
      outcome.conflicts += 1;
      continue;
    }

    try {
      await transferAsset(
        item.assetId,
        {
          expected_prior_custody_status: item.expected_prior_custody_status,
          new_custody_status: item.new_custody_status,
          receiving_officer_badge_number: item.receiving_officer_badge_number,
          client_signature: item.client_signature,
        },
        item.mfaCode,
      );
      remove(item.id);
      outcome.applied += 1;
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        update(item.id, { conflict: true, lastError: err.message });
        outcome.conflicts += 1;
      } else {
        update(item.id, { lastError: err instanceof Error ? err.message : "Sync failed" });
        outcome.failed += 1;
      }
    }
  }

  return outcome;
}
