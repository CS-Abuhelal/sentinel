import type { AuditRecord } from "./types/contracts";

export const GENESIS = "0".repeat(64);

export type ChainCheck = { intact: true } | { intact: false; brokenAt: number };

export function canonical(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export async function recordHash(record: AuditRecord): Promise<string> {
  const { hash: _ignored, ...body } = record;
  const bytes = new TextEncoder().encode(canonical(body));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function verifyChain(records: AuditRecord[]): Promise<ChainCheck> {
  let previous = GENESIS;
  for (const [index, record] of records.entries()) {
    if (record.sequence !== index || record.prev_hash !== previous) return { intact: false, brokenAt: index };
    if ((await recordHash(record)) !== record.hash) return { intact: false, brokenAt: index };
    previous = record.hash;
  }
  return { intact: true };
}
