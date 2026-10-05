/**
 * STRATA-1499 (SF-1): protected production-minter boundary, vault side.
 *
 * The vault is the last gate before key material is decrypted. A protected
 * signer (the dedicated production minter) may only ever be used through
 * `Vault.signTransaction` carrying a one-use internal signing permit that was
 * issued by the human-approval continuation in the API. Every other key use
 * (message, typed-data, EIP-7702 authorization, Solana, export, import) is
 * refused here regardless of which route or internal module calls the vault.
 *
 * The guard is registered by the API process (see
 * `packages/api/src/services/prod-minter-boundary.ts`). If no guard is
 * registered, NO persisted-protected agent may be used at all (fail closed):
 * the `agents.protected` column is an env-independent marker and the vault
 * refuses every operation on such an agent unless a guard recognises it.
 */

import { agents, approvalQueue, getDb, transactions } from "@stwd/db";
import { and, eq, isNull, sql } from "drizzle-orm";
import { keccak256, stringToHex } from "viem";

export interface ProtectedTransactionShape {
  chainId: number;
  to: string;
  value: string;
  data?: string | null;
}

export type ProtectedValidation = { ok: true } | { ok: false; reason: string };

export interface ProtectedSignerGuard {
  /** True when (tenantId, agentId) is the protected production minter. */
  isProtected(tenantId: string, agentId: string): boolean;
  /** Manifest-pinned EVM address of the protected signer, or null when not pinned. */
  expectedAddress(tenantId: string, agentId: string): string | null;
  /** Canonical digest of the deployment-controlled manifest. */
  manifestDigest(): string;
  /** Hard shape validation (chain, value, target, selector, decoded arguments). */
  validateTransaction(tx: ProtectedTransactionShape): ProtectedValidation;
}

let registeredGuard: ProtectedSignerGuard | null = null;

export function registerProtectedSignerGuard(guard: ProtectedSignerGuard | null): void {
  registeredGuard = guard;
}

export function getProtectedSignerGuard(): ProtectedSignerGuard | null {
  return registeredGuard;
}

export function isProtectedSigner(tenantId: string, agentId: string): boolean {
  return registeredGuard?.isProtected(tenantId, agentId) ?? false;
}

export class ProtectedSignerError extends Error {
  readonly code = "PROTECTED_SIGNER_REFUSED";
  constructor(message: string) {
    super(`Protected signer: ${message}`);
    this.name = "ProtectedSignerError";
  }
}

/** Throw unless the operation is permitted for a protected signer. Non-protected agents pass. */
export function assertNotProtected(tenantId: string, agentId: string, operation: string): void {
  if (isProtectedSigner(tenantId, agentId)) {
    throw new ProtectedSignerError(`${operation} is refused for the protected signer`);
  }
}

/**
 * Persisted marker check (REVIEW-STEWARD-28 F1). A row with `protected=true`
 * is refused for every key operation unless the installed guard recognises
 * it; a missing/invalid manifest therefore never un-protects a signer.
 */
export async function isPersistedProtected(tenantId: string, agentId: string): Promise<boolean> {
  return (await persistedProtectedRow(tenantId, agentId)) !== null;
}

/**
 * The persisted-protected row (marker + wallet address) for (tenantId, agentId),
 * or null when the row is absent or not protected.
 */
export async function persistedProtectedRow(
  tenantId: string,
  agentId: string,
): Promise<{ walletAddress: string } | null> {
  try {
    const [row] = await getDb()
      .select({ protected: agents.protected, walletAddress: agents.walletAddress })
      .from(agents)
      .where(and(eq(agents.id, agentId), eq(agents.tenantId, tenantId)));
    return row?.protected === true ? { walletAddress: row.walletAddress } : null;
  } catch (e) {
    // Pre-0029 schema: the marker column cannot exist, so no agent can be
    // persisted-protected. Any other error propagates (fail closed).
    if (isUndefinedColumn(e)) return null;
    throw e;
  }
}

/** Postgres 42703 (undefined_column), possibly wrapped by drizzle. */
export function isUndefinedColumn(e: unknown): boolean {
  let cur: unknown = e;
  for (let i = 0; i < 4 && cur && typeof cur === "object"; i++) {
    const code = (cur as { code?: unknown }).code;
    if (code === "42703") return true;
    cur = (cur as { cause?: unknown }).cause;
  }
  return false;
}

/**
 * REVIEW-STEWARD-28-R2 R2-2: a persisted-protected row is "covered" only when
 * the installed manifest names its tenant AND agent AND pins exactly its
 * persisted wallet address. Anything less is zero capability.
 */
export async function assertProtectedPostureIntact(
  tenantId: string,
  agentId: string,
  operation: string,
): Promise<void> {
  const row = await persistedProtectedRow(tenantId, agentId);
  if (!row) return; // ordinary agent (or not yet provisioned); route/vault checks apply
  if (!isProtectedSigner(tenantId, agentId)) {
    throw new ProtectedSignerError(
      `${operation} refused: agent is persisted-protected but no valid manifest is installed`,
    );
  }
  const expected = registeredGuard?.expectedAddress(tenantId, agentId) ?? null;
  if (!expected || expected.toLowerCase() !== row.walletAddress.toLowerCase()) {
    throw new ProtectedSignerError(
      `${operation} refused: persisted wallet address does not match the manifest pin`,
    );
  }
}

// ─── Review digest ───────────────────────────────────────────────────────────

export interface ReviewDigestInput {
  tenantId: string;
  agentId: string;
  signerAddress: string;
  chainId: number;
  to: string;
  value: string;
  data: string | null | undefined;
  executionRef: string;
  manifestDigest: string;
}

function normalizeData(data: string | null | undefined): string | null {
  if (data === undefined || data === null) return null;
  const lower = data.toLowerCase();
  if (lower === "" || lower === "0x") return null;
  return lower;
}

/**
 * Digest binding the exact immutable payload a human reviews. Canonical JSON
 * with a fixed key order, hashed with keccak256. Any change to any field
 * (including the manifest the payload was validated against) yields a
 * different digest, so a stale or substituted review can never be consumed.
 */
export function computeProtectedReviewDigest(input: ReviewDigestInput): `0x${string}` {
  const canonical = JSON.stringify({
    v: 1,
    tenantId: input.tenantId,
    agentId: input.agentId,
    signerAddress: input.signerAddress.toLowerCase(),
    chainId: input.chainId,
    to: input.to.toLowerCase(),
    value: BigInt(input.value).toString(),
    data: normalizeData(input.data),
    executionRef: input.executionRef,
    manifestDigest: input.manifestDigest.toLowerCase(),
  });
  return keccak256(stringToHex(canonical));
}

// ─── One-use internal signing permits ────────────────────────────────────────

interface Permit {
  tenantId: string;
  agentId: string;
  reviewDigest: string;
  expiresAt: number;
}

const PERMIT_TTL_MS = 60_000;
const permits = new Map<string, Permit>();

/**
 * Issued only by the human-approval continuation after the approval-queue
 * CAS succeeded. The returned handle is module-private state, never a caller
 * field or HTTP token; it is consumed exactly once by `consumeSigningPermit`.
 *
 * REVIEW-STEWARD-28-R2 R2-1: issuance itself is a durable single-use claim.
 * One approval row yields at most ONE permit, ever. The claim is taken by a
 * DB compare-and-set on `approval_queue.issuance_claimed_at` (NULL -> now)
 * conditioned on `status='approved'` and the exact review digest, in the
 * same statement, so two concurrent issuers get exactly one success. Once
 * claimed, the row is permanently spent: a signing that already happened,
 * is in flight, or failed after the claim never yields a fresh permit. A
 * lost/unknown outcome must be resolved by the executionRef status lookup,
 * never by re-issuing.
 */
export async function issueProtectedSigningPermit(input: {
  tenantId: string;
  agentId: string;
  txId: string;
  reviewDigest: string;
}): Promise<string> {
  const db = getDb();
  const digest = input.reviewDigest.toLowerCase();

  // Belt-and-braces: the transaction row itself must still be pending for
  // this tenant/agent. Any terminal or in-progress state refuses issuance
  // regardless of the queue row.
  const [tx] = await db
    .select({ status: transactions.status })
    .from(transactions)
    .where(
      and(
        eq(transactions.id, input.txId),
        eq(transactions.agentId, input.agentId),
        eq(transactions.tenantId, input.tenantId),
      ),
    );
  if (!tx) {
    throw new ProtectedSignerError("permit refused: no consumed approval for this transaction");
  }
  if (tx.status !== "pending") {
    throw new ProtectedSignerError(
      `permit refused: transaction already ${tx.status}; resolve via executionRef lookup`,
    );
  }

  // Atomic claim. Exactly one caller can move issuance_claimed_at NULL -> now
  // for an approved row with this digest.
  const claimed = await db
    .update(approvalQueue)
    .set({ issuanceClaimedAt: new Date() })
    .where(
      and(
        eq(approvalQueue.txId, input.txId),
        eq(approvalQueue.agentId, input.agentId),
        eq(approvalQueue.status, "approved"),
        isNull(approvalQueue.issuanceClaimedAt),
        sql`lower(${approvalQueue.reviewDigest}) = ${digest}`,
      ),
    )
    .returning({ id: approvalQueue.id });

  if (claimed.length === 1) {
    const handle = crypto.randomUUID();
    permits.set(handle, { ...input, expiresAt: Date.now() + PERMIT_TTL_MS });
    return handle;
  }

  // Diagnose (read-only) for an accurate refusal reason; every branch refuses.
  const [row] = await db
    .select({
      status: approvalQueue.status,
      reviewDigest: approvalQueue.reviewDigest,
      issuanceClaimedAt: approvalQueue.issuanceClaimedAt,
    })
    .from(approvalQueue)
    .where(and(eq(approvalQueue.txId, input.txId), eq(approvalQueue.agentId, input.agentId)));
  if (!row || row.status !== "approved") {
    throw new ProtectedSignerError("permit refused: no consumed approval for this transaction");
  }
  if (!row.reviewDigest || row.reviewDigest.toLowerCase() !== digest) {
    throw new ProtectedSignerError("permit refused: approval digest does not match");
  }
  if (row.issuanceClaimedAt) {
    throw new ProtectedSignerError(
      "permit refused: a permit was already issued for this approval; resolve via executionRef lookup",
    );
  }
  throw new ProtectedSignerError("permit refused: issuance claim lost");
}

/** Diagnostic: whether the one-time issuance claim for a txId has been taken. */
export async function isProtectedIssuanceClaimed(txId: string): Promise<boolean> {
  const [row] = await getDb()
    .select({ issuanceClaimedAt: approvalQueue.issuanceClaimedAt })
    .from(approvalQueue)
    .where(eq(approvalQueue.txId, txId));
  return Boolean(row?.issuanceClaimedAt);
}

export function consumeProtectedSigningPermit(
  handle: string | undefined,
  expected: { tenantId: string; agentId: string; reviewDigest: string },
): ProtectedValidation {
  if (!handle) return { ok: false, reason: "no signing permit" };
  const permit = permits.get(handle);
  permits.delete(handle); // one use, success or failure
  if (!permit) return { ok: false, reason: "unknown or already-consumed signing permit" };
  if (permit.expiresAt < Date.now()) return { ok: false, reason: "signing permit expired" };
  if (
    permit.tenantId !== expected.tenantId ||
    permit.agentId !== expected.agentId ||
    permit.reviewDigest.toLowerCase() !== expected.reviewDigest.toLowerCase()
  ) {
    return { ok: false, reason: "signing permit does not match the approved payload" };
  }
  return { ok: true };
}

/** Test/diagnostic helper: number of unconsumed permits. */
export function outstandingProtectedPermits(): number {
  return permits.size;
}
