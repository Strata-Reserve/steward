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

import {
  agents,
  approvalQueue,
  getDb,
  protectedMinterControls,
  protectedMinterTokens,
  transactions,
} from "@stwd/db";
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
  /**
   * Hard shape validation (chain, value, target, selector, decoded arguments).
   * STRATA-1673 S1: `scope` lets the guard include the agent's active admitted
   * tokens (re-read at call time, so a revocation is immediate).
   */
  validateTransaction(
    tx: ProtectedTransactionShape,
    scope?: { tenantId: string; agentId: string },
  ): ProtectedValidation | Promise<ProtectedValidation>;

  /**
   * REVIEW-STEWARD-28-R5 N1: true only when `userId` is a pinned approver in
   * the installed manifest allowlist. Empty allowlist / unknown user => false.
   */
  isApprover(userId: string | null | undefined): boolean;
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
 *
 * REVIEW-STEWARD-28-R5 N1: the approving identity is verified here too, not
 * only at the HTTP route. The claim CAS additionally requires the row's
 * `approved_by_user_id` to be a pinned approver in the installed manifest
 * (via `guard.isApprover`). No guard, no approver or a non-allowlisted
 * approver refuses WITHOUT spending the durable claim.
 */
/**
 * STRATA-1673 S1: an optional executor lets the caller take the claim inside
 * the same DB transaction that inserted the read-back approval, so insert,
 * approval and claim commit (or roll back) together.
 */
type DbExecutor =
  | ReturnType<typeof getDb>
  | Parameters<Parameters<ReturnType<typeof getDb>["transaction"]>[0]>[0];

export async function issueProtectedSigningPermit(
  input: {
    tenantId: string;
    agentId: string;
    txId: string;
    reviewDigest: string;
  },
  executor?: DbExecutor,
): Promise<string> {
  const db = executor ?? getDb();
  const digest = input.reviewDigest.toLowerCase();

  const guard = registeredGuard;
  if (!guard || !guard.isProtected(input.tenantId, input.agentId)) {
    throw new ProtectedSignerError(
      "permit refused: no valid manifest covers this agent (no approver allowlist)",
    );
  }

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

  // The approving identity must be in the allowlist BEFORE the claim is
  // spent; a refused row must stay claimable by a legitimate re-approval.
  const [pre] = await db
    .select({
      status: approvalQueue.status,
      approvedByUserId: approvalQueue.approvedByUserId,
      approvalSource: approvalQueue.approvalSource,
      instructionDigest: approvalQueue.instructionDigest,
    })
    .from(approvalQueue)
    .where(and(eq(approvalQueue.txId, input.txId), eq(approvalQueue.agentId, input.agentId)));
  if (!pre || pre.status !== "approved") {
    throw new ProtectedSignerError("permit refused: no consumed approval for this transaction");
  }

  // STRATA-1673 S1 (JJ 2026-11-25 option 1): a row approved by a live Strata
  // read-back match. Accepted only with a recorded instruction digest, no
  // human approver on the row, and an unsuspended agent (re-read here).
  if (pre.approvalSource === "issuance_readback") {
    if (!pre.instructionDigest || !/^0x[0-9a-fA-F]{64}$/.test(pre.instructionDigest)) {
      throw new ProtectedSignerError(
        "permit refused: read-back approval has no instruction digest",
      );
    }
    if (pre.approvedByUserId) {
      throw new ProtectedSignerError("permit refused: read-back approval carries a human approver");
    }
    // STRATA-1673 H4: read through the same executor AND share-lock the
    // controls row (created if absent), so a concurrent suspend upsert is
    // serialized against this claim: it either commits first (seen here) or
    // waits for this transaction and then finds the claim.
    const control = await lockProtectedControls(db, input.tenantId, input.agentId);
    if (control?.at) {
      throw new ProtectedSignerError(
        "permit refused: protected minting is suspended for this agent",
      );
    }
    const readbackClaim = await db
      .update(approvalQueue)
      .set({ issuanceClaimedAt: new Date() })
      .where(
        and(
          eq(approvalQueue.txId, input.txId),
          eq(approvalQueue.agentId, input.agentId),
          eq(approvalQueue.status, "approved"),
          eq(approvalQueue.approvalSource, "issuance_readback"),
          eq(approvalQueue.instructionDigest, pre.instructionDigest),
          isNull(approvalQueue.approvedByUserId),
          isNull(approvalQueue.issuanceClaimedAt),
          sql`lower(${approvalQueue.reviewDigest}) = ${digest}`,
        ),
      )
      .returning({ id: approvalQueue.id });
    if (readbackClaim.length !== 1) {
      throw new ProtectedSignerError(
        "permit refused: a permit was already issued for this approval or the digest does not match; resolve via executionRef lookup",
      );
    }
    const handle = crypto.randomUUID();
    permits.set(handle, { ...input, expiresAt: Date.now() + PERMIT_TTL_MS });
    return handle;
  }

  const approver = pre.approvedByUserId ?? null;
  if (!approver) {
    throw new ProtectedSignerError("permit refused: approval has no recorded approver");
  }
  if (!guard.isApprover(approver)) {
    throw new ProtectedSignerError(
      "permit refused: recorded approver is not in the pinned manifest allowlist",
    );
  }

  // Atomic claim. Exactly one caller can move issuance_claimed_at NULL -> now
  // for an approved row with this digest AND the same allowlisted approver
  // (the row cannot be re-pointed at a different identity between the check
  // above and the claim).
  // STRATA-1673 (c): a read-back row handed off to the human queue keeps its
  // original claim; the human claim is then the one-use
  // `readbackHandoff.humanClaimedAt` (NULL -> now) on the same row.
  const claimed = await db
    .update(approvalQueue)
    .set({
      issuanceClaimedAt: sql`coalesce(${approvalQueue.issuanceClaimedAt}, now())`,
      reviewProjection: sql`CASE WHEN ${approvalQueue.issuanceClaimedAt} IS NULL THEN ${approvalQueue.reviewProjection} ELSE jsonb_set(${approvalQueue.reviewProjection}, '{readbackHandoff,humanClaimedAt}', to_jsonb(${new Date().toISOString()}::text)) END`,
    })
    .where(
      and(
        eq(approvalQueue.txId, input.txId),
        eq(approvalQueue.agentId, input.agentId),
        eq(approvalQueue.status, "approved"),
        eq(approvalQueue.approvedByUserId, approver),
        humanClaimable(),
        sql`${approvalQueue.approvalSource} IS DISTINCT FROM 'issuance_readback'`,
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
      approvedByUserId: approvalQueue.approvedByUserId,
    })
    .from(approvalQueue)
    .where(and(eq(approvalQueue.txId, input.txId), eq(approvalQueue.agentId, input.agentId)));
  if (!row || row.status !== "approved") {
    throw new ProtectedSignerError("permit refused: no consumed approval for this transaction");
  }
  if (row.approvedByUserId !== approver || !guard.isApprover(row.approvedByUserId)) {
    throw new ProtectedSignerError(
      "permit refused: recorded approver is not in the pinned manifest allowlist",
    );
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

/**
 * STRATA-1673 H1: resume a claimed protected issuance whose process was lost
 * BEFORE any signature was recorded. Does not touch the claim (it stays
 * spent); it only hands out a fresh one-use permit, and only when:
 *   - the transaction row is still `pending` with NO recorded signed bytes,
 *   - the approval is `approved` and claimed, and the claim is older than the
 *     permit TTL (the original permit can no longer be used),
 *   - the approval source is still valid (pinned human approver, or a
 *     read-back row with its digest).
 * Duplicate-safe by construction: the signer persists bytes with a CAS on
 * (status='pending' AND signed_raw IS NULL) BEFORE sending, so however many
 * resumes race, at most one signed transaction is ever recorded or sent.
 * Brakes are re-checked at key use (`authorizeProtectedKeyUse`).
 */
export async function issueProtectedResumePermit(input: {
  tenantId: string;
  agentId: string;
  txId: string;
  reviewDigest: string;
}): Promise<string | null> {
  const guard = registeredGuard;
  if (!guard || !guard.isProtected(input.tenantId, input.agentId)) return null;
  const db = getDb();
  const [tx] = await db
    .select({ status: transactions.status, signedRaw: transactions.signedRaw })
    .from(transactions)
    .where(
      and(
        eq(transactions.id, input.txId),
        eq(transactions.agentId, input.agentId),
        eq(transactions.tenantId, input.tenantId),
      ),
    );
  if (!tx || tx.status !== "pending" || tx.signedRaw) return null;
  const [q] = await db
    .select({
      status: approvalQueue.status,
      reviewDigest: approvalQueue.reviewDigest,
      issuanceClaimedAt: approvalQueue.issuanceClaimedAt,
      approvalSource: approvalQueue.approvalSource,
      approvedByUserId: approvalQueue.approvedByUserId,
      instructionDigest: approvalQueue.instructionDigest,
      reviewProjection: approvalQueue.reviewProjection,
    })
    .from(approvalQueue)
    .where(and(eq(approvalQueue.txId, input.txId), eq(approvalQueue.agentId, input.agentId)));
  if (!q || q.status !== "approved" || !q.issuanceClaimedAt) return null;
  if (!q.reviewDigest || q.reviewDigest.toLowerCase() !== input.reviewDigest.toLowerCase()) {
    return null;
  }
  // STRATA-1673 (c): after a handoff the live claim is the human re-claim.
  const claimAt = effectiveClaimAt(q.issuanceClaimedAt, q.reviewProjection);
  if (!claimAt || Date.now() - claimAt.getTime() <= PERMIT_TTL_MS) return null;
  if (q.approvalSource === "issuance_readback") {
    if (!q.instructionDigest || q.approvedByUserId) return null;
  } else if (!q.approvedByUserId || !guard.isApprover(q.approvedByUserId)) {
    return null;
  }
  const handle = crypto.randomUUID();
  permits.set(handle, { ...input, expiresAt: Date.now() + PERMIT_TTL_MS });
  return handle;
}

/**
 * STRATA-1673 (c): the claim a human may take on an approved row: the
 * original one (claim NULL) or, for a read-back row handed off to the human
 * queue, the one-use handoff re-claim.
 */
function humanClaimable() {
  return sql`(${approvalQueue.issuanceClaimedAt} IS NULL OR (${approvalQueue.reviewProjection} -> 'readbackHandoff' IS NOT NULL AND ${approvalQueue.reviewProjection} -> 'readbackHandoff' ->> 'humanClaimedAt' IS NULL))`;
}

/** The timestamp of the live claim: the handoff re-claim if any, else the original. */
export function effectiveClaimAt(
  claimedAt: Date | null,
  projection: Record<string, unknown> | null | undefined,
): Date | null {
  const h = projection?.readbackHandoff as { humanClaimedAt?: unknown } | undefined;
  if (h && typeof h === "object") {
    return typeof h.humanClaimedAt === "string" ? new Date(h.humanClaimedAt) : null;
  }
  return claimedAt;
}

/** Permit lifetime; a claim older than this cannot have a usable permit. */
export const PROTECTED_PERMIT_TTL_MS = PERMIT_TTL_MS;

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

/** Drop an unconsumed permit (e.g. its issuing DB transaction rolled back). */
export function discardProtectedSigningPermit(handle: string): void {
  permits.delete(handle);
}

/** Test/diagnostic helper: number of unconsumed permits. */
export function outstandingProtectedPermits(): number {
  return permits.size;
}

/**
 * STRATA-1673 H4: ensure the controls row exists and share-lock it. The
 * suspend/resume upsert takes the row lock, so every brake change is ordered
 * against claim and key-use transactions.
 */
async function lockProtectedControls(
  db: DbExecutor,
  tenantId: string,
  agentId: string,
): Promise<{ at: Date | null } | undefined> {
  await db.insert(protectedMinterControls).values({ tenantId, agentId }).onConflictDoNothing();
  const [control] = await db
    .select({ at: protectedMinterControls.protectedMintingSuspendedAt })
    .from(protectedMinterControls)
    .where(
      and(
        eq(protectedMinterControls.tenantId, tenantId),
        eq(protectedMinterControls.agentId, agentId),
      ),
    )
    .for("share");
  return control;
}

/**
 * STRATA-1673 H4: thrown when key use was refused by a brake BEFORE any
 * signature existed and the read-back approval was handed back to the human
 * queue (claim released in the same transaction that proved nothing was
 * signed). Callers must not mark the transaction failed.
 */
export class ProtectedKeyUseReleasedError extends ProtectedSignerError {
  readonly released = true;
}

const MINT_SELECTOR = "0x40c10f19";

/**
 * STRATA-1673 H4: the brakes, re-checked at key use under row locks.
 *
 * One transaction: share-lock the controls row, lock the approval row, and
 * share-lock the target token's admission row. Suspend (controls upsert)
 * and revoke (token upsert) conflict with these locks, so each brake either
 * committed before this check (and refuses here) or is ordered after it
 * (and the work is already-authorized, to be reconciled, never re-signed).
 *
 *  - revoked token -> refused for every approval source;
 *  - read-back row whose token has no active admission -> refused;
 *  - read-back row while suspended -> refused, and because nothing has been
 *    signed yet the row is returned to the existing human queue (claim
 *    cleared, readback approval removed) rather than stranded.
 */
export async function authorizeProtectedKeyUse(input: {
  tenantId: string;
  agentId: string;
  txId: string;
  chainId: number;
  to: string;
  data?: string | null;
}): Promise<void> {
  const outcome = await getDb().transaction(async (tx) => {
    const control = await lockProtectedControls(tx, input.tenantId, input.agentId);
    const [q] = await tx
      .select({
        id: approvalQueue.id,
        status: approvalQueue.status,
        approvalSource: approvalQueue.approvalSource,
        issuanceClaimedAt: approvalQueue.issuanceClaimedAt,
        resolvedAt: approvalQueue.resolvedAt,
        resolvedBy: approvalQueue.resolvedBy,
        instructionDigest: approvalQueue.instructionDigest,
      })
      .from(approvalQueue)
      .where(and(eq(approvalQueue.txId, input.txId), eq(approvalQueue.agentId, input.agentId)))
      .for("update");
    if (!q || q.status !== "approved" || !q.issuanceClaimedAt) {
      return { refuse: "no claimed approval for this transaction", released: false };
    }
    const readback = q.approvalSource === "issuance_readback";
    const isMint =
      typeof input.data === "string" && input.data.toLowerCase().startsWith(MINT_SELECTOR);
    if (isMint) {
      const [tok] = await tx
        .select({ status: protectedMinterTokens.status })
        .from(protectedMinterTokens)
        .where(
          and(
            eq(protectedMinterTokens.tenantId, input.tenantId),
            eq(protectedMinterTokens.agentId, input.agentId),
            eq(protectedMinterTokens.chainId, input.chainId),
            eq(protectedMinterTokens.tokenAddress, input.to.toLowerCase()),
          ),
        )
        .for("share");
      if (tok?.status === "revoked") {
        return { refuse: "token admission is revoked", released: false };
      }
      if (readback && tok?.status !== "active") {
        return { refuse: "read-back signing requires an active token admission", released: false };
      }
    }
    if (readback && control?.at) {
      await tx
        .update(approvalQueue)
        // STRATA-1673 (c): hand off to the human queue WITHOUT resetting the
        // claim. `issuance_claimed_at`, `instruction_digest`, `resolved_*`
        // keep the original read-back claim/audit identity; the handoff is
        // recorded on the same row. A later human approval re-claims through
        // `readbackHandoff.humanClaimedAt` (single use), never by clearing.
        .set({
          status: "pending",
          approvalSource: null,
          reviewProjection: sql`jsonb_set(coalesce(${approvalQueue.reviewProjection}, '{}'::jsonb), '{readbackHandoff}', ${JSON.stringify(
            {
              at: new Date().toISOString(),
              reason: "agent_suspended",
              from: "issuance_readback",
              claimedAt: q.issuanceClaimedAt.toISOString(),
              resolvedAt: q.resolvedAt?.toISOString() ?? null,
              resolvedBy: q.resolvedBy,
              instructionDigest: q.instructionDigest,
              humanClaimedAt: null,
            },
          )}::jsonb)`,
        })
        .where(eq(approvalQueue.id, q.id));
      return {
        refuse: "protected minting is suspended; returned to the human queue before key use",
        released: true,
      };
    }
    return null;
  });
  if (outcome?.released) throw new ProtectedKeyUseReleasedError(outcome.refuse);
  if (outcome) throw new ProtectedSignerError(outcome.refuse);
}
