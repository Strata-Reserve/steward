/**
 * Vault routes — transaction signing, approval/rejection, history, key import,
 * multi-wallet addresses, RPC passthrough, Solana signing, EIP-712 typed data.
 *
 * Mount: app.route("/vault", vaultRoutes)
 */

import { issueProtectedSigningPermit } from "@stwd/vault";
import { and, eq } from "drizzle-orm";
import { type Context, Hono } from "hono";
import { enforceRateLimit, recordVaultSpend } from "../middleware/redis-enforcement";
import { trackAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  approvalQueue,
  db,
  ensureAgentForTenant,
  extractRpcErrorMessage,
  getPolicySet,
  getTransactionStats,
  isNonEmptyString,
  isRpcError,
  isValidAddress,
  isValidAgentId,
  isValidAnyAddress,
  isValidSolanaAddress,
  policyEngine,
  priceOracle,
  type RpcRequest,
  type RpcResponse,
  requireAgentAccess,
  requireHumanOwnerAdmin,
  requireTenantLevel,
  type SignRequest,
  type SignTypedDataRequest,
  safeJsonParse,
  sanitizeErrorMessage,
  toSignRequest,
  toTxRecord,
  transactions,
  vault,
} from "../services/context";
import {
  getProtectedMinterManifest,
  getProtectedMinterManifestDigest,
  isProtectedMinter,
  protectedReviewDigest,
  validateProtectedShape,
} from "../services/prod-minter-boundary";
import { dispatchWebhook } from "../services/webhook-dispatch";

export const vaultRoutes = new Hono<{ Variables: AppVariables }>();

// ─── Protected production minter (STRATA-1499 SF-1) ────────────────────────────
//
// For the manifest-protected signer every valid proposal queues; nothing is
// ever auto-signed. The queue entry freezes a review digest over the exact
// immutable payload plus the manifest digest. Only a verified human
// owner/admin session can consume the approval (CAS), after which the stored
// payload is re-validated, its digest recomputed and compared, and a one-use
// internal permit is handed to the vault which rechecks everything again
// before key use.

const PROTECTED_SIGN_FIELDS = new Set([
  "to",
  "value",
  "data",
  "chainId",
  "executionRef",
  "broadcast",
]);

function protectedRefused(
  c: Context<{ Variables: AppVariables }>,
  error: string,
  status: 403 | 400 = 403,
) {
  return c.json<ApiResponse>({ ok: false, error: `Protected signer: ${error}` }, status);
}

/** Caller may propose for the protected signer: its own agent JWT, or a human owner/admin session. */
function protectedProposerIdentity(
  c: Context<{ Variables: AppVariables }>,
  agentId: string,
): string | null {
  const authType = c.get("authType");
  if (authType === "agent-token" && c.get("agentScope") === agentId) return `agent:${agentId}`;
  const userId = requireHumanOwnerAdmin(c);
  if (userId) return `user:${userId}`;
  return null;
}

async function handleProtectedSign(
  c: Context<{ Variables: AppVariables }>,
  tenantId: string,
  agentId: string,
  rawRequest: Record<string, unknown>,
  executionRef: string | undefined,
  requestedBy: string,
) {
  for (const key of Object.keys(rawRequest)) {
    if (!PROTECTED_SIGN_FIELDS.has(key)) {
      return protectedRefused(c, `unknown request field '${key}' is refused`, 400);
    }
  }
  if (rawRequest.broadcast !== undefined && rawRequest.broadcast !== true) {
    return protectedRefused(
      c,
      "broadcast:false is refused (no signed raw transaction is released)",
    );
  }
  if (!executionRef) {
    return protectedRefused(c, "executionRef is required", 400);
  }
  if (rawRequest.chainId !== 8453) {
    return protectedRefused(c, "chainId must be exactly 8453");
  }
  const manifest = getProtectedMinterManifest();
  if (!manifest) return protectedRefused(c, "manifest not installed");

  const to = String(rawRequest.to);
  const value = String(rawRequest.value);
  const data = typeof rawRequest.data === "string" ? rawRequest.data : undefined;
  const chainId = 8453;

  const incoming = normalizeSignPayload({ to, value, data, chainId });
  const existing = await findByExecutionRef(tenantId, agentId, executionRef);
  if (existing) return replayExistingAction(c, existing, incoming);

  const shape = validateProtectedShape(manifest, { chainId, to, value, data, executionRef });
  if (!shape.ok) {
    trackAuditEvent({
      tenantId,
      actorType: "agent",
      actorId: agentId,
      action: "vault.sign.protected_refused",
      resourceType: "agent",
      resourceId: agentId,
      metadata: {
        chainId,
        to,
        value,
        data: data ?? null,
        executionRef,
        reason: shape.reason,
        requestedBy,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
    return protectedRefused(c, shape.reason);
  }

  const reviewDigest = protectedReviewDigest({
    tenantId,
    agentId,
    chainId,
    to,
    value,
    data,
    executionRef,
  });
  const manifestDigest = getProtectedMinterManifestDigest();
  const txId = crypto.randomUUID();
  const queueId = crypto.randomUUID();

  const inserted = await db.transaction(async (tx) => {
    const rows = await tx
      .insert(transactions)
      .values({
        id: txId,
        agentId,
        tenantId,
        executionRef,
        status: "pending",
        toAddress: to,
        value,
        data,
        chainId,
        policyResults: [],
      })
      .onConflictDoNothing({
        target: [transactions.tenantId, transactions.agentId, transactions.executionRef],
      })
      .returning({ id: transactions.id });
    if (rows.length === 0) return false;
    await tx.insert(approvalQueue).values({
      id: queueId,
      txId,
      agentId,
      status: "pending",
      reviewDigest,
      manifestDigest,
      reviewProjection: shape.projection as unknown as Record<string, unknown>,
      requestedBy,
    });
    return true;
  });
  if (!inserted) {
    const winner = await findByExecutionRef(tenantId, agentId, executionRef);
    if (!winner) {
      return c.json<ApiResponse>(
        { ok: false, error: "Execution reference reservation failed; retry" },
        503,
      );
    }
    return replayExistingAction(c, winner, incoming);
  }

  trackAuditEvent({
    tenantId,
    actorType: "agent",
    actorId: agentId,
    action: "vault.sign.protected_queued",
    resourceType: "transaction",
    resourceId: txId,
    metadata: {
      queueId,
      executionRef,
      reviewDigest,
      manifestDigest,
      requestedBy,
      review: shape.projection,
    },
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });
  dispatchWebhook(tenantId, agentId, "approval_required", { txId, executionRef, reviewDigest });

  return c.json<ApiResponse>(
    {
      ok: false,
      error: "Transaction requires manual approval",
      data: {
        txId,
        executionRef,
        status: "pending_approval",
        results: [],
        reviewDigest,
        manifestDigest,
        review: shape.projection,
      },
    },
    202,
  );
}

type QueueRow = typeof approvalQueue.$inferSelect;

async function handleProtectedApprove(
  c: Context<{ Variables: AppVariables }>,
  tenantId: string,
  agentId: string,
  txId: string,
) {
  const userId = requireHumanOwnerAdmin(c);
  if (!userId) {
    return protectedRefused(c, "approval requires an authenticated human owner/admin session");
  }
  const body = await safeJsonParse<{ reviewDigest?: unknown }>(c);
  const echoed = typeof body?.reviewDigest === "string" ? body.reviewDigest.toLowerCase() : null;
  if (!echoed) return protectedRefused(c, "approval must echo the reviewed 'reviewDigest'", 400);

  const [row] = await db
    .select({ transaction: transactions, queue: approvalQueue })
    .from(transactions)
    .innerJoin(approvalQueue, eq(approvalQueue.txId, transactions.id))
    .where(
      and(
        eq(transactions.id, txId),
        eq(transactions.agentId, agentId),
        eq(transactions.tenantId, tenantId),
        eq(approvalQueue.agentId, agentId),
      ),
    );
  if (!row) return c.json<ApiResponse>({ ok: false, error: "Transaction not found" }, 404);
  const transaction = row.transaction;
  const queue: QueueRow = row.queue;

  if (queue.requestedBy === `user:${userId}`) {
    return protectedRefused(c, "requester cannot approve their own proposal");
  }
  if (!queue.reviewDigest || !queue.manifestDigest || !transaction.executionRef) {
    return protectedRefused(c, "queue entry lacks a frozen review digest");
  }
  if (queue.manifestDigest.toLowerCase() !== getProtectedMinterManifestDigest().toLowerCase()) {
    return protectedRefused(c, "manifest changed since this proposal was reviewed; re-propose");
  }
  if (queue.reviewDigest.toLowerCase() !== echoed) {
    return protectedRefused(c, "echoed reviewDigest does not match the pending review");
  }
  // Recompute from the stored immutable payload: any substitution after
  // queueing (DB edit, replaced row) changes the digest and is refused.
  const recomputed = protectedReviewDigest({
    tenantId,
    agentId,
    chainId: transaction.chainId,
    to: transaction.toAddress,
    value: transaction.value,
    data: transaction.data,
    executionRef: transaction.executionRef,
  });
  if (recomputed.toLowerCase() !== queue.reviewDigest.toLowerCase()) {
    return protectedRefused(c, "stored payload no longer matches the reviewed digest");
  }
  const manifest = getProtectedMinterManifest();
  if (!manifest) return protectedRefused(c, "manifest not installed");
  const shape = validateProtectedShape(manifest, {
    chainId: transaction.chainId,
    to: transaction.toAddress,
    value: transaction.value,
    data: transaction.data,
    executionRef: transaction.executionRef,
  });
  if (!shape.ok) return protectedRefused(c, `stored payload fails current scope: ${shape.reason}`);

  const resolvedAt = new Date();
  const claim = await db
    .update(approvalQueue)
    .set({ status: "approved", resolvedAt, resolvedBy: `user:${userId}`, approvedByUserId: userId })
    .where(
      and(
        eq(approvalQueue.id, queue.id),
        eq(approvalQueue.txId, txId),
        eq(approvalQueue.status, "pending"),
        eq(approvalQueue.reviewDigest, queue.reviewDigest),
      ),
    )
    .returning({ id: approvalQueue.id });
  if (claim.length === 0) {
    return c.json<ApiResponse>(
      { ok: false, error: "Transaction already processed or not found" },
      409,
    );
  }

  trackAuditEvent({
    tenantId,
    actorType: "user",
    actorId: userId,
    action: "vault.approve.protected_claimed",
    resourceType: "transaction",
    resourceId: txId,
    metadata: {
      agentId,
      executionRef: transaction.executionRef,
      reviewDigest: queue.reviewDigest,
      review: shape.projection,
    },
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });

  try {
    const permit = await issueProtectedSigningPermit({
      tenantId,
      agentId,
      txId,
      reviewDigest: queue.reviewDigest,
    });
    const txHash = await vault.signTransaction(
      { ...toSignRequest(transaction), tenantId, broadcast: true },
      {
        txId,
        policyResults: transaction.policyResults,
        status: "signed",
        protectedPermit: permit,
        protectedReviewDigest: queue.reviewDigest,
      },
    );
    await db
      .update(transactions)
      .set({ status: "signed", txHash, signedAt: resolvedAt })
      .where(eq(transactions.id, txId));
    trackAuditEvent({
      tenantId,
      actorType: "user",
      actorId: userId,
      action: "vault.approve",
      resourceType: "transaction",
      resourceId: txId,
      metadata: {
        agentId,
        chainId: transaction.chainId,
        txHash,
        reviewDigest: queue.reviewDigest,
        protected: true,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
    dispatchWebhook(tenantId, agentId, "tx_signed", { txId, txHash });
    return c.json<ApiResponse<{ txId: string; txHash: string; executionRef: string }>>({
      ok: true,
      data: { txId, txHash, executionRef: transaction.executionRef },
    });
  } catch (e: unknown) {
    // Same fail-closed rule as #24: the claim is consumed and never released.
    const requestId = c.get("requestId") || "unknown";
    const rawMessage = e instanceof Error ? e.message : "Unknown error";
    console.error(`[${requestId}] Protected approve failed for agent ${agentId}, tx ${txId}:`, e);
    await db
      .update(transactions)
      .set({ status: "failed" })
      .where(and(eq(transactions.id, txId), eq(transactions.status, "pending")))
      .catch((updateErr) =>
        console.error(`[${requestId}] Failed to mark approved tx ${txId} failed:`, updateErr),
      );
    dispatchWebhook(tenantId, agentId, "tx_failed", {
      txId,
      executionRef: transaction.executionRef,
      error: rawMessage,
      requestId,
    });
    if (isRpcError(e)) {
      return c.json<ApiResponse>({ ok: false, error: extractRpcErrorMessage(e) }, 502);
    }
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
}

// ─── Execution reference (STRATA-1486) ───────────────────────────────────────
//
// A caller may attach a stable, opaque `executionRef` (body field, or the
// `Idempotency-Key` header) to POST /:agentId/sign. The reference is scoped to
// (tenant, agent) and backed by a DB unique index, so a duplicate request can
// never create a second independently executable action:
//   - same ref + same payload  → the existing action is returned, nothing is signed
//   - same ref + other payload → 409, nothing is signed
// The reference is NOT a policy input and never changes evaluation outcomes.

const EXECUTION_REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$/;

export function isValidExecutionRef(value: unknown): value is string {
  return typeof value === "string" && EXECUTION_REF_PATTERN.test(value);
}

type ExecutionRefResolution = { ok: true; executionRef?: string } | { ok: false; error: string };

function resolveExecutionRef(
  headerValue: string | undefined,
  bodyValue: unknown,
): ExecutionRefResolution {
  const fromHeader = headerValue?.trim() || undefined;
  const fromBody = bodyValue === undefined || bodyValue === null ? undefined : bodyValue;
  if (fromBody !== undefined && typeof fromBody !== "string") {
    return { ok: false, error: "'executionRef' must be a string" };
  }
  if (fromHeader !== undefined && fromBody !== undefined && fromHeader !== fromBody) {
    return {
      ok: false,
      error: "'executionRef' and Idempotency-Key header must match when both are present",
    };
  }
  const candidate = fromBody ?? fromHeader;
  if (candidate === undefined) return { ok: true };
  if (!isValidExecutionRef(candidate)) {
    return {
      ok: false,
      error:
        "'executionRef' must be 1-128 chars of [A-Za-z0-9_.:@-] and start with an alphanumeric",
    };
  }
  return { ok: true, executionRef: candidate };
}

interface NormalizedSignPayload {
  to: string;
  value: string;
  data: string | null;
  chainId: number;
}

function normalizeSignPayload(input: {
  to: string;
  value: string;
  data?: string | null;
  chainId: number;
}): NormalizedSignPayload {
  const to = input.to.startsWith("0x") ? input.to.toLowerCase() : input.to;
  let value = String(input.value);
  try {
    value = BigInt(value).toString();
  } catch {
    // leave as-is; a malformed value fails later in signing exactly as before
  }
  const rawData = input.data ?? null;
  const data =
    rawData === null || rawData === "" || rawData === "0x" ? null : rawData.toLowerCase();
  return { to, value, data, chainId: input.chainId };
}

function samePayload(a: NormalizedSignPayload, b: NormalizedSignPayload): boolean {
  return a.to === b.to && a.value === b.value && a.data === b.data && a.chainId === b.chainId;
}

type TransactionRow = typeof transactions.$inferSelect;

async function findByExecutionRef(
  tenantId: string,
  agentId: string,
  executionRef: string,
): Promise<TransactionRow | undefined> {
  const [row] = await db
    .select()
    .from(transactions)
    .where(
      and(
        eq(transactions.tenantId, tenantId),
        eq(transactions.agentId, agentId),
        eq(transactions.executionRef, executionRef),
      ),
    );
  return row;
}

/**
 * Externally visible status of an action created via executionRef.
 * A "pending" row without an approval-queue entry is a reservation whose
 * original request is still in flight (policy evaluation or signing).
 */
async function resolveActionStatus(
  row: TransactionRow,
): Promise<"processing" | "pending_approval" | TransactionRow["status"]> {
  if (row.status !== "pending") return row.status;
  const [queueEntry] = await db
    .select({ id: approvalQueue.id })
    .from(approvalQueue)
    .where(eq(approvalQueue.txId, row.id));
  return queueEntry ? "pending_approval" : "processing";
}

function actionView(row: TransactionRow, status: string) {
  return {
    txId: row.id,
    executionRef: row.executionRef ?? undefined,
    status,
    txHash: row.txHash ?? undefined,
    chainId: row.chainId,
    to: row.toAddress,
    value: row.value,
    data: row.data ?? undefined,
    policyResults: row.policyResults ?? [],
    createdAt: row.createdAt,
    signedAt: row.signedAt ?? undefined,
    confirmedAt: row.confirmedAt ?? undefined,
  };
}

/**
 * Replay the response for an existing action found under the caller's
 * executionRef. Never signs. Status codes mirror the original outcome so
 * callers can treat the replay exactly like the first response.
 */
async function replayExistingAction(
  c: Context<{ Variables: AppVariables }>,
  row: TransactionRow,
  incoming: NormalizedSignPayload,
) {
  const stored = normalizeSignPayload({
    to: row.toAddress,
    value: row.value,
    data: row.data,
    chainId: row.chainId,
  });
  if (!samePayload(stored, incoming)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "executionRef already used for a different transaction payload",
        data: { txId: row.id, executionRef: row.executionRef, status: "conflict" },
      },
      409,
    );
  }

  const status = await resolveActionStatus(row);
  c.header("Idempotency-Replayed", "true");
  const view = { ...actionView(row, status), replayed: true };

  switch (status) {
    case "pending_approval":
      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Transaction requires manual approval",
          data: { ...view, results: row.policyResults ?? [] },
        },
        202,
      );
    case "processing":
      return c.json<ApiResponse>(
        { ok: false, error: "Transaction is still being processed", data: view },
        202,
      );
    case "rejected":
      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Transaction rejected by policy",
          data: { ...view, results: row.policyResults ?? [] },
        },
        403,
      );
    case "failed":
      return c.json<ApiResponse>(
        { ok: false, error: "Transaction signing failed", data: view },
        500,
      );
    default:
      // signed / broadcast / confirmed / approved: the action exists and is
      // (or is about to be) on chain. Return it; never sign again.
      return c.json<ApiResponse>({ ok: true, data: view }, 200);
  }
}

// ─── Sign transaction (EVM) ───────────────────────────────────────────────────

vaultRoutes.post("/:agentId/sign", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const protectedMinter = isProtectedMinter(tenantId, agentId);
  let protectedRequester: string | null = null;
  if (protectedMinter) {
    protectedRequester = protectedProposerIdentity(c, agentId);
    if (!protectedRequester) {
      return protectedRefused(
        c,
        "only the signer's own agent token or a human owner/admin session may propose",
      );
    }
  }

  const request = await safeJsonParse<Omit<SignRequest, "agentId" | "tenantId">>(c);
  if (!request) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isNonEmptyString(request.to)) {
    return c.json<ApiResponse>({ ok: false, error: "'to' address is required" }, 400);
  }
  if (!isValidAnyAddress(request.to)) {
    const errMsg = request.to.startsWith("0x")
      ? "'to' must be a valid Ethereum address (0x + 40 hex chars)"
      : "'to' must be a valid Ethereum address (0x + 40 hex chars) or a valid Solana address (base58, 32–44 chars)";
    return c.json<ApiResponse>({ ok: false, error: errMsg }, 400);
  }
  if (request.value === undefined || request.value === null) {
    return c.json<ApiResponse>(
      { ok: false, error: "'value' is required (wei amount as string)" },
      400,
    );
  }

  const refResolution = resolveExecutionRef(
    c.req.header("Idempotency-Key"),
    (request as { executionRef?: unknown }).executionRef,
  );
  if (!refResolution.ok) {
    return c.json<ApiResponse>({ ok: false, error: refResolution.error }, 400);
  }
  const executionRef = refResolution.executionRef;

  if (protectedMinter && protectedRequester) {
    return handleProtectedSign(
      c,
      tenantId,
      agentId,
      request as unknown as Record<string, unknown>,
      executionRef,
      protectedRequester,
    );
  }

  const resolvedChainId = request.chainId || parseInt(process.env.CHAIN_ID || "8453", 10);
  const signRequest: SignRequest = {
    ...request,
    tenantId,
    agentId,
    chainId: resolvedChainId,
    ...(executionRef ? { executionRef } : {}),
  };
  const incomingPayload = normalizeSignPayload({
    to: signRequest.to,
    value: String(signRequest.value),
    data: signRequest.data,
    chainId: resolvedChainId,
  });

  // Fast path: an action already exists under this reference → replay it
  // without consuming rate limit, evaluating policy or signing.
  if (executionRef) {
    const existing = await findByExecutionRef(tenantId, agentId, executionRef);
    if (existing) return replayExistingAction(c, existing, incomingPayload);
  }

  const policySet = await getPolicySet(tenantId, agentId);

  // ── Redis rate-limit check (before policy evaluation) ──────────────────────
  const rateLimitResult = await enforceRateLimit(agentId, policySet);
  if (!rateLimitResult.allowed) {
    if (rateLimitResult.headers) {
      for (const [key, value] of Object.entries(rateLimitResult.headers)) {
        c.header(key, value);
      }
    }
    return c.json<ApiResponse>(
      { ok: false, error: rateLimitResult.reason || "Rate limit exceeded" },
      429,
    );
  }
  // Set rate limit headers on success too
  if (rateLimitResult.headers) {
    for (const [key, value] of Object.entries(rateLimitResult.headers)) {
      c.header(key, value);
    }
  }

  // Reserve the reference BEFORE any signing. The DB unique index on
  // (tenant_id, agent_id, execution_ref) is the arbiter: exactly one of N
  // concurrent identical requests inserts; the rest observe the winner's row.
  const txId = crypto.randomUUID();
  let reserved = false;
  if (executionRef) {
    const inserted = await db
      .insert(transactions)
      .values({
        id: txId,
        agentId,
        tenantId,
        executionRef,
        status: "pending",
        toAddress: signRequest.to,
        value: String(signRequest.value),
        data: signRequest.data,
        chainId: resolvedChainId,
        policyResults: [],
      })
      .onConflictDoNothing({
        target: [transactions.tenantId, transactions.agentId, transactions.executionRef],
      })
      .returning({ id: transactions.id });
    if (inserted.length === 0) {
      const winner = await findByExecutionRef(tenantId, agentId, executionRef);
      if (!winner) {
        return c.json<ApiResponse>(
          { ok: false, error: "Execution reference reservation failed; retry" },
          503,
        );
      }
      return replayExistingAction(c, winner, incomingPayload);
    }
    reserved = true;
  }

  const stats = await getTransactionStats(agentId);

  const evaluation = await policyEngine.evaluate(policySet, {
    request: signRequest,
    recentTxCount1h: stats.recentTxCount1h,
    recentTxCount24h: stats.recentTxCount24h,
    spentToday: stats.spentToday,
    spentThisWeek: stats.spentThisWeek,
    priceOracle,
  });

  if (!evaluation.approved) {
    if (evaluation.requiresManualApproval) {
      await db.transaction(async (tx) => {
        if (reserved) {
          await tx
            .update(transactions)
            .set({ policyResults: evaluation.results })
            .where(eq(transactions.id, txId));
        } else {
          await tx.insert(transactions).values({
            id: txId,
            agentId,
            status: "pending",
            toAddress: signRequest.to,
            value: signRequest.value,
            data: signRequest.data,
            chainId: signRequest.chainId,
            policyResults: evaluation.results,
          });
        }
        await tx.insert(approvalQueue).values({
          id: crypto.randomUUID(),
          txId,
          agentId,
          status: "pending",
        });
      });

      trackAuditEvent({
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: "vault.sign.queued_for_approval",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId: signRequest.chainId,
          to: signRequest.to,
          value: signRequest.value,
          policyResults: evaluation.results,
        },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });

      dispatchWebhook(tenantId, agentId, "approval_required", {
        txId,
        results: evaluation.results,
      });

      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Transaction requires manual approval",
          data: {
            txId,
            ...(executionRef ? { executionRef } : {}),
            results: evaluation.results,
            status: "pending_approval",
          },
        },
        202,
      );
    }

    if (reserved) {
      await db
        .update(transactions)
        .set({ status: "rejected", policyResults: evaluation.results })
        .where(eq(transactions.id, txId));
    } else {
      await db.insert(transactions).values({
        id: txId,
        agentId,
        status: "rejected",
        toAddress: signRequest.to,
        value: signRequest.value,
        data: signRequest.data,
        chainId: signRequest.chainId,
        policyResults: evaluation.results,
      });
    }

    trackAuditEvent({
      tenantId,
      actorType: "agent",
      actorId: agentId,
      action: "vault.sign.rejected_by_policy",
      resourceType: "transaction",
      resourceId: txId,
      metadata: {
        chainId: signRequest.chainId,
        to: signRequest.to,
        value: signRequest.value,
        policyResults: evaluation.results,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    dispatchWebhook(tenantId, agentId, "tx_rejected", {
      txId,
      results: evaluation.results,
    });

    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction rejected by policy",
        data: {
          txId,
          ...(executionRef ? { executionRef } : {}),
          results: evaluation.results,
        },
      },
      403,
    );
  }

  try {
    const shouldBroadcast = signRequest.broadcast !== false;
    const result = await vault.signTransaction(signRequest, {
      txId,
      policyResults: evaluation.results,
      status: "signed",
    });

    await db
      .update(transactions)
      .set({
        status: "signed",
        txHash: shouldBroadcast ? result : undefined,
        policyResults: evaluation.results,
        signedAt: new Date(),
      })
      .where(eq(transactions.id, txId));

    // ── Record spend in Redis (fire-and-forget) ──────────────────────────────
    recordVaultSpend(agentId, tenantId, signRequest.value, resolvedChainId).catch((err) =>
      console.error("[vault] Failed to record spend:", err),
    );

    trackAuditEvent({
      tenantId,
      actorType: "agent",
      actorId: agentId,
      action: "vault.sign",
      resourceType: "transaction",
      resourceId: txId,
      metadata: {
        chainId: resolvedChainId,
        to: signRequest.to,
        value: signRequest.value,
        broadcast: shouldBroadcast,
        txHash: shouldBroadcast ? result : undefined,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    dispatchWebhook(tenantId, agentId, "tx_signed", {
      txId,
      txHash: shouldBroadcast ? result : undefined,
    });

    if (shouldBroadcast) {
      return c.json<ApiResponse<{ txId: string; txHash: string; executionRef?: string }>>({
        ok: true,
        data: { txId, txHash: result, ...(executionRef ? { executionRef } : {}) },
      });
    }

    return c.json<ApiResponse<{ txId: string; signedTx: string; executionRef?: string }>>({
      ok: true,
      data: { txId, signedTx: result, ...(executionRef ? { executionRef } : {}) },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    const rawMessage = e instanceof Error ? e.message : "Unknown error";
    console.error(`[${requestId}] Sign transaction failed for agent ${agentId}:`, e);

    if (reserved) {
      // The reservation stays bound to this reference as a terminal failure.
      // A replay reports "failed"; it never re-signs under the same reference,
      // because an RPC error after broadcast is indeterminate on our side.
      await db
        .update(transactions)
        .set({ status: "failed", policyResults: evaluation.results })
        .where(and(eq(transactions.id, txId), eq(transactions.status, "pending")))
        .catch((updateErr) =>
          console.error(`[${requestId}] Failed to mark reserved tx ${txId} failed:`, updateErr),
        );
    }

    dispatchWebhook(tenantId, agentId, "tx_failed", {
      txId,
      ...(executionRef ? { executionRef } : {}),
      error: rawMessage,
      requestId,
    });

    if (isRpcError(e)) {
      return c.json<ApiResponse>({ ok: false, error: extractRpcErrorMessage(e) }, 502);
    }
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Approve transaction ──────────────────────────────────────────────────────

vaultRoutes.post("/:agentId/approve/:txId", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction approval requires tenant-level authentication",
      },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const txId = c.req.param("txId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  if (isProtectedMinter(tenantId, agentId)) {
    return handleProtectedApprove(c, tenantId, agentId, txId);
  }

  const [transaction] = await db
    .select()
    .from(transactions)
    .where(and(eq(transactions.id, txId), eq(transactions.agentId, agentId)));
  if (!transaction) {
    return c.json<ApiResponse>({ ok: false, error: "Transaction not found" }, 404);
  }

  const resolvedAt = new Date();
  const claimResult = await db
    .update(approvalQueue)
    .set({ status: "approved", resolvedAt, resolvedBy: tenantId })
    .where(
      and(
        eq(approvalQueue.txId, txId),
        eq(approvalQueue.agentId, agentId),
        eq(approvalQueue.status, "pending"),
      ),
    )
    .returning();

  if (claimResult.length === 0) {
    return c.json<ApiResponse>(
      { ok: false, error: "Transaction already processed or not found" },
      409,
    );
  }

  try {
    const isSolana = transaction.chainId === 101 || transaction.chainId === 102;
    let txHash: string;

    if (isSolana) {
      if (!transaction.data) {
        return c.json<ApiResponse>(
          {
            ok: false,
            error: "Solana transaction blob not found — cannot replay approval",
          },
          500,
        );
      }
      const result = await vault.signSolanaTransaction({
        agentId,
        tenantId,
        transaction: transaction.data,
        chainId: transaction.chainId,
        broadcast: true,
      });
      txHash = result.signature;
    } else {
      txHash = await vault.signTransaction(
        { ...toSignRequest(transaction), tenantId },
        { txId, policyResults: transaction.policyResults, status: "signed" },
      );
    }

    await db
      .update(transactions)
      .set({ status: "signed", txHash, signedAt: resolvedAt })
      .where(eq(transactions.id, txId));

    trackAuditEvent({
      tenantId,
      actorType: "user",
      actorId: tenantId,
      action: "vault.approve",
      resourceType: "transaction",
      resourceId: txId,
      metadata: { agentId, chainId: transaction.chainId, txHash },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    dispatchWebhook(tenantId, agentId, "tx_signed", { txId, txHash });

    return c.json<ApiResponse<{ txId: string; txHash: string }>>({
      ok: true,
      data: { txId, txHash },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    const rawMessage = e instanceof Error ? e.message : "Unknown error";
    console.error(`[${requestId}] Approve transaction failed for agent ${agentId}, tx ${txId}:`, e);

    // STRATA-1499: fail closed. The approval claim has been consumed and the
    // broadcaster was invoked; an RPC can accept a transaction and still
    // throw, so a thrown error here is NOT proof that nothing was broadcast.
    // The claim is therefore never released back to `pending` and the row is
    // bound to a terminal, hashless `failed` state that only lookup /
    // reconciliation reads. A second approval hits the 409 claim guard and a
    // /sign replay under the same executionRef reports `failed`; neither can
    // sign. There is no provable pre-broadcast boundary inside this try: the
    // vault call is a single opaque step that may have reached the RPC, and
    // every earlier step is a DB read/decrypt we cannot distinguish from here.
    // The status update is a CAS on `pending` so a row the vault already
    // upserted with a hash is never downgraded to failed-without-hash.
    await db
      .update(transactions)
      .set({ status: "failed" })
      .where(and(eq(transactions.id, txId), eq(transactions.status, "pending")))
      .catch((updateErr) =>
        console.error(`[${requestId}] Failed to mark approved tx ${txId} failed:`, updateErr),
      );

    dispatchWebhook(tenantId, agentId, "tx_failed", {
      txId,
      ...(transaction.executionRef ? { executionRef: transaction.executionRef } : {}),
      error: rawMessage,
      requestId,
    });

    if (isRpcError(e)) {
      return c.json<ApiResponse>({ ok: false, error: extractRpcErrorMessage(e) }, 502);
    }
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Reject transaction ───────────────────────────────────────────────────────

vaultRoutes.post("/:agentId/reject/:txId", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction approval requires tenant-level authentication",
      },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const txId = c.req.param("txId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  if (isProtectedMinter(tenantId, agentId) && !requireHumanOwnerAdmin(c)) {
    return protectedRefused(c, "rejection requires an authenticated human owner/admin session");
  }

  const rejectResult = await db
    .update(approvalQueue)
    .set({ status: "rejected", resolvedAt: new Date(), resolvedBy: tenantId })
    .where(
      and(
        eq(approvalQueue.txId, txId),
        eq(approvalQueue.agentId, agentId),
        eq(approvalQueue.status, "pending"),
      ),
    )
    .returning();

  if (rejectResult.length === 0) {
    return c.json<ApiResponse>(
      { ok: false, error: "Transaction already processed or not found" },
      409,
    );
  }

  await db
    .update(transactions)
    .set({ status: "rejected" })
    .where(and(eq(transactions.id, txId), eq(transactions.agentId, agentId)));

  trackAuditEvent({
    tenantId,
    actorType: "user",
    actorId: tenantId,
    action: "vault.reject",
    resourceType: "transaction",
    resourceId: txId,
    metadata: { agentId },
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });

  return c.json<ApiResponse>({ ok: true });
});

// ─── Lookup action by execution reference (STRATA-1486) ───────────────────────

vaultRoutes.get("/:agentId/actions/by-ref/:executionRef", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const executionRef = c.req.param("executionRef");
  if (!isValidExecutionRef(executionRef)) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid executionRef" }, 400);
  }
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const row = await findByExecutionRef(tenantId, agentId, executionRef);
  if (!row) {
    return c.json<ApiResponse>({ ok: false, error: "Action not found" }, 404);
  }
  const status = await resolveActionStatus(row);
  return c.json<ApiResponse>({ ok: true, data: actionView(row, status) });
});

// ─── Pending approvals ────────────────────────────────────────────────────────

vaultRoutes.get("/:agentId/pending", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const protectedView = isProtectedMinter(tenantId, agentId);
  if (protectedView && !requireHumanOwnerAdmin(c)) {
    return protectedRefused(
      c,
      "pending review requires an authenticated human owner/admin session",
    );
  }

  const pendingTransactions = await db
    .select({
      queueId: approvalQueue.id,
      status: approvalQueue.status,
      requestedAt: approvalQueue.requestedAt,
      reviewDigest: approvalQueue.reviewDigest,
      manifestDigest: approvalQueue.manifestDigest,
      reviewProjection: approvalQueue.reviewProjection,
      requestedBy: approvalQueue.requestedBy,
      transaction: transactions,
    })
    .from(approvalQueue)
    .innerJoin(transactions, eq(transactions.id, approvalQueue.txId))
    .where(
      and(
        eq(approvalQueue.agentId, agentId),
        eq(approvalQueue.status, "pending"),
        eq(transactions.agentId, agentId),
      ),
    );

  return c.json<ApiResponse>({
    ok: true,
    data: pendingTransactions.map((entry) => ({
      queueId: entry.queueId,
      status: entry.status,
      requestedAt: entry.requestedAt,
      transaction: toTxRecord(entry.transaction),
      ...(protectedView
        ? {
            protected: true,
            reviewDigest: entry.reviewDigest,
            manifestDigest: entry.manifestDigest,
            requestedBy: entry.requestedBy,
            review: entry.reviewProjection,
            originalCalldata: entry.transaction.data,
            executionRef: entry.transaction.executionRef,
          }
        : {}),
    })),
  });
});

// ─── Transaction history ──────────────────────────────────────────────────────

vaultRoutes.get("/:agentId/history", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const history = await db.select().from(transactions).where(eq(transactions.agentId, agentId));

  return c.json<ApiResponse>({
    ok: true,
    data: history.map(toTxRecord),
  });
});

// ─── EIP-712 Typed Data Signing ───────────────────────────────────────────────

// ─── Sign arbitrary message (personal_sign / eth_sign) ───────────────────────────────
//
// Used by server-to-server flows that need an off-chain signature from an
// agent (e.g. four.meme SIWE login). EVM uses viem's personal_sign over the
// UTF-8 bytes of the message. Solana uses Ed25519 over the message bytes.
//
// POST /vault/:agentId/sign-message
// body: { "message": "<string>" }
// resp: { ok: true, data: { signature: "0x..." } }
vaultRoutes.post("/:agentId/sign-message", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  if (isProtectedMinter(c.get("tenantId"), c.req.param("agentId"))) {
    return protectedRefused(c, "message signing is refused for every credential");
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<{ message: string }>(c);
  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }
  if (!isNonEmptyString(body.message)) {
    return c.json<ApiResponse>({ ok: false, error: "'message' is required" }, 400);
  }

  try {
    const signature = await vault.signMessage(tenantId, agentId, body.message);
    return c.json<ApiResponse>({ ok: true, data: { signature } });
  } catch (e) {
    console.error(`[Vault] sign-message failed for ${tenantId}/${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

vaultRoutes.post("/:agentId/sign-typed-data", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  if (isProtectedMinter(c.get("tenantId"), c.req.param("agentId"))) {
    return protectedRefused(c, "typed-data signing is refused for every credential");
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<{
    domain: SignTypedDataRequest["domain"];
    types: SignTypedDataRequest["types"];
    primaryType: string;
    value: Record<string, unknown>;
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!body.domain || typeof body.domain !== "object") {
    return c.json<ApiResponse>(
      { ok: false, error: "'domain' is required and must be an object" },
      400,
    );
  }
  if (!body.types || typeof body.types !== "object") {
    return c.json<ApiResponse>(
      { ok: false, error: "'types' is required and must be an object" },
      400,
    );
  }
  if (!isNonEmptyString(body.primaryType)) {
    return c.json<ApiResponse>({ ok: false, error: "'primaryType' is required" }, 400);
  }
  if (!body.value || typeof body.value !== "object") {
    return c.json<ApiResponse>(
      { ok: false, error: "'value' is required and must be an object" },
      400,
    );
  }

  const resolvedChainId =
    (typeof body.domain.chainId === "number" ? body.domain.chainId : 0) ||
    parseInt(process.env.CHAIN_ID || "8453", 10);
  const signRequest: SignRequest = {
    agentId,
    tenantId,
    to: "0x0000000000000000000000000000000000000000",
    value: "0",
    chainId: resolvedChainId,
  };

  const policySet = await getPolicySet(tenantId, agentId);

  // ── Redis rate-limit check (typed data) ────────────────────────────────────
  const rlResult = await enforceRateLimit(agentId, policySet);
  if (!rlResult.allowed) {
    if (rlResult.headers) {
      for (const [key, value] of Object.entries(rlResult.headers)) {
        c.header(key, value);
      }
    }
    return c.json<ApiResponse>({ ok: false, error: rlResult.reason || "Rate limit exceeded" }, 429);
  }

  const stats = await getTransactionStats(agentId);

  const evaluation = await policyEngine.evaluate(policySet, {
    request: signRequest,
    recentTxCount1h: stats.recentTxCount1h,
    recentTxCount24h: stats.recentTxCount24h,
    spentToday: stats.spentToday,
    spentThisWeek: stats.spentThisWeek,
    priceOracle,
  });

  if (!evaluation.approved) {
    const txId = crypto.randomUUID();

    if (evaluation.requiresManualApproval) {
      await db.transaction(async (tx) => {
        await tx.insert(transactions).values({
          id: txId,
          agentId,
          status: "pending",
          toAddress: signRequest.to,
          value: signRequest.value,
          chainId: signRequest.chainId,
          policyResults: evaluation.results,
        });
        await tx.insert(approvalQueue).values({
          id: crypto.randomUUID(),
          txId,
          agentId,
          status: "pending",
        });
      });

      trackAuditEvent({
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: "vault.sign.typed_data.queued_for_approval",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId: signRequest.chainId,
          primaryType: body.primaryType,
          policyResults: evaluation.results,
        },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });

      dispatchWebhook(tenantId, agentId, "approval_required", {
        txId,
        results: evaluation.results,
      });

      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Transaction requires manual approval",
          data: {
            txId,
            results: evaluation.results,
            status: "pending_approval",
          },
        },
        202,
      );
    }

    await db.insert(transactions).values({
      id: txId,
      agentId,
      status: "rejected",
      toAddress: signRequest.to,
      value: signRequest.value,
      chainId: signRequest.chainId,
      policyResults: evaluation.results,
    });

    trackAuditEvent({
      tenantId,
      actorType: "agent",
      actorId: agentId,
      action: "vault.sign.typed_data.rejected_by_policy",
      resourceType: "transaction",
      resourceId: txId,
      metadata: {
        chainId: signRequest.chainId,
        primaryType: body.primaryType,
        policyResults: evaluation.results,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    dispatchWebhook(tenantId, agentId, "tx_rejected", {
      txId,
      results: evaluation.results,
    });

    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction rejected by policy",
        data: { txId, results: evaluation.results },
      },
      403,
    );
  }

  const txId = crypto.randomUUID();

  try {
    const signature = await vault.signTypedData({
      agentId,
      tenantId,
      domain: body.domain,
      types: body.types,
      primaryType: body.primaryType,
      value: body.value,
    });

    await db.insert(transactions).values({
      id: txId,
      agentId,
      status: "signed",
      toAddress: signRequest.to,
      value: signRequest.value,
      chainId: signRequest.chainId,
      policyResults: evaluation.results,
      signedAt: new Date(),
    });

    trackAuditEvent({
      tenantId,
      actorType: "agent",
      actorId: agentId,
      action: "vault.sign.typed_data",
      resourceType: "transaction",
      resourceId: txId,
      metadata: {
        chainId: signRequest.chainId,
        primaryType: body.primaryType,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    dispatchWebhook(tenantId, agentId, "tx_signed", { txId });

    return c.json<ApiResponse<{ signature: string; txId: string }>>({
      ok: true,
      data: { signature, txId },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    const rawMessage = e instanceof Error ? e.message : "Unknown error";
    console.error(`[${requestId}] Sign typed data failed for agent ${agentId}:`, e);

    dispatchWebhook(tenantId, agentId, "tx_failed", {
      txId,
      error: rawMessage,
      requestId,
    });

    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Solana Transaction Signing ───────────────────────────────────────────────

vaultRoutes.post("/:agentId/sign-solana", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  if (isProtectedMinter(c.get("tenantId"), c.req.param("agentId"))) {
    return protectedRefused(c, "Solana signing is refused for every credential");
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<{
    transaction: string;
    chainId?: number;
    broadcast?: boolean;
    to?: string;
    value?: string;
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isNonEmptyString(body.transaction)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "'transaction' is required (base64-encoded serialized Solana transaction)",
      },
      400,
    );
  }

  if (body.to !== undefined && body.to !== "") {
    if (!isValidSolanaAddress(body.to) && !isValidAddress(body.to)) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: "'to' must be a valid Solana address (base58, 32–44 chars) or Ethereum address",
        },
        400,
      );
    }
  }

  if (!body.to || !body.value) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error:
          "Solana signing requires 'to' (recipient address) and 'value' (lamports as string) for policy evaluation",
      },
      400,
    );
  }

  const chainId = body.chainId ?? 101;
  const toAddress = body.to;
  const txValue = body.value;

  const signRequest = {
    agentId,
    tenantId,
    to: toAddress,
    value: txValue,
    chainId,
  };

  const policySet = await getPolicySet(tenantId, agentId);

  // ── Redis rate-limit check (Solana) ────────────────────────────────────────
  const solRlResult = await enforceRateLimit(agentId, policySet);
  if (!solRlResult.allowed) {
    if (solRlResult.headers) {
      for (const [key, value] of Object.entries(solRlResult.headers)) {
        c.header(key, value);
      }
    }
    return c.json<ApiResponse>(
      { ok: false, error: solRlResult.reason || "Rate limit exceeded" },
      429,
    );
  }

  const stats = await getTransactionStats(agentId);

  const evaluation = await policyEngine.evaluate(policySet, {
    request: signRequest,
    recentTxCount1h: stats.recentTxCount1h,
    recentTxCount24h: stats.recentTxCount24h,
    spentToday: stats.spentToday,
    spentThisWeek: stats.spentThisWeek,
    priceOracle,
  });

  if (!evaluation.approved) {
    const txId = crypto.randomUUID();

    if (evaluation.requiresManualApproval) {
      await db.transaction(async (tx) => {
        await tx.insert(transactions).values({
          id: txId,
          agentId,
          status: "pending",
          toAddress,
          value: txValue,
          data: body.transaction,
          chainId,
          policyResults: evaluation.results,
        });
        await tx.insert(approvalQueue).values({
          id: crypto.randomUUID(),
          txId,
          agentId,
          status: "pending",
        });
      });

      trackAuditEvent({
        tenantId,
        actorType: "agent",
        actorId: agentId,
        action: "vault.sign.solana.queued_for_approval",
        resourceType: "transaction",
        resourceId: txId,
        metadata: {
          chainId,
          to: toAddress,
          value: txValue,
          policyResults: evaluation.results,
        },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });

      dispatchWebhook(tenantId, agentId, "approval_required", {
        txId,
        results: evaluation.results,
      });

      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Transaction requires manual approval",
          data: {
            txId,
            results: evaluation.results,
            status: "pending_approval",
          },
        },
        202,
      );
    }

    await db.insert(transactions).values({
      id: txId,
      agentId,
      status: "rejected",
      toAddress,
      value: txValue,
      chainId,
      policyResults: evaluation.results,
    });

    trackAuditEvent({
      tenantId,
      actorType: "agent",
      actorId: agentId,
      action: "vault.sign.solana.rejected_by_policy",
      resourceType: "transaction",
      resourceId: txId,
      metadata: {
        chainId,
        to: toAddress,
        value: txValue,
        policyResults: evaluation.results,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    dispatchWebhook(tenantId, agentId, "tx_rejected", {
      txId,
      results: evaluation.results,
    });

    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Transaction rejected by policy",
        data: { txId, results: evaluation.results },
      },
      403,
    );
  }

  try {
    const txId = crypto.randomUUID();

    const result = await vault.signSolanaTransaction({
      agentId,
      tenantId,
      transaction: body.transaction,
      chainId,
      broadcast: body.broadcast,
    });

    await db.insert(transactions).values({
      id: txId,
      agentId,
      status: "signed",
      toAddress,
      value: txValue,
      chainId,
      txHash: result.broadcast ? result.signature : undefined,
      policyResults: evaluation.results,
      signedAt: new Date(),
    });

    // ── Record spend in Redis (fire-and-forget) ──────────────────────────────
    recordVaultSpend(agentId, tenantId, txValue, chainId).catch((err) =>
      console.error("[vault] Failed to record Solana spend:", err),
    );

    trackAuditEvent({
      tenantId,
      actorType: "agent",
      actorId: agentId,
      action: "vault.sign.solana",
      resourceType: "transaction",
      resourceId: txId,
      metadata: {
        chainId,
        to: toAddress,
        value: txValue,
        broadcast: result.broadcast,
        signature: result.broadcast ? result.signature : undefined,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });

    dispatchWebhook(tenantId, agentId, "tx_signed", {
      txId,
      txHash: result.broadcast ? result.signature : undefined,
    });

    return c.json<
      ApiResponse<{
        txId: string;
        signature: string;
        broadcast: boolean;
        chainId: number;
        caip2?: string;
      }>
    >({
      ok: true,
      data: { txId, ...result },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] Solana sign failed for agent ${agentId}:`, e);

    dispatchWebhook(tenantId, agentId, "tx_failed", {
      error: e instanceof Error ? e.message : "Unknown error",
      requestId,
    });

    if (isRpcError(e)) {
      return c.json<ApiResponse>({ ok: false, error: extractRpcErrorMessage(e) }, 502);
    }
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Generic RPC Passthrough ──────────────────────────────────────────────────

vaultRoutes.post("/:agentId/rpc", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<RpcRequest>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isNonEmptyString(body.method)) {
    return c.json<ApiResponse>({ ok: false, error: "'method' is required" }, 400);
  }

  if (!body.chainId || typeof body.chainId !== "number") {
    return c.json<ApiResponse>(
      { ok: false, error: "'chainId' is required and must be a number" },
      400,
    );
  }

  try {
    const result = await vault.rpcPassthrough(body);
    return c.json<ApiResponse<RpcResponse>>({
      ok: true,
      data: result,
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    const message = e instanceof Error ? e.message : "Unknown error";
    console.error(`[${requestId}] RPC passthrough failed for agent ${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: message }, 400);
  }
});

// ─── Multi-Wallet Address List ────────────────────────────────────────────────

vaultRoutes.get("/:agentId/addresses", async (c) => {
  if (!requireAgentAccess(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: token scope does not match agent" },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  try {
    const addresses = await vault.getAddresses(tenantId, agentId);
    return c.json<
      ApiResponse<{
        agentId: string;
        addresses: Array<{ chainFamily: "evm" | "solana"; address: string }>;
      }>
    >({
      ok: true,
      data: { agentId, addresses },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] getAddresses failed for agent ${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Key Import ───────────────────────────────────────────────────────────────

vaultRoutes.post("/:agentId/import", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key import requires tenant-level authentication" },
      403,
    );
  }
  if (isProtectedMinter(c.get("tenantId"), c.req.param("agentId"))) {
    return protectedRefused(c, "key import is refused for every credential");
  }

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");

  if (!isValidAgentId(agentId)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Invalid agent id — must be 1-128 alphanumeric characters (plus _ - . :)",
      },
      400,
    );
  }

  const body = await safeJsonParse<{
    privateKey: string;
    chain: "evm" | "solana";
  }>(c);
  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isNonEmptyString(body.privateKey)) {
    return c.json<ApiResponse>({ ok: false, error: "privateKey is required" }, 400);
  }

  if (body.chain !== "evm" && body.chain !== "solana") {
    return c.json<ApiResponse>({ ok: false, error: "chain must be 'evm' or 'solana'" }, 400);
  }

  try {
    const result = await vault.importKey(tenantId, agentId, body.privateKey, body.chain);
    return c.json<ApiResponse<{ agentId: string; walletAddress: string; chain: string }>>({
      ok: true,
      data: { agentId, walletAddress: result.walletAddress, chain: body.chain },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] Key import failed for agent ${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

// ─── Key Export ──────────────────────────────────────────────────────────

vaultRoutes.post("/:agentId/export", async (c) => {
  if (!requireTenantLevel(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Key export requires tenant-level authentication" },
      403,
    );
  }
  if (isProtectedMinter(c.get("tenantId"), c.req.param("agentId"))) {
    return protectedRefused(c, "key export is refused for every credential");
  }

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const agent = await ensureAgentForTenant(tenantId, agentId);

  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  try {
    const keys = await vault.exportPrivateKey(tenantId, agentId);

    return c.json<
      ApiResponse<{
        evm?: { privateKey: string; address: string };
        solana?: { privateKey: string; address: string };
        warning: string;
      }>
    >({
      ok: true,
      data: {
        ...keys,
        warning: "This key controls real funds. Store securely.",
      },
    });
  } catch (e: unknown) {
    const requestId = c.get("requestId") || "unknown";
    console.error(`[${requestId}] Key export failed for agent ${agentId}:`, e);
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});
