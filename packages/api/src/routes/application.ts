import { type Context, Hono } from "hono";
import { z } from "zod";
import { requireApplicationCapability } from "../middleware/application-principal";
import {
  ApplicationBoundaryError,
  type ApplicationCapability,
  isValidApplicationReference,
  isValidIdempotencyKey,
} from "../services/application-boundary";
import {
  prepareApplicationTransaction,
  proposeApplicationTransaction,
} from "../services/application-proposals";
import {
  ensureApplicationWallet,
  readApplicationWalletAddress,
} from "../services/application-wallets";
import { writeAuditEvent } from "../services/audit";
import { type ApiResponse, type AppVariables, safeJsonParse } from "../services/context";

export const applicationRoutes = new Hono<{ Variables: AppVariables }>();
type AppContext = Context<{ Variables: AppVariables }>;

const ensureSchema = z.object({ resourceId: z.string().min(1).max(255) }).strict();
// uint256 max (2^256-1) is 78 decimal digits; anything longer is not a
// representable EVM value. Bounding this is a SECURITY control, not tidiness:
// `prepareApplicationTransaction` calls BigInt(command.value), whose decimal ->
// binary conversion is superlinear, and the runtime is a single-threaded event
// loop. Unbounded, a valid LEAST-PRIVILEGE principal could block the API for
// every tenant (measured: 200k digits => 666ms of blocking; ~1M digits fits
// inside the 1MB body limit and throws a BigInt OOM that surfaces as a 500).
// Rejecting oversized input at the schema means the expensive conversion is
// never reached. Capability checks do not help here — the cost is paid by an
// authorized caller — so the bound is the control.
const EVM_UINT256_MAX_DIGITS = 78;
// 1MB body limit / 2 hex chars per byte, with headroom. Bounded for the same
// reason: `data` is lowercased and canonically JSON-hashed downstream.
const EVM_CALLDATA_MAX_CHARS = 262_144;
const prepareSchema = z
  .object({
    walletId: z.string().min(1).max(64),
    network: z.object({ type: z.literal("evm"), chainId: z.number().int().positive() }).strict(),
    transaction: z
      .object({
        to: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
        value: z.string().regex(/^\d+$/).max(EVM_UINT256_MAX_DIGITS),
        data: z
          .string()
          .regex(/^0x(?:[0-9a-fA-F]{2})*$/)
          .max(EVM_CALLDATA_MAX_CHARS)
          .optional(),
      })
      .strict(),
  })
  .strict();
const proposeSchema = z.object({ preparedTransactionId: z.string().min(1).max(64) }).strict();

function requestMetadata(c: AppContext) {
  return {
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  };
}

async function auditApplicationAction(
  c: AppContext,
  action: string,
  capability: ApplicationCapability,
  resourceType: string,
  resourceId: string | null,
  metadata: Record<string, unknown> = {},
) {
  const principal = c.get("applicationPrincipal")!;
  await writeAuditEvent({
    tenantId: principal.tenantId,
    actorType: "application",
    actorId: principal.id,
    action,
    resourceType,
    resourceId,
    metadata: {
      credentialKeyId: principal.credentialKeyId,
      capability,
      ...metadata,
    },
    ...requestMetadata(c),
  });
}

async function forbidden(c: AppContext, capability: ApplicationCapability) {
  await auditApplicationAction(
    c,
    "application.command.denied",
    capability,
    "application_command",
    null,
    { reason: "capability_denied" },
  );
  return c.json<ApiResponse>({ ok: false, error: "Application command denied" }, 403);
}

async function invalidRequest(c: AppContext, capability: ApplicationCapability) {
  await auditApplicationAction(
    c,
    "application.command.denied",
    capability,
    "application_command",
    null,
    { reason: "invalid_request" },
  );
  return c.json<ApiResponse>({ ok: false, error: "Invalid application command" }, 400);
}

async function commandError(c: AppContext, capability: ApplicationCapability, error: unknown) {
  if (error instanceof ApplicationBoundaryError) {
    await auditApplicationAction(
      c,
      "application.command.denied",
      capability,
      "application_command",
      null,
      { reason: error.code },
    );
    return c.json<ApiResponse>({ ok: false, error: error.message }, error.status);
  }
  throw error;
}

applicationRoutes.post("/wallets/ensure", async (c) => {
  const capability = "wallet:ensure" as const;
  if (!requireApplicationCapability(c, capability)) return forbidden(c, capability);
  const raw = await safeJsonParse<unknown>(c);
  const parsed = ensureSchema.safeParse(raw);
  const idempotencyKey = c.req.header("Idempotency-Key");
  if (
    !parsed.success ||
    !isValidApplicationReference(parsed.data.resourceId) ||
    !isValidIdempotencyKey(idempotencyKey)
  ) {
    return invalidRequest(c, capability);
  }
  try {
    const result = await ensureApplicationWallet(
      c.get("applicationPrincipal")!,
      parsed.data.resourceId,
      idempotencyKey,
    );
    await auditApplicationAction(
      c,
      "application.wallet.ensure",
      capability,
      "application_wallet",
      result.wallet.id,
      {
        resourceKind: result.wallet.resourceKind,
        resourceId: result.wallet.resourceId,
        requestHash: result.requestHash,
        replay: !result.created,
      },
    );
    return c.json<ApiResponse>(
      { ok: true, data: { wallet: result.wallet, replay: !result.created } },
      result.created ? 201 : 200,
    );
  } catch (error) {
    return commandError(c, capability, error);
  }
});

applicationRoutes.get("/wallets/:walletId/address", async (c) => {
  const capability = "wallet:address:read" as const;
  if (!requireApplicationCapability(c, capability)) return forbidden(c, capability);
  try {
    const wallet = await readApplicationWalletAddress(
      c.get("applicationPrincipal")!,
      c.req.param("walletId"),
    );
    await auditApplicationAction(
      c,
      "application.wallet_address.read",
      capability,
      "application_wallet",
      wallet.id,
    );
    return c.json<ApiResponse>({ ok: true, data: wallet });
  } catch (error) {
    return commandError(c, capability, error);
  }
});

applicationRoutes.post("/transactions/prepare", async (c) => {
  const capability = "transaction:prepare" as const;
  if (!requireApplicationCapability(c, capability)) return forbidden(c, capability);
  const raw = await safeJsonParse<unknown>(c);
  const parsed = prepareSchema.safeParse(raw);
  const idempotencyKey = c.req.header("Idempotency-Key");
  if (!parsed.success || !isValidIdempotencyKey(idempotencyKey)) {
    return invalidRequest(c, capability);
  }
  try {
    const result = await prepareApplicationTransaction(c.get("applicationPrincipal")!, {
      idempotencyKey,
      walletId: parsed.data.walletId,
      chainId: parsed.data.network.chainId,
      to: parsed.data.transaction.to,
      value: parsed.data.transaction.value,
      ...(parsed.data.transaction.data !== undefined ? { data: parsed.data.transaction.data } : {}),
    });
    await auditApplicationAction(
      c,
      "application.transaction.prepare",
      capability,
      "application_transaction_intent",
      result.preparedTransaction.id,
      {
        walletId: parsed.data.walletId,
        requestHash: result.requestHash,
        replay: !result.created,
      },
    );
    return c.json<ApiResponse>(
      {
        ok: true,
        data: { preparedTransaction: result.preparedTransaction, replay: !result.created },
      },
      result.created ? 201 : 200,
    );
  } catch (error) {
    return commandError(c, capability, error);
  }
});

applicationRoutes.post("/transactions/propose", async (c) => {
  const capability = "transaction:propose" as const;
  if (!requireApplicationCapability(c, capability)) return forbidden(c, capability);
  const raw = await safeJsonParse<unknown>(c);
  const parsed = proposeSchema.safeParse(raw);
  const idempotencyKey = c.req.header("Idempotency-Key");
  if (!parsed.success || !isValidIdempotencyKey(idempotencyKey)) {
    return invalidRequest(c, capability);
  }
  try {
    const result = await proposeApplicationTransaction(c.get("applicationPrincipal")!, {
      idempotencyKey,
      preparedTransactionId: parsed.data.preparedTransactionId,
    });
    await auditApplicationAction(
      c,
      "application.transaction.propose",
      capability,
      "application_transaction_proposal",
      result.proposal.id,
      {
        intentId: result.intentId,
        requestHash: result.requestHash,
        replay: !result.created,
      },
    );
    return c.json<ApiResponse>(
      { ok: true, data: { proposal: result.proposal, replay: !result.created } },
      result.created ? 202 : 200,
    );
  } catch (error) {
    return commandError(c, capability, error);
  }
});
