import { createHash, randomBytes } from "node:crypto";
import { hashApiKey } from "@stwd/auth";

export const APPLICATION_CAPABILITIES = [
  "ensure_wallet",
  "read_wallet_address",
  "prepare_transaction",
  "propose_transaction",
] as const;

export type ApplicationCapability = (typeof APPLICATION_CAPABILITIES)[number];

export type ApplicationPrincipalContext = {
  id: string;
  tenantId: string;
  auditIdentity: string;
  capabilities: ApplicationCapability[];
  ownerReferences: string[];
  expiresAt: Date;
};

export type ApplicationCredential = {
  keyId: string;
  secret: string;
  secretHash: string;
};

function canonicalizeValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalizeValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, item]) => [key, canonicalizeValue(item)]),
    );
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalizeValue(value));
}

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function deterministicId(prefix: string, ...parts: string[]): string {
  return `${prefix}_${sha256(canonicalJson(parts)).slice(0, 40)}`;
}

export function generateApplicationCredential(): ApplicationCredential {
  const keyId = `apk_${randomBytes(12).toString("hex")}`;
  const secret = `aps_${randomBytes(32).toString("hex")}`;
  return { keyId, secret, secretHash: hashApiKey(secret) };
}

export function isApplicationCapability(value: unknown): value is ApplicationCapability {
  return (
    typeof value === "string" && (APPLICATION_CAPABILITIES as readonly string[]).includes(value)
  );
}

export function hasApplicationCapability(
  principal: ApplicationPrincipalContext,
  capability: ApplicationCapability,
): boolean {
  return principal.capabilities.includes(capability);
}

export function isValidApplicationReference(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 255 &&
    /^[a-zA-Z0-9][a-zA-Z0-9_.:@/-]*$/.test(value)
  );
}

export function parseFutureExpiry(value: unknown, upperBound?: Date): Date | null {
  if (typeof value !== "string") return null;
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.getTime() <= Date.now()) return null;
  if (upperBound && parsed.getTime() > upperBound.getTime()) return null;
  return parsed;
}

// ─── Canonical application command service ───────────────────────────────────
// This is the sole writer for application-owned wallets, prepared intents, and
// proposals. HTTP routes are validation/adaptation only.
import {
  applicationTransactionIntents,
  applicationTransactionProposals,
  applicationWallets,
  getDb,
} from "@stwd/db";
import { and, eq } from "drizzle-orm";
import { vault } from "./context";

export class ApplicationBoundaryError extends Error {
  constructor(
    readonly status: 403 | 404 | 409 | 500,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

export async function ensureApplicationWallet(
  principal: ApplicationPrincipalContext,
  ownerReference: string,
  chainFamily: "evm" | "solana",
) {
  if (!principal.ownerReferences.includes(ownerReference)) {
    throw new ApplicationBoundaryError(
      403,
      "owner_not_assigned",
      "Owner reference is not assigned to this principal",
    );
  }
  const db = getDb();
  const walletId = deterministicId("aw", principal.id, ownerReference, chainFamily);
  const [existing] = await db
    .select()
    .from(applicationWallets)
    .where(
      and(eq(applicationWallets.id, walletId), eq(applicationWallets.principalId, principal.id)),
    );
  if (existing) return { wallet: existing, created: false };

  const stewardAgentId = deterministicId(
    "appw",
    principal.tenantId,
    principal.id,
    ownerReference,
  ).slice(0, 64);
  let identity = await vault.getAgent(principal.tenantId, stewardAgentId);
  if (!identity) {
    try {
      identity = await vault.createAgent(
        principal.tenantId,
        stewardAgentId,
        `Application wallet ${ownerReference}`,
        `application-principal:${principal.id}`,
      );
    } catch {
      identity = await vault.getAgent(principal.tenantId, stewardAgentId);
      if (!identity) {
        throw new ApplicationBoundaryError(
          500,
          "wallet_ensure_failed",
          "Failed to ensure application wallet",
        );
      }
    }
  }
  const address =
    identity.walletAddresses?.[chainFamily] ??
    (chainFamily === "evm" ? identity.walletAddress : undefined);
  if (!address) {
    throw new ApplicationBoundaryError(
      500,
      "wallet_address_unavailable",
      `Wallet address unavailable for ${chainFamily}`,
    );
  }
  const inserted = await db
    .insert(applicationWallets)
    .values({
      id: walletId,
      tenantId: principal.tenantId,
      principalId: principal.id,
      ownerReference,
      chainFamily,
      stewardAgentId,
      address,
    })
    .onConflictDoNothing()
    .returning({ id: applicationWallets.id });
  const [wallet] = await db
    .select()
    .from(applicationWallets)
    .where(
      and(eq(applicationWallets.id, walletId), eq(applicationWallets.principalId, principal.id)),
    );
  if (!wallet) {
    throw new ApplicationBoundaryError(
      500,
      "wallet_persistence_failed",
      "Application wallet persistence failed",
    );
  }
  return { wallet, created: inserted.length > 0 };
}

export async function readApplicationWalletAddress(
  principal: ApplicationPrincipalContext,
  walletId: string,
) {
  const db = getDb();
  const [wallet] = await db
    .select({
      id: applicationWallets.id,
      ownerReference: applicationWallets.ownerReference,
      chainFamily: applicationWallets.chainFamily,
      address: applicationWallets.address,
    })
    .from(applicationWallets)
    .where(
      and(
        eq(applicationWallets.id, walletId),
        eq(applicationWallets.principalId, principal.id),
        eq(applicationWallets.tenantId, principal.tenantId),
      ),
    );
  if (!wallet) throw new ApplicationBoundaryError(404, "wallet_not_found", "Wallet not found");
  return wallet;
}

export type PrepareApplicationTransactionCommand = {
  idempotencyKey: string;
  walletId: string;
  chainId: number;
  to: string;
  value: string;
  data?: string;
};

export async function prepareApplicationTransaction(
  principal: ApplicationPrincipalContext,
  command: PrepareApplicationTransactionCommand,
) {
  const db = getDb();
  const [wallet] = await db
    .select()
    .from(applicationWallets)
    .where(
      and(
        eq(applicationWallets.id, command.walletId),
        eq(applicationWallets.principalId, principal.id),
        eq(applicationWallets.tenantId, principal.tenantId),
      ),
    );
  if (!wallet) throw new ApplicationBoundaryError(404, "wallet_not_found", "Wallet not found");
  if (wallet.chainFamily !== "evm") {
    throw new ApplicationBoundaryError(
      409,
      "unsupported_wallet_family",
      "Prepared EVM transaction requires an EVM wallet",
    );
  }
  const intent = {
    version: "1",
    kind: "evm_transaction",
    wallet: { id: wallet.id, ownerReference: wallet.ownerReference, address: wallet.address },
    network: { namespace: "eip155", chainId: command.chainId },
    transaction: {
      to: command.to.toLowerCase(),
      value: BigInt(command.value).toString(),
      ...(command.data !== undefined ? { data: command.data.toLowerCase() } : {}),
    },
  };
  const requestHash = sha256(canonicalJson(intent));
  const intentId = deterministicId("ati", principal.id, command.idempotencyKey);
  const inserted = await db
    .insert(applicationTransactionIntents)
    .values({
      id: intentId,
      tenantId: principal.tenantId,
      principalId: principal.id,
      walletId: wallet.id,
      idempotencyKey: command.idempotencyKey,
      requestHash,
      intent,
    })
    .onConflictDoNothing()
    .returning({ id: applicationTransactionIntents.id });
  const [preparedTransaction] = await db
    .select()
    .from(applicationTransactionIntents)
    .where(
      and(
        eq(applicationTransactionIntents.principalId, principal.id),
        eq(applicationTransactionIntents.idempotencyKey, command.idempotencyKey),
      ),
    );
  if (!preparedTransaction) {
    throw new ApplicationBoundaryError(
      500,
      "intent_persistence_failed",
      "Prepared transaction persistence failed",
    );
  }
  if (preparedTransaction.requestHash !== requestHash) {
    throw new ApplicationBoundaryError(
      409,
      "idempotency_conflict",
      "Idempotency key was already used for a different transaction",
    );
  }
  return { preparedTransaction, requestHash, created: inserted.length > 0 };
}

export async function proposeApplicationTransaction(
  principal: ApplicationPrincipalContext,
  command: { idempotencyKey: string; preparedTransactionId: string },
) {
  const db = getDb();
  const [intent] = await db
    .select()
    .from(applicationTransactionIntents)
    .where(
      and(
        eq(applicationTransactionIntents.id, command.preparedTransactionId),
        eq(applicationTransactionIntents.principalId, principal.id),
        eq(applicationTransactionIntents.tenantId, principal.tenantId),
      ),
    );
  if (!intent) {
    throw new ApplicationBoundaryError(
      404,
      "prepared_transaction_not_found",
      "Prepared transaction not found",
    );
  }
  const requestHash = sha256(
    canonicalJson({ intentId: intent.id, intentHash: intent.requestHash }),
  );
  const proposalId = deterministicId("atp", principal.id, command.idempotencyKey);
  const inserted = await db
    .insert(applicationTransactionProposals)
    .values({
      id: proposalId,
      tenantId: principal.tenantId,
      principalId: principal.id,
      intentId: intent.id,
      idempotencyKey: command.idempotencyKey,
      requestHash,
      status: "proposed",
    })
    .onConflictDoNothing()
    .returning({ id: applicationTransactionProposals.id });
  const [proposal] = await db
    .select()
    .from(applicationTransactionProposals)
    .where(
      and(
        eq(applicationTransactionProposals.principalId, principal.id),
        eq(applicationTransactionProposals.idempotencyKey, command.idempotencyKey),
      ),
    );
  if (!proposal)
    throw new ApplicationBoundaryError(
      500,
      "proposal_persistence_failed",
      "Proposal persistence failed",
    );
  if (proposal.requestHash !== requestHash) {
    throw new ApplicationBoundaryError(
      409,
      "idempotency_conflict",
      "Idempotency key was already used for a different proposal",
    );
  }
  return { proposal, intentId: intent.id, requestHash, created: inserted.length > 0 };
}
