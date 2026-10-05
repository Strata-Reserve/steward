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
 * registered, no agent is protected and legacy behaviour is unchanged.
 */

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
 */
export function issueProtectedSigningPermit(input: {
  tenantId: string;
  agentId: string;
  reviewDigest: string;
}): string {
  const handle = crypto.randomUUID();
  permits.set(handle, { ...input, expiresAt: Date.now() + PERMIT_TTL_MS });
  return handle;
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
