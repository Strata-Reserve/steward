import { createHash, randomBytes } from "node:crypto";
import { hashApiKey } from "@stwd/auth";

export const APPLICATION_CAPABILITIES = [
  "wallet:ensure",
  "wallet:address:read",
  "transaction:prepare",
  "transaction:propose",
] as const;

export type ApplicationCapability = (typeof APPLICATION_CAPABILITIES)[number];

export type ApplicationPrincipalContext = {
  id: string;
  tenantId: string;
  credentialKeyId: string;
  capabilities: ApplicationCapability[];
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

export function isValidIdempotencyKey(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= 128 &&
    /^[\x21-\x7e]+$/.test(value)
  );
}

export function parseFutureExpiry(value: unknown, upperBound?: Date): Date | null {
  if (typeof value !== "string") return null;
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.getTime() <= Date.now()) return null;
  if (upperBound && parsed.getTime() > upperBound.getTime()) return null;
  return parsed;
}

export class ApplicationBoundaryError extends Error {
  constructor(
    readonly status: 403 | 404 | 409 | 500,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}
