import { hashApiKey, validateApiKey } from "@stwd/auth";
import { applicationPrincipalCredentials, applicationPrincipals, getDb } from "@stwd/db";
import { and, eq } from "drizzle-orm";
import type { Context, Next } from "hono";
import type { ApplicationPrincipalContext } from "../services/application-boundary";
import type { ApiResponse, AppVariables } from "../services/context";

const DUMMY_KEY_ID = "apk_000000000000000000000000";
const DUMMY_SECRET = `aps_${"0".repeat(64)}`;
const DUMMY_SECRET_HASH = hashApiKey(DUMMY_SECRET);
const KEY_ID_RE = /^apk_[0-9a-f]{24}$/;
const SECRET_RE = /^aps_[0-9a-f]{64}$/;
const AUTH_WINDOW_MS = 60_000;
const AUTH_SELECTOR_MAX_ATTEMPTS = 600;
const AUTH_GLOBAL_MAX_ATTEMPTS = 10_000;
const AUTH_MAX_TRACKED_SELECTORS = 10_000;
const authBuckets = new Map<string, { count: number; resetAt: number }>();
let globalAuthBucket = { count: 0, resetAt: 0 };

function applicationAuthRateLimited(selector: string): boolean {
  const now = Date.now();
  if (globalAuthBucket.resetAt <= now) {
    globalAuthBucket = { count: 0, resetAt: now + AUTH_WINDOW_MS };
    for (const [candidate, value] of authBuckets) {
      if (value.resetAt <= now) authBuckets.delete(candidate);
    }
  }
  globalAuthBucket.count += 1;
  if (globalAuthBucket.count > AUTH_GLOBAL_MAX_ATTEMPTS) return true;

  const key = selector || "malformed";
  const bucket = authBuckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    if (!bucket && authBuckets.size >= AUTH_MAX_TRACKED_SELECTORS) return true;
    authBuckets.set(key, { count: 1, resetAt: now + AUTH_WINDOW_MS });
    return false;
  }
  bucket.count += 1;
  return bucket.count > AUTH_SELECTOR_MAX_ATTEMPTS;
}

function deny(c: Context, error = "Invalid or inactive application credential") {
  c.header("Cache-Control", "no-store");
  return c.json<ApiResponse>({ ok: false, error }, 401);
}

export async function applicationPrincipalAuth(
  c: Context<{ Variables: AppVariables }>,
  next: Next,
) {
  // Presence of application headers commits this route to application auth.
  // Caller-controlled tenant or legacy credentials are never considered.
  if (
    c.req.header("X-Steward-Tenant") !== undefined ||
    c.req.header("X-Steward-Key") !== undefined ||
    c.req.header("X-Steward-Platform-Key") !== undefined ||
    c.req.header("Authorization") !== undefined
  ) {
    return deny(c);
  }

  const rawKeyId = c.req.header("X-Steward-Application-Key-Id") ?? "";
  if (applicationAuthRateLimited(rawKeyId)) {
    c.header("Retry-After", "60");
    return c.json<ApiResponse>(
      { ok: false, error: "Application authentication rate limit exceeded" },
      429,
    );
  }

  const rawSecret = c.req.header("X-Steward-Application-Secret") ?? "";
  const keyId = KEY_ID_RE.test(rawKeyId) ? rawKeyId : DUMMY_KEY_ID;
  const secret = SECRET_RE.test(rawSecret) ? rawSecret : DUMMY_SECRET;

  // Every malformed/unknown/known credential performs the same indexed lookup
  // and exactly one timing-safe secret comparison.
  const [record] = await getDb()
    .select({
      keyId: applicationPrincipalCredentials.keyId,
      credentialTenantId: applicationPrincipalCredentials.tenantId,
      secretHash: applicationPrincipalCredentials.secretHash,
      credentialExpiresAt: applicationPrincipalCredentials.expiresAt,
      credentialRevokedAt: applicationPrincipalCredentials.revokedAt,
      principalId: applicationPrincipals.id,
      principalTenantId: applicationPrincipals.tenantId,
      capabilities: applicationPrincipals.capabilities,
      principalExpiresAt: applicationPrincipals.expiresAt,
      principalRevokedAt: applicationPrincipals.revokedAt,
    })
    .from(applicationPrincipalCredentials)
    .innerJoin(
      applicationPrincipals,
      and(
        eq(applicationPrincipals.tenantId, applicationPrincipalCredentials.tenantId),
        eq(applicationPrincipals.id, applicationPrincipalCredentials.principalId),
      ),
    )
    .where(eq(applicationPrincipalCredentials.keyId, keyId));

  const secretValid = validateApiKey(secret, record?.secretHash ?? DUMMY_SECRET_HASH);
  const now = Date.now();
  if (
    !record ||
    rawKeyId !== keyId ||
    rawSecret !== secret ||
    !secretValid ||
    record.credentialTenantId !== record.principalTenantId ||
    record.credentialRevokedAt !== null ||
    record.principalRevokedAt !== null ||
    record.credentialExpiresAt.getTime() <= now ||
    record.principalExpiresAt.getTime() <= now
  ) {
    return deny(c);
  }

  const principal: ApplicationPrincipalContext = {
    id: record.principalId,
    tenantId: record.principalTenantId,
    credentialKeyId: record.keyId,
    capabilities: record.capabilities,
    expiresAt: record.principalExpiresAt,
  };
  c.set("tenantId", principal.tenantId);
  c.set("applicationPrincipal", principal);
  c.set("authType", "application-principal");
  return next();
}

export function requireApplicationCapability(
  c: Context<{ Variables: AppVariables }>,
  capability: ApplicationPrincipalContext["capabilities"][number],
) {
  return c.get("applicationPrincipal")?.capabilities.includes(capability) === true;
}
