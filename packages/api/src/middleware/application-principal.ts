import { hashApiKey, validateApiKey } from "@stwd/auth";
import { applicationPrincipalCredentials, applicationPrincipals, getDb } from "@stwd/db";
import { eq } from "drizzle-orm";
import type { Context, Next } from "hono";
import {
  type ApplicationCapability,
  type ApplicationPrincipalContext,
  hasApplicationCapability,
  isApplicationCapability,
} from "../services/application-boundary";
import type { ApiResponse, AppVariables } from "../services/context";

const DUMMY_SECRET_HASH = hashApiKey("aps_constant_time_dummy_secret_value");

function deny(c: Context, status: 401 | 403, error: string) {
  return c.json<ApiResponse>({ ok: false, error }, status);
}

export async function applicationPrincipalAuth(
  c: Context<{ Variables: AppVariables }>,
  next: Next,
) {
  const keyId = c.req.header("X-Steward-Application-Key-Id") ?? "";
  const secret = c.req.header("X-Steward-Application-Secret") ?? "";
  const db = getDb();
  const [record] = keyId
    ? await db
        .select({
          keyId: applicationPrincipalCredentials.keyId,
          secretHash: applicationPrincipalCredentials.secretHash,
          credentialExpiresAt: applicationPrincipalCredentials.expiresAt,
          credentialRevokedAt: applicationPrincipalCredentials.revokedAt,
          principalId: applicationPrincipals.id,
          tenantId: applicationPrincipals.tenantId,
          auditIdentity: applicationPrincipals.auditIdentity,
          capabilities: applicationPrincipals.capabilities,
          ownerReferences: applicationPrincipals.ownerReferences,
          principalExpiresAt: applicationPrincipals.expiresAt,
          principalRevokedAt: applicationPrincipals.revokedAt,
        })
        .from(applicationPrincipalCredentials)
        .innerJoin(
          applicationPrincipals,
          eq(applicationPrincipals.id, applicationPrincipalCredentials.principalId),
        )
        .where(eq(applicationPrincipalCredentials.keyId, keyId))
    : [];

  // Always perform exactly one timing-safe hash comparison, including unknown
  // key IDs, so credential validation has no secret-dependent comparison path.
  const secretValid = validateApiKey(secret, record?.secretHash ?? DUMMY_SECRET_HASH);
  const now = Date.now();
  if (
    !record ||
    !secretValid ||
    record.credentialRevokedAt !== null ||
    record.principalRevokedAt !== null ||
    record.credentialExpiresAt.getTime() <= now ||
    record.principalExpiresAt.getTime() <= now
  ) {
    return deny(c, 401, "Invalid or inactive application credential");
  }

  const capabilities = record.capabilities.filter(isApplicationCapability);
  if (capabilities.length !== record.capabilities.length) {
    return deny(c, 403, "Application principal has invalid capabilities");
  }

  const principal: ApplicationPrincipalContext = {
    id: record.principalId,
    tenantId: record.tenantId,
    auditIdentity: record.auditIdentity,
    capabilities,
    ownerReferences: record.ownerReferences,
    expiresAt: record.principalExpiresAt,
  };
  c.set("tenantId", principal.tenantId);
  c.set("applicationPrincipal", principal);
  c.set("authType", "application-principal");
  return next();
}

export function requireApplicationCapability(
  c: Context<{ Variables: AppVariables }>,
  capability: ApplicationCapability,
) {
  const principal = c.get("applicationPrincipal");
  return principal ? hasApplicationCapability(principal, capability) : false;
}
