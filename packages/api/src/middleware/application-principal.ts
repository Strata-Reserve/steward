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

// A rate limiter that denies LEGITIMATE callers when saturated is a free DoS:
// the attacker pays nothing and authorized principals are locked out. Both
// original failure modes were reachable WITHOUT any valid credential:
//
//   1. the global counter was incremented for every request and, once tripped,
//      429'd valid credentials too;
//   2. `size >= MAX_TRACKED -> return true` denied any principal not ALREADY in
//      the map, so filling the map with junk selectors locked out new legitimate
//      principals while staying under the global cap.
//
// The fix makes saturation cost the ATTACKER rather than the user. But the
// FIRST version of this fix over-corrected and a delta review caught it: a
// blanket global-ceiling EXEMPTION for known-good selectors removed the only
// aggregate backstop on DB lookups from credentialed callers
// (10_000 selectors x 600/min = ~6M/min admitted vs a former hard 10_000).
// Trading a lockout defect for a 601x load-amplification defect is not a fix.
//
// So known-good traffic is PRIORITISED, not exempt: it draws on its own
// separate, larger aggregate ceiling. A junk flood can no longer lock out an
// established principal (the two budgets are independent), while total
// admitted load stays bounded by construction.
const AUTH_KNOWN_GOOD_GLOBAL_MAX_ATTEMPTS = 60_000;
const knownGoodSelectors = new Set<string>();
const KNOWN_GOOD_MAX = 10_000;
let knownGoodGlobalBucket = { count: 0, resetAt: 0 };

/** Called after a credential successfully authenticates. */
export function markApplicationSelectorKnownGood(selector: string): void {
  if (!selector) return;
  // Bounded, LRU-ish: re-inserting refreshes recency via delete+add.
  knownGoodSelectors.delete(selector);
  knownGoodSelectors.add(selector);
  if (knownGoodSelectors.size > KNOWN_GOOD_MAX) {
    const oldest = knownGoodSelectors.values().next();
    if (!oldest.done) knownGoodSelectors.delete(oldest.value);
  }
}

/**
 * Drop a selector's known-good standing. MUST be called on revoke and on
 * rotate: without it a revoked credential keeps its prioritised standing
 * forever. The credential is still DENIED by the auth gate either way — this
 * governs resource budget, not authority — but a revoked key should not retain
 * a privileged share of it.
 */
export function clearApplicationSelectorKnownGood(selector: string): void {
  if (!selector) return;
  knownGoodSelectors.delete(selector);
}

/** Test seam only. Not part of the auth path. */
export function __resetApplicationAuthRateLimiterForTests(): void {
  authBuckets.clear();
  knownGoodSelectors.clear();
  globalAuthBucket = { count: 0, resetAt: 0 };
  knownGoodGlobalBucket = { count: 0, resetAt: 0 };
}

/**
 * Exported so tests bind to the REAL function. The first regression suite for
 * this code tested private re-implementations, which meant reverting the source
 * left every test green — documentation masquerading as a guard.
 */
export function applicationAuthRateLimited(selector: string, nowMs?: number): boolean {
  const now = nowMs ?? Date.now();
  if (globalAuthBucket.resetAt <= now) {
    globalAuthBucket = { count: 0, resetAt: now + AUTH_WINDOW_MS };
    for (const [candidate, value] of authBuckets) {
      if (value.resetAt <= now) authBuckets.delete(candidate);
    }
  }
  if (knownGoodGlobalBucket.resetAt <= now) {
    knownGoodGlobalBucket = { count: 0, resetAt: now + AUTH_WINDOW_MS };
  }

  const key = selector || "malformed";
  const wellFormed = KEY_ID_RE.test(key);
  const knownGood = wellFormed && knownGoodSelectors.has(key);

  // Two INDEPENDENT aggregate ceilings. A junk flood exhausts only the unknown
  // budget, so it cannot lock out an established principal; and known-good
  // traffic is still bounded, so a set of valid credentials cannot saturate the
  // database either.
  if (knownGood) {
    knownGoodGlobalBucket.count += 1;
    if (knownGoodGlobalBucket.count > AUTH_KNOWN_GOOD_GLOBAL_MAX_ATTEMPTS) return true;
  } else {
    globalAuthBucket.count += 1;
    if (globalAuthBucket.count > AUTH_GLOBAL_MAX_ATTEMPTS) return true;
  }

  const bucket = authBuckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    if (!bucket && authBuckets.size >= AUTH_MAX_TRACKED_SELECTORS) {
      // Evict the least-recently-inserted entry instead of denying. Denying
      // here would fail CLOSED against a brand-new legitimate principal.
      //
      // Eviction alone let a caller RESET its own per-selector count mid-window
      // by forcing its bucket out of the map (burn 600, cycle the map, get a
      // fresh count). Evicting only entries whose window has EXPIRED closes
      // that: a live bucket is never discarded, so the 600/min invariant holds
      // for the whole window. If every tracked bucket is live we admit the new
      // selector without evicting — still fail-open for legitimate callers,
      // still bounded by the two aggregate ceilings above.
      for (const [candidate, value] of authBuckets) {
        if (value.resetAt <= now) {
          authBuckets.delete(candidate);
          break;
        }
      }
    }
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

  // Only reached on a fully valid, non-revoked, non-expired credential. From
  // here on this selector draws on the known-good aggregate ceiling rather than
  // the unknown/flood one, so a junk flood cannot lock out a principal that has
  // demonstrably authenticated. It is still bounded — by its own per-selector
  // bucket AND by that separate aggregate ceiling.
  markApplicationSelectorKnownGood(record.keyId);

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
