/**
 * tenant-cors.ts — Per-tenant dynamic CORS middleware
 *
 * Reads the tenant from the X-Steward-Tenant header, looks up that tenant's
 * allowed_origins from tenant_configs, and validates the request Origin against
 * the list. Origin lists are cached in memory with a 60 s TTL to avoid
 * per-request DB hits.
 *
 * ─── STRATA-1115: THIS MIDDLEWARE USED TO FAIL OPEN ──────────────────────────
 *
 * `allowOrigin` was initialised to `"*"` and TWO separate paths fell through to
 * that initial value rather than denying:
 *
 *   1. A tenant with an EMPTY `allowed_origins` list ("no config yet → dev
 *      mode") returned `Access-Control-Allow-Origin: *` to every origin.
 *   2. A THROWN error from the config lookup — a transient database blip, a
 *      pool exhaustion, a migration window — was caught, logged as a warning,
 *      and then also produced `*`.
 *
 * The second is the sharper one: an infrastructure failure silently downgraded
 * a security control. A tenant that HAD correctly configured its allowlist lost
 * that allowlist for the duration of a database wobble, and got a wildcard
 * instead of an error. Availability pressure must never quietly relax an
 * authorization boundary — if we cannot READ the policy, we cannot claim the
 * request satisfies it.
 *
 * Compounding it, `Vary: Origin` was only set on the selective path, so the
 * wildcard response was the cacheable one.
 *
 * Both paths now DENY. Denial here means: emit no CORS headers at all (so the
 * browser enforces the block) and, for preflight specifically, answer 403 so
 * the failure is loud and immediate rather than surfacing as a confusing opaque
 * response later.
 *
 * ─── WHAT IS DELIBERATELY UNCHANGED ──────────────────────────────────────────
 *
 * AUTHENTICATION SEMANTICS ARE NOT TOUCHED. CORS governs which browser ORIGINS
 * may read a response; it never decides who is authenticated. No route's auth
 * requirements, credential handling or status codes change here. In particular
 * a denied CORS request is not a 401 and must not be mistaken for one.
 *
 * REQUESTS WITH NO `Origin` HEADER ARE NOT AFFECTED. Server-to-server callers
 * (the Strata API, CI, curl) send no `Origin`, are not subject to the same-origin
 * policy, and are left exactly as they were. Tightening that path would break
 * every non-browser integration while adding no security: CORS is enforced by
 * the browser, not by us, so a header-less client was never constrained by it.
 *
 * REQUESTS WITH AN `Origin` BUT NO `X-Steward-Tenant` KEEP THE PERMISSIVE
 * RESPONSE, and this is a deliberate, narrow exception rather than an oversight.
 * Un-tenanted browser surfaces exist today — `/health` (used by the dashboard's
 * reachability probe) and the `/user/me/tenants` session routes are called
 * without a tenant header. There is no tenant, hence no allowlist to consult,
 * so there is nothing to fail closed AGAINST; denying would break those
 * surfaces without consulting any policy. The exposure is bounded because these
 * responses carry no ambient authority: the dashboard authenticates with an
 * `Authorization: Bearer` token from localStorage, never with cookies, and
 * `credentials: "include"` appears nowhere in the web client — so a wildcard
 * cannot be combined with credentials by a hostile page. Closing this path is
 * tracked separately; it needs a platform-origin allowlist, which is a
 * different change from honouring a tenant's configured policy.
 */

import { getDb, tenantConfigs as tenantConfigsTable } from "@stwd/db";
import { eq } from "drizzle-orm";
import type { Context, Next } from "hono";
import { DEFAULT_TENANT_CONFIGS } from "../defaults/tenant-configs";

// ─── Cache ────────────────────────────────────────────────────────────────────

interface CacheEntry {
  origins: string[];
  expiresAt: number;
}

const CACHE_TTL_MS = 60_000; // 60 seconds
const originsCache = new Map<string, CacheEntry>();

/**
 * Load a tenant's configured origins.
 *
 * THROWS on lookup failure. It deliberately does NOT catch and return `[]`:
 * "this tenant allows nothing" and "we could not find out what this tenant
 * allows" are different facts and the caller must be able to tell them apart.
 * Collapsing them here would reintroduce the STRATA-1115 failure mode one layer
 * down, where it would be much harder to see.
 *
 * Failures are NOT cached — a transient error must not pin a tenant into a
 * degraded state for the rest of the TTL.
 *
 * ─── STRATA-1115 FOLLOW-UP: ABSENT ROW FALLS BACK TO THE CODE DEFAULT ────────
 *
 * Resolution order is: DB row → `DEFAULT_TENANT_CONFIGS` → `[]` (deny).
 *
 * A PRESENT row always wins, INCLUDING when its `allowed_origins` is empty. An
 * operator who saved an empty allowlist decided "no cross-origin reader", and
 * that decision must not be silently overridden by a code default. This is why
 * the row's EXISTENCE is tested separately from its contents below rather than
 * collapsing both into `row?.allowedOrigins ?? []` as before — that expression
 * cannot tell "no row" from "row saying nothing".
 *
 * The fallback is NOT a fail-open path, for three reasons:
 *   1. The DB read SUCCEEDED. "No row exists" is a fact we positively learned,
 *      not an absence of information. The throw path — where we learned nothing
 *      — still denies, unchanged.
 *   2. A committed entry in DEFAULT_TENANT_CONFIGS is an EXPLICIT operator
 *      decision: reviewed, versioned, attributable in git. It is the same class
 *      of deliberate choice as the explicit `"*"` an operator writes into their
 *      own allowlist, which #16 preserved on exactly this reasoning. The defect
 *      #16 fixed was INFERRING permission from absence or from an error; reading
 *      it from checked-in configuration is the opposite of inferring.
 *   3. It widens nothing by itself. A tenant with no row and no default still
 *      resolves to `[]` and is denied, and a default is matched by the very same
 *      allowlist comparison as a DB row — it grants only the origins it names.
 */
async function getTenantOrigins(tenantId: string): Promise<string[]> {
  const now = Date.now();
  const cached = originsCache.get(tenantId);
  if (cached && cached.expiresAt > now) return cached.origins;

  const db = getDb();
  const [row] = await db
    .select({ allowedOrigins: tenantConfigsTable.allowedOrigins })
    .from(tenantConfigsTable)
    .where(eq(tenantConfigsTable.tenantId, tenantId));

  // Note the deliberate `row ?` — presence of the row, not truthiness of its
  // contents. An empty allowlist on a real row is a policy, not a gap.
  const origins: string[] = row
    ? (row.allowedOrigins ?? [])
    : (DEFAULT_TENANT_CONFIGS[tenantId]?.allowedOrigins ?? []);

  originsCache.set(tenantId, { origins, expiresAt: now + CACHE_TTL_MS });
  return origins;
}

/** Evict a tenant's origin list from cache (call after updating tenant config). */
export function invalidateTenantCorsCache(tenantId: string): void {
  originsCache.delete(tenantId);
}

// ─── Constants ────────────────────────────────────────────────────────────────

const ALLOW_METHODS = "GET, POST, PUT, DELETE, OPTIONS";
const ALLOW_HEADERS =
  "Content-Type, X-Steward-Tenant, X-Steward-Key, X-Steward-Platform-Key, X-Steward-Email-Grant, X-Steward-Application-Key-Id, X-Steward-Application-Secret, Idempotency-Key, Authorization";
const EXPOSE_HEADERS = "Content-Length, X-Request-Id";
const MAX_AGE = "86400";

// ─── Middleware ───────────────────────────────────────────────────────────────

/**
 * Deny a cross-origin request.
 *
 * No `Access-Control-Allow-Origin` is emitted, so the browser blocks the read.
 * Preflight gets an explicit 403 rather than a silent 204-without-headers,
 * because a 403 names the refusal instead of leaving the caller to infer it.
 * Non-preflight requests still run the handler (the request already reached us;
 * refusing to answer would change API behaviour for non-browser clients) but
 * carry no CORS headers, so a browser cannot read the response.
 */
async function denyCors(c: Context, next: Next): Promise<Response | undefined> {
  if (c.req.method === "OPTIONS") {
    return c.newResponse(null, 403);
  }
  await next();
  return;
}

export async function tenantCors(c: Context, next: Next): Promise<Response | undefined> {
  const origin = c.req.header("origin") ?? "";
  const tenantId = c.req.header("X-Steward-Tenant");

  // Default stays `*` ONLY for the paths documented in the file header (no
  // Origin at all, or an un-tenanted browser surface). Every path that DOES
  // have a tenant policy to consult now resolves explicitly below.
  let allowOrigin = "*";

  if (tenantId && origin) {
    let origins: string[];
    try {
      origins = await getTenantOrigins(tenantId);
    } catch (err) {
      // STRATA-1115: was `fall back to *`. A failed policy READ is not evidence
      // that the request is permitted. Deny, and log at error level — this is a
      // security-relevant failure, not a warning.
      console.error(
        "[tenant-cors] Failed to load allowed origins; denying cross-origin request:",
        err,
      );
      return denyCors(c, next);
    }

    if (origins.length === 0) {
      // STRATA-1115: was `no config yet → fall through to wildcard`. An empty
      // allowlist is a real, readable policy that permits no cross-origin
      // reader. It is not an invitation to permit everyone.
      return denyCors(c, next);
    }

    if (origins.includes("*") || origins.includes(origin)) {
      // Exact match, or an EXPLICIT wildcard the tenant deliberately configured.
      // Preserved intentionally: an operator who writes "*" into their own
      // allowlist has made a decision. The defect was inferring that decision
      // from absence or from an error.
      allowOrigin = origin;
    } else {
      return denyCors(c, next);
    }
  }

  c.header("Access-Control-Allow-Origin", allowOrigin);
  c.header("Access-Control-Allow-Methods", ALLOW_METHODS);
  c.header("Access-Control-Allow-Headers", ALLOW_HEADERS);
  c.header("Access-Control-Expose-Headers", EXPOSE_HEADERS);
  c.header("Access-Control-Max-Age", MAX_AGE);

  if (allowOrigin !== "*") {
    // Selective allow is Origin-dependent, so shared caches must key on it.
    // Without this a cache could serve one origin's allowed response to another.
    c.header("Vary", "Origin");
  }

  if (c.req.method === "OPTIONS") {
    return c.newResponse(null, 204);
  }

  await next();
  return;
}
