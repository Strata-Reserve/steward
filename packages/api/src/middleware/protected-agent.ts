/**
 * STRATA-1499 (REVIEW-STEWARD-28 F1/F2, R2 R2-2/R2-3/N1): protected-agent dispatch.
 *
 * Two layers:
 *
 *  1. `protectedBearerGuard` — GLOBAL, app-level, mounted on "*" before every
 *     route prefix (including /auth, /platform, /user, /application,
 *     /discovery, /health, /). It inspects the bearer itself (no auth
 *     middleware has run yet). A bearer that is a protected agent credential
 *     may reach ONLY its own allowlist:
 *        POST /vault/:own/sign, GET /vault/:own/actions/by-ref/:ref,
 *        GET /vault/:own/addresses, GET /agents/:own.
 *     Everything else, including public/unauthenticated endpoints, is 403
 *     before any handler, so /auth/session, /auth/logout, /auth/nonce,
 *     /health etc. never process the protected identity. Public endpoints
 *     stay public only when called WITHOUT the protected bearer.
 *
 *  2. `protectedAgentDispatch` — per-prefix, after auth. Repeats the
 *     allowlist on `authType === "agent-token"` (covers RS256 agent JWTs
 *     verified by `requireAgentJwt`, which the global guard cannot decode
 *     offline) and refuses any request whose TARGET agent is a
 *     persisted-protected row not exactly covered by the manifest
 *     (tenant + agent + persisted wallet address). Such a quarantined agent
 *     has zero capability (R2-2 / N1).
 */
import { verifyToken } from "@stwd/auth";
import type { Context, Next } from "hono";
import type { ApiResponse, AppVariables } from "../services/context";
import {
  isPersistedProtectedAgent,
  isProtectedMinterAgentId,
  isQuarantinedProtectedAgent,
} from "../services/prod-minter-boundary";

const AGENT_PATH_RE = /^\/(?:v1\/)?(?:vault|agents)\/([^/]+)(?:\/|$)/;

export function protectedAgentAllowed(method: string, path: string, agentId: string): boolean {
  const own = (suffix: string) => path === `/vault/${agentId}${suffix}`;
  if (method === "POST" && own("/sign")) return true;
  if (method === "GET" && path.startsWith(`/vault/${agentId}/actions/by-ref/`)) return true;
  if (method === "GET" && own("/addresses")) return true;
  if (method === "GET" && path === `/agents/${agentId}`) return true;
  return false;
}

function refuse(c: Context, error: string): Response {
  return c.json<ApiResponse>({ ok: false, error }, 403);
}

/**
 * Decide for a protected agent credential. Returns a 403 response or null.
 * Quarantined (persisted-protected, not exactly covered) => always 403.
 */
async function decideForProtectedScope(
  c: Context,
  scope: string,
  method: string,
  path: string,
): Promise<Response | null> {
  const isProtected = isProtectedMinterAgentId(scope) || (await isPersistedProtectedAgent(scope));
  if (!isProtected) return null;
  if (await isQuarantinedProtectedAgent(scope)) {
    return refuse(
      c,
      "Protected signer: no valid manifest covers this agent; all operations refused",
    );
  }
  if (!protectedAgentAllowed(method, path, scope)) {
    return refuse(c, "Protected signer: this credential may only propose and read its own status");
  }
  return null;
}

/** Offline decode of a bearer as a Steward agent session token; null otherwise. */
async function protectedScopeFromBearer(c: Context): Promise<string | null> {
  const auth = c.req.header("Authorization");
  if (!auth?.startsWith("Bearer ")) return null;
  try {
    const payload = (await verifyToken(auth.slice(7))) as { scope?: unknown; agentId?: unknown };
    if (payload.scope === "agent" && typeof payload.agentId === "string" && payload.agentId) {
      return payload.agentId;
    }
  } catch {
    // Not a Steward-signed token (or expired/invalid): nothing to decide here.
    // Route-level auth will reject it as usual.
  }
  return null;
}

/** R2-3: global, pre-auth guard. Mounted on "*" ahead of every route prefix. */
export async function protectedBearerGuard(
  c: Context<{ Variables: AppVariables }>,
  next: Next,
): Promise<Response | void> {
  const scope = await protectedScopeFromBearer(c);
  if (scope) {
    const refused = await decideForProtectedScope(c, scope, c.req.method, c.req.path);
    if (refused) return refused;
  }
  return next();
}

export async function protectedAgentDispatch(
  c: Context<{ Variables: AppVariables }>,
  next: Next,
): Promise<Response | void> {
  const path = c.req.path;
  const method = c.req.method;
  // F2: protected agent credential (any namespace that sets agentScope).
  if (c.get("authType") === "agent-token") {
    const scope = c.get("agentScope");
    if (scope) {
      const refused = await decideForProtectedScope(c, scope, method, path);
      if (refused) return refused;
    }
  }
  // F1(b)/R2-2/N1: persisted-protected target not exactly covered => quarantined.
  const m = AGENT_PATH_RE.exec(path);
  if (m?.[1]) {
    const agentId = decodeURIComponent(m[1]);
    if (await isQuarantinedProtectedAgent(agentId)) {
      return refuse(
        c,
        "Protected signer: no valid manifest covers this agent; all operations refused",
      );
    }
  }
  return next();
}
