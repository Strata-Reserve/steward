/**
 * STRATA-1499 (REVIEW-STEWARD-28 F1/F2): central protected-agent dispatch.
 *
 * Runs after tenant auth on every mounted route group.
 *  - F2: a protected agent JWT may reach ONLY its own allowlist:
 *      POST /vault/:own/sign, GET /vault/:own/actions/by-ref/:ref,
 *      GET /vault/:own/addresses, GET /agents/:own. Everything else is 403
 *      before any handler.
 *  - F1(b): any request naming a persisted-protected agent is refused when
 *      no valid manifest covers that agent (deny-by-default).
 */
import type { Context, Next } from "hono";
import type { ApiResponse, AppVariables } from "../services/context";
import {
  isPersistedProtectedAgent,
  isProtectedMinter,
  isProtectedMinterAgentId,
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

export async function protectedAgentDispatch(
  c: Context<{ Variables: AppVariables }>,
  next: Next,
): Promise<Response | void> {
  const path = c.req.path;
  const method = c.req.method;
  // F2: protected agent credential (any namespace that sets agentScope).
  if (c.get("authType") === "agent-token") {
    const scope = c.get("agentScope");
    if (
      scope &&
      (isProtectedMinterAgentId(scope) || (await isPersistedProtectedAgent(scope))) &&
      !protectedAgentAllowed(method, path, scope)
    ) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Protected signer: this credential may only propose and read its own status",
        },
        403,
      );
    }
  }
  // F1(b): persisted-protected target with no covering manifest.
  const m = AGENT_PATH_RE.exec(path);
  if (m?.[1]) {
    const agentId = decodeURIComponent(m[1]);
    const tenantId = c.get("tenantId") ?? "";
    if (!isProtectedMinter(tenantId, agentId) && (await isPersistedProtectedAgent(agentId))) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Protected signer: no valid manifest installed; all operations refused",
        },
        403,
      );
    }
  }
  return next();
}
