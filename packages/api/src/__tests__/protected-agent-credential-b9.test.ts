/**
 * STRATA-1499 SF-1 delta B9 (Steward side): agent-scoped credential for the
 * protected agent.
 *
 * Steward ALREADY issues an agent-scoped credential; nothing new is added here
 * and the tenant API key's authority is NOT expanded. Issuance call:
 *
 *   POST /agents/:agentId/token
 *     auth:   human owner/admin session JWT of the tenant (for the protected
 *             agent the tenant API key and any agent token are refused, 403)
 *     body:   { "expiresIn"?: "<zeit/ms>", "scopes"?: ["agent"] }
 *             "api:proxy" is refused for the protected agent (403)
 *     result: { token, agentId, tenantId, scope: "agent", scopes: ["agent"], expiresIn }
 *
 *   The token is a Steward-signed JWT with claims
 *     { agentId, tenantId, scope: "agent", scopes: ["agent"] }
 *   and authenticates as authType "agent-token" with agentScope == agentId.
 *   For the protected agent that credential may reach ONLY
 *     POST /vault/:own/sign, GET /vault/:own/actions/by-ref/:ref,
 *     GET /vault/:own/addresses, GET /agents/:own
 *   (protectedBearerGuard + protectedAgentDispatch). Proposals require
 *   `agentScope === :agentId` (protectedProposerIdentity), so agent A's
 *   credential can never propose for agent B.
 *
 * This file pins those properties adversarially.
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { generateApiKey, signAccessToken, signAgentToken } from "@stwd/auth";
import { approvalQueue, closeDb, getDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import type { Hono } from "hono";
import { encodeFunctionData, parseAbi } from "viem";

const TENANT = "strata-b9";
const OTHER_TENANT = "other-b9";
const AGENT = "b9-prod-minter";
const OTHER_AGENT = "b9-ordinary-agent";
const FACTORY = "0x00000000000000000000000000000000000f0003";
const TOKEN = "0x0000000000000000000000000000000000700004";
const SAFE = "0x3Ea77cDf3eC33603bF4135bb1a36712B5e21d721";
const RECIPIENT = "0x00000000000000000000000000000000000000ac";
const OWNER_USER = crypto.randomUUID();

const TOKEN_ABI = parseAbi(["function mint(address to, uint256 amount)"]);

let app: Hono;
let rootKey: string;
let otherRootKey: string;
let signerAddress: string;
let ownerToken: string;
let issuedAgentJwt: string;
let otherAgentJwt: string;
let boundary: typeof import("../services/prod-minter-boundary");
let refCounter = 0;
const ref = () => `b9:test:${++refCounter}`;

const rootHeaders = (key = rootKey, tenant = TENANT) => ({
  "Content-Type": "application/json",
  "X-Steward-Tenant": tenant,
  "X-Steward-Key": key,
});
const bearer = (t: string) => ({ "Content-Type": "application/json", Authorization: `Bearer ${t}` });

function mintCalldata() {
  return encodeFunctionData({
    abi: TOKEN_ABI,
    functionName: "mint",
    args: [RECIPIENT as `0x${string}`, 1000n * 10n ** 18n],
  });
}
const validBody = () => ({ to: TOKEN, value: "0", data: mintCalldata(), chainId: 8453, executionRef: ref() });

async function sign(agent: string, headers: Record<string, string>, body = validBody()) {
  return app.request(`/vault/${agent}/sign`, { method: "POST", headers, body: JSON.stringify(body) });
}
// biome-ignore lint/suspicious/noExplicitAny: test helper
async function json<T = any>(r: Response): Promise<T> {
  return (await r.json()) as T;
}
async function pendingCount(agent: string) {
  const q = await getDb().select().from(approvalQueue).where(eq(approvalQueue.agentId, agent));
  return q.filter((x) => x.status === "pending").length;
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "protected-b9-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "protected-b9-audit-key-32-bytes-minimum-aaaaaa";
  process.env.STEWARD_JWT_SECRET = "protected-b9-jwt-secret-with-enough-bytes-aaaaaaaa";
  process.env.RPC_URL_8453 = "https://protected-tests-mainnet.invalid/v2/UNUSED";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  const k = generateApiKey();
  const k2 = generateApiKey();
  rootKey = k.key;
  otherRootKey = k2.key;
  await db.insert(tenants).values([
    { id: TENANT, name: "Strata B9", apiKeyHash: k.hash },
    { id: OTHER_TENANT, name: "Other B9", apiKeyHash: k2.hash },
  ]);
  await db.insert(users).values([{ id: OWNER_USER, email: `owner-${OWNER_USER}@example.test` }]);
  await db.insert(userTenants).values([{ userId: OWNER_USER, tenantId: TENANT, role: "owner" }]);

  ({ app } = await import("../app"));
  boundary = await import("../services/prod-minter-boundary");

  for (const id of [AGENT, OTHER_AGENT]) {
    const r = await app.request("/agents", {
      method: "POST",
      headers: rootHeaders(),
      body: JSON.stringify({ id, name: id }),
    });
    if (r.status !== 200) throw new Error(`POST /agents ${id} → ${r.status}: ${await r.text()}`);
    if (id === AGENT) signerAddress = (await json(r)).data.walletAddress;
  }

  boundary.installProtectedMinterManifest({
    tenantId: TENANT,
    agentId: AGENT,
    signerAddress,
    chainId: 8453,
    safeAdmin: SAFE,
    factories: [FACTORY],
    verifiedTokens: [{ address: TOKEN, provenance: "0xdeploytx:receipt:verified-by-human" }],
    approvers: [OWNER_USER],
  });

  ownerToken = await signAccessToken(
    { address: `0x${"1".repeat(40)}`, tenantId: TENANT, userId: OWNER_USER } as never,
    "1h",
  );
  otherAgentJwt = await signAgentToken({ agentId: OTHER_AGENT, tenantId: TENANT }, "1h");
}, 120000);

afterAll(async () => {
  boundary?.installProtectedMinterManifest(null);
  await closeDb();
  for (const k of [
    "STEWARD_PGLITE_MEMORY",
    "DATABASE_URL",
    "STEWARD_MASTER_PASSWORD",
    "STEWARD_AUDIT_HMAC_KEY",
    "STEWARD_JWT_SECRET",
    "RPC_URL_8453",
  ])
    delete process.env[k];
});

describe("B9: issuance of the protected agent's own credential", () => {
  it("tenant API key and agent tokens cannot issue it; api:proxy refused; human owner issues scope=agent", async () => {
    const issue = (headers: Record<string, string>, body: unknown = {}) =>
      app.request(`/agents/${AGENT}/token`, { method: "POST", headers, body: JSON.stringify(body) });

    expect((await issue(rootHeaders())).status).toBe(403);
    expect((await issue(bearer(otherAgentJwt))).status).toBe(403);
    expect((await issue(bearer(ownerToken), { scopes: ["api:proxy"] })).status).toBe(403);
    expect((await issue(bearer(ownerToken), { scopes: ["agent", "api:proxy"] })).status).toBe(403);

    const ok = await issue(bearer(ownerToken), { expiresIn: "1h" });
    expect(ok.status).toBe(200);
    const b = await json(ok);
    expect(b.data.agentId).toBe(AGENT);
    expect(b.data.tenantId).toBe(TENANT);
    expect(b.data.scope).toBe("agent");
    expect(b.data.scopes).toEqual(["agent"]);
    issuedAgentJwt = b.data.token;

    // The issued credential is a Steward JWT bound to exactly this agent.
    const { verifyToken } = await import("@stwd/auth");
    const payload = (await verifyToken(issuedAgentJwt)) as Record<string, unknown>;
    expect(payload.scope).toBe("agent");
    expect(payload.agentId).toBe(AGENT);
    expect(payload.tenantId).toBe(TENANT);
    expect(payload.scopes).toEqual(["agent"]);
  });

  it("the issued credential proposes for its own agent (and only reaches its allowlist)", async () => {
    const r = await sign(AGENT, bearer(issuedAgentJwt));
    expect(r.status).toBe(202);
    expect((await json(r)).data.status).toBe("pending_approval");
    // allowlisted reads
    expect((await app.request(`/agents/${AGENT}`, { headers: bearer(issuedAgentJwt) })).status).toBe(200);
    expect((await app.request(`/vault/${AGENT}/addresses`, { headers: bearer(issuedAgentJwt) })).status).toBe(200);
    // outside the allowlist: 403 before any handler
    for (const [method, path] of [
      ["GET", "/agents"],
      ["POST", `/agents/${AGENT}/token`],
      ["GET", `/vault/${AGENT}/pending`],
      ["GET", `/agents/${OTHER_AGENT}`],
      ["GET", "/health"],
    ] as const) {
      const r2 = await app.request(path, { method, headers: bearer(issuedAgentJwt), body: method === "POST" ? "{}" : undefined });
      expect(r2.status).toBe(403);
    }
  });
});

describe("B9: tenant API key is still refused for protected proposals", () => {
  it("own-tenant API key, other-tenant API key, and API key with X-Steward-Tenant spoof => 403, nothing queued", async () => {
    const before = await pendingCount(AGENT);
    expect((await sign(AGENT, rootHeaders())).status).toBe(403);
    expect((await sign(AGENT, rootHeaders(otherRootKey, OTHER_TENANT))).status).not.toBe(202);
    expect((await sign(AGENT, rootHeaders(otherRootKey, TENANT))).status).not.toBe(202);
    const r = await sign(AGENT, rootHeaders());
    expect((await json(r)).error).toBe(
      "Protected signer: only the signer's own agent token or a human owner/admin session may propose",
    );
    expect(await pendingCount(AGENT)).toBe(before);
  });

  it("the API key cannot approve what the agent credential proposed", async () => {
    const r = await sign(AGENT, bearer(issuedAgentJwt));
    expect(r.status).toBe(202);
    const b = await json(r);
    const a = await app.request(`/vault/${AGENT}/approve/${b.data.txId}`, {
      method: "POST",
      headers: rootHeaders(),
      body: JSON.stringify({ reviewDigest: b.data.reviewDigest }),
    });
    expect(a.status).toBe(403);
  });
});

describe("B9: agent A's credential cannot propose for agent B", () => {
  it("ordinary agent B's credential cannot propose for protected agent A", async () => {
    const before = await pendingCount(AGENT);
    const r = await sign(AGENT, bearer(otherAgentJwt));
    expect(r.status).toBe(403);
    expect(await pendingCount(AGENT)).toBe(before);
  });

  it("protected agent A's credential cannot propose (or sign) for ordinary agent B", async () => {
    const r = await sign(OTHER_AGENT, bearer(issuedAgentJwt), {
      to: RECIPIENT,
      value: "1",
      chainId: 8453,
      executionRef: ref(),
    });
    expect(r.status).toBe(403);
    expect((await json(r)).error).toMatch(/^Protected signer: /);
  });

  it("a forged agent token for A under another tenant, or with a foreign agentId, is refused", async () => {
    const crossTenant = await signAgentToken({ agentId: AGENT, tenantId: OTHER_TENANT }, "1h");
    const before = await pendingCount(AGENT);
    expect((await sign(AGENT, bearer(crossTenant))).status).not.toBe(202);
    // A agent-token minted with B's agentId but presented against A's path.
    const bAsA = await signAgentToken({ agentId: OTHER_AGENT, tenantId: TENANT, scopes: ["agent", "api:proxy"] }, "1h");
    expect((await sign(AGENT, bearer(bAsA))).status).toBe(403);
    // A token missing the agent scope marker is not an agent credential at all.
    const noScope = await signAccessToken({ address: `0x${"2".repeat(40)}`, tenantId: TENANT, userId: crypto.randomUUID() } as never, "1h");
    expect((await sign(AGENT, bearer(noScope))).status).not.toBe(202);
    expect(await pendingCount(AGENT)).toBe(before);
  });

  it("the platform-level issuance path also refuses the protected agent", async () => {
    const r = await app.request(`/platform/tenants/${TENANT}/agents/${AGENT}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${issuedAgentJwt}` },
      body: "{}",
    });
    expect(r.status).toBe(403);
  });
});
