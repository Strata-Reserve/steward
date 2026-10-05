/**
 * STRATA-1499 — REVIEW-STEWARD-28-R2 resolution tests (R2-1, R2-2, R2-3, N1).
 *
 * Harness ported from the independent reviewer's `independent-r2.test.ts`.
 * Each test is expected to FAIL on 876d0832 on its own assertion and pass
 * after. In-memory PGLite; vault broadcast seam stubbed; no RPC.
 */

import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import { generateApiKey, signAccessToken, signAgentToken } from "@stwd/auth";
import { agents, approvalQueue, closeDb, tenants, transactions, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import type { Hono } from "hono";
import { encodeFunctionData, parseAbi } from "viem";

const TENANT = "strata";
const OTHER_TENANT = "other-tenant";
const AGENT = "prod-minter-r2";
const OTHER_AGENT = "legacy-agent-r2";
const FACTORY = "0x00000000000000000000000000000000000f0001";
const TOKEN = "0x0000000000000000000000000000000000700001";
const SAFE = "0x3Ea77cDf3eC33603bF4135bb1a36712B5e21d721";
const RECIPIENT = "0x00000000000000000000000000000000000000aa";
const PLACEHOLDER = "0x00000000000000000000000000000000000000ff";
const OWNER_USER = crypto.randomUUID();
const ADMIN_USER = crypto.randomUUID();
const PLATFORM_KEY = "r2-platform-key-for-tests";

const TOKEN_ABI = parseAbi(["function mint(address to, uint256 amount)"]);

let app: Hono;
let db: Awaited<ReturnType<typeof createPGLiteDb>>["db"];
let rootKey: string;
let otherRootKey: string;
let signerAddress: string;
let ownerToken: string;
let adminToken: string;
let agentJwt: string;
let vault: Awaited<typeof import("../services/context")>["vault"];
let boundary: typeof import("../services/prod-minter-boundary");
let vaultLib: typeof import("@stwd/vault");
let refCounter = 0;
const ref = () => `strata:r2:${++refCounter}`;
const sent: unknown[] = [];

const rootHeaders = () => ({
  "Content-Type": "application/json",
  "X-Steward-Tenant": TENANT,
  "X-Steward-Key": rootKey,
});
const bearer = (t: string) => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${t}`,
});

function manifest(addr: string) {
  return {
    tenantId: TENANT,
    agentId: AGENT,
    signerAddress: addr,
    chainId: 8453 as const,
    safeAdmin: SAFE,
    factories: [FACTORY],
    verifiedTokens: [{ address: TOKEN, provenance: "0xdeploytx:verified" }],
  };
}
const mintCalldata = () =>
  encodeFunctionData({ abi: TOKEN_ABI, functionName: "mint", args: [RECIPIENT, 10n ** 18n] });
const proposal = () => ({
  to: TOKEN,
  value: "0",
  data: mintCalldata(),
  chainId: 8453,
  executionRef: ref(),
});

async function call(method: string, path: string, h: Record<string, string>, body?: unknown) {
  return app.request(path, {
    method,
    headers: h,
    body: ["GET", "HEAD", "DELETE"].includes(method) && body === undefined
      ? undefined
      : JSON.stringify(body ?? {}),
  });
}
async function queue() {
  const p = proposal();
  const r = await call("POST", `/vault/${AGENT}/sign`, bearer(agentJwt), p);
  const b = (await r.json()) as { data?: { txId: string; reviewDigest: string } };
  return { ...p, txId: b.data?.txId ?? "", reviewDigest: b.data?.reviewDigest ?? "", status: r.status };
}
async function approve(q: { txId: string; reviewDigest: string }, h = bearer(ownerToken)) {
  return call("POST", `/vault/${AGENT}/approve/${q.txId}`, h, { reviewDigest: q.reviewDigest });
}
const freshAgentJwt = () => signAgentToken({ agentId: AGENT, tenantId: TENANT }, "1h");

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "r2-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "r2-audit-key-32-bytes-minimum-aaaaaaaaaaa";
  process.env.STEWARD_JWT_SECRET = "r2-jwt-secret-with-enough-bytes-aaaaaaaaaaa";
  process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;

  const created = await createPGLiteDb("memory://");
  db = created.db;
  setPGLiteOverride(db, async () => created.client.close());
  const k = generateApiKey();
  rootKey = k.key;
  const k2 = generateApiKey();
  otherRootKey = k2.key;
  await db.insert(tenants).values([
    { id: TENANT, name: "Strata", apiKeyHash: k.hash },
    { id: OTHER_TENANT, name: "Other", apiKeyHash: k2.hash },
  ]);
  await db
    .insert(users)
    .values([OWNER_USER, ADMIN_USER].map((id) => ({ id, email: `${id}@x.test` })));
  await db.insert(userTenants).values([
    { userId: OWNER_USER, tenantId: TENANT, role: "owner" },
    { userId: ADMIN_USER, tenantId: TENANT, role: "admin" },
  ]);

  ({ app } = await import("../app"));
  ({ vault } = await import("../services/context"));
  boundary = await import("../services/prod-minter-boundary");
  vaultLib = await import("@stwd/vault");

  ownerToken = await signAccessToken(
    { address: `0x${"1".repeat(40)}`, tenantId: TENANT, userId: OWNER_USER } as never,
    "1h",
  );
  adminToken = await signAccessToken(
    { address: `0x${"2".repeat(40)}`, tenantId: TENANT, userId: ADMIN_USER } as never,
    "1h",
  );
  agentJwt = await freshAgentJwt();

  let r = await app.request("/agents", {
    method: "POST",
    headers: rootHeaders(),
    body: JSON.stringify({ id: OTHER_AGENT, name: OTHER_AGENT }),
  });
  if (r.status !== 200) throw new Error(`legacy create ${r.status}`);

  boundary.installProtectedMinterManifest(manifest(PLACEHOLDER));
  r = await app.request("/agents", {
    method: "POST",
    headers: bearer(ownerToken),
    body: JSON.stringify({ id: AGENT, name: AGENT }),
  });
  if (r.status !== 200) throw new Error(`protected create ${r.status}: ${await r.text()}`);
  signerAddress = ((await r.json()) as { data: { walletAddress: string } }).data.walletAddress;
  boundary.installProtectedMinterManifest(manifest(signerAddress));

  spyOn(vault as never, "broadcastEvm" as never).mockImplementation((async (
    _client: unknown,
    tx: unknown,
  ) => {
    sent.push(tx);
    return `0x${sent.length.toString(16).padStart(64, "0")}`;
  }) as never);
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
    "STEWARD_PLATFORM_KEYS",
  ])
    delete process.env[k];
}, 120000);

async function directSign(q: ReturnType<typeof proposal> & { txId: string; reviewDigest: string }) {
  const permit = await vaultLib.issueProtectedSigningPermit({
    tenantId: TENANT,
    agentId: AGENT,
    txId: q.txId,
    reviewDigest: q.reviewDigest,
  });
  return vault.signTransaction(
    {
      to: q.to,
      value: q.value,
      data: q.data,
      chainId: q.chainId,
      executionRef: q.executionRef,
      tenantId: TENANT,
      agentId: AGENT,
      broadcast: true,
    } as never,
    { txId: q.txId, protectedPermit: permit, protectedReviewDigest: q.reviewDigest },
  );
}

describe.serial("R2-1: issuance consumes a durable single-use claim", () => {
  it("[R2-1a] re-issue after the HTTP approval consumed the claim is refused; direct Vault call gives zero extra broadcasts", async () => {
    const q = await queue();
    expect(q.status).toBe(202);
    expect((await approve(q)).status).toBe(200);
    const before = sent.length;
    expect(await vaultLib.isProtectedIssuanceClaimed(q.txId)).toBe(true);
    let error = "";
    try {
      await directSign(q);
    } catch (e) {
      error = String(e);
    }
    expect(error).toMatch(/permit refused/);
    expect(sent.length - before).toBe(0);
    expect(vaultLib.outstandingProtectedPermits()).toBe(0);
  });

  it("[R2-1b] two concurrent issuances for one approved row give exactly one success", async () => {
    const q = await queue();
    expect(q.status).toBe(202);
    // Claim the approval without signing (CAS only), then race the issuer.
    const claim = await db
      .update(approvalQueue)
      .set({ status: "approved", resolvedAt: new Date(), resolvedBy: `user:${ADMIN_USER}` })
      .where(eq(approvalQueue.txId, q.txId))
      .returning({ id: approvalQueue.id });
    expect(claim.length).toBe(1);
    const issue = () =>
      vaultLib
        .issueProtectedSigningPermit({
          tenantId: TENANT,
          agentId: AGENT,
          txId: q.txId,
          reviewDigest: q.reviewDigest,
        })
        .then(
          (handle) => ({ ok: true as const, handle }),
          (e) => ({ ok: false as const, error: String(e) }),
        );
    const results = await Promise.all([issue(), issue(), issue()]);
    const winners = results.filter((r) => r.ok);
    expect(winners.length).toBe(1);
    expect(results.filter((r) => !r.ok && /already issued/.test(r.error)).length).toBe(2);
    // The single permit signs exactly once; a fourth issuance is still refused.
    const before = sent.length;
    const winner = winners[0] as { ok: true; handle: string };
    const hash = await vault.signTransaction(
      { ...proposal(), ...q, tenantId: TENANT, agentId: AGENT, broadcast: true } as never,
      { txId: q.txId, protectedPermit: winner.handle, protectedReviewDigest: q.reviewDigest },
    );
    expect(hash.startsWith("0x")).toBe(true);
    expect(sent.length - before).toBe(1);
    const again = await issue();
    expect(again.ok).toBe(false);
    expect((again as { error: string }).error).toMatch(/already issued|already signed/);
    expect(sent.length - before).toBe(1);
    expect(vaultLib.outstandingProtectedPermits()).toBe(0);
  });

  it("[R2-1c] signing already done / in flight for a txId refuses any new permit; outcome resolves via executionRef only", async () => {
    const q = await queue();
    expect(q.status).toBe(202);
    // Mark approved + signed directly (simulates a completed or in-flight sign
    // whose outcome was lost by the caller).
    await db.update(approvalQueue).set({ status: "approved" }).where(eq(approvalQueue.txId, q.txId));
    await db
      .update(transactions)
      .set({ status: "signed", txHash: `0x${"ab".repeat(32)}` })
      .where(eq(transactions.id, q.txId));
    let error = "";
    try {
      await vaultLib.issueProtectedSigningPermit({
        tenantId: TENANT,
        agentId: AGENT,
        txId: q.txId,
        reviewDigest: q.reviewDigest,
      });
    } catch (e) {
      error = String(e);
    }
    expect(error).toMatch(/already signed|executionRef lookup/);
    const lookup = await call(
      "GET",
      `/vault/${AGENT}/actions/by-ref/${q.executionRef}`,
      bearer(agentJwt),
    );
    expect(lookup.status).toBe(200);
    const body = (await lookup.json()) as { data: { txId: string; status: string } };
    expect(body.data.txId).toBe(q.txId);
    expect(body.data.status).toBe("signed");
  });

  it("[R2-1d] issuance with no approval row or a pending approval is refused and claims nothing", async () => {
    const q = await queue();
    expect(q.status).toBe(202);
    await expect(
      vaultLib.issueProtectedSigningPermit({
        tenantId: TENANT,
        agentId: AGENT,
        txId: q.txId,
        reviewDigest: q.reviewDigest,
      }),
    ).rejects.toThrow(/no consumed approval/);
    expect(await vaultLib.isProtectedIssuanceClaimed(q.txId)).toBe(false);
    await expect(
      vaultLib.issueProtectedSigningPermit({
        tenantId: TENANT,
        agentId: AGENT,
        txId: "no-such-tx",
        reviewDigest: q.reviewDigest,
      }),
    ).rejects.toThrow(/no consumed approval/);
    expect(vaultLib.outstandingProtectedPermits()).toBe(0);
    // Pending row still approves normally afterwards (claim untouched).
    expect((await approve(q)).status).toBe(200);
  });
});
