/**
 * STRATA-1499 SF-1 — #27 (explicit chain RPC) x #28 (protected minter)
 * integration tests (REVIEW-STEWARD-28-R3, finding R3-MERGE).
 *
 * On the merged tree the readiness preflight `assertChainRpcReady` runs
 * ABOVE the protected permit consume in `Vault.signTransaction` and ABOVE the
 * approval claim in the protected approve route. These tests pin:
 *
 *   1. Protected signer, Base (8453) endpoint missing or http://, after a
 *      human approval: the permit and the issuance claim are NOT consumed, the
 *      approval row stays pending and is still usable once the configuration
 *      is fixed. Exactly one broadcast in total.
 *   2. Protected path error with a key-bearing synthetic endpoint: no URL,
 *      host or key appears in the HTTP body or in console output.
 *
 * Network: `globalThis.fetch` is replaced by a local interceptor before the
 * app is imported. Run with `--preload ./scripts/test-no-network-preload.ts`.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it, spyOn } from "bun:test";
import { inspect } from "node:util";
import { generateApiKey, signAccessToken, signAgentToken } from "@stwd/auth";
import { approvalQueue, closeDb, tenants, transactions, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import type { Hono } from "hono";
import { encodeFunctionData, parseAbi } from "viem";

const TENANT = "strata";
const AGENT = "prod-minter-sf1";
const FACTORY = "0x00000000000000000000000000000000000f0001";
const TOKEN = "0x0000000000000000000000000000000000700001";
const SAFE = "0x3Ea77cDf3eC33603bF4135bb1a36712B5e21d721";
const RECIPIENT = "0x00000000000000000000000000000000000000aa";
const PLACEHOLDER = "0x00000000000000000000000000000000000000ff";
const OWNER_USER = crypto.randomUUID();
const HOST = "explicit-mainnet.invalid";
const KEY = "SYNTHETIC_SF1_REVIEW_KEY";
const PATH = `/v2/${KEY}`;
const GOOD_URL = `https://${HOST}${PATH}`;
const HTTP_URL = `http://${HOST}${PATH}`;
const HASH = `0x${"a".repeat(64)}`;

const TOKEN_ABI = parseAbi(["function mint(address to, uint256 amount)"]);

let app: Hono;
let db: Awaited<ReturnType<typeof createPGLiteDb>>["db"];
let signerAddress: string;
let ownerToken: string;
let agentJwt: string;
let vault: Awaited<typeof import("../services/context")>["vault"];
let boundary: typeof import("../services/prod-minter-boundary");
let vaultLib: typeof import("@stwd/vault");
let refCounter = 0;
const ref = () => `strata:sf1:${++refCounter}`;
const sent: unknown[] = [];
let broadcastMode: "record" | "passthrough" = "record";
let rpcMode: "ok" | "revert" = "ok";
let networkCalls = 0;
const logs: string[] = [];
let errSpy: ReturnType<typeof spyOn> | undefined;

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
    approvers: [OWNER_USER],
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
  return app.request(path, { method, headers: h, body: JSON.stringify(body ?? {}) });
}
async function queue() {
  const p = proposal();
  const r = await call("POST", `/vault/${AGENT}/sign`, bearer(agentJwt), p);
  const b = (await r.json()) as { data?: { txId: string; reviewDigest: string } };
  return {
    ...p,
    txId: b.data?.txId ?? "",
    reviewDigest: b.data?.reviewDigest ?? "",
    status: r.status,
  };
}
async function approve(q: { txId: string; reviewDigest: string }) {
  return call("POST", `/vault/${AGENT}/approve/${q.txId}`, bearer(ownerToken), {
    reviewDigest: q.reviewDigest,
  });
}
const queueRow = async (txId: string) =>
  (await db.select().from(approvalQueue).where(eq(approvalQueue.txId, txId)))[0];
const txRow = async (txId: string) =>
  (await db.select().from(transactions).where(eq(transactions.id, txId)))[0];

function setChainUrls(urls: Record<number, string | undefined>) {
  (
    vault as unknown as { config: { chainRpcUrls: Record<number, string | undefined> } }
  ).config.chainRpcUrls = urls;
}

/** Everything that could leak: full URL, host, path, key, URL-encoded key. */
const LEAKS = [GOOD_URL, HTTP_URL, HOST, PATH, KEY, encodeURIComponent(PATH)];
function expectNoLeak(text: string) {
  for (const leak of LEAKS) expect(text).not.toContain(leak);
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "sf1-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "sf1-audit-key-32-bytes-minimum-aaaaaaaaaaa";
  process.env.STEWARD_JWT_SECRET = "sf1-jwt-secret-with-enough-bytes-aaaaaaaaaaa";
  process.env.RPC_URL = "https://generic.invalid/forbidden";
  delete process.env.RPC_URL_8453;
  delete process.env.RPC_URL_84532;

  // Local RPC interceptor: counts every non-webhook call; never reaches a network.
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    networkCalls++;
    const b = JSON.parse(String(init?.body ?? "{}")) as { id: number; method: string };
    if (rpcMode === "revert") {
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: b.id,
          error: { code: -32000, message: `execution reverted (via ${url})` },
        }),
        { headers: { "Content-Type": "application/json" } },
      );
    }
    let result: unknown;
    switch (b.method) {
      case "eth_chainId":
        result = "0x2105";
        break;
      case "eth_getTransactionCount":
        result = "0x0";
        break;
      case "eth_gasPrice":
      case "eth_maxPriorityFeePerGas":
        result = "0x3b9aca00";
        break;
      case "eth_getBlockByNumber":
        result = { number: "0x1", baseFeePerGas: "0x3b9aca00", hash: HASH, transactions: [] };
        break;
      case "eth_estimateGas":
        result = "0x5208";
        break;
      case "eth_sendRawTransaction":
        result = HASH;
        break;
      default:
        throw new Error(`Unexpected mocked method ${b.method}`);
    }
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: b.id, result }), {
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof fetch;

  const created = await createPGLiteDb("memory://");
  db = created.db;
  setPGLiteOverride(db, async () => created.client.close());
  const k = generateApiKey();
  await db.insert(tenants).values([{ id: TENANT, name: "Strata", apiKeyHash: k.hash }]);
  await db.insert(users).values([{ id: OWNER_USER, email: `${OWNER_USER}@x.test` }]);
  await db.insert(userTenants).values([{ userId: OWNER_USER, tenantId: TENANT, role: "owner" }]);

  ({ app } = await import("../app"));
  ({ vault } = await import("../services/context"));
  boundary = await import("../services/prod-minter-boundary");
  vaultLib = await import("@stwd/vault");

  ownerToken = await signAccessToken(
    { address: `0x${"1".repeat(40)}`, tenantId: TENANT, userId: OWNER_USER } as never,
    "1h",
  );
  agentJwt = await signAgentToken({ agentId: AGENT, tenantId: TENANT }, "1h");

  boundary.installProtectedMinterManifest(manifest(PLACEHOLDER));
  const r = await app.request("/agents", {
    method: "POST",
    headers: bearer(ownerToken),
    body: JSON.stringify({ id: AGENT, name: AGENT }),
  });
  if (r.status !== 200) throw new Error(`protected create ${r.status}: ${await r.text()}`);
  signerAddress = ((await r.json()) as { data: { walletAddress: string } }).data.walletAddress;
  boundary.installProtectedMinterManifest(manifest(signerAddress));

  const original = vaultLib.Vault.prototype.broadcastEvm as unknown as (
    this: unknown,
    client: unknown,
    tx: unknown,
  ) => Promise<string>;
  spyOn(vault as never, "broadcastEvm" as never).mockImplementation(async function (
    this: unknown,
    client: unknown,
    tx: unknown,
  ) {
    if (broadcastMode === "passthrough") return original.call(vault, client, tx);
    sent.push(tx);
    return `0x${sent.length.toString(16).padStart(64, "0")}`;
  } as never);

  errSpy = spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    logs.push(args.map((a) => (typeof a === "string" ? a : inspect(a, { depth: 6 }))).join(" "));
  });
}, 120000);

afterEach(() => {
  broadcastMode = "record";
  rpcMode = "ok";
  setChainUrls({ 8453: GOOD_URL });
});

afterAll(async () => {
  errSpy?.mockRestore();
  boundary?.installProtectedMinterManifest(null);
  await closeDb();
  for (const k of [
    "STEWARD_PGLITE_MEMORY",
    "DATABASE_URL",
    "STEWARD_MASTER_PASSWORD",
    "STEWARD_AUDIT_HMAC_KEY",
    "STEWARD_JWT_SECRET",
    "RPC_URL",
  ])
    delete process.env[k];
}, 120000);

describe.serial("SF-1: readiness preflight sits above the protected permit consume", () => {
  it("HTTP approve with 8453 endpoint missing: 500, approval stays pending, no issuance claim, no broadcast; fixed config -> same approval signs exactly once", async () => {
    setChainUrls({ 8453: GOOD_URL });
    const q = await queue();
    expect(q.status).toBe(202);
    const before = sent.length;
    const outstandingBefore = vaultLib.outstandingProtectedPermits();

    // Operator misconfiguration AFTER the proposal was queued.
    setChainUrls({ 8453: undefined });
    let r = await approve(q);
    expect(r.status).toBe(500);
    let body = (await r.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toMatch(/RPC endpoint not configured for chainId 8453/);
    expect(body.error).toContain("RPC_URL_8453");

    let qr = await queueRow(q.txId);
    expect(qr?.status).toBe("pending");
    expect(qr?.issuanceClaimedAt).toBeNull();
    expect(await vaultLib.isProtectedIssuanceClaimed(q.txId)).toBe(false);
    expect((await txRow(q.txId))?.status).toBe("pending");
    expect(vaultLib.outstandingProtectedPermits()).toBe(outstandingBefore);
    expect(sent.length - before).toBe(0);

    // http:// is equally a configuration error: nothing consumed.
    setChainUrls({ 8453: HTTP_URL });
    r = await approve(q);
    expect(r.status).toBe(500);
    body = (await r.json()) as { ok: boolean; error: string };
    expect(body.error).toMatch(/must be an https URL/);
    expectNoLeak(body.error);
    qr = await queueRow(q.txId);
    expect(qr?.status).toBe("pending");
    expect(qr?.issuanceClaimedAt).toBeNull();
    expect(sent.length - before).toBe(0);

    // Fix the configuration: the SAME approval is still usable.
    setChainUrls({ 8453: GOOD_URL });
    r = await approve(q);
    expect(r.status).toBe(200);
    const ok = (await r.json()) as { ok: boolean; data: { txId: string; txHash: string } };
    expect(ok.ok).toBe(true);
    expect(ok.data.txId).toBe(q.txId);
    expect(ok.data.txHash.startsWith("0x")).toBe(true);
    qr = await queueRow(q.txId);
    expect(qr?.status).toBe("approved");
    expect(qr?.issuanceClaimedAt).not.toBeNull();
    expect((await txRow(q.txId))?.status).toBe("signed");
    expect(sent.length - before).toBe(1);
    expect(vaultLib.outstandingProtectedPermits()).toBe(outstandingBefore);

    // A second approval of the spent row cannot mint a second broadcast.
    r = await approve(q);
    expect([403, 409]).toContain(r.status);
    expect(sent.length - before).toBe(1);
  });

  it("direct Vault call with a live permit and 8453 endpoint missing: permit NOT consumed, usable once config is fixed; one broadcast", async () => {
    setChainUrls({ 8453: GOOD_URL });
    const q = await queue();
    expect(q.status).toBe(202);
    // Human claim without signing (CAS only), then issue the one-use permit.
    const claim = await db
      .update(approvalQueue)
      .set({ status: "approved", resolvedAt: new Date(), resolvedBy: `user:${OWNER_USER}` })
      .where(eq(approvalQueue.txId, q.txId))
      .returning({ id: approvalQueue.id });
    expect(claim.length).toBe(1);
    const permit = await vaultLib.issueProtectedSigningPermit({
      tenantId: TENANT,
      agentId: AGENT,
      txId: q.txId,
      reviewDigest: q.reviewDigest,
    });
    const outstanding = vaultLib.outstandingProtectedPermits();
    const before = sent.length;
    const req = {
      to: q.to,
      value: q.value,
      data: q.data,
      chainId: q.chainId,
      executionRef: q.executionRef,
      tenantId: TENANT,
      agentId: AGENT,
      broadcast: true,
    } as never;
    const opts = { txId: q.txId, protectedPermit: permit, protectedReviewDigest: q.reviewDigest };

    setChainUrls({ 8453: undefined });
    let error = "";
    try {
      await vault.signTransaction(req, opts);
    } catch (e) {
      error = String(e);
    }
    expect(error).toMatch(/RPC endpoint not configured for chainId 8453/);
    // Preflight threw ABOVE the permit consume: the permit is still live.
    expect(vaultLib.outstandingProtectedPermits()).toBe(outstanding);
    expect(sent.length - before).toBe(0);
    expect((await txRow(q.txId))?.status).toBe("pending");

    setChainUrls({ 8453: HTTP_URL });
    error = "";
    try {
      await vault.signTransaction(req, opts);
    } catch (e) {
      error = String(e);
    }
    expect(error).toMatch(/must be an https URL/);
    expectNoLeak(error);
    expect(vaultLib.outstandingProtectedPermits()).toBe(outstanding);
    expect(sent.length - before).toBe(0);

    // Fixed: the same permit signs exactly once and is then spent.
    setChainUrls({ 8453: GOOD_URL });
    const hash = await vault.signTransaction(req, opts);
    expect(hash.startsWith("0x")).toBe(true);
    expect(sent.length - before).toBe(1);
    expect(vaultLib.outstandingProtectedPermits()).toBe(outstanding - 1);

    // #28 gate intact: the consumed permit cannot be replayed.
    error = "";
    try {
      await vault.signTransaction(req, opts);
    } catch (e) {
      error = String(e);
    }
    expect(error).toMatch(/already-consumed signing permit/);
    expect(sent.length - before).toBe(1);
  });

  it("protected path RPC failure with a key-bearing endpoint: no URL/host/key in the HTTP body or logs; approval consumed, no broadcast", async () => {
    setChainUrls({ 8453: GOOD_URL });
    const q = await queue();
    expect(q.status).toBe(202);
    const before = sent.length;
    const callsBefore = networkCalls;
    logs.length = 0;

    // Real viem client -> interceptor replies with a revert that names the URL.
    broadcastMode = "passthrough";
    rpcMode = "revert";
    const r = await approve(q);
    expect([500, 502]).toContain(r.status);
    const text = await r.text();
    expectNoLeak(text);
    const body = JSON.parse(text) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error.length).toBeGreaterThan(0);

    expect(networkCalls).toBeGreaterThan(callsBefore); // the protected client really hit the resolver's endpoint
    expect(sent.length - before).toBe(0);
    expectNoLeak(logs.join("\n"));
    expect(logs.join("\n")).toMatch(/Protected approve failed/);

    // #28 fail-closed rule: the claim is spent, the row is terminal, no re-issue.
    const qr = await queueRow(q.txId);
    expect(qr?.status).toBe("approved");
    expect(qr?.issuanceClaimedAt).not.toBeNull();
    expect((await txRow(q.txId))?.status).toBe("failed");
    expect(vaultLib.outstandingProtectedPermits()).toBe(0);
  });

  it("protected broadcast builds its client only from the explicit resolver (never CHAIN_RPCS / config.rpcUrl)", async () => {
    const q = await queue();
    expect(q.status).toBe(202);
    const seenUrls: string[] = [];
    const prevFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      seenUrls.push(String(input));
      return prevFetch(input, init);
    }) as typeof fetch;
    try {
      broadcastMode = "passthrough";
      const r = await approve(q);
      expect(r.status).toBe(200);
    } finally {
      globalThis.fetch = prevFetch;
    }
    expect(seenUrls.length).toBeGreaterThan(0);
    for (const u of seenUrls) expect(u).toBe(GOOD_URL);
  });

  it("existing #28 gates hold on the merged tree: wrong digest burns the permit, no broadcast", async () => {
    const q = await queue();
    expect(q.status).toBe(202);
    await db
      .update(approvalQueue)
      .set({ status: "approved", resolvedAt: new Date(), resolvedBy: `user:${OWNER_USER}` })
      .where(eq(approvalQueue.txId, q.txId));
    const permit = await vaultLib.issueProtectedSigningPermit({
      tenantId: TENANT,
      agentId: AGENT,
      txId: q.txId,
      reviewDigest: q.reviewDigest,
    });
    const before = sent.length;
    let error = "";
    try {
      await vault.signTransaction(
        {
          to: q.to,
          value: "1", // substituted bytes
          data: q.data,
          chainId: q.chainId,
          executionRef: q.executionRef,
          tenantId: TENANT,
          agentId: AGENT,
          broadcast: true,
        } as never,
        { txId: q.txId, protectedPermit: permit, protectedReviewDigest: q.reviewDigest },
      );
    } catch (e) {
      error = String(e);
    }
    expect(error).toMatch(/signing permit does not match the approved payload/);
    expect(sent.length - before).toBe(0);
    expect(vaultLib.outstandingProtectedPermits()).toBe(0);
  });
});
