/**
 * STRATA-1499 — REVIEW-STEWARD-27 F1 + F2 regression tests (ported from the
 * independent review, inverted to assert the FIXED behaviour).
 *
 * F1: a missing / non-https Base endpoint is a deterministic configuration
 *     error. It must make NO row change and consume NO approval; the same
 *     request must succeed once the configuration is fixed.
 * F2: a configured endpoint that then fails (RPC revert or transport error)
 *     must never appear in the HTTP body, console output or webhook payload.
 *
 * Network: `globalThis.fetch` is replaced with a local interceptor before the
 * app is imported. Run with `--preload ./scripts/test-no-network-preload.ts`
 * for the fail-closed guard; nothing here falls back to real fetch.
 */

import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import { inspect } from "node:util";
import { generateApiKey } from "@stwd/auth";
import { approvalQueue, getDb, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";

const T = "preflight-tenant";
const A = "preflight-agent";
const TO = "0x000000000000000000000000000000000000dEaD";
const HOST = "explicit-mainnet.invalid";
const KEY = "SYNTHETIC_REVIEW_KEY";
const PATH = `/v2/${KEY}`;
const URL = `https://${HOST}${PATH}`;
const HASH = `0x${"a".repeat(64)}`;
const WEBHOOK_URL = "https://webhook-sink.invalid/hook";

let app: Awaited<typeof import("../app")>["app"];
let vault: Awaited<typeof import("../services/context")>["vault"];
let tenantConfigs: Awaited<typeof import("../services/context")>["tenantConfigs"];
let client: { close(): Promise<void> };
let key: string;
let networkCalls = 0;
let rpcMode: "ok" | "revert" | "transport" = "ok";
const webhookBodies: string[] = [];
const logs: string[] = [];
const realFetch = globalThis.fetch;
let logSpy: ReturnType<typeof spyOn> | undefined;

const headers = () => ({
  "Content-Type": "application/json",
  "X-Steward-Tenant": T,
  "X-Steward-Key": key,
});
const sign = (chainId: number, ref: string, broadcast = true) =>
  app.request(`/vault/${A}/sign`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ to: TO, value: "1", chainId, executionRef: ref, broadcast }),
  });
const approve = (txId: string) =>
  app.request(`/vault/${A}/approve/${txId}`, { method: "POST", headers: headers(), body: "{}" });
const rows = (ref: string) =>
  getDb()
    .select()
    .from(transactions)
    .where(and(eq(transactions.agentId, A), eq(transactions.executionRef, ref)));
const allRows = () => getDb().select().from(transactions).where(eq(transactions.agentId, A));

function setChainUrls(urls: Record<number, string | undefined>) {
  (
    vault as unknown as { config: { chainRpcUrls: Record<number, string | undefined> } }
  ).config.chainRpcUrls = urls;
}

async function flushWebhooks() {
  for (let i = 0; i < 20; i++) await new Promise((r) => setTimeout(r, 5));
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "preflight-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "preflight-audit-key-32-bytes-minimum-aaaa";
  process.env.RPC_URL = "https://generic.invalid/forbidden";
  // Tenant-config webhooks sign with this secret; without it the dispatcher
  // throws before fetch and the webhook-payload assertions would be vacuous.
  process.env.STEWARD_WEBHOOK_SECRET = "preflight-webhook-secret";
  delete process.env.RPC_URL_8453;
  delete process.env.RPC_URL_84532;

  const db = await createPGLiteDb("memory://");
  client = db.client;
  setPGLiteOverride(db.db as never, async () => client.close());
  const k = generateApiKey();
  key = k.key;
  await getDb().insert(tenants).values({ id: T, name: T, apiKeyHash: k.hash });

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === WEBHOOK_URL) {
      webhookBodies.push(String(init?.body ?? ""));
      return new Response("ok", { status: 200 });
    }
    networkCalls++;
    if (rpcMode === "transport") {
      throw new Error(`mock transport cannot connect to ${url}`);
    }
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
        result = url.startsWith("https://explicit-sepolia") ? "0x14a34" : "0x2105";
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

  logSpy = spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    logs.push(args.map((a) => (typeof a === "string" ? a : inspect(a, { depth: 6 }))).join(" "));
  });

  ({ app } = await import("../app"));
  ({ vault, tenantConfigs } = await import("../services/context"));
  await vault.createAgent(T, A, A);
  tenantConfigs.set(T, { ...(tenantConfigs.get(T) ?? {}), webhookUrl: WEBHOOK_URL } as never);
});

afterAll(async () => {
  globalThis.fetch = realFetch;
  logSpy?.mockRestore();
  await client.close();
  delete process.env.STEWARD_WEBHOOK_SECRET;
});

const goodUrl = (chainId: number) =>
  chainId === 84532 ? `https://explicit-sepolia.invalid${PATH}` : URL;

describe.serial("F1: configuration errors mutate nothing and are recoverable", () => {
  for (const chainId of [8453, 84532]) {
    for (const bad of [undefined, `http://unsafe.invalid${PATH}`]) {
      const label = bad ? "non-https" : "missing";

      it(`${label} ${chainId}: /sign makes zero new rows, then succeeds once after the fix`, async () => {
        setChainUrls({ [chainId]: bad });
        rpcMode = "ok";
        const ref = `preflight:${chainId}:${label}:sign`;
        const before = (await allRows()).length;
        networkCalls = 0;

        const res = await sign(chainId, ref);
        expect(res.status).toBe(500);
        const body = (await res.json()) as { ok: boolean; error: string };
        expect(body.ok).toBe(false);
        expect(body.error).toContain(`RPC_URL_${chainId}`);
        if (bad) expect(body.error).not.toContain("unsafe.invalid");
        expect(await rows(ref)).toHaveLength(0);
        expect((await allRows()).length).toBe(before);
        expect(networkCalls).toBe(0);

        // Fix the configuration: the SAME request now succeeds exactly once.
        setChainUrls({ [chainId]: goodUrl(chainId) });
        const fixed = await sign(chainId, ref);
        expect(fixed.status).toBe(200);
        const fb = (await fixed.json()) as { data: { txId: string; txHash: string } };
        expect(fb.data.txHash).toBe(HASH);
        expect(networkCalls).toBeGreaterThan(0);
        const r = await rows(ref);
        expect(r).toHaveLength(1);
        expect(r[0]?.status).toBe("signed");

        // Replay under the same ref: same action, no re-sign.
        const sends = networkCalls;
        const replay = await sign(chainId, ref);
        const rb = (await replay.json()) as { data: { txId: string; replayed: boolean } };
        expect(rb.data.txId).toBe(fb.data.txId);
        expect(rb.data.replayed).toBe(true);
        expect(networkCalls).toBe(sends);
        expect(await rows(ref)).toHaveLength(1);
      });

      it(`${label} ${chainId}: approve leaves the approval pending and the tx unchanged, then succeeds once after the fix`, async () => {
        const ref = `preflight:${chainId}:${label}:approve`;
        const id = crypto.randomUUID();
        await getDb().insert(transactions).values({
          id,
          tenantId: T,
          agentId: A,
          executionRef: ref,
          status: "pending",
          toAddress: TO,
          value: "1",
          chainId,
        });
        await getDb()
          .insert(approvalQueue)
          .values({
            id: crypto.randomUUID(),
            agentId: A,
            txId: id,
            status: "pending",
            reason: "manual",
          });
        setChainUrls({ [chainId]: bad });
        rpcMode = "ok";
        networkCalls = 0;

        const res = await approve(id);
        expect(res.status).toBe(500);
        expect(((await res.json()) as { error: string }).error).toContain(`RPC_URL_${chainId}`);
        const [claim] = await getDb()
          .select()
          .from(approvalQueue)
          .where(eq(approvalQueue.txId, id));
        expect(claim?.status).toBe("pending");
        expect(claim?.resolvedAt).toBeNull();
        const [tx] = await rows(ref);
        expect(tx?.status).toBe("pending");
        expect(tx?.txHash).toBeNull();
        expect(networkCalls).toBe(0);

        // Fix the configuration: the SAME approval now succeeds exactly once.
        setChainUrls({ [chainId]: goodUrl(chainId) });
        const fixed = await approve(id);
        expect(fixed.status).toBe(200);
        expect(((await fixed.json()) as { data: { txHash: string } }).data.txHash).toBe(HASH);
        expect(networkCalls).toBeGreaterThan(0);
        const [claim2] = await getDb()
          .select()
          .from(approvalQueue)
          .where(eq(approvalQueue.txId, id));
        expect(claim2?.status).toBe("approved");
        expect((await rows(ref))[0]?.status).toBe("signed");

        // Second approval: 409, nothing resent.
        const sends = networkCalls;
        expect((await approve(id)).status).toBe(409);
        expect(networkCalls).toBe(sends);
      });
    }
  }

  it("ambiguous post-broadcast failure keeps the no-release / no-resend behaviour", async () => {
    const ref = "preflight:ambiguous:approve";
    const id = crypto.randomUUID();
    await getDb().insert(transactions).values({
      id,
      tenantId: T,
      agentId: A,
      executionRef: ref,
      status: "pending",
      toAddress: TO,
      value: "1",
      chainId: 8453,
    });
    await getDb()
      .insert(approvalQueue)
      .values({
        id: crypto.randomUUID(),
        agentId: A,
        txId: id,
        status: "pending",
        reason: "manual",
      });
    setChainUrls({ 8453: URL });
    rpcMode = "revert";
    const res = await approve(id);
    expect(res.status).toBe(502);
    const [claim] = await getDb().select().from(approvalQueue).where(eq(approvalQueue.txId, id));
    expect(claim?.status).toBe("approved");
    expect((await rows(ref))[0]?.status).toBe("failed");
    rpcMode = "ok";
    expect((await approve(id)).status).toBe(409);
    expect((await rows(ref))[0]?.status).toBe("failed");
  });
});

describe.serial("F2: configured endpoint never leaks through errors", () => {
  const leakFree = (s: string) => {
    expect(s).not.toContain(URL);
    expect(s).not.toContain(HOST);
    expect(s).not.toContain(PATH);
    expect(s).not.toContain(KEY);
  };

  for (const mode of ["revert", "transport"] as const) {
    it(`${mode}: /sign HTTP body + console + webhook payload contain none of host, path or key`, async () => {
      setChainUrls({ 8453: URL });
      rpcMode = mode;
      logs.length = 0;
      webhookBodies.length = 0;
      networkCalls = 0;

      const res = await sign(8453, `preflight:leak:${mode}`, false);
      expect(networkCalls).toBeGreaterThan(0);
      expect([500, 502]).toContain(res.status);
      const body = JSON.stringify(await res.json());
      leakFree(body);

      await flushWebhooks();
      expect(logs.length).toBeGreaterThan(0);
      for (const line of logs) leakFree(line);
      // Earlier tests' fire-and-forget deliveries may still be landing; every
      // payload must be leak-free and at least one must be this tx_failed.
      expect(webhookBodies.some((p) => p.includes("tx_failed"))).toBe(true);
      for (const payload of webhookBodies) leakFree(payload);
      rpcMode = "ok";
    });
  }

  it("transport: /rpc passthrough response + console contain none of host, path or key", async () => {
    setChainUrls({ 8453: URL });
    rpcMode = "transport";
    logs.length = 0;
    const res = await app.request(`/vault/${A}/rpc`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        chainId: 8453,
        method: "eth_getTransactionReceipt",
        params: ["0x1234"],
      }),
    });
    expect(res.status).toBe(400);
    const body = JSON.stringify(await res.json());
    leakFree(body);
    expect(body).toContain("[redacted-rpc-endpoint]");
    for (const line of logs) leakFree(line);
    rpcMode = "ok";
  });
});
