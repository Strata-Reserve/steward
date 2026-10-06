/**
 * STRATA-1499 (SF-1): `calldata-amount-window` on POST /vault/:agentId/sign.
 *
 * Runs against an in-memory PGLite so the window sum is computed from real
 * `transactions` rows by the API-bound history lookup. `vault.signTransaction`
 * is replaced with a fake that mirrors the real upsert-and-return-hash
 * behaviour, so every signature is observable as a spy call and no RPC is
 * ever touched.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it, type Mock, spyOn } from "bun:test";
import { generateApiKey } from "@stwd/auth";
import { approvalQueue, closeDb, getDb, policies, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { SignRequest } from "@stwd/shared";
import { eq } from "drizzle-orm";
import type { Hono } from "hono";

const TENANT = "caw-tenant";
const AGENT = "caw-minter";
const TOKEN = "0x1111111111111111111111111111111111111111";
const OTHER_TOKEN = "0x2222222222222222222222222222222222222222";
const SAFE = "0x3333333333333333333333333333333333333333";
const SELECTOR_MINT = "0x40c10f19";
const SELECTOR_TRANSFER = "0xa9059cbb";
const CHAIN = 8453;
const POLICY_ID = "caw-mint-cap";

let app: Hono;
let apiKey: string;
let vault: Awaited<typeof import("../services/context")>["vault"];
let signSpy: Mock<(request: SignRequest, options?: unknown) => Promise<string>>;
let signCalls: SignRequest[] = [];

function word(value: bigint | string): string {
  const hex = typeof value === "bigint" ? value.toString(16) : value.replace(/^0x/, "");
  return hex.padStart(64, "0");
}

function mintCalldata(amount: bigint, selector = SELECTOR_MINT): string {
  return `${selector}${word(SAFE)}${word(amount)}`;
}

function headers() {
  return {
    "Content-Type": "application/json",
    "X-Steward-Tenant": TENANT,
    "X-Steward-Key": apiKey,
  };
}

function sign(body: Record<string, unknown>, extraHeaders: Record<string, string> = {}) {
  return app.request(`/vault/${AGENT}/sign`, {
    method: "POST",
    headers: { ...headers(), ...extraHeaders },
    body: JSON.stringify(body),
  });
}

function mint(amount: bigint, overrides: Record<string, unknown> = {}) {
  return sign({
    to: TOKEN,
    value: "0",
    data: mintCalldata(amount),
    chainId: CHAIN,
    ...overrides,
  });
}

function putPolicies(body: unknown) {
  return app.request(`/agents/${AGENT}/policies`, {
    method: "PUT",
    headers: headers(),
    body: JSON.stringify(body),
  });
}

function mintCapPolicy(maxPerWindow: string, extra: Record<string, unknown> = {}) {
  return {
    id: POLICY_ID,
    type: "calldata-amount-window",
    enabled: true,
    config: {
      rules: [
        {
          contract: TOKEN,
          selector: SELECTOR_MINT,
          amountArgIndex: 1,
          maxPerWindow,
          windowSeconds: 86400,
        },
      ],
      ...extra,
    },
  };
}

async function setMintCap(maxPerWindow: string, extra: Record<string, unknown> = {}) {
  const res = await putPolicies([mintCapPolicy(maxPerWindow, extra)]);
  if (res.status !== 200) throw new Error(`PUT policies → ${res.status}: ${await res.text()}`);
}

async function clearAgentState() {
  const db = getDb();
  await db.delete(approvalQueue).where(eq(approvalQueue.agentId, AGENT));
  await db.delete(transactions).where(eq(transactions.agentId, AGENT));
  await db.delete(policies).where(eq(policies.agentId, AGENT));
  signCalls = [];
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "caw-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "caw-audit-key-32-bytes-minimum-aaaaaaaaaaaaa";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  const generated = generateApiKey();
  apiKey = generated.key;
  await db.insert(tenants).values({ id: TENANT, name: "CAW", apiKeyHash: generated.hash });

  ({ app } = await import("../app"));
  ({ vault } = await import("../services/context"));

  const created = await app.request("/agents", {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ id: AGENT, name: AGENT }),
  });
  if (created.status !== 200) throw new Error(`POST /agents → ${created.status}`);

  signSpy = spyOn(vault, "signTransaction").mockImplementation(
    async (request: SignRequest, options: unknown = {}) => {
      const opts = options as { txId?: string; policyResults?: unknown[] };
      signCalls.push(request);
      const txId = opts.txId ?? crypto.randomUUID();
      const hash = `0x${signCalls.length.toString(16).padStart(64, "0")}`;
      const now = new Date();
      await getDb()
        .insert(transactions)
        .values({
          id: txId,
          agentId: request.agentId,
          status: "signed",
          toAddress: request.to,
          value: request.value,
          data: request.data,
          chainId: request.chainId,
          txHash: hash,
          policyResults: (opts.policyResults as never) ?? [],
          signedAt: now,
          createdAt: now,
        })
        .onConflictDoUpdate({
          target: transactions.id,
          set: { status: "signed", txHash: hash, signedAt: now },
        });
      return hash;
    },
  );
});

beforeEach(clearAgentState);

afterAll(async () => {
  signSpy?.mockRestore();
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.DATABASE_URL;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_AUDIT_HMAC_KEY;
});

describe.serial("calldata-amount-window on /vault/:agentId/sign (STRATA-1499)", () => {
  it("signs mints under the cap and denies the one that crosses it without signing", async () => {
    await setMintCap("1000");

    const first = await mint(600n);
    expect(first.status).toBe(200);
    expect(signCalls).toHaveLength(1);

    const second = await mint(400n); // sum == cap, allowed
    expect(second.status).toBe(200);
    expect(signCalls).toHaveLength(2);

    const third = await mint(1n); // sum would be 1001
    expect(third.status).toBe(403);
    const body = (await third.json()) as {
      ok: boolean;
      error: string;
      data: { txId: string; results: Array<{ type: string; passed: boolean; reason?: string }> };
    };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Transaction rejected by policy");
    const result = body.data.results.find((r) => r.type === "calldata-amount-window");
    expect(result?.passed).toBe(false);
    expect(result?.reason).toContain("prior 1000");
    expect(result?.reason).toContain("cap 1000");
    expect(signCalls).toHaveLength(2);

    const [rejectedRow] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, body.data.txId));
    expect(rejectedRow?.status).toBe("rejected");
    expect(rejectedRow?.txHash).toBeNull();
  });

  it("does not count rejected rows toward the window", async () => {
    await setMintCap("1000");
    expect((await mint(5000n)).status).toBe(403);
    expect((await mint(5000n)).status).toBe(403);
    expect(signCalls).toHaveLength(0);
    // Window still empty: a within-cap mint signs.
    expect((await mint(1000n)).status).toBe(200);
    expect(signCalls).toHaveLength(1);
  });

  it("does not count failed rows toward the window", async () => {
    await setMintCap("1000");
    signSpy.mockImplementationOnce(async () => {
      throw new Error("insufficient funds for gas * price + value");
    });
    const failed = await mint(900n, { executionRef: "caw:failed:1" });
    expect(failed.status).toBe(502);
    const [failedRow] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.executionRef, "caw:failed:1"));
    expect(failedRow?.status).toBe("failed");

    expect((await mint(1000n)).status).toBe(200);
  });

  it("counts a queued (pending approval) mint toward the window", async () => {
    await setMintCap("1000", { overCap: "manual-approval" });
    const auto = {
      id: "caw-auto",
      type: "auto-approve-threshold",
      enabled: true,
      config: { threshold: "0" },
    };
    await putPolicies([mintCapPolicy("1000", { overCap: "manual-approval" }), auto]);

    // value "1" > threshold 0 → queued, not signed. Row is `pending`.
    const queued = await mint(700n, { value: "1" });
    expect(queued.status).toBe(202);
    expect(signCalls).toHaveLength(0);

    // 700 pending + 400 → over cap → queued by the window rule as well
    // (overCap manual-approval), still not signed.
    const next = await mint(400n, { value: "1" });
    expect(next.status).toBe(202);
    const body = (await next.json()) as {
      data: { results: Array<{ type: string; passed: boolean }> };
    };
    const windowResult = body.data.results.find((r) => r.type === "calldata-amount-window");
    expect(windowResult?.passed).toBe(false);
    expect(signCalls).toHaveLength(0);
  });

  it("queues instead of rejecting when overCap is manual-approval", async () => {
    await setMintCap("1000", { overCap: "manual-approval" });
    expect((await mint(1000n)).status).toBe(200);
    const over = await mint(1n);
    expect(over.status).toBe(202);
    const body = (await over.json()) as { data: { txId: string; status: string } };
    expect(body.data.status).toBe("pending_approval");
    expect(signCalls).toHaveLength(1);
    const queue = await getDb()
      .select()
      .from(approvalQueue)
      .where(eq(approvalQueue.txId, body.data.txId));
    expect(queue).toHaveLength(1);
    expect(queue[0]?.status).toBe("pending");
  });

  it("does not count the request's own executionRef reservation against itself", async () => {
    await setMintCap("1000");
    const res = await mint(1000n, { executionRef: "caw:self:1" });
    expect(res.status).toBe(200);
    expect(signCalls).toHaveLength(1);
  });

  it("binds a window denial to its executionRef (replay stays 403, never signs)", async () => {
    await setMintCap("1000");
    expect((await mint(1000n)).status).toBe(200);
    const denied = await mint(1n, { executionRef: "caw:denied:1" });
    expect(denied.status).toBe(403);
    // Even after the window would have room, the reference is bound to the
    // rejected action.
    await getDb().delete(policies).where(eq(policies.agentId, AGENT));
    const replay = await mint(1n, { executionRef: "caw:denied:1" });
    expect(replay.status).toBe(403);
    expect(((await replay.json()) as { data: { replayed: boolean } }).data.replayed).toBe(true);
    expect(signCalls).toHaveLength(1);
  });

  it("scopes the window per contract, selector and chain", async () => {
    await setMintCap("1000");
    expect((await mint(1000n)).status).toBe(200);
    // Same selector, other contract: not governed, passes (unmatched: pass).
    expect((await mint(5000n, { to: OTHER_TOKEN })).status).toBe(200);
    // Same contract, other selector: not governed.
    expect(
      (
        await sign({
          to: TOKEN,
          value: "0",
          data: mintCalldata(5000n, SELECTOR_TRANSFER),
          chainId: CHAIN,
        })
      ).status,
    ).toBe(200);
    // Same contract + selector, other chain: separate window.
    expect((await mint(1000n, { chainId: 84532 })).status).toBe(200);
    // Back on the governed chain the window is full.
    expect((await mint(1n)).status).toBe(403);
    expect(signCalls).toHaveLength(4);
  });

  it("is case-insensitive on the contract address", async () => {
    await setMintCap("1000");
    const mixedCase = "0xAbCd000000000000000000000000000000000001";
    await putPolicies([
      {
        ...mintCapPolicy("1000"),
        config: {
          rules: [
            {
              contract: mixedCase.toLowerCase(),
              selector: SELECTOR_MINT,
              amountArgIndex: 1,
              maxPerWindow: "1000",
              windowSeconds: 86400,
            },
          ],
        },
      },
    ]);
    expect((await mint(600n, { to: mixedCase })).status).toBe(200);
    expect((await mint(401n, { to: mixedCase.toLowerCase() })).status).toBe(403);
    expect((await mint(400n, { to: mixedCase.toUpperCase().replace("0X", "0x") })).status).toBe(
      200,
    );
    expect(signCalls).toHaveLength(2);
  });

  it("denies with unmatched: deny for anything the rules do not cover", async () => {
    await setMintCap("1000", { unmatched: "deny" });
    expect((await mint(1n, { to: OTHER_TOKEN })).status).toBe(403);
    expect((await sign({ to: TOKEN, value: "1", chainId: CHAIN })).status).toBe(403);
    expect((await mint(1n)).status).toBe(200);
  });

  it("denies malformed calldata to the governed contract", async () => {
    await setMintCap("1000");
    for (const data of ["0x40c1", "0x40c10f19" + word(SAFE)]) {
      const res = await sign({ to: TOKEN, value: "0", data, chainId: CHAIN });
      expect(res.status).toBe(403);
    }
    expect(signCalls).toHaveLength(0);
  });

  it("denies when a stored policy config is malformed", async () => {
    // Bypass the API validation to simulate a hand-edited row.
    await getDb()
      .insert(policies)
      .values({
        id: POLICY_ID,
        agentId: AGENT,
        type: "calldata-amount-window",
        enabled: true,
        config: { rules: [{ contract: TOKEN, selector: "bad", amountArgIndex: 1 }] },
      });
    const res = await mint(1n, { to: OTHER_TOKEN });
    expect(res.status).toBe(403);
    const body = (await res.json()) as {
      data: { results: Array<{ type: string; reason?: string }> };
    };
    expect(body.data.results.find((r) => r.type === "calldata-amount-window")?.reason).toContain(
      "invalid config",
    );
    expect(signCalls).toHaveLength(0);
  });

  it("counts the mint that was actually signed, not the request-supplied value", async () => {
    await setMintCap("1000");
    // `value` (native wei) is irrelevant to the window; the decoded amount is.
    expect((await mint(1000n, { value: "0" })).status).toBe(200);
    expect((await mint(1n, { value: "0", priorSum: "0" })).status).toBe(403);
  });
});

describe.serial("calldata-amount-window policy writes (STRATA-1499)", () => {
  it("accepts a well-formed policy on PUT /agents/:id/policies", async () => {
    const res = await putPolicies([mintCapPolicy("1000")]);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: Array<{ type: string }> };
    expect(body.data.map((p) => p.type)).toEqual(["calldata-amount-window"]);
  });

  it("rejects malformed configs at write time", async () => {
    const cases: unknown[] = [
      { ...mintCapPolicy("1000"), config: {} },
      { ...mintCapPolicy("1000"), config: { rules: [] } },
      mintCapPolicy("-1"),
      mintCapPolicy("1e18"),
      {
        ...mintCapPolicy("1"),
        config: {
          rules: [
            {
              contract: "0x12",
              selector: SELECTOR_MINT,
              amountArgIndex: 1,
              maxPerWindow: "1",
              windowSeconds: 1,
            },
          ],
        },
      },
      {
        ...mintCapPolicy("1"),
        config: {
          rules: [
            {
              contract: TOKEN,
              selector: SELECTOR_MINT,
              amountArgIndex: 1,
              maxPerWindow: "1",
              windowSeconds: 0,
            },
          ],
        },
      },
      mintCapPolicy("1", { overCap: "ignore" }),
      mintCapPolicy("1", { unmatched: "allow" }),
    ];
    for (const policy of cases) {
      const res = await putPolicies([policy]);
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error: string };
      expect(body.error).toContain(POLICY_ID);
    }
    // A disabled rule is validated too.
    const disabled = await putPolicies([{ ...mintCapPolicy("-1"), enabled: false }]);
    expect(disabled.status).toBe(400);
  });

  it("rejects malformed applyPolicies on POST /agents/batch", async () => {
    const res = await app.request("/agents/batch", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        agents: [{ id: "caw-batch-1", name: "batch" }],
        applyPolicies: [mintCapPolicy("-1")],
      }),
    });
    expect(res.status).toBe(400);
  });
});
