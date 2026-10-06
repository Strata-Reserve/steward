/**
 * STRATA-1499 (SF-1) — contract-allowlist policy end to end.
 *
 * Runs against in-memory PGLite. Proves:
 *   - PUT /agents/:id/policies accepts a well-formed contract-allowlist and
 *     rejects malformed configs with 400 (write-time validation)
 *   - POST /vault/:id/sign is denied (403, no signer call) for out-of-shape
 *     calldata: wrong target, wrong selector, over-cap mint, bad recipient,
 *     hostile calldata, native value, empty calldata
 *   - the compliant mint and createDealToken are signed
 *   - the rejection is recorded on the transactions row with the policy reason
 *
 * `vault.signTransaction` is stubbed so no RPC is touched.
 */

import { afterAll, beforeAll, describe, expect, it, type Mock, spyOn } from "bun:test";
import { generateApiKey } from "@stwd/auth";
import { closeDb, getDb, policies, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { PolicyResult, SignRequest } from "@stwd/shared";
import { eq } from "drizzle-orm";
import type { Hono } from "hono";
import { encodeFunctionData, parseAbi } from "viem";

const TENANT = "ca-tenant";
const AGENT = "ca-minter";
const TOKEN = "0x1111111111111111111111111111111111111111";
const FACTORY = "0x2222222222222222222222222222222222222222";
const SAFE = "0x3333333333333333333333333333333333333333";
const STRANGER = "0x5555555555555555555555555555555555555555";
const SELECTOR_MINT = "0x40c10f19";
const SELECTOR_CREATE_DEAL_TOKEN = "0x0bab7086";
const MAX_MINT = 1_000_000n;

const ABI = parseAbi([
  "function mint(address to, uint256 amount)",
  "function transfer(address to, uint256 amount)",
  "function createDealToken(string name, string symbol, address admin, bytes32 salt)",
]);

let app: Hono;
let apiKey: string;
let signSpy: Mock<(request: SignRequest, options?: unknown) => Promise<string>>;
let signCalls: SignRequest[] = [];

function headers() {
  return {
    "Content-Type": "application/json",
    "X-Steward-Tenant": TENANT,
    "X-Steward-Key": apiKey,
  };
}

function mint(to: string, amount: bigint) {
  return encodeFunctionData({
    abi: ABI,
    functionName: "mint",
    args: [to as `0x${string}`, amount],
  });
}

function createDealToken(admin: string) {
  return encodeFunctionData({
    abi: ABI,
    functionName: "createDealToken",
    args: ["Deal", "DEAL", admin as `0x${string}`, `0x${"ab".repeat(32)}`],
  });
}

function minterPolicy(config?: Record<string, unknown>) {
  return {
    id: "minter-shape",
    type: "contract-allowlist",
    enabled: true,
    config: config ?? {
      contracts: [
        {
          address: FACTORY,
          selectors: [SELECTOR_CREATE_DEAL_TOKEN],
          constraints: { [SELECTOR_CREATE_DEAL_TOKEN]: { adminAllowlist: [SAFE] } },
        },
        {
          address: TOKEN,
          selectors: [SELECTOR_MINT],
          constraints: {
            [SELECTOR_MINT]: { maxAmount: MAX_MINT.toString(), recipientAllowlist: [SAFE] },
          },
        },
      ],
    },
  };
}

function putPolicies(body: unknown) {
  return app.request(`/agents/${AGENT}/policies`, {
    method: "PUT",
    headers: headers(),
    body: JSON.stringify(body),
  });
}

function sign(body: Record<string, unknown>) {
  return app.request(`/vault/${AGENT}/sign`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ chainId: 8453, value: "0", ...body }),
  });
}

async function expectDenied(body: Record<string, unknown>, reasonNeedle: string) {
  const before = signCalls.length;
  const res = await sign(body);
  expect(res.status).toBe(403);
  const json = (await res.json()) as {
    ok: boolean;
    error: string;
    data: { txId: string; results: PolicyResult[] };
  };
  expect(json.ok).toBe(false);
  expect(json.error).toBe("Transaction rejected by policy");
  const result = json.data.results.find((r) => r.type === "contract-allowlist");
  expect(result?.passed).toBe(false);
  expect(result?.reason).toContain(reasonNeedle);
  expect(signCalls.length).toBe(before);

  const [row] = await getDb()
    .select()
    .from(transactions)
    .where(eq(transactions.id, json.data.txId));
  expect(row?.status).toBe("rejected");
  expect(JSON.stringify(row?.policyResults)).toContain(reasonNeedle);
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "contract-allowlist-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "contract-allowlist-audit-key-32-bytes-min-aaaa";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  const key = generateApiKey();
  apiKey = key.key;
  await db.insert(tenants).values({ id: TENANT, name: "Contract Allowlist", apiKeyHash: key.hash });

  ({ app } = await import("../app"));
  const { vault } = await import("../services/context");

  const created = await app.request("/agents", {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ id: AGENT, name: AGENT }),
  });
  if (created.status !== 200) {
    throw new Error(`POST /agents → ${created.status}: ${await created.text()}`);
  }

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

afterAll(async () => {
  signSpy?.mockRestore();
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.DATABASE_URL;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_AUDIT_HMAC_KEY;
});

describe.serial("contract-allowlist policy (STRATA-1499)", () => {
  describe("write-time validation", () => {
    it("rejects malformed configs with 400 and persists nothing", async () => {
      const cases: Array<[Record<string, unknown>, string]> = [
        [{ contracts: [] }, "contracts must be a non-empty array"],
        [{ contracts: [{ address: "0x1", selectors: [SELECTOR_MINT] }] }, "address"],
        [
          {
            contracts: [
              {
                address: TOKEN,
                selectors: [SELECTOR_MINT],
                constraints: { [SELECTOR_MINT]: { maxAmount: "lots" } },
              },
            ],
          },
          "maxAmount",
        ],
        [
          {
            contracts: [
              {
                address: TOKEN,
                selectors: ["0xdeadbeef"],
                constraints: { "0xdeadbeef": { maxAmount: "1" } },
              },
            ],
          },
          "no decoder",
        ],
        [
          { contracts: [{ address: TOKEN, selectors: [SELECTOR_MINT] }], extra: 1 },
          "unknown config",
        ],
      ];
      for (const [config, needle] of cases) {
        const res = await putPolicies([minterPolicy(config)]);
        expect(res.status).toBe(400);
        const body = (await res.json()) as { error: string };
        expect(body.error).toContain('Policy "minter-shape"');
        expect(body.error).toContain(needle);
      }
      const rows = await getDb().select().from(policies).where(eq(policies.agentId, AGENT));
      expect(rows).toHaveLength(0);
    });

    it("rejects a malformed config even when the rule is disabled", async () => {
      const res = await putPolicies([{ ...minterPolicy({ contracts: [] }), enabled: false }]);
      expect(res.status).toBe(400);
    });

    it("rejects malformed applyPolicies on batch agent creation", async () => {
      const res = await app.request("/agents/batch", {
        method: "POST",
        headers: headers(),
        body: JSON.stringify({
          agents: [{ id: "ca-batch-1", name: "batch" }],
          applyPolicies: [minterPolicy({ contracts: [] })],
        }),
      });
      expect(res.status).toBe(400);
    });

    it("accepts the Strata minter policy and lists it as a supported type", async () => {
      const res = await putPolicies([minterPolicy()]);
      expect(res.status).toBe(200);
      const body = (await res.json()) as { data: Array<{ type: string }> };
      expect(body.data.map((p) => p.type)).toEqual(["contract-allowlist"]);

      const unknown = await putPolicies([{ ...minterPolicy(), type: "nope" }]);
      expect(unknown.status).toBe(400);
      expect(((await unknown.json()) as { error: string }).error).toContain("contract-allowlist");
    });
  });

  describe("sign path", () => {
    it("signs a compliant mint and createDealToken", async () => {
      signCalls = [];
      const mintRes = await sign({ to: TOKEN, data: mint(SAFE, MAX_MINT) });
      expect(mintRes.status).toBe(200);
      const deployRes = await sign({ to: FACTORY, data: createDealToken(SAFE) });
      expect(deployRes.status).toBe(200);
      expect(signCalls).toHaveLength(2);
      const body = (await mintRes.json()) as { data: { txId: string } };
      const [row] = await getDb()
        .select()
        .from(transactions)
        .where(eq(transactions.id, body.data.txId));
      expect(row?.status).toBe("signed");
    });

    it("denies a mint above maxAmount", async () => {
      await expectDenied({ to: TOKEN, data: mint(SAFE, MAX_MINT + 1n) }, "exceeds maxAmount");
    });

    it("denies a mint to a non-allowlisted recipient", async () => {
      await expectDenied({ to: TOKEN, data: mint(STRANGER, 1n) }, "not in recipientAllowlist");
    });

    it("denies a mint on an unlisted token contract", async () => {
      await expectDenied({ to: STRANGER, data: mint(SAFE, 1n) }, "not an allowlisted contract");
    });

    it("denies an unlisted selector on a listed contract", async () => {
      const data = encodeFunctionData({ abi: ABI, functionName: "transfer", args: [SAFE, 1n] });
      await expectDenied({ to: TOKEN, data }, "not allowlisted on");
    });

    it("denies createDealToken with a non-Safe admin", async () => {
      await expectDenied({ to: FACTORY, data: createDealToken(STRANGER) }, "not in adminAllowlist");
    });

    it("denies hostile calldata that does not decode", async () => {
      const good = mint(SAFE, 1n);
      await expectDenied({ to: TOKEN, data: good.slice(0, -2) }, "does not decode");
      await expectDenied({ to: TOKEN, data: `${good}00` }, "does not decode");
      await expectDenied(
        { to: TOKEN, data: `${good.slice(0, 10)}f${good.slice(11)}` },
        "does not decode",
      );
    });

    it("denies calldata shorter than a selector", async () => {
      await expectDenied({ to: TOKEN, data: "0x40c1" }, "malformed or shorter");
    });

    it("denies empty calldata (native transfer) by default", async () => {
      await expectDenied({ to: TOKEN, data: "0x" }, "empty calldata");
      await expectDenied({ to: TOKEN }, "empty calldata");
    });

    it("denies native value riding along with a contract call", async () => {
      await expectDenied(
        { to: TOKEN, data: mint(SAFE, 1n), value: "1" },
        "exceeds maxNativeValueWei",
      );
    });

    it("denies everything once the stored config is no longer valid", async () => {
      // Simulate a config that bypassed API validation (e.g. written directly
      // to the DB or by an older build): the evaluator still refuses.
      await getDb()
        .update(policies)
        .set({ config: { contracts: [] } })
        .where(eq(policies.agentId, AGENT));
      await expectDenied({ to: TOKEN, data: mint(SAFE, 1n) }, "invalid config");
      const restore = await putPolicies([minterPolicy()]);
      expect(restore.status).toBe(200);
    });
  });
});
