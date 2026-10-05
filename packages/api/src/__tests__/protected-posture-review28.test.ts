/**
 * STRATA-1499 — REVIEW-STEWARD-28 resolution tests (F1, F2, residuals).
 *
 * Expected to FAIL on 50de32d3 (each on its own assertion) and pass after.
 * In-memory PGLite; vault broadcast seam stubbed; no RPC.
 */

import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import { generateApiKey, signAccessToken, signAgentToken } from "@stwd/auth";
import { closeDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { sql } from "drizzle-orm";
import type { Hono } from "hono";
import { encodeFunctionData, parseAbi } from "viem";

const TENANT = "strata";
const AGENT = "prod-minter-r28";
const OTHER_AGENT = "legacy-agent-r28";
const FACTORY = "0x00000000000000000000000000000000000f0001";
const TOKEN = "0x0000000000000000000000000000000000700001";
const SAFE = "0x3Ea77cDf3eC33603bF4135bb1a36712B5e21d721";
const RECIPIENT = "0x00000000000000000000000000000000000000aa";
const PLACEHOLDER = "0x00000000000000000000000000000000000000ff";
const OWNER_USER = crypto.randomUUID();
const PLATFORM_KEY = "r28-platform-key-for-tests";

const FACTORY_ABI = parseAbi([
  "function createDealToken(string name, string symbol, address admin, address minter, bytes32 salt) returns (address)",
]);
const TOKEN_ABI = parseAbi(["function mint(address to, uint256 amount)"]);

let app: Hono;
let db: Awaited<ReturnType<typeof createPGLiteDb>>["db"];
let rootKey: string;
let signerAddress: string;
let ownerToken: string;
let agentJwt: string;
let vault: Awaited<typeof import("../services/context")>["vault"];
let boundary: typeof import("../services/prod-minter-boundary");
let vaultLib: typeof import("@stwd/vault");
let refCounter = 0;
const ref = () => `strata:r28:${++refCounter}`;

const rootHeaders = () => ({
  "Content-Type": "application/json",
  "X-Steward-Tenant": TENANT,
  "X-Steward-Key": rootKey,
});
const bearer = (t: string) => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${t}`,
});
const platformHeaders = () => ({
  "Content-Type": "application/json",
  "X-Steward-Platform-Key": PLATFORM_KEY,
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
const createCalldata = () =>
  encodeFunctionData({
    abi: FACTORY_ABI,
    functionName: "createDealToken",
    args: ["Deal", "DL", SAFE, signerAddress as `0x${string}`, `0x${"11".repeat(32)}`],
  });

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "r28-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "r28-audit-key-32-bytes-minimum-aaaaaaaaaa";
  process.env.STEWARD_JWT_SECRET = "r28-jwt-secret-with-enough-bytes-aaaaaaaaaa";
  process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;

  const created = await createPGLiteDb("memory://");
  db = created.db;
  setPGLiteOverride(db, async () => created.client.close());
  const k = generateApiKey();
  rootKey = k.key;
  await db.insert(tenants).values({ id: TENANT, name: "Strata", apiKeyHash: k.hash });
  await db.insert(users).values([{ id: OWNER_USER, email: `o-${OWNER_USER}@x.test` }]);
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

  // Legacy agent, no manifest.
  let r = await app.request("/agents", {
    method: "POST",
    headers: rootHeaders(),
    body: JSON.stringify({ id: OTHER_AGENT, name: OTHER_AGENT }),
  });
  if (r.status !== 200) throw new Error(`legacy create ${r.status}`);

  // Protected agent: manifest names it (placeholder pin) while a human creates it; then re-pin.
  boundary.installProtectedMinterManifest(manifest(PLACEHOLDER));
  r = await app.request("/agents", {
    method: "POST",
    headers: bearer(ownerToken),
    body: JSON.stringify({ id: AGENT, name: AGENT }),
  });
  if (r.status !== 200) throw new Error(`protected create ${r.status}: ${await r.text()}`);
  signerAddress = (await r.json()).data.walletAddress;
  boundary.installProtectedMinterManifest(manifest(signerAddress));

  spyOn(vault as never, "broadcastEvm" as never).mockImplementation(
    (async () => `0x${"ab".repeat(32)}`) as never,
  );
});

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
});

describe.serial("REVIEW-STEWARD-28 F1: missing manifest never un-protects", () => {
  it("[F1a] protected creation persists an env-independent marker", async () => {
    const rows = (await db.execute(sql`select protected from agents where id = ${AGENT}`)) as {
      rows?: Array<{ protected: boolean }>;
    };
    const row = (rows.rows ?? (rows as unknown as Array<{ protected: boolean }>))[0];
    expect(row?.protected).toBe(true);
  });

  it("[F1c] startup refuses when a persisted-protected agent has no manifest", async () => {
    const check = (boundary as Record<string, unknown>).assertProtectedPostureAtStartup as
      | (() => Promise<void>)
      | undefined;
    expect(typeof check).toBe("function");
    boundary.installProtectedMinterManifest(null);
    await expect(check!()).rejects.toThrow(/refusing to start/);
    boundary.installProtectedMinterManifest(manifest(signerAddress));
    await expect(check!()).resolves.toBeUndefined();
  });

  it("[F1b] absent manifest: every route on the persisted-protected agent is 403 (root key + human)", async () => {
    boundary.installProtectedMinterManifest(null);
    try {
      for (const h of [rootHeaders(), bearer(ownerToken)]) {
        const calls: Array<[string, string, string?]> = [
          [
            "POST",
            `/vault/${AGENT}/sign`,
            JSON.stringify({
              to: TOKEN,
              value: "0",
              data: mintCalldata(),
              chainId: 8453,
              executionRef: ref(),
            }),
          ],
          ["POST", `/vault/${AGENT}/export`],
          [
            "POST",
            `/vault/${AGENT}/import`,
            JSON.stringify({ privateKey: `0x${"22".repeat(32)}`, chain: "evm" }),
          ],
          ["PUT", `/agents/${AGENT}/policies`, "[]"],
          ["DELETE", `/agents/${AGENT}`],
          ["POST", `/vault/${AGENT}/approve/some-tx`, "{}"],
          ["POST", `/vault/${AGENT}/sign-message`, JSON.stringify({ message: "x" })],
        ];
        for (const [method, path, body] of calls) {
          const r = await app.request(path, { method, headers: h, body });
          expect(`${method} ${path} -> ${r.status}`).toBe(`${method} ${path} -> 403`);
        }
      }
    } finally {
      boundary.installProtectedMinterManifest(manifest(signerAddress));
    }
  });

  it("[F1b] absent manifest: direct Vault calls refused; legacy agent unaffected", async () => {
    boundary.installProtectedMinterManifest(null);
    try {
      await expect(
        vault.signTransaction(
          {
            tenantId: TENANT,
            agentId: AGENT,
            to: TOKEN,
            value: "0",
            data: mintCalldata(),
            chainId: 8453,
            executionRef: ref(),
            broadcast: true,
          } as never,
          {} as never,
        ),
      ).rejects.toThrow(/persisted-protected/);
      await expect(vault.exportPrivateKey(TENANT, AGENT)).rejects.toThrow(/persisted-protected/);
      await expect(vault.signMessage(TENANT, AGENT, "hello")).rejects.toThrow(
        /persisted-protected/,
      );
      // Legacy agent keeps legacy behaviour.
      const sig = await vault.signMessage(TENANT, OTHER_AGENT, "hello");
      expect(sig.startsWith("0x")).toBe(true);
      const r = await app.request(`/vault/${OTHER_AGENT}/addresses`, { headers: rootHeaders() });
      expect(r.status).toBe(200);
    } finally {
      boundary.installProtectedMinterManifest(manifest(signerAddress));
    }
  });
});

describe.serial("REVIEW-STEWARD-28 F2: protected agent JWT allowlist", () => {
  it("[F2] webhook PUT and trade sessions are 403 before handlers", async () => {
    const h = bearer(agentJwt);
    const w = await app.request(`/tenants/${TENANT}/webhook`, {
      method: "PUT",
      headers: h,
      body: JSON.stringify({ webhookUrl: "https://attacker.example/cb", defaultPolicies: [] }),
    });
    expect(w.status).toBe(403);
    const t = await app.request("/trade/sessions", {
      method: "POST",
      headers: h,
      body: JSON.stringify({ agentId: AGENT, venue: "hyperliquid" }),
    });
    expect(t.status).toBe(403);
  });

  it("[F2] enumerated route sweep: 403 everywhere except the own-agent allowlist", async () => {
    const h = bearer(agentJwt);
    const denied: Array<[string, string]> = [
      ["POST", `/vault/${AGENT}/export`],
      ["POST", `/vault/${AGENT}/import`],
      ["POST", `/vault/${AGENT}/sign-message`],
      ["POST", `/vault/${AGENT}/sign-typed-data`],
      ["POST", `/vault/${AGENT}/sign-solana`],
      ["POST", `/vault/${AGENT}/rpc`],
      ["POST", `/vault/${AGENT}/approve/x`],
      ["POST", `/vault/${AGENT}/reject/x`],
      ["GET", `/vault/${AGENT}/pending`],
      ["GET", `/vault/${AGENT}/history`],
      ["GET", `/agents/${AGENT}/policies`],
      ["PUT", `/agents/${AGENT}/policies`],
      ["POST", `/agents/${AGENT}/token`],
      ["POST", `/agents/${AGENT}/wallets`],
      ["DELETE", `/agents/${AGENT}`],
      ["POST", "/agents"],
      ["GET", "/agents"],
      ["POST", "/agents/batch"],
      ["GET", `/agents/${OTHER_AGENT}`],
      ["POST", `/vault/${OTHER_AGENT}/sign`],
      ["GET", `/vault/${OTHER_AGENT}/addresses`],
      ["GET", "/secrets"],
      ["POST", "/secrets"],
      ["PUT", `/tenants/${TENANT}/webhook`],
      ["GET", `/tenants/${TENANT}`],
      ["PUT", `/tenants/${TENANT}/config`],
      ["GET", "/webhooks"],
      ["POST", "/webhooks"],
      ["GET", "/approvals"],
      ["POST", "/approvals/x/approve"],
      ["POST", "/approvals/x/deny"],
      ["PUT", "/approvals/rules"],
      ["GET", "/audit"],
      ["GET", "/policies"],
      ["POST", "/policies"],
      ["POST", "/trade/sessions"],
      ["GET", "/trade/sessions"],
      ["POST", "/v1/trade/sessions"],
      ["GET", "/application-principals"],
      ["GET", "/dashboard/agents"],
    ];
    const results: string[] = [];
    for (const [method, path] of denied) {
      const r = await app.request(path, {
        method,
        headers: h,
        body: method === "GET" ? undefined : "{}",
      });
      if (r.status !== 403) results.push(`${method} ${path} -> ${r.status}`);
    }
    expect(results).toEqual([]);

    const allowed: Array<[string, string, string?]> = [
      [
        "POST",
        `/vault/${AGENT}/sign`,
        JSON.stringify({
          to: TOKEN,
          value: "0",
          data: mintCalldata(),
          chainId: 8453,
          executionRef: ref(),
        }),
      ],
      ["GET", `/vault/${AGENT}/actions/by-ref/nope`],
      ["GET", `/vault/${AGENT}/addresses`],
      ["GET", `/agents/${AGENT}`],
    ];
    for (const [method, path, body] of allowed) {
      const r = await app.request(path, { method, headers: h, body });
      expect(`${method} ${path} -> ${r.status === 403}`).toBe(`${method} ${path} -> false`);
    }
  });
});

describe.serial("REVIEW-STEWARD-28 residuals", () => {
  it("[permit] issuance without a consumed approval is refused", async () => {
    const r = await app.request(`/vault/${AGENT}/sign`, {
      method: "POST",
      headers: bearer(agentJwt),
      body: JSON.stringify({
        to: TOKEN,
        value: "0",
        data: mintCalldata(),
        chainId: 8453,
        executionRef: ref(),
      }),
    });
    expect(r.status).toBe(202);
    const body = await r.json();
    const txId = body.data.txId as string;
    const reviewDigest = body.data.reviewDigest as string;
    let threw = false;
    try {
      await (vaultLib.issueProtectedSigningPermit as unknown as (i: unknown) => Promise<string>)({
        tenantId: TENANT,
        agentId: AGENT,
        txId,
        reviewDigest,
      });
    } catch (e) {
      threw = /no consumed approval/.test(String(e));
    }
    expect(threw).toBe(true);
    expect(vaultLib.outstandingProtectedPermits()).toBe(0);
  });

  it("[calldata] swapped-tail / noncanonical createDealToken is rejected", () => {
    const canonical = createCalldata();
    expect(boundary.decodeCreateDealToken(canonical)?.kind).toBe("createDealToken");
    // Swap the two dynamic tails: symbol tail first, name tail second, with offsets pointing accordingly.
    const hex = canonical.slice(10);
    const words = hex.match(/.{64}/g)!;
    const head = words.slice(0, 5);
    const nameTail = words.slice(5, 7); // len + 1 word ("Deal")
    const symTail = words.slice(7, 9); // len + 1 word ("DL")
    const swappedHead = [...head];
    swappedHead[0] = (32 * 7).toString(16).padStart(64, "0"); // name at 224
    swappedHead[1] = (32 * 5).toString(16).padStart(64, "0"); // symbol at 160
    const swapped = `0x2217bc2d${[...swappedHead, ...symTail, ...nameTail].join("")}`;
    expect(swapped).not.toBe(canonical);
    expect(boundary.decodeCreateDealToken(swapped)).toBeNull();
  });

  it("[platform] platform key cannot delete / batch-policy / token the protected tenant+agent", async () => {
    const h = platformHeaders();
    const d = await app.request(`/platform/tenants/${TENANT}`, { method: "DELETE", headers: h });
    expect(d.status).toBe(403);
    const p = await app.request(`/platform/tenants/${TENANT}/policies`, {
      method: "PUT",
      headers: h,
      body: "[]",
    });
    expect(p.status).toBe(403);
    const b = await app.request(`/platform/tenants/${TENANT}/agents/batch`, {
      method: "POST",
      headers: h,
      body: JSON.stringify({ agents: [{ id: "z", name: "z" }] }),
    });
    expect(b.status).toBe(403);
    const t = await app.request(`/platform/tenants/${TENANT}/agents/${AGENT}/token`, {
      method: "POST",
      headers: h,
      body: "{}",
    });
    expect(t.status).toBe(403);
    const rows = (await db.execute(sql`select id from tenants where id = ${TENANT}`)) as {
      rows?: unknown[];
    };
    expect((rows.rows ?? (rows as unknown as unknown[])).length).toBe(1);
  });

  it("[retention] executionRef tombstones survive for any persisted-protected identity, not only the configured one", async () => {
    const txId = `r28-tomb-${crypto.randomUUID()}`;
    const execRef = ref();
    await db.execute(sql`
      insert into transactions (id, agent_id, tenant_id, chain_id, status, to_address, value, data, execution_ref, created_at)
      values (${txId}, ${AGENT}, ${TENANT}, 8453, 'failed', ${TOKEN}, '0', null, ${execRef}, now() - interval '400 days')
    `);
    // Point the manifest at a different identity so only the persisted marker can protect the row.
    boundary.installProtectedMinterManifest({
      ...manifest(signerAddress),
      agentId: "some-other-id",
    });
    try {
      const { runRetentionSweep } = await import("../services/retention");
      await runRetentionSweep();
    } finally {
      boundary.installProtectedMinterManifest(manifest(signerAddress));
    }
    const rows = (await db.execute(sql`select id from transactions where id = ${txId}`)) as {
      rows?: unknown[];
    };
    expect((rows.rows ?? (rows as unknown as unknown[])).length).toBe(1);
  });
});
