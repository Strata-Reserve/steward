/**
 * STRATA-1499 SF-1 delta B1: a protected-minter manifest/signer is bound to
 * exactly ONE chain.
 *
 * Unit half: manifest/env parsing refuses no-chain, two-chain and
 * non-allowlisted chains; `validateProtectedShape` is bound to the manifest's
 * chain in both directions (8453 manifest refuses 84532 tx and vice versa);
 * the digest differs per chain.
 *
 * Integration half: a separately pinned 84532 (Base Sepolia rehearsal)
 * manifest installed in this process. The protected agent's own JWT cannot
 * propose for 8453; a valid 84532 proposal queues; a row whose chainId is
 * substituted to 8453 in storage after queueing is refused at signing; the
 * approved 84532 proposal signs exactly 84532 bytes.
 *
 * This file is adversarial for the 84532 binding; the existing SF-1 suite
 * (protected-minter-boundary.test.ts) remains the 8453 oracle and must pass
 * unchanged.
 */
import { afterAll, beforeAll, describe, expect, it, type Mock, spyOn } from "bun:test";
import { generateApiKey, signAccessToken, signAgentToken } from "@stwd/auth";
import {
  approvalQueue,
  closeDb,
  getDb,
  tenants,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import type { Hono } from "hono";
import { encodeFunctionData, parseAbi } from "viem";

const TENANT = "strata-rehearsal";
const AGENT = "rehearsal-minter";
const FACTORY = "0x00000000000000000000000000000000000f0002";
const TOKEN = "0x0000000000000000000000000000000000700003";
const SAFE = "0x3Ea77cDf3eC33603bF4135bb1a36712B5e21d721";
const RECIPIENT = "0x00000000000000000000000000000000000000ab";
const OWNER_USER = crypto.randomUUID();

const TOKEN_ABI = parseAbi(["function mint(address to, uint256 amount)"]);

let app: Hono;
let rootKey: string;
let signerAddress: string;
let ownerToken: string;
let agentJwt: string;
let vault: Awaited<typeof import("../services/context")>["vault"];
let boundary: typeof import("../services/prod-minter-boundary");
let sendSpy: Mock<(...args: unknown[]) => Promise<unknown>>;
const signedBytes: Array<{ to: string; value: bigint; data?: string; chainId: number }> = [];
let refCounter = 0;
const ref = () => `rehearsal:test:${++refCounter}`;

const rootHeaders = () => ({
  "Content-Type": "application/json",
  "X-Steward-Tenant": TENANT,
  "X-Steward-Key": rootKey,
});
const bearer = (t: string) => ({ "Content-Type": "application/json", Authorization: `Bearer ${t}` });

function mintCalldata(to = RECIPIENT, amount = 1000n * 10n ** 18n) {
  return encodeFunctionData({ abi: TOKEN_ABI, functionName: "mint", args: [to as `0x${string}`, amount] });
}
async function sign(body: Record<string, unknown>, headers: Record<string, string>) {
  return app.request(`/vault/${AGENT}/sign`, { method: "POST", headers, body: JSON.stringify(body) });
}
async function approve(txId: string, headers: Record<string, string>, body: Record<string, unknown>) {
  return app.request(`/vault/${AGENT}/approve/${txId}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}
// biome-ignore lint/suspicious/noExplicitAny: test helper
async function json<T = any>(r: Response): Promise<T> {
  return (await r.json()) as T;
}

function baseManifest(chainId: unknown) {
  return {
    tenantId: TENANT,
    agentId: AGENT,
    signerAddress: `0x${"a".repeat(40)}`,
    chainId,
    safeAdmin: SAFE,
    factories: [FACTORY],
    verifiedTokens: [{ address: TOKEN, provenance: "0xdeploytx:sepolia:verified" }],
    approvers: [OWNER_USER],
  } as unknown as import("../services/prod-minter-boundary").ProtectedMinterManifest;
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "protected-rehearsal-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "protected-rehearsal-audit-key-32-bytes-minimum-aa";
  process.env.STEWARD_JWT_SECRET = "protected-rehearsal-jwt-secret-with-enough-bytes-aaaa";
  // Synthetic, never dialled: broadcast seam is stubbed; no-network preload blocks fetch.
  process.env.RPC_URL_84532 = "https://protected-tests-sepolia.invalid/v2/UNUSED";
  process.env.RPC_URL_8453 = "https://protected-tests-mainnet.invalid/v2/UNUSED";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  const k = generateApiKey();
  rootKey = k.key;
  await db.insert(tenants).values({ id: TENANT, name: "Strata rehearsal", apiKeyHash: k.hash });
  await db.insert(users).values([{ id: OWNER_USER, email: `owner-${OWNER_USER}@example.test` }]);
  await db.insert(userTenants).values([{ userId: OWNER_USER, tenantId: TENANT, role: "owner" }]);

  ({ app } = await import("../app"));
  ({ vault } = await import("../services/context"));
  boundary = await import("../services/prod-minter-boundary");

  const r = await app.request("/agents", {
    method: "POST",
    headers: rootHeaders(),
    body: JSON.stringify({ id: AGENT, name: AGENT }),
  });
  if (r.status !== 200) throw new Error(`POST /agents → ${r.status}: ${await r.text()}`);
  signerAddress = (await json(r)).data.walletAddress;

  // Separately pinned REHEARSAL manifest: 84532 and nothing else.
  boundary.installProtectedMinterManifest({ ...baseManifest(84532), signerAddress });

  ownerToken = await signAccessToken(
    { address: `0x${"1".repeat(40)}`, tenantId: TENANT, userId: OWNER_USER } as never,
    "1h",
  );
  agentJwt = await signAgentToken({ agentId: AGENT, tenantId: TENANT }, "1h");

  sendSpy = spyOn(vault as never, "broadcastEvm" as never).mockImplementation((async (
    _client: unknown,
    tx: { to: string; value: bigint; data?: string; chainId: number },
  ) => {
    signedBytes.push(tx);
    return `0x${signedBytes.length.toString(16).padStart(64, "0")}`;
  }) as never) as never;
}, 120000);

afterAll(async () => {
  sendSpy?.mockRestore();
  boundary?.installProtectedMinterManifest(null);
  await closeDb();
  for (const k of [
    "STEWARD_PGLITE_MEMORY",
    "DATABASE_URL",
    "STEWARD_MASTER_PASSWORD",
    "STEWARD_AUDIT_HMAC_KEY",
    "STEWARD_JWT_SECRET",
    "RPC_URL_84532",
    "RPC_URL_8453",
  ])
    delete process.env[k];
});

describe("B1 unit: one manifest, exactly one chain", () => {
  it("default (env unset) is 8453; explicit 8453 and 84532 are the only accepted values", () => {
    expect(boundary.parseChainIdEnv(undefined)).toBe(8453);
    expect(boundary.parseChainIdEnv("8453")).toBe(8453);
    expect(boundary.parseChainIdEnv("84532")).toBe(84532);
    expect(boundary.PROTECTED_MINTER_CHAIN_ID).toBe(8453);
    expect(boundary.PROTECTED_MINTER_REHEARSAL_CHAIN_ID).toBe(84532);
    expect([...boundary.PROTECTED_MINTER_ALLOWED_CHAIN_IDS]).toEqual([8453, 84532]);
  });

  it("env: no chain, two chains, another chain, hex, padded, signed => malformed manifest", () => {
    for (const raw of ["", " ", "8453,84532", "84532,8453", "8453 84532", "1", "0x2105", "0x14a34", "08453", " 8453", "8453 ", "+8453", "-8453", "8453.0", "1e4", "NaN", "undefined"]) {
      expect(() => boundary.parseChainIdEnv(raw)).toThrow(/must be exactly one of 8453\|84532/);
    }
  });

  it("manifestFromEnv: unset chain => 8453 (production unchanged); 84532 pinned when set; garbage refused", () => {
    const env: NodeJS.ProcessEnv = {
      STEWARD_PROTECTED_MINTER_TENANT: TENANT,
      STEWARD_PROTECTED_MINTER_AGENT: AGENT,
      STEWARD_PROTECTED_MINTER_ADDRESS: `0x${"b".repeat(40)}`,
      STEWARD_PROTECTED_MINTER_FACTORIES: FACTORY,
      STEWARD_PROTECTED_MINTER_TOKENS: `${TOKEN}@0xprov`,
      STEWARD_PROTECTED_MINTER_APPROVERS: OWNER_USER,
    };
    expect(boundary.manifestFromEnv(env)?.chainId).toBe(8453);
    expect(boundary.manifestFromEnv({ ...env, STEWARD_PROTECTED_MINTER_CHAIN_ID: "8453" })?.chainId).toBe(8453);
    expect(boundary.manifestFromEnv({ ...env, STEWARD_PROTECTED_MINTER_CHAIN_ID: "84532" })?.chainId).toBe(84532);
    for (const bad of ["", "8453,84532", "1", "0x2105"]) {
      expect(() => boundary.manifestFromEnv({ ...env, STEWARD_PROTECTED_MINTER_CHAIN_ID: bad })).toThrow();
    }
    // The chain knob alone still activates validation (R5-F1 posture kept): a
    // chain-only env is a partial manifest and fatal, not ignored.
    expect(() => boundary.manifestFromEnv({ STEWARD_PROTECTED_MINTER_CHAIN_ID: "84532" })).toThrow();
  });

  it("validateManifest: missing chain, null, string, array of two chains, other chain all refused", () => {
    for (const chain of [undefined, null, "8453", "84532", [8453, 84532], [8453], 1, 0, 8453.5, NaN, 10, 42161, 84531, {}]) {
      expect(() => boundary.validateManifest(baseManifest(chain))).toThrow(/chainId must be exactly one of/);
    }
    expect(() => boundary.validateManifest(baseManifest(8453))).not.toThrow();
    expect(() => boundary.validateManifest(baseManifest(84532))).not.toThrow();
  });

  it("validateProtectedShape is bound to the manifest chain in BOTH directions", () => {
    const m8453 = baseManifest(8453);
    const m84532 = baseManifest(84532);
    const tx = (chainId: unknown) => ({ chainId: chainId as number, to: TOKEN, value: "0", data: mintCalldata() });
    expect(boundary.validateProtectedShape(m8453, tx(8453)).ok).toBe(true);
    expect(boundary.validateProtectedShape(m84532, tx(84532)).ok).toBe(true);
    const a = boundary.validateProtectedShape(m8453, tx(84532));
    expect(a.ok).toBe(false);
    if (!a.ok) expect(a.reason).toBe("chainId must be exactly 8453");
    const b = boundary.validateProtectedShape(m84532, tx(8453));
    expect(b.ok).toBe(false);
    if (!b.ok) expect(b.reason).toBe("chainId must be exactly 84532");
    for (const other of [1, 10, "84532", undefined, null, 84532n]) {
      expect(boundary.validateProtectedShape(m84532, tx(other)).ok).toBe(false);
    }
  });

  it("manifest digest differs by chain (8453 and 84532 reviews can never cross)", () => {
    expect(boundary.computeManifestDigest(baseManifest(8453))).not.toBe(
      boundary.computeManifestDigest(baseManifest(84532)),
    );
  });

  it("installProtectedMinterManifest refuses a no-chain / two-chain manifest and leaves the installed one intact", () => {
    const before = boundary.getProtectedMinterManifestDigest();
    expect(() => boundary.installProtectedMinterManifest(baseManifest(undefined))).toThrow();
    expect(() => boundary.installProtectedMinterManifest(baseManifest([8453, 84532]))).toThrow();
    expect(boundary.getProtectedMinterManifestDigest()).toBe(before);
    expect(boundary.getProtectedMinterManifest()?.chainId).toBe(84532);
  });
});

describe("B1 integration: separately pinned 84532 rehearsal manifest", () => {
  it("an 84532-bound signer cannot propose for 8453 (or any other chain)", async () => {
    for (const chainId of [8453, 1, 10, "84532", undefined]) {
      const r = await sign(
        { to: TOKEN, value: "0", data: mintCalldata(), chainId, executionRef: ref() },
        bearer(agentJwt),
      );
      expect(r.status).toBe(403);
      expect((await json(r)).error).toBe("Protected signer: chainId must be exactly 84532");
    }
    const q = await getDb().select().from(approvalQueue).where(eq(approvalQueue.agentId, AGENT));
    expect(q).toHaveLength(0);
    expect(signedBytes).toHaveLength(0);
  });

  it("a valid 84532 proposal queues with the 84532 projection and signs exactly 84532 bytes", async () => {
    const executionRef = ref();
    const r = await sign(
      { to: TOKEN, value: "0", data: mintCalldata(), chainId: 84532, executionRef },
      bearer(agentJwt),
    );
    expect(r.status).toBe(202);
    const b = await json(r);
    expect(b.data.status).toBe("pending_approval");
    expect(b.data.review.chainId).toBe(84532);
    const txId = b.data.txId as string;
    const [row] = await getDb().select().from(transactions).where(eq(transactions.id, txId));
    expect(row?.chainId).toBe(84532);

    const ok = await approve(txId, bearer(ownerToken), { reviewDigest: b.data.reviewDigest });
    expect(ok.status).toBe(200);
    expect(signedBytes).toHaveLength(1);
    expect(signedBytes[0]!.chainId).toBe(84532);
    expect(signedBytes[0]!.to.toLowerCase()).toBe(TOKEN.toLowerCase());
    expect(signedBytes[0]!.value).toBe(0n);
  });

  it("a queued 84532 row whose chainId is substituted to 8453 in storage is refused at signing", async () => {
    const r = await sign(
      { to: TOKEN, value: "0", data: mintCalldata(), chainId: 84532, executionRef: ref() },
      bearer(agentJwt),
    );
    expect(r.status).toBe(202);
    const b = await json(r);
    const txId = b.data.txId as string;
    await getDb().update(transactions).set({ chainId: 8453 }).where(eq(transactions.id, txId));
    const bad = await approve(txId, bearer(ownerToken), { reviewDigest: b.data.reviewDigest });
    expect(bad.status).toBe(403);
    const [q] = await getDb().select().from(approvalQueue).where(eq(approvalQueue.txId, txId));
    expect(q?.status).toBe("pending");
    expect(signedBytes).toHaveLength(1); // unchanged from the previous test
  });

  it("the tenant API key cannot propose for the rehearsal signer either", async () => {
    const r = await sign(
      { to: TOKEN, value: "0", data: mintCalldata(), chainId: 84532, executionRef: ref() },
      rootHeaders(),
    );
    expect(r.status).toBe(403);
    expect(signedBytes).toHaveLength(1);
  });
});
