/**
 * STRATA-1673 E7 S1: protected minter auto-signs read-back-validated issuance.
 *
 * In-memory PGLite; the vault's final EVM send is replaced by a recorder so
 * "one signature" is observable and no RPC is hit. Strata's read-back
 * endpoint (S2, not built yet) is a typed fake implementing the contract in
 * services/issuance-readback-client.ts.
 *
 * Must-hold map: [M1]..[M9] (see PR body).
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it, type Mock, spyOn } from "bun:test";
import { generateApiKey, signAccessToken, signAgentToken } from "@stwd/auth";
import {
  approvalQueue,
  closeDb,
  getDb,
  protectedMinterTokens,
  tenants,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import {
  issueProtectedSigningPermit,
  ProtectedKeyUseReleasedError,
  Vault as VaultClass,
} from "@stwd/vault";
import { and, eq } from "drizzle-orm";
import type { Hono } from "hono";
import {
  encodeAbiParameters,
  encodeEventTopics,
  encodeFunctionData,
  keccak256,
  parseAbi,
  parseAbiParameters,
} from "viem";
import type { IssuanceInstruction } from "../services/issuance-readback-client";

const TENANT = "strata";
const AGENT = "prod-minter-1673";
const FACTORY = "0x00000000000000000000000000000000000f0001";
const TOKEN = "0x0000000000000000000000000000000000700001";
const DEPLOYED_TOKEN = "0x0000000000000000000000000000000000700abc";
const FOREIGN_TOKEN = "0x0000000000000000000000000000000000700def";
/** H3: in the manifest, never admitted -> human path only. */
const MANIFEST_ONLY_TOKEN = "0x0000000000000000000000000000000000700002";
/** H3: in the manifest AND admitted; revoked in the H3 test. */
const OVERLAP_TOKEN = "0x0000000000000000000000000000000000700003";
const SAFE = "0x3Ea77cDf3eC33603bF4135bb1a36712B5e21d721";
const RECIPIENT = "0x00000000000000000000000000000000000000aa";
const OTHER_RECIPIENT = "0x00000000000000000000000000000000000000bb";
const OWNER_USER = crypto.randomUUID();
const AMOUNT = 1000n * 10n ** 18n;
const DIGEST = `0x${"ab".repeat(32)}`;
const DEPLOY_HASH = `0x${"de".repeat(32)}`;
const READBACK_URL = "https://strata.readback.invalid";
const READBACK_TOKEN = "read-only-principal-token";

const TOKEN_ABI = parseAbi(["function mint(address to, uint256 amount)"]);
const FACTORY_ABI = parseAbi([
  "function createDealToken(string name, string symbol, address admin, address minter, bytes32 salt) returns (address)",
]);
const EVENT_ABI = parseAbi([
  "event DealTokenDeployed(address indexed token, address indexed admin, address indexed minter, address deployer, string name, string symbol, bytes32 salt)",
]);

const RESTRICTED_FACTORY_ABI = parseAbi([
  "struct RoleConfig { address admin; address issuer; address operator; address pauser; }",
  "function createRestrictedDealToken(string name, string symbol, uint8 decimals, RoleConfig roles, bytes32 salt) returns (address token)",
]);
const RESTRICTED_EVENT_ABI = parseAbi([
  "event RestrictedDealTokenDeployed(address indexed token, address indexed admin, address indexed issuer, address operator, address pauser, address deployer, bytes32 salt, bytes32 versionId)",
]);

let app: Hono;
let signerAddress: string;
let ownerToken: string;
let agentJwt: string;
let vault: Awaited<typeof import("../services/context")>["vault"];
let boundary: typeof import("../services/prod-minter-boundary");
let readback: typeof import("../services/issuance-readback-client");
let sendSpy: Mock<(...args: unknown[]) => Promise<unknown>>;
let signed: Array<{ to: string; data?: string; chainId: number }> = [];
let refN = 0;

/** Typed fake of Strata's S2 endpoint. */
type FakeReply =
  | { kind: "ok"; instruction: Partial<IssuanceInstruction> }
  | { kind: "status"; status: number; body?: unknown }
  | { kind: "hang" }
  | { kind: "throw" }
  | { kind: "raw"; body: unknown };
let reply: FakeReply = { kind: "status", status: 409, body: { reason: "unset" } };
let calls: Array<{ url: string; method: string; auth: string | null }> = [];

function fakeFetch(input: string, init: RequestInit): Promise<Response> {
  const h = new Headers(init.headers);
  calls.push({ url: input, method: String(init.method), auth: h.get("authorization") });
  const ref = decodeURIComponent(input.split("/").pop() ?? "");
  const r = reply;
  if (r.kind === "throw") return Promise.reject(new TypeError("fetch failed"));
  if (r.kind === "hang") {
    return new Promise((_, reject) => {
      init.signal?.addEventListener("abort", () => {
        const e = new Error("aborted");
        e.name = "AbortError";
        reject(e);
      });
    });
  }
  if (r.kind === "status") {
    return Promise.resolve(new Response(JSON.stringify(r.body ?? {}), { status: r.status }));
  }
  if (r.kind === "raw")
    return Promise.resolve(new Response(JSON.stringify(r.body), { status: 200 }));
  const body: IssuanceInstruction = {
    tenantRef: "strata-tenant",
    chainId: 8453,
    token: TOKEN,
    recipient: RECIPIENT,
    amount: AMOUNT.toString(),
    participationId: "par_1",
    mintId: "mint_1",
    executionRef: ref,
    status: "authorized",
    instructionDigest: DIGEST,
    ...r.instruction,
  };
  return Promise.resolve(new Response(JSON.stringify(body), { status: 200 }));
}

function installReadback(enabled = true) {
  readback.setIssuanceReadbackClient(
    new readback.IssuanceReadbackClient(
      enabled ? { baseUrl: READBACK_URL, token: READBACK_TOKEN, timeoutMs: 200 } : null,
      fakeFetch,
    ),
  );
}

const bearer = (t: string) => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${t}`,
});
const ref = () => `tokenization:mint:${++refN}`;
const mint = (to = RECIPIENT, amount = AMOUNT) =>
  encodeFunctionData({ abi: TOKEN_ABI, functionName: "mint", args: [to as `0x${string}`, amount] });

async function sign(body: Record<string, unknown>) {
  return app.request(`/vault/${AGENT}/sign`, {
    method: "POST",
    headers: bearer(agentJwt),
    body: JSON.stringify(body),
  });
}
async function signMint(executionRef = ref(), token = TOKEN, data = mint()) {
  return sign({ to: token, value: "0", data, chainId: 8453, executionRef });
}
async function queueRowByRef(executionRef: string) {
  const [t] = await getDb()
    .select()
    .from(transactions)
    .where(and(eq(transactions.agentId, AGENT), eq(transactions.executionRef, executionRef)));
  if (!t) return { tx: undefined, q: undefined };
  const [q] = await getDb().select().from(approvalQueue).where(eq(approvalQueue.txId, t.id));
  return { tx: t, q };
}
async function post(path: string, body: Record<string, unknown> = {}, token = ownerToken) {
  return app.request(`/vault/${AGENT}${path}`, {
    method: "POST",
    headers: bearer(token),
    body: JSON.stringify(body),
  });
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "readback-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "readback-audit-key-32-bytes-minimum-aaaaaaa";
  process.env.STEWARD_JWT_SECRET = "readback-jwt-secret-with-enough-bytes-aaaaaaaa";
  process.env.RPC_URL_8453 = "https://readback-tests.invalid/v2/UNUSED";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  const k = generateApiKey();
  await db.insert(tenants).values({ id: TENANT, name: "Strata", apiKeyHash: k.hash });
  await db.insert(users).values({ id: OWNER_USER, email: `owner-${OWNER_USER}@example.test` });
  await db.insert(userTenants).values({ userId: OWNER_USER, tenantId: TENANT, role: "owner" });

  ({ app } = await import("../app"));
  ({ vault } = await import("../services/context"));
  boundary = await import("../services/prod-minter-boundary");
  readback = await import("../services/issuance-readback-client");

  const r = await app.request("/agents", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Steward-Tenant": TENANT,
      "X-Steward-Key": k.key,
    },
    body: JSON.stringify({ id: AGENT, name: AGENT }),
  });
  if (r.status !== 200) throw new Error(`create agent ${r.status}`);
  signerAddress = ((await r.json()) as any).data.walletAddress;

  boundary.installProtectedMinterManifest({
    tenantId: TENANT,
    agentId: AGENT,
    signerAddress,
    chainId: 8453,
    safeAdmin: SAFE,
    factories: [FACTORY],
    verifiedTokens: [
      { address: TOKEN, provenance: "0xdeploy:verified" },
      { address: MANIFEST_ONLY_TOKEN, provenance: "0xdeploy:verified2" },
      { address: OVERLAP_TOKEN, provenance: "0xdeploy:verified3" },
    ],
    approvers: [OWNER_USER],
  });
  // H3: auto-sign needs an active admission; TOKEN and OVERLAP_TOKEN have one.
  for (const [address, n] of [
    [TOKEN, "a1"],
    [OVERLAP_TOKEN, "a3"],
  ] as const) {
    await db.insert(protectedMinterTokens).values({
      id: crypto.randomUUID(),
      tenantId: TENANT,
      agentId: AGENT,
      chainId: 8453,
      tokenAddress: address,
      deployTxHash: `0x${n.repeat(32)}`,
      deployExecutionRef: `tokenization:deploy:${n}`,
    });
  }
  ownerToken = await signAccessToken(
    { address: `0x${"1".repeat(40)}`, tenantId: TENANT, userId: OWNER_USER } as never,
    "1h",
  );
  agentJwt = await signAgentToken({ agentId: AGENT, tenantId: TENANT }, "1h");

  sendSpy = spyOn(vault as never, "broadcastEvm" as never).mockImplementation((async (
    _c: unknown,
    tx: { to: string; data?: string; chainId: number },
  ) => {
    signed.push(tx);
    return `0x${signed.length.toString(16).padStart(64, "0")}`;
  }) as never) as never;
}, 120000);

afterAll(async () => {
  sendSpy?.mockRestore();
  readback?.setIssuanceReadbackClient(null);
  boundary?.setProtectedChainReader(null);
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

beforeEach(() => {
  installReadback(true);
  reply = { kind: "ok", instruction: {} };
  calls = [];
});

describe.serial("STRATA-1673 S1 read-back auto-sign", () => {
  it("[M1] exact match on (chainId, token, recipient, amount) -> approved by readback, claimed once, signed once", async () => {
    const before = signed.length;
    const r = ref();
    const res = await signMint(r);
    expect(res.status).toBe(200);
    const b = (await res.json()) as any;
    expect(b.data.status).toBe("signed");
    expect(b.data.approvalSource).toBe("issuance_readback");
    expect(signed.length).toBe(before + 1);
    expect(signed.at(-1)!.to.toLowerCase()).toBe(TOKEN);
    expect(signed.at(-1)!.data).toBe(mint());
    const { tx, q } = await queueRowByRef(r);
    expect(tx!.status).toBe("signed");
    expect(q!.status).toBe("approved");
    expect(q!.approvalSource).toBe("issuance_readback");
    expect(q!.instructionDigest).toBe(DIGEST);
    expect(q!.approvedByUserId).toBeNull();
    expect(q!.issuanceClaimedAt).not.toBeNull();
    // The Strata read principal is used only for the read-back GET.
    expect(calls).toHaveLength(1);
    expect(calls[0]!.method).toBe("GET");
    expect(calls[0]!.url).toBe(
      `${READBACK_URL}/internal/steward/issuance-instructions/${encodeURIComponent(r)}`,
    );
    expect(calls[0]!.auth).toBe(`Bearer ${READBACK_TOKEN}`);
  });

  it("[M2] any field mismatch -> NOT signed, queued for a human with the reason", async () => {
    const cases: Array<[Partial<IssuanceInstruction>, string]> = [
      [{ amount: (AMOUNT + 1n).toString() }, "readback_mismatch:amount"],
      [{ recipient: OTHER_RECIPIENT }, "readback_mismatch:recipient"],
      [{ token: FOREIGN_TOKEN }, "readback_mismatch:token"],
      [{ chainId: 84532 }, "readback_mismatch:chainId"],
    ];
    for (const [instruction, reason] of cases) {
      reply = { kind: "ok", instruction };
      const before = signed.length;
      const r = ref();
      const res = await signMint(r);
      expect(res.status, reason).toBe(202);
      const b = (await res.json()) as any;
      expect(b.data.status).toBe("pending_approval");
      expect(b.data.readbackRefusal).toBe(reason);
      expect(signed.length).toBe(before);
      const { q } = await queueRowByRef(r);
      expect(q!.status).toBe("pending");
      expect(q!.approvalSource).toBeNull();
      expect(q!.issuanceClaimedAt).toBeNull();
    }
  });

  it("[M2] 409 / timeout / unreachable / 5xx / malformed / wrong executionRef -> NOT signed, human queue", async () => {
    const cases: Array<[FakeReply, string]> = [
      [
        { kind: "status", status: 409, body: { reason: "settlement_not_final" } },
        "settlement_not_final",
      ],
      [{ kind: "hang" }, "readback_timeout"],
      [{ kind: "throw" }, "readback_unreachable"],
      [{ kind: "status", status: 503 }, "readback_http_503"],
      [{ kind: "status", status: 401 }, "readback_http_401"],
      [{ kind: "raw", body: { status: "authorized" } }, "readback_malformed"],
      [{ kind: "ok", instruction: { status: "pending" as never } }, "readback_malformed"],
      [
        { kind: "ok", instruction: { executionRef: "tokenization:mint:other" } },
        "readback_execution_ref_mismatch",
      ],
    ];
    for (const [r0, reason] of cases) {
      reply = r0;
      const before = signed.length;
      const r = ref();
      const res = await signMint(r);
      expect(res.status, reason).toBe(202);
      expect(((await res.json()) as any).data.readbackRefusal).toBe(reason);
      expect(signed.length).toBe(before);
      const { q } = await queueRowByRef(r);
      expect(q!.status).toBe("pending");
    }
  });

  it("[M3] executionRef replay returns the same action and never a second signature", async () => {
    const r = ref();
    const first = await signMint(r);
    expect(first.status).toBe(200);
    const firstBody = (await first.json()) as any;
    const before = signed.length;
    for (let i = 0; i < 3; i++) {
      const again = await signMint(r);
      expect(again.status).toBe(200);
      expect(again.headers.get("Idempotency-Replayed")).toBe("true");
      const b = (await again.json()) as any;
      expect(b.data.txId).toBe(firstBody.data.txId);
      expect(b.data.txHash).toBe(firstBody.data.txHash);
    }
    // Different payload under the same ref -> 409, nothing signed.
    const conflict = await signMint(r, TOKEN, mint(OTHER_RECIPIENT));
    expect(conflict.status).toBe(409);
    expect(signed.length).toBe(before);
  });

  it("[M3] concurrent identical requests -> exactly one signature", async () => {
    const r = ref();
    const before = signed.length;
    const results = await Promise.all(Array.from({ length: 8 }, () => signMint(r)));
    for (const res of results) expect([200, 202]).toContain(res.status);
    expect(signed.length).toBe(before + 1);
  });

  it("[M3] the readback claim is single-use: a second permit for the same row is refused", async () => {
    const r = ref();
    expect((await signMint(r)).status).toBe(200);
    const { tx, q } = await queueRowByRef(r);
    await getDb()
      .update(transactions)
      .set({ status: "pending" })
      .where(eq(transactions.id, tx!.id));
    await expect(
      issueProtectedSigningPermit({
        tenantId: TENANT,
        agentId: AGENT,
        txId: tx!.id,
        reviewDigest: q!.reviewDigest!,
      }),
    ).rejects.toThrow(/already issued|resolve via executionRef/);
    await getDb().update(transactions).set({ status: "signed" }).where(eq(transactions.id, tx!.id));
  });

  it("[M6] readback env unset -> no auto-sign (today's behaviour), Strata never called", async () => {
    installReadback(false);
    const before = signed.length;
    const res = await signMint();
    expect(res.status).toBe(202);
    expect(((await res.json()) as any).data.readbackRefusal).toBe("readback_disabled");
    expect(signed.length).toBe(before);
    expect(calls).toHaveLength(0);
    expect(readback.readbackConfigFromEnv({})).toBeNull();
    expect(
      readback.readbackConfigFromEnv({ STRATA_ISSUANCE_READBACK_URL: READBACK_URL }),
    ).toBeNull();
  });

  it("[M5] suspend agent -> immediate human fallback; resume -> auto again; no restart", async () => {
    // Only a pinned human approver can suspend; the agent credential cannot.
    expect((await post("/protected-minter/suspend", { reason: "x" }, agentJwt)).status).toBe(403);
    expect((await post("/protected-minter/suspend", { reason: "incident 42" })).status).toBe(200);
    const before = signed.length;
    const res = await signMint();
    expect(res.status).toBe(202);
    expect(((await res.json()) as any).data.readbackRefusal).toBe("agent_suspended");
    expect(signed.length).toBe(before);
    expect(calls).toHaveLength(0);
    expect((await post("/protected-minter/resume")).status).toBe(200);
    expect((await signMint()).status).toBe(200);
    expect(signed.length).toBe(before + 1);
  });

  it("[M5] suspension also refuses at permit time (re-read in the vault)", async () => {
    const r = ref();
    reply = { kind: "status", status: 503 };
    expect((await signMint(r)).status).toBe(202);
    const { tx, q } = await queueRowByRef(r);
    // Simulate a row that became readback-approved, then the agent is suspended.
    await getDb()
      .update(approvalQueue)
      .set({ status: "approved", approvalSource: "issuance_readback", instructionDigest: DIGEST })
      .where(eq(approvalQueue.id, q!.id));
    expect((await post("/protected-minter/suspend", { reason: "late" })).status).toBe(200);
    try {
      await expect(
        issueProtectedSigningPermit({
          tenantId: TENANT,
          agentId: AGENT,
          txId: tx!.id,
          reviewDigest: q!.reviewDigest!,
        }),
      ).rejects.toThrow(/suspended/);
      const { q: after } = await queueRowByRef(r);
      expect(after!.issuanceClaimedAt).toBeNull();
    } finally {
      expect((await post("/protected-minter/resume")).status).toBe(200);
    }
  });

  it("[M1] permit: readback row without digest, or carrying a human approver, is refused; human CAS cannot consume a readback row", async () => {
    // DB CHECK: readback source requires a digest.
    const r = ref();
    reply = { kind: "status", status: 503 };
    expect((await signMint(r)).status).toBe(202);
    const { tx, q } = await queueRowByRef(r);
    await expect(
      (async () => {
        await getDb()
          .update(approvalQueue)
          .set({ status: "approved", approvalSource: "issuance_readback" })
          .where(eq(approvalQueue.id, q!.id));
      })(),
    ).rejects.toThrow();
    await getDb()
      .update(approvalQueue)
      .set({
        status: "approved",
        approvalSource: "issuance_readback",
        instructionDigest: DIGEST,
        approvedByUserId: OWNER_USER,
      })
      .where(eq(approvalQueue.id, q!.id));
    await expect(
      issueProtectedSigningPermit({
        tenantId: TENANT,
        agentId: AGENT,
        txId: tx!.id,
        reviewDigest: q!.reviewDigest!,
      }),
    ).rejects.toThrow(/human approver/);
    const { q: after } = await queueRowByRef(r);
    expect(after!.issuanceClaimedAt).toBeNull();
  });

  it("[M4/H2] token from Steward's own protected RestrictedDealToken deploy is admitted (receipt, event, depth, live roles); every negative is refused", async () => {
    const digestBefore = boundary.getProtectedMinterManifestDigest();
    const OPERATOR = "0x00000000000000000000000000000000000000c1";
    const PAUSER = "0x00000000000000000000000000000000000000c2";
    const SALT = `0x${"11".repeat(32)}` as `0x${string}`;
    const signer = signerAddress.toLowerCase();
    // Unknown token, no deploy evidence -> refused (not even queued).
    reply = { kind: "ok", instruction: { token: DEPLOYED_TOKEN } };
    expect((await signMint(ref(), DEPLOYED_TOKEN)).status).toBe(403);

    // Legacy DealToken: Steward's own createDealToken + DealTokenDeployed + MINTER_ROLE.
    const LEGACY_HASH = `0x${"1e".repeat(32)}`;
    const legacyTxId = crypto.randomUUID();
    await getDb()
      .insert(transactions)
      .values({
        id: legacyTxId,
        agentId: AGENT,
        tenantId: TENANT,
        executionRef: "tokenization:deploy:legacy",
        status: "signed",
        toAddress: FACTORY,
        value: "0",
        data: encodeFunctionData({
          abi: FACTORY_ABI,
          functionName: "createDealToken",
          args: ["Deal", "DL", SAFE, signerAddress as `0x${string}`, SALT],
        }),
        chainId: 8453,
        txHash: LEGACY_HASH,
        policyResults: [],
      });
    const legacyTopics = encodeEventTopics({
      abi: EVENT_ABI,
      eventName: "DealTokenDeployed",
      args: { token: DEPLOYED_TOKEN, admin: SAFE, minter: signerAddress as `0x${string}` },
    });
    const legacyData = encodeAbiParameters(parseAbiParameters("address, string, string, bytes32"), [
      signerAddress as `0x${string}`,
      "Deal",
      "DL",
      SALT,
    ]);

    // Steward's own RestrictedDealToken deploy row.
    const deployTxId = crypto.randomUUID();
    await getDb()
      .insert(transactions)
      .values({
        id: deployTxId,
        agentId: AGENT,
        tenantId: TENANT,
        executionRef: "tokenization:deploy:1",
        status: "signed",
        toAddress: FACTORY,
        value: "0",
        data: encodeFunctionData({
          abi: RESTRICTED_FACTORY_ABI,
          functionName: "createRestrictedDealToken",
          args: [
            "Deal",
            "DL",
            18,
            {
              admin: SAFE,
              issuer: signerAddress as `0x${string}`,
              operator: OPERATOR,
              pauser: PAUSER,
            },
            SALT,
          ],
        }),
        chainId: 8453,
        txHash: DEPLOY_HASH,
        policyResults: [],
      });
    const rTopics = encodeEventTopics({
      abi: RESTRICTED_EVENT_ABI,
      eventName: "RestrictedDealTokenDeployed",
      args: { token: DEPLOYED_TOKEN, admin: SAFE, issuer: signerAddress as `0x${string}` },
    });
    const rData = (deployer: string, versionId = boundary.RESTRICTED_FACTORY_VERSION_ID) =>
      encodeAbiParameters(parseAbiParameters("address, address, address, bytes32, bytes32"), [
        OPERATOR,
        PAUSER,
        deployer as `0x${string}`,
        SALT,
        versionId,
      ]);

    // Chain state the reader reports (mutated per negative case).
    const st = {
      from: signer,
      deployer: signer,
      versionId: boundary.RESTRICTED_FACTORY_VERSION_ID as `0x${string}`,
      block: 100n,
      head: 200n,
      roles: new Set<string>(), // `${role}:${account}`
    };
    const grant = (role: string, account: string) =>
      st.roles.add(`${role}:${account.toLowerCase()}`);
    const readerCalls: string[] = [];
    boundary.setProtectedChainReader({
      async getReceipt(_chainId, hash) {
        readerCalls.push(`receipt:${hash}`);
        if (hash === LEGACY_HASH)
          return {
            status: "success",
            to: FACTORY,
            from: signer,
            blockNumber: 50n,
            logs: [{ address: FACTORY, topics: legacyTopics, data: legacyData }],
          };
        if (hash !== DEPLOY_HASH) return null;
        return {
          status: "success",
          to: FACTORY,
          from: st.from,
          blockNumber: st.block,
          logs: [{ address: FACTORY, topics: rTopics, data: rData(st.deployer, st.versionId) }],
        };
      },
      async getBlockNumber() {
        return st.head;
      },
      async hasRole(_chainId, _token, role, account) {
        return st.roles.has(`${role}:${account.toLowerCase()}`);
      },
    });
    const refusedNow = async (label: string) => {
      const before = signed.length;
      expect((await signMint(ref(), DEPLOYED_TOKEN)).status, label).toBe(403);
      expect(signed.length, label).toBe(before);
      const rows = await getDb()
        .select()
        .from(protectedMinterTokens)
        .where(eq(protectedMinterTokens.tokenAddress, DEPLOYED_TOKEN));
      expect(rows, label).toHaveLength(0);
    };
    try {
      // Legacy row even with every role granted -> never admitted.
      grant(boundary.MINTER_ROLE, signer);
      grant(boundary.DEFAULT_ADMIN_ROLE, SAFE);
      grant(boundary.ISSUER_ROLE, signer);
      // Restricted deploy row WITHOUT a protected approval (not Steward's protected deploy).
      await refusedNow("no protected approval binding");
      expect(readerCalls).not.toContain(`receipt:${LEGACY_HASH}`);
      await getDb().insert(approvalQueue).values({
        id: crypto.randomUUID(),
        txId: deployTxId,
        agentId: AGENT,
        status: "approved",
        reviewDigest: DIGEST,
        approvedByUserId: OWNER_USER,
        issuanceClaimedAt: new Date(),
      });
      await getDb().insert(approvalQueue).values({
        id: crypto.randomUUID(),
        txId: legacyTxId,
        agentId: AGENT,
        status: "approved",
        reviewDigest: DIGEST,
        approvedByUserId: OWNER_USER,
        issuanceClaimedAt: new Date(),
      });
      st.roles.clear();
      // Unrelated deployer: receipt sender is someone else.
      st.from = FOREIGN_TOKEN;
      await refusedNow("receipt.from != signer");
      st.from = signer;
      // Event deployer differs.
      st.deployer = FOREIGN_TOKEN;
      await refusedNow("event deployer != signer");
      st.deployer = signer;
      // Untrusted factory version.
      st.versionId = `0x${"99".repeat(32)}`;
      await refusedNow("versionId mismatch");
      st.versionId = boundary.RESTRICTED_FACTORY_VERSION_ID as `0x${string}`;
      // Unconfirmed receipt (too shallow).
      st.head = st.block + 2n;
      grant(boundary.DEFAULT_ADMIN_ROLE, SAFE);
      grant(boundary.ISSUER_ROLE, signer);
      await refusedNow("unconfirmed receipt");
      st.head = 200n;
      // Missing roles.
      st.roles.clear();
      grant(boundary.ISSUER_ROLE, signer);
      await refusedNow("Safe lacks DEFAULT_ADMIN_ROLE");
      st.roles.clear();
      grant(boundary.DEFAULT_ADMIN_ROLE, SAFE);
      grant(boundary.MINTER_ROLE, signer); // legacy role is not ISSUER_ROLE
      await refusedNow("signer lacks ISSUER_ROLE");
      grant(boundary.ISSUER_ROLE, signer);
      grant(boundary.DEFAULT_ADMIN_ROLE, signer);
      await refusedNow("signer holds DEFAULT_ADMIN_ROLE");
      st.roles.delete(`${boundary.DEFAULT_ADMIN_ROLE}:${signer}`);

      // Everything holds -> admitted and auto-signed.
      const before = signed.length;
      const ok = await signMint(ref(), DEPLOYED_TOKEN);
      expect(ok.status).toBe(200);
      expect(signed.length).toBe(before + 1);
      const [row] = await getDb()
        .select()
        .from(protectedMinterTokens)
        .where(eq(protectedMinterTokens.tokenAddress, DEPLOYED_TOKEN));
      expect(row!.status).toBe("active");
      expect(row!.chainId).toBe(8453); // [M7] from the admission + configured network
      expect(row!.deployTxHash).toBe(DEPLOY_HASH);
      expect(row!.deployExecutionRef).toBe("tokenization:deploy:1");
      expect(boundary.getProtectedMinterManifestDigest()).toBe(digestBefore);
      // A token Steward did not deploy is never admitted.
      reply = { kind: "ok", instruction: { token: FOREIGN_TOKEN } };
      expect((await signMint(ref(), FOREIGN_TOKEN)).status).toBe(403);
    } finally {
      boundary.setProtectedChainReader(null);
    }
  });

  it("[H2] createRestrictedDealToken shape: Safe admin + signer issuer queues for a human; substitutions refused", async () => {
    const OPERATOR = "0x00000000000000000000000000000000000000c1";
    const PAUSER = "0x00000000000000000000000000000000000000c2";
    const call = (roles: { admin: string; issuer: string; operator: string; pauser: string }) =>
      sign({
        to: FACTORY,
        value: "0",
        data: encodeFunctionData({
          abi: RESTRICTED_FACTORY_ABI,
          functionName: "createRestrictedDealToken",
          args: ["Deal", "DL", 18, roles as never, `0x${"22".repeat(32)}`],
        }),
        chainId: 8453,
        executionRef: ref(),
      });
    const good = { admin: SAFE, issuer: signerAddress, operator: OPERATOR, pauser: PAUSER };
    const before = signed.length;
    const ok = await call(good);
    expect(ok.status).toBe(202); // deploys are never auto-signed
    expect(((await ok.json()) as any).data.review.kind).toBe("createRestrictedDealToken");
    for (const [label, roles] of [
      ["admin not Safe", { ...good, admin: OPERATOR }],
      ["issuer not signer", { ...good, issuer: OPERATOR }],
      ["operator = signer", { ...good, operator: signerAddress }],
      ["pauser = signer", { ...good, pauser: signerAddress }],
    ] as const) {
      expect((await call(roles)).status, label).toBe(403);
    }
    expect(signed.length).toBe(before);
  });

  it("[M5] revoke an admitted token -> next mint refused (human or readback), immediately, terminal", async () => {
    reply = { kind: "ok", instruction: { token: DEPLOYED_TOKEN } };
    expect(
      (await post(`/protected-minter/tokens/${DEPLOYED_TOKEN}/revoke`, { reason: "x" }, agentJwt))
        .status,
    ).toBe(403);
    // Queue one for a human first (readback down), then revoke.
    reply = { kind: "status", status: 503 };
    const pendingRef = ref();
    expect((await signMint(pendingRef, DEPLOYED_TOKEN)).status).toBe(202);
    const res = await post(`/protected-minter/tokens/${DEPLOYED_TOKEN}/revoke`, {
      reason: "wrong deal",
    });
    expect(res.status).toBe(200);
    reply = { kind: "ok", instruction: { token: DEPLOYED_TOKEN } };
    const before = signed.length;
    expect((await signMint(ref(), DEPLOYED_TOKEN)).status).toBe(403);
    // The already-queued human approval is refused too (current scope).
    const { tx, q } = await queueRowByRef(pendingRef);
    const approve = await app.request(`/vault/${AGENT}/approve/${tx!.id}`, {
      method: "POST",
      headers: bearer(ownerToken),
      body: JSON.stringify({ reviewDigest: q!.reviewDigest }),
    });
    expect(approve.status).toBe(403);
    expect(signed.length).toBe(before);
    // Terminal: the DB refuses re-activation.
    await expect(
      (async () => {
        await getDb()
          .update(protectedMinterTokens)
          .set({ status: "active", revokedAt: null, revokedBy: null })
          .where(eq(protectedMinterTokens.tokenAddress, DEPLOYED_TOKEN));
      })(),
    ).rejects.toThrow();
    // Revoking again is reported as already revoked, never as a fresh revoke.
    expect(
      (await post(`/protected-minter/tokens/${DEPLOYED_TOKEN}/revoke`, { reason: "again" })).status,
    ).toBe(409);
  });

  it("[H3] manifest-only token (no admission) -> never auto-signed, existing human path", async () => {
    reply = { kind: "ok", instruction: { token: MANIFEST_ONLY_TOKEN } };
    const before = signed.length;
    const r = ref();
    const res = await signMint(r, MANIFEST_ONLY_TOKEN);
    expect(res.status).toBe(202);
    expect(((await res.json()) as any).data.readbackRefusal).toBe("token_not_admitted");
    expect(signed.length).toBe(before);
    const { q } = await queueRowByRef(r);
    expect(q!.status).toBe("pending");
    expect(q!.issuanceClaimedAt).toBeNull();
    // The Strata read principal is not even consulted.
    expect(calls).toHaveLength(0);
  });

  it("[H3] overlap: manifest + admitted auto-signs; revoke overrides the manifest for every path", async () => {
    reply = { kind: "ok", instruction: { token: OVERLAP_TOKEN } };
    expect((await signMint(ref(), OVERLAP_TOKEN)).status).toBe(200);
    // Queue one for a human (readback down) before the revoke.
    reply = { kind: "status", status: 503 };
    const pendingRef = ref();
    expect((await signMint(pendingRef, OVERLAP_TOKEN)).status).toBe(202);
    const res = await post(`/protected-minter/tokens/${OVERLAP_TOKEN}/revoke`, {
      reason: "manifest token incident",
    });
    expect(res.status).toBe(200);
    const before = signed.length;
    reply = { kind: "ok", instruction: { token: OVERLAP_TOKEN } };
    expect((await signMint(ref(), OVERLAP_TOKEN)).status).toBe(403);
    reply = { kind: "status", status: 503 };
    expect((await signMint(ref(), OVERLAP_TOKEN)).status).toBe(403);
    const { tx, q } = await queueRowByRef(pendingRef);
    const approve = await app.request(`/vault/${AGENT}/approve/${tx!.id}`, {
      method: "POST",
      headers: bearer(ownerToken),
      body: JSON.stringify({ reviewDigest: q!.reviewDigest }),
    });
    expect(approve.status).toBe(403);
    expect(signed.length).toBe(before);
  });

  it("[H3] revoke a manifest-only token (no prior admission row) -> refused everywhere", async () => {
    const res = await post(`/protected-minter/tokens/${MANIFEST_ONLY_TOKEN}/revoke`, {
      reason: "manifest-only incident",
    });
    expect(res.status).toBe(200);
    const [row] = await getDb()
      .select()
      .from(protectedMinterTokens)
      .where(eq(protectedMinterTokens.tokenAddress, MANIFEST_ONLY_TOKEN));
    expect(row!.status).toBe("revoked");
    const before = signed.length;
    reply = { kind: "status", status: 503 };
    expect((await signMint(ref(), MANIFEST_ONLY_TOKEN)).status).toBe(403);
    expect(signed.length).toBe(before);
  });

  /** H4 helper: a read-back-approved, claimed row with an outstanding permit. */
  async function outstandingReadbackPermit(token = TOKEN) {
    const r = ref();
    reply = { kind: "status", status: 503 };
    expect((await signMint(r, token)).status).toBe(202);
    const { tx, q } = await queueRowByRef(r);
    await getDb()
      .update(approvalQueue)
      .set({ status: "approved", approvalSource: "issuance_readback", instructionDigest: DIGEST })
      .where(eq(approvalQueue.id, q!.id));
    const permit = await issueProtectedSigningPermit({
      tenantId: TENANT,
      agentId: AGENT,
      txId: tx!.id,
      reviewDigest: q!.reviewDigest!,
    });
    const keyUse = () =>
      vault.signTransaction(
        {
          agentId: AGENT,
          tenantId: TENANT,
          to: token,
          value: "0",
          data: mint(),
          chainId: 8453,
          executionRef: r,
          broadcast: true,
        },
        {
          txId: tx!.id,
          policyResults: [],
          status: "signed",
          protectedPermit: permit,
          protectedReviewDigest: q!.reviewDigest!,
        },
      );
    return { r, txId: tx!.id, keyUse };
  }

  it("[H4] suspend completes while a permit is outstanding -> no key use; row back on the human queue, not failed", async () => {
    const { r, keyUse } = await outstandingReadbackPermit();
    const { q: claimBefore } = await queueRowByRef(r);
    expect(claimBefore!.issuanceClaimedAt).not.toBeNull();
    expect((await post("/protected-minter/suspend", { reason: "incident" })).status).toBe(200);
    const before = signed.length;
    try {
      await expect(keyUse()).rejects.toBeInstanceOf(ProtectedKeyUseReleasedError);
      expect(signed.length).toBe(before);
      const { tx, q } = await queueRowByRef(r);
      expect(tx!.status).toBe("pending");
      expect(tx!.txHash).toBeNull();
      expect(q!.status).toBe("pending");
      expect(q!.approvalSource).toBeNull();
      // (c): the original claim and read-back audit identity survive the handoff.
      expect(q!.issuanceClaimedAt?.getTime()).toBe(claimBefore!.issuanceClaimedAt?.getTime());
      expect(q!.instructionDigest).toBe(claimBefore!.instructionDigest);
      expect(q!.resolvedBy).toBe(claimBefore!.resolvedBy);
      const h = (q!.reviewProjection as any).readbackHandoff;
      expect(h.reason).toBe("agent_suspended");
      expect(h.from).toBe("issuance_readback");
      expect(new Date(h.claimedAt).getTime()).toBe(
        new Date(claimBefore!.issuanceClaimedAt as never).getTime(),
      );
      expect(h.resolvedBy).toBe(claimBefore!.resolvedBy);
      expect(h.instructionDigest).toBe(claimBefore!.instructionDigest);
      expect(h.humanClaimedAt).toBeNull();
    } finally {
      expect((await post("/protected-minter/resume")).status).toBe(200);
    }
    // The existing human path can still complete it exactly once.
    const { tx, q } = await queueRowByRef(r);
    const approve = await app.request(`/vault/${AGENT}/approve/${tx!.id}`, {
      method: "POST",
      headers: bearer(ownerToken),
      body: JSON.stringify({ reviewDigest: q!.reviewDigest }),
    });
    expect(approve.status).toBe(200);
    expect(signed.length).toBe(before + 1);
    const after = (await queueRowByRef(r)).q!;
    expect(after.issuanceClaimedAt?.getTime()).toBe(claimBefore!.issuanceClaimedAt?.getTime());
    expect((after.reviewProjection as any).readbackHandoff.humanClaimedAt).not.toBeNull();
    // Human re-claim is single use: a replayed approval cannot issue a second permit.
    const again = await app.request(`/vault/${AGENT}/approve/${tx!.id}`, {
      method: "POST",
      headers: bearer(ownerToken),
      body: JSON.stringify({ reviewDigest: q!.reviewDigest }),
    });
    expect(again.status).not.toBe(200);
    expect(signed.length).toBe(before + 1);
  });

  it("[H4] suspend lands after key-use authorization -> already-sent work is kept (signed once), never re-signed or orphaned", async () => {
    sendSpy.mockImplementationOnce((async (
      _c: unknown,
      tx: { to: string; data?: string; chainId: number },
    ) => {
      // The brake commits while the transaction is on the wire.
      expect((await post("/protected-minter/suspend", { reason: "late incident" })).status).toBe(
        200,
      );
      signed.push(tx);
      return `0x${signed.length.toString(16).padStart(64, "0")}`;
    }) as never);
    const before = signed.length;
    const r = ref();
    reply = { kind: "ok", instruction: {} };
    try {
      const res = await signMint(r);
      expect(res.status).toBe(200);
      const first = (await res.json()) as any;
      expect(signed.length).toBe(before + 1);
      const { tx } = await queueRowByRef(r);
      expect(tx!.status).toBe("signed");
      expect(tx!.txHash).toBe(first.data.txHash);
      // Replay while suspended observes the same hash; no second signature.
      const again = await signMint(r);
      expect(((await again.json()) as any).data.txHash).toBe(first.data.txHash);
      expect(signed.length).toBe(before + 1);
    } finally {
      expect((await post("/protected-minter/resume")).status).toBe(200);
    }
  });

  it("[H4] revoke completes while a permit is outstanding -> refused at key use", async () => {
    const LATE = "0x0000000000000000000000000000000000700004";
    await getDb()
      .insert(protectedMinterTokens)
      .values({
        id: crypto.randomUUID(),
        tenantId: TENANT,
        agentId: AGENT,
        chainId: 8453,
        tokenAddress: LATE,
        deployTxHash: `0x${"a4".repeat(32)}`,
        deployExecutionRef: "tokenization:deploy:a4",
      });
    const { keyUse } = await outstandingReadbackPermit(LATE);
    expect((await post(`/protected-minter/tokens/${LATE}/revoke`, { reason: "late" })).status).toBe(
      200,
    );
    const before = signed.length;
    await expect(keyUse()).rejects.toThrow(/revoked/);
    expect(signed.length).toBe(before);
  });

  it("[H4] revoke vs first admission, both orders -> never an active row after a completed revoke", async () => {
    const admit = (address: string) =>
      getDb()
        .insert(protectedMinterTokens)
        .values({
          id: crypto.randomUUID(),
          tenantId: TENANT,
          agentId: AGENT,
          chainId: 8453,
          tokenAddress: address,
          deployTxHash: `0x${"a5".repeat(32)}`,
          deployExecutionRef: "tokenization:deploy:a5",
        })
        .onConflictDoNothing(); // exactly what admitOwnDeployedToken does
    const status = async (address: string) =>
      (
        await getDb()
          .select({ s: protectedMinterTokens.status })
          .from(protectedMinterTokens)
          .where(eq(protectedMinterTokens.tokenAddress, address))
      ).map((x) => x.s);
    // Order 1: revoke first (tombstone), admission second -> stays revoked.
    const A = "0x0000000000000000000000000000000000700005";
    expect((await post(`/protected-minter/tokens/${A}/revoke`, { reason: "pre" })).status).toBe(
      200,
    );
    await admit(A);
    expect(await status(A)).toEqual(["revoked"]);
    // Order 2: admission wins the race, revoke second -> flipped, reported revoked.
    const B = "0x0000000000000000000000000000000000700006";
    await admit(B);
    const res = await post(`/protected-minter/tokens/${B}/revoke`, { reason: "post" });
    expect(res.status).toBe(200);
    expect(await status(B)).toEqual(["revoked"]);
    // Concurrent: admission and revoke together -> revoked either way.
    const C = "0x0000000000000000000000000000000000700007";
    const [rv] = await Promise.all([
      post(`/protected-minter/tokens/${C}/revoke`, { reason: "race" }),
      admit(C),
    ]);
    expect(rv.status).toBe(200);
    expect(await status(C)).toEqual(["revoked"]);
  });

  /**
   * H1 harness: the REAL protected broadcast (prepare -> sign -> persist ->
   * send raw) against an in-memory chain. `mode` scripts the failure.
   */
  async function withFakeChain(
    run: (chain: {
      mined: Map<string, string>; // hash -> raw
      sends: string[]; // every raw handed to sendRawEvm
      mode: {
        send: "ok" | "crash_before" | "lost_ack";
        observe: "ok" | "down";
        depth: "deep" | "shallow";
      };
      bumpNonce: () => void;
    }) => Promise<void>,
  ) {
    const original = VaultClass.prototype.broadcastEvm as unknown as (
      ...a: unknown[]
    ) => Promise<string>;
    const mined = new Map<string, string>();
    const sends: string[] = [];
    let nonce = 0;
    const mode = {
      send: "ok" as "ok" | "crash_before" | "lost_ack",
      observe: "ok" as "ok" | "down",
      // "shallow": the latest nonce moved but nothing is yet at the
      // confirmation depth (propagation lag / reorg window).
      depth: "deep" as "deep" | "shallow",
    };
    const spies = [
      spyOn(vault as never, "prepareProtectedEvm" as never).mockImplementation((async (
        _c: unknown,
        tx: { to: `0x${string}`; value: bigint; data?: `0x${string}`; chainId: number },
      ) => ({
        type: "eip1559",
        to: tx.to,
        value: tx.value,
        data: tx.data,
        gas: 100000n,
        nonce,
        maxFeePerGas: 2_000_000_000n,
        maxPriorityFeePerGas: 1_000_000n,
        chainId: tx.chainId,
      })) as never),
      spyOn(vault as never, "sendRawEvm" as never).mockImplementation((async (
        _c: unknown,
        raw: `0x${string}`,
      ) => {
        sends.push(raw);
        if (mode.send === "crash_before") throw new Error("socket hang up");
        const h = keccak256(raw);
        if (!mined.has(h)) {
          mined.set(h, raw);
          nonce += 1;
          signed.push({ to: "mined", chainId: 8453 });
        }
        if (mode.send === "lost_ack") throw new Error("socket hang up");
        return h;
      }) as never),
      spyOn(vault as never, "observeProtectedTx" as never).mockImplementation((async (
        _chainId: number,
        hash: string,
      ) => {
        if (mode.observe === "down") throw new Error("rpc down");
        const h = hash.toLowerCase();
        return {
          latestNonce: nonce,
          nonceAtDepth: mode.depth === "shallow" ? 0 : nonce,
          receipt: mined.has(h) ? "success" : null,
          known: mined.has(h),
        };
      }) as never),
    ];
    sendSpy.mockImplementation(async function (this: unknown, ...a: unknown[]) {
      return original.apply(vault, a);
    } as never);
    try {
      await run({ mined, sends, mode, bumpNonce: () => (nonce += 1) });
    } finally {
      for (const sp of spies) sp.mockRestore();
      sendSpy.mockImplementation((async (
        _c: unknown,
        tx: { to: string; data?: string; chainId: number },
      ) => {
        signed.push(tx);
        return `0x${signed.length.toString(16).padStart(64, "0")}`;
      }) as never);
    }
  }

  it("[H1] signed bytes, nonce and hash are durable BEFORE send; happy path records sent_at", async () => {
    await withFakeChain(async (chain) => {
      reply = { kind: "ok", instruction: {} };
      const r = ref();
      const res = await signMint(r);
      expect(res.status).toBe(200);
      const { tx } = await queueRowByRef(r);
      expect(tx!.signedRaw).toBe(chain.sends[0]);
      expect(tx!.txHash).toBe(keccak256(tx!.signedRaw as `0x${string}`));
      expect(tx!.signedNonce).toBe(0);
      expect(tx!.signerAddress).toBe(signerAddress.toLowerCase());
      expect(tx!.sentAt).not.toBeNull();
      expect(chain.mined.size).toBe(1);
    });
  });

  it("[H1] crash after sign, before send: row kept signed (not failed); replay retransmits the SAME bytes -> exactly one mint", async () => {
    await withFakeChain(async (chain) => {
      chain.mode.send = "crash_before";
      chain.mode.observe = "down"; // the in-request reconcile cannot see the chain either
      reply = { kind: "ok", instruction: {} };
      const r = ref();
      const res = await signMint(r);
      expect(res.status).toBe(202);
      expect(((await res.json()) as any).data.reconciling).toBe(true);
      const { tx, q } = await queueRowByRef(r);
      expect(tx!.status).toBe("signed");
      expect(tx!.signedRaw).not.toBeNull();
      expect(tx!.sentAt).toBeNull();
      expect(q!.issuanceClaimedAt).not.toBeNull(); // claim never reset
      expect(chain.mined.size).toBe(0);
      // Network back. Replays reconcile: unknown to chain -> same bytes resent.
      chain.mode.send = "ok";
      chain.mode.observe = "ok";
      const again = await Promise.all([signMint(r), signMint(r), signMint(r)]);
      for (const a of again) expect([200, 202]).toContain(a.status);
      expect(new Set(chain.sends)).toEqual(new Set([tx!.signedRaw!]));
      expect(chain.mined.size).toBe(1);
      const last = await signMint(r);
      expect(last.status).toBe(200);
      const body = (await last.json()) as any;
      expect(body.data.status).toBe("confirmed");
      expect(body.data.txHash).toBe(tx!.txHash);
      expect(chain.mined.size).toBe(1);
    });
  });

  it("[H1] lost acknowledgement (send landed, response lost): reconciled to confirmed, never failed, never resent", async () => {
    await withFakeChain(async (chain) => {
      chain.mode.send = "lost_ack";
      reply = { kind: "ok", instruction: {} };
      const r = ref();
      const res = await signMint(r);
      expect(res.status).toBe(202);
      const body = (await res.json()) as any;
      expect(body.data.status).toBe("confirmed");
      expect(chain.mined.size).toBe(1);
      expect(chain.sends).toHaveLength(1);
      const { tx } = await queueRowByRef(r);
      expect(tx!.status).toBe("confirmed");
      const lookup = await app.request(`/vault/${AGENT}/actions/by-ref/${encodeURIComponent(r)}`, {
        headers: bearer(agentJwt),
      });
      expect(((await lookup.json()) as any).data.status).toBe("confirmed");
      expect(chain.sends).toHaveLength(1);
      expect(chain.mined.size).toBe(1);
    });
  });

  it("[H1] crash after claim, before any signature: replay resumes under the SAME claim and ref -> exactly one mint, no stranded row", async () => {
    await withFakeChain(async (chain) => {
      // Readback down -> queued; then simulate a read-back approval whose
      // process died right after the claim (no permit survives, nothing signed).
      reply = { kind: "status", status: 503 };
      const r = ref();
      expect((await signMint(r)).status).toBe(202);
      const { tx, q } = await queueRowByRef(r);
      const claimedAt = new Date(Date.now() - 5 * 60_000);
      await getDb()
        .update(approvalQueue)
        .set({
          status: "approved",
          approvalSource: "issuance_readback",
          instructionDigest: DIGEST,
          issuanceClaimedAt: claimedAt,
        })
        .where(eq(approvalQueue.id, q!.id));
      // Status is "processing" (not misreported as pending_approval).
      const look = await app.request(`/vault/${AGENT}/actions/by-ref/${encodeURIComponent(r)}`, {
        headers: bearer(agentJwt),
      });
      expect(look.status).toBe(200);
      // The lookup itself resumed: one signature, one mint.
      expect(chain.mined.size).toBe(1);
      const results = await Promise.all([signMint(r), signMint(r)]);
      for (const x of results) expect(x.status).toBe(200);
      expect(chain.mined.size).toBe(1);
      expect(new Set(chain.sends).size).toBe(1);
      const { tx: after, q: qa } = await queueRowByRef(r);
      expect(after!.id).toBe(tx!.id);
      expect(["signed", "confirmed"]).toContain(after!.status);
      expect(qa!.issuanceClaimedAt!.getTime()).toBe(claimedAt.getTime());
    });
  });

  it("[H1] a fresh claim (< permit TTL) is not resumed: the original request may still hold its permit", async () => {
    await withFakeChain(async (chain) => {
      reply = { kind: "status", status: 503 };
      const r = ref();
      expect((await signMint(r)).status).toBe(202);
      const { q } = await queueRowByRef(r);
      await getDb()
        .update(approvalQueue)
        .set({
          status: "approved",
          approvalSource: "issuance_readback",
          instructionDigest: DIGEST,
          issuanceClaimedAt: new Date(),
        })
        .where(eq(approvalQueue.id, q!.id));
      const res = await signMint(r);
      expect(res.status).toBe(202);
      expect(((await res.json()) as any).data.status).toBe("processing");
      expect(chain.sends).toHaveLength(0);
    });
  });

  it("[H1] nonce consumed by a different transaction: marked failed for human reconciliation, never re-signed or resent", async () => {
    await withFakeChain(async (chain) => {
      chain.mode.send = "crash_before";
      chain.mode.observe = "down";
      reply = { kind: "ok", instruction: {} };
      const r = ref();
      expect((await signMint(r)).status).toBe(202);
      chain.bumpNonce(); // someone else's tx used our nonce
      chain.mode.send = "ok";
      chain.mode.observe = "ok";
      const sendsBefore = chain.sends.length;
      const res = await signMint(r);
      expect(res.status).toBe(500);
      expect(((await res.json()) as any).data.status).toBe("failed");
      expect(chain.sends.length).toBe(sendsBefore);
      expect(chain.mined.size).toBe(0);
      const { q } = await queueRowByRef(r);
      expect(q!.issuanceClaimedAt).not.toBeNull();
    });
  });

  it("[H1] RPC error during reconcile is UNKNOWN: row stays signed (never failed), later recovers to exactly one mint", async () => {
    await withFakeChain(async (chain) => {
      chain.mode.send = "crash_before";
      chain.mode.observe = "down";
      reply = { kind: "ok", instruction: {} };
      const r = ref();
      expect((await signMint(r)).status).toBe(202);
      const { tx } = await queueRowByRef(r);
      const scope = { tenantId: tx!.tenantId, agentId: tx!.agentId, txId: tx!.id };
      for (let i = 0; i < 3; i++) {
        expect(await vault.reconcileProtectedTransaction(scope)).toBe("unknown");
      }
      const mid = (await queueRowByRef(r)).tx!;
      expect(mid.status).toBe("signed");
      expect(mid.signedRaw).toBe(tx!.signedRaw);
      chain.mode.send = "ok";
      chain.mode.observe = "ok";
      expect(await vault.reconcileProtectedTransaction(scope)).toBe("sent");
      expect(await vault.reconcileProtectedTransaction(scope)).toBe("confirmed");
      expect(chain.mined.size).toBe(1);
      expect(new Set(chain.sends).size).toBe(1);
      const { q } = await queueRowByRef(r);
      expect(q!.issuanceClaimedAt).not.toBeNull();
    });
  });

  it("[H1] nonce consumed above the confirmation depth only: stays signed, not failed, not resent", async () => {
    await withFakeChain(async (chain) => {
      chain.mode.send = "crash_before";
      chain.mode.observe = "down";
      reply = { kind: "ok", instruction: {} };
      const r = ref();
      expect((await signMint(r)).status).toBe(202);
      const { tx } = await queueRowByRef(r);
      const scope = { tenantId: tx!.tenantId, agentId: tx!.agentId, txId: tx!.id };
      chain.bumpNonce();
      chain.mode.send = "ok";
      chain.mode.observe = "ok";
      chain.mode.depth = "shallow";
      const sendsBefore = chain.sends.length;
      expect(await vault.reconcileProtectedTransaction(scope)).toBe("unknown");
      expect((await queueRowByRef(r)).tx!.status).toBe("signed");
      expect(chain.sends.length).toBe(sendsBefore);
      chain.mode.depth = "deep";
      expect(await vault.reconcileProtectedTransaction(scope)).toBe("nonce_consumed");
      expect((await queueRowByRef(r)).tx!.status).toBe("failed");
      expect(chain.sends.length).toBe(sendsBefore);
      expect(chain.mined.size).toBe(0);
    });
  });

  it("[M8] the readback path never touches the human approve route; the agent token still cannot approve", async () => {
    reply = { kind: "status", status: 409, body: { reason: "no_standing_authorization" } };
    const r = ref();
    expect((await signMint(r)).status).toBe(202);
    const { tx, q } = await queueRowByRef(r);
    const res = await app.request(`/vault/${AGENT}/approve/${tx!.id}`, {
      method: "POST",
      headers: bearer(agentJwt),
      body: JSON.stringify({ reviewDigest: q!.reviewDigest }),
    });
    expect(res.status).toBe(403);
  });
});

describe("issuance readback client (contract with Strata S2)", () => {
  it("strict schema: exact keys, types, authorized status", () => {
    const good: IssuanceInstruction = {
      tenantRef: "t",
      chainId: 8453,
      token: TOKEN,
      recipient: RECIPIENT,
      amount: "1",
      participationId: "p",
      mintId: "m",
      executionRef: "r",
      status: "authorized",
      instructionDigest: DIGEST,
    };
    expect(readback.parseIssuanceInstruction(good)).not.toBeNull();
    expect(readback.parseIssuanceInstruction({ ...good, extra: 1 })).toBeNull();
    expect(readback.parseIssuanceInstruction({ ...good, amount: "0" })).toBeNull();
    expect(readback.parseIssuanceInstruction({ ...good, amount: "01" })).toBeNull();
    expect(readback.parseIssuanceInstruction({ ...good, amount: 1 })).toBeNull();
    expect(readback.parseIssuanceInstruction({ ...good, chainId: "8453" })).toBeNull();
    expect(readback.parseIssuanceInstruction({ ...good, chainId: 0 })).toBeNull();
    expect(readback.parseIssuanceInstruction({ ...good, token: "0x1" })).toBeNull();
    expect(readback.parseIssuanceInstruction({ ...good, instructionDigest: "0x12" })).toBeNull();
    expect(readback.parseIssuanceInstruction({ ...good, status: "approved" })).toBeNull();
    expect(readback.parseIssuanceInstruction([good])).toBeNull();
  });

  it("config: https only (loopback http allowed), bounded timeout", () => {
    const cfg = readback.readbackConfigFromEnv;
    expect(
      cfg({
        STRATA_ISSUANCE_READBACK_URL: "http://strata.example",
        STRATA_ISSUANCE_READBACK_TOKEN: "t",
      }),
    ).toBeNull();
    expect(
      cfg({
        STRATA_ISSUANCE_READBACK_URL: "http://127.0.0.1:3000",
        STRATA_ISSUANCE_READBACK_TOKEN: "t",
      })?.baseUrl,
    ).toBe("http://127.0.0.1:3000");
    const c = cfg({
      STRATA_ISSUANCE_READBACK_URL: "https://strata.example/",
      STRATA_ISSUANCE_READBACK_TOKEN: "t",
      STRATA_ISSUANCE_READBACK_TIMEOUT_MS: "999999",
    });
    expect(c?.baseUrl).toBe("https://strata.example");
    expect(c?.timeoutMs).toBe(readback.DEFAULT_READBACK_TIMEOUT_MS);
  });

  it("compareInstruction: case-insensitive addresses, integer amount", () => {
    const ins = {
      chainId: 8453,
      token: TOKEN.toUpperCase().replace("0X", "0x"),
      recipient: RECIPIENT,
      amount: "5",
    } as IssuanceInstruction;
    const base = { chainId: 8453, token: TOKEN, recipient: RECIPIENT, amount: 5n };
    expect(readback.compareInstruction(ins, base)).toBeNull();
    expect(readback.compareInstruction(ins, { ...base, amount: 6n })).toBe("amount");
    expect(readback.compareInstruction(ins, { ...base, chainId: 84532 })).toBe("chainId");
  });
});
