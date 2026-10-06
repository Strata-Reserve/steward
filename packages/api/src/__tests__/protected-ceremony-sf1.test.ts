/**
 * STRATA-1499 SF-1 ceremony: protected-first signer creation.
 *
 *   POST /agents/protected   (human owner/admin session ONLY)
 *     body:   { id, name? }
 *     result: { id, tenantId, walletAddress, protected: true, status: "inert" }
 *
 * Lifecycle pinned here: create protected + inert -> obtain address -> install
 * manifest pinned to that exact address -> verify -> activate/use. The Safe
 * MINTER_ROLE grant is a separate human step and is asserted to NOT happen.
 *
 * Every case is adversarial and fail-closed: the key exists from step one, but
 * nothing can sign with it until a manifest exactly covers tenant + agent +
 * address + one chain.
 */
import { afterAll, beforeAll, describe, expect, it, type Mock, spyOn } from "bun:test";
import { generateApiKey, signAccessToken, signAgentToken } from "@stwd/auth";
import {
  agents,
  approvalQueue,
  closeDb,
  getDb,
  tenants,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";
import type { Hono } from "hono";
import { encodeFunctionData, parseAbi } from "viem";

const TENANT = "strata-ceremony";
const OTHER_TENANT = "other-ceremony";
const AGENT = "ceremony-minter";
const ORDINARY = "ceremony-ordinary";
const FACTORY = "0x00000000000000000000000000000000000f0005";
const TOKEN = "0x0000000000000000000000000000000000700006";
const SAFE = "0x3Ea77cDf3eC33603bF4135bb1a36712B5e21d721";
const RECIPIENT = "0x00000000000000000000000000000000000000ad";
const OWNER_USER = crypto.randomUUID();
const ADMIN_USER = crypto.randomUUID();
const MEMBER_USER = crypto.randomUUID();
const OTHER_OWNER_USER = crypto.randomUUID();

const TOKEN_ABI = parseAbi(["function mint(address to, uint256 amount)"]);

type Manifest = import("../services/prod-minter-boundary").ProtectedMinterManifest;

let app: Hono;
let rootKey: string;
let otherRootKey: string;
let signerAddress: string;
let ownerToken: string;
let adminToken: string;
let memberToken: string;
let otherOwnerToken: string;
let ordinaryAgentJwt: string;
let vault: Awaited<typeof import("../services/context")>["vault"];
let boundary: typeof import("../services/prod-minter-boundary");
let sendSpy: Mock<(...args: unknown[]) => Promise<unknown>>;
let fetchSpy: Mock<typeof fetch>;
const signedBytes: Array<{ to: string; value: bigint; data?: string; chainId: number }> = [];
let refCounter = 0;
const ref = () => `ceremony:test:${++refCounter}`;

const rootHeaders = (key = rootKey, tenant = TENANT) => ({
  "Content-Type": "application/json",
  "X-Steward-Tenant": tenant,
  "X-Steward-Key": key,
});
const bearer = (t: string) => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${t}`,
});

function mintCalldata() {
  return encodeFunctionData({
    abi: TOKEN_ABI,
    functionName: "mint",
    args: [RECIPIENT as `0x${string}`, 1000n * 10n ** 18n],
  });
}
function manifest(
  addr: string,
  chainId: 8453 | 84532 = 8453,
  overrides: Partial<Manifest> = {},
): Manifest {
  return {
    tenantId: TENANT,
    agentId: AGENT,
    signerAddress: addr,
    chainId,
    safeAdmin: SAFE,
    factories: [FACTORY],
    verifiedTokens: [{ address: TOKEN, provenance: `0xdeploytx:${chainId}:verified` }],
    approvers: [OWNER_USER, ADMIN_USER],
    ...overrides,
  };
}
async function call(method: string, path: string, headers: Record<string, string>, body?: unknown) {
  return app.request(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}
async function json<T = any>(r: Response): Promise<T> {
  return (await r.json()) as T;
}
const createProtected = (headers: Record<string, string>, body: unknown = { id: AGENT }) =>
  call("POST", "/agents/protected", headers, body);
const propose = (
  agent: string,
  headers: Record<string, string>,
  chainId: unknown = 8453,
  executionRef = ref(),
) =>
  call("POST", `/vault/${agent}/sign`, headers, {
    to: TOKEN,
    value: "0",
    data: mintCalldata(),
    chainId,
    executionRef,
  });
const freshAgentJwt = (agent = AGENT) => signAgentToken({ agentId: agent, tenantId: TENANT }, "1h");

async function protectedRow(agent = AGENT) {
  const [row] = await getDb()
    .select({ protected: agents.protected, walletAddress: agents.walletAddress })
    .from(agents)
    .where(and(eq(agents.id, agent), eq(agents.tenantId, TENANT)));
  return row ?? null;
}
async function agentTxCount(agent = AGENT) {
  return (await getDb().select().from(transactions).where(eq(transactions.agentId, agent))).length;
}

/** Every capability a signer could have, exercised with every credential kind. */
async function assertZeroCapability(label: string) {
  const jwt = await freshAgentJwt();
  const failures: Array<Record<string, unknown>> = [];
  const probes: Array<[string, () => Promise<Response>]> = [
    ["propose:agentJwt:8453", () => propose(AGENT, bearer(jwt), 8453)],
    ["propose:agentJwt:84532", () => propose(AGENT, bearer(jwt), 84532)],
    ["propose:owner", () => propose(AGENT, bearer(ownerToken), 8453)],
    ["propose:apiKey", () => propose(AGENT, rootHeaders(), 8453)],
    ["addresses:agentJwt", () => call("GET", `/vault/${AGENT}/addresses`, bearer(jwt))],
    ["own:agentJwt", () => call("GET", `/agents/${AGENT}`, bearer(jwt))],
    [
      "signMessage:apiKey",
      () => call("POST", `/vault/${AGENT}/sign-message`, rootHeaders(), { message: "x" }),
    ],
    [
      "signMessage:owner",
      () => call("POST", `/vault/${AGENT}/sign-message`, bearer(ownerToken), { message: "x" }),
    ],
    ["export:apiKey", () => call("POST", `/vault/${AGENT}/export`, rootHeaders(), {})],
    ["export:owner", () => call("POST", `/vault/${AGENT}/export`, bearer(ownerToken), {})],
    [
      "import:owner",
      () =>
        call("POST", `/vault/${AGENT}/import`, bearer(ownerToken), {
          privateKey: `0x${"2".repeat(64)}`,
        }),
    ],
    [
      "rpc:apiKey",
      () =>
        call("POST", `/vault/${AGENT}/rpc`, rootHeaders(), { method: "eth_chainId", params: [] }),
    ],
    ["token:owner", () => call("POST", `/agents/${AGENT}/token`, bearer(ownerToken), {})],
    ["token:apiKey", () => call("POST", `/agents/${AGENT}/token`, rootHeaders(), {})],
    [
      "wallets:owner",
      () => call("POST", `/agents/${AGENT}/wallets`, bearer(ownerToken), { chainFamily: "evm" }),
    ],
    ["delete:owner", () => call("DELETE", `/agents/${AGENT}`, bearer(ownerToken))],
    ["delete:apiKey", () => call("DELETE", `/agents/${AGENT}`, rootHeaders())],
    [
      "approve:owner",
      () =>
        call("POST", `/vault/${AGENT}/approve/none`, bearer(ownerToken), {
          reviewDigest: `0x${"0".repeat(64)}`,
        }),
    ],
  ];
  for (const [name, fn] of probes) {
    const r = await fn();
    if (r.status !== 403) failures.push({ label, name, status: r.status, body: await r.text() });
  }
  const direct: Record<string, string> = {};
  for (const [name, fn] of [
    ["signMessage", () => vault.signMessage(TENANT, AGENT, "x")],
    ["export", () => vault.exportPrivateKey(TENANT, AGENT)],
    [
      "signTransaction",
      () =>
        vault.signTransaction({
          tenantId: TENANT,
          agentId: AGENT,
          to: TOKEN,
          value: "0",
          data: mintCalldata(),
          chainId: 8453,
        } as never),
    ],
  ] as Array<[string, () => Promise<unknown>]>) {
    try {
      await fn();
      direct[name] = "SUCCEEDED";
    } catch (e) {
      direct[name] = /Protected signer:/.test(String(e)) ? "refused" : String(e);
    }
    if (direct[name] !== "refused") failures.push({ label, direct: name, outcome: direct[name] });
  }
  expect(failures).toEqual([]);
  // Nothing was queued, signed or broadcast, and the marker is intact.
  expect(await agentTxCount()).toBe(0);
  expect(signedBytes).toHaveLength(0);
  expect((await protectedRow())?.protected).toBe(true);
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL = "postgres://test:test@localhost:5432/steward";
  process.env.STEWARD_MASTER_PASSWORD = "protected-ceremony-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "protected-ceremony-audit-key-32-bytes-minimum-aa";
  process.env.STEWARD_JWT_SECRET = "protected-ceremony-jwt-secret-with-enough-bytes-aaaa";
  // Synthetic, never dialled: broadcast seam is stubbed and fetch is spied.
  process.env.RPC_URL_84532 = "https://protected-tests-sepolia.invalid/v2/UNUSED";
  process.env.RPC_URL_8453 = "https://protected-tests-mainnet.invalid/v2/UNUSED";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  const k = generateApiKey();
  const k2 = generateApiKey();
  rootKey = k.key;
  otherRootKey = k2.key;
  await db.insert(tenants).values([
    { id: TENANT, name: "Strata ceremony", apiKeyHash: k.hash },
    { id: OTHER_TENANT, name: "Other ceremony", apiKeyHash: k2.hash },
  ]);
  await db.insert(users).values(
    [OWNER_USER, ADMIN_USER, MEMBER_USER, OTHER_OWNER_USER].map((id) => ({
      id,
      email: `${id}@example.test`,
    })),
  );
  await db.insert(userTenants).values([
    { userId: OWNER_USER, tenantId: TENANT, role: "owner" },
    { userId: ADMIN_USER, tenantId: TENANT, role: "admin" },
    { userId: MEMBER_USER, tenantId: TENANT, role: "member" },
    { userId: OTHER_OWNER_USER, tenantId: OTHER_TENANT, role: "owner" },
  ]);

  fetchSpy = spyOn(globalThis, "fetch");
  ({ app } = await import("../app"));
  ({ vault } = await import("../services/context"));
  boundary = await import("../services/prod-minter-boundary");
  boundary.installProtectedMinterManifest(null); // env is unset; make the start state explicit

  const mk = (userId: string, tenantId = TENANT) =>
    signAccessToken({ address: `0x${"1".repeat(40)}`, tenantId, userId } as never, "1h");
  ownerToken = await mk(OWNER_USER);
  adminToken = await mk(ADMIN_USER);
  memberToken = await mk(MEMBER_USER);
  otherOwnerToken = await mk(OTHER_OWNER_USER, OTHER_TENANT);

  const r = await call("POST", "/agents", rootHeaders(), { id: ORDINARY, name: ORDINARY });
  if (r.status !== 200) throw new Error(`ordinary create ${r.status}: ${await r.text()}`);
  ordinaryAgentJwt = await freshAgentJwt(ORDINARY);

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
  fetchSpy?.mockRestore();
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

describe.serial("SF-1 ceremony: POST /agents/protected", () => {
  it("[T9a] a tenant credential cannot create the protected signer: API key, agent token, member, other tenant all refuse before any key exists", async () => {
    const attempts: Array<[string, Record<string, string>]> = [
      ["apiKey", rootHeaders()],
      ["otherTenantApiKey", rootHeaders(otherRootKey, OTHER_TENANT)],
      ["ordinaryAgentJwt", bearer(ordinaryAgentJwt)],
      ["member", bearer(memberToken)],
      ["noAuth", { "Content-Type": "application/json" }],
    ];
    for (const [name, headers] of attempts) {
      const r = await createProtected(headers);
      expect([name, r.status]).toEqual([name, name === "noAuth" ? 401 : 403]);
    }
    expect(await protectedRow()).toBeNull();
    const [otherRow] = await getDb().select().from(agents).where(eq(agents.tenantId, OTHER_TENANT));
    expect(otherRow).toBeUndefined();
    // Another tenant's owner may bootstrap ONLY inside their own tenant, under their own id;
    // that row is protected+quarantined there and never reaches this tenant.
    const other = await createProtected(bearer(otherOwnerToken), { id: "ceremony-other-minter" });
    expect(other.status).toBe(201);
    expect((await json(other)).data.tenantId).toBe(OTHER_TENANT);
    expect(await boundary.isQuarantinedProtectedAgent("ceremony-other-minter")).toBe(true);
    expect(await protectedRow("ceremony-other-minter")).toBeNull();
  });

  it("[T1] human owner creates a PROTECTED, INERT signer; response carries only id + address; marker is persisted; no manifest => cannot sign", async () => {
    const r = await createProtected(bearer(ownerToken), { id: AGENT, name: "Prod minter" });
    expect(r.status).toBe(201);
    const b = await json(r);
    expect(b.ok).toBe(true);
    expect(Object.keys(b.data).sort()).toEqual(
      ["id", "protected", "status", "tenantId", "walletAddress"].sort(),
    );
    expect(b.data.id).toBe(AGENT);
    expect(b.data.tenantId).toBe(TENANT);
    expect(b.data.protected).toBe(true);
    expect(b.data.status).toBe("inert");
    expect(b.data.walletAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);
    // No chain authority, no Safe roles, no credentials, no Solana address.
    for (const k of [
      "token",
      "roles",
      "safe",
      "safeAdmin",
      "minterRole",
      "chainId",
      "walletAddresses",
    ]) {
      expect(b.data[k]).toBeUndefined();
    }
    signerAddress = b.data.walletAddress;

    const row = await protectedRow();
    expect(row?.protected).toBe(true);
    expect(row?.walletAddress.toLowerCase()).toBe(signerAddress.toLowerCase());
    expect(boundary.getProtectedMinterManifest()).toBeNull();
    expect(await boundary.isQuarantinedProtectedAgent(AGENT)).toBe(true);

    await assertZeroCapability("created-no-manifest");
  });

  it("[T1b] the bootstrap is one-shot: the same id cannot be re-created or rebound (lost response => no second key)", async () => {
    const again = await createProtected(bearer(ownerToken));
    expect(again.status).toBe(409);
    const admin = await createProtected(bearer(adminToken));
    expect(admin.status).toBe(409);
    // Ordinary create with the protected id is refused as a duplicate too.
    const ordinary = await call("POST", "/agents", rootHeaders(), { id: AGENT, name: AGENT });
    expect(ordinary.status).toBe(400);
    const row = await protectedRow();
    expect(row?.protected).toBe(true);
    expect(row?.walletAddress.toLowerCase()).toBe(signerAddress.toLowerCase());
  });

  it("[T2] missing manifest -> fail closed (startup posture reports quarantine; every path 403)", async () => {
    boundary.installProtectedMinterManifest(null);
    const q = await boundary.assertProtectedPostureAtStartup();
    expect(q.filter((e) => e.tenantId === TENANT)).toEqual([
      { tenantId: TENANT, agentId: AGENT, reason: "no-manifest" },
    ]);
    // The other tenant's bootstrap row is quarantined too (never covered by this manifest).
    expect(q.find((e) => e.agentId === "ceremony-other-minter")?.reason).toBe("no-manifest");
    await assertZeroCapability("missing-manifest");
  });

  it("[T3] malformed manifest -> fail closed (install throws, nothing becomes active)", async () => {
    const bad: Array<[string, unknown]> = [
      ["zeroAddress", manifest(`0x${"0".repeat(40)}`)],
      ["badAddress", manifest("not-an-address")],
      ["noChain", { ...manifest(signerAddress), chainId: undefined }],
      ["twoChains", { ...manifest(signerAddress), chainId: [8453, 84532] }],
      ["wrongSafe", manifest(signerAddress, 8453, { safeAdmin: RECIPIENT })],
      [
        "noProvenance",
        manifest(signerAddress, 8453, { verifiedTokens: [{ address: TOKEN, provenance: "" }] }),
      ],
      ["badApprover", manifest(signerAddress, 8453, { approvers: ["owner"] })],
      ["emptyIds", manifest(signerAddress, 8453, { tenantId: "", agentId: "" })],
    ];
    for (const [name, m] of bad) {
      expect(() => boundary.installProtectedMinterManifest(m as Manifest), name).toThrow();
      expect(boundary.getProtectedMinterManifest()).toBeNull();
    }
    expect(() =>
      boundary.manifestFromEnv({
        STEWARD_PROTECTED_MINTER_TENANT: TENANT,
        STEWARD_PROTECTED_MINTER_AGENT: AGENT,
        STEWARD_PROTECTED_MINTER_ADDRESS: "bad",
      } as NodeJS.ProcessEnv),
    ).toThrow();
    await assertZeroCapability("malformed-manifest");
  });

  it("[T4] manifest for another signer / address / tenant -> fail closed", async () => {
    const postures: Array<[string, Manifest]> = [
      ["otherAddress", manifest(`0x${"a".repeat(40)}`)],
      ["ordinaryAgentsAddress", manifest((await protectedRow(ORDINARY))!.walletAddress)],
      ["otherAgent", manifest(signerAddress, 8453, { agentId: ORDINARY })],
      ["otherTenant", manifest(signerAddress, 8453, { tenantId: OTHER_TENANT })],
    ];
    try {
      for (const [name, m] of postures) {
        boundary.installProtectedMinterManifest(m);
        expect([
          name,
          boundary.isProtectedMinterCovered({
            tenantId: TENANT,
            id: AGENT,
            walletAddress: signerAddress,
          }),
        ]).toEqual([name, false]);
        expect([name, await boundary.isQuarantinedProtectedAgent(AGENT)]).toEqual([name, true]);
        await assertZeroCapability(name);
      }
    } finally {
      boundary.installProtectedMinterManifest(null);
    }
  });

  it("[T5] wrong-chain manifest -> fail closed (non-allowlisted chain refused at install; a pinned chain refuses every other chain's proposal)", async () => {
    for (const chainId of [1, 10, 8454, "8453", "84532", null]) {
      expect(() =>
        boundary.installProtectedMinterManifest({ ...manifest(signerAddress), chainId } as never),
      ).toThrow();
    }
    expect(boundary.getProtectedMinterManifest()).toBeNull();
    try {
      for (const [pinned, wrong] of [
        [8453, 84532],
        [84532, 8453],
      ] as const) {
        boundary.installProtectedMinterManifest(manifest(signerAddress, pinned));
        const jwt = await freshAgentJwt();
        // An omitted chainId defaults to 8453 in the Vault, so it is only "wrong" for the 84532 pin.
        const wrongChains: unknown[] = [wrong, 1, 10, String(pinned)];
        if (pinned === 84532) wrongChains.push(undefined);
        for (const chainId of wrongChains) {
          const r = await propose(AGENT, bearer(jwt), chainId);
          expect([pinned, chainId, r.status]).toEqual([pinned, chainId, 403]);
          expect((await json(r)).error).toBe(`Protected signer: chainId must be exactly ${pinned}`);
        }
      }
    } finally {
      boundary.installProtectedMinterManifest(null);
    }
    expect(await agentTxCount()).toBe(0);
    expect(signedBytes).toHaveLength(0);
  });

  it("[T6] correct 84532 manifest pinned to the exact address activates: only the Sepolia-authorized operation is possible", async () => {
    boundary.installProtectedMinterManifest(manifest(signerAddress, 84532));
    expect(
      boundary.isProtectedMinterCovered({
        tenantId: TENANT,
        id: AGENT,
        walletAddress: signerAddress,
      }),
    ).toBe(true);
    expect(await boundary.isQuarantinedProtectedAgent(AGENT)).toBe(false);
    expect(
      (await boundary.assertProtectedPostureAtStartup()).filter((e) => e.tenantId === TENANT),
    ).toEqual([]);
    const jwt = await freshAgentJwt();

    // Still no ordinary capability for the activated signer.
    for (const [name, fn] of [
      [
        "signMessage",
        () => call("POST", `/vault/${AGENT}/sign-message`, bearer(ownerToken), { message: "x" }),
      ],
      ["export", () => call("POST", `/vault/${AGENT}/export`, bearer(ownerToken), {})],
      [
        "import",
        () =>
          call("POST", `/vault/${AGENT}/import`, bearer(ownerToken), {
            privateKey: `0x${"2".repeat(64)}`,
          }),
      ],
      ["delete", () => call("DELETE", `/agents/${AGENT}`, bearer(ownerToken))],
      [
        "unshapedCall",
        () =>
          call("POST", `/vault/${AGENT}/sign`, bearer(jwt), {
            to: RECIPIENT,
            value: "1",
            data: "0x",
            chainId: 84532,
            executionRef: ref(),
          }),
      ],
      ["apiKeyPropose", () => propose(AGENT, rootHeaders(), 84532)],
    ] as Array<[string, () => Promise<Response>]>) {
      const r = await fn();
      expect([name, r.status]).toEqual([name, 403]);
    }

    const executionRef = ref();
    const r = await propose(AGENT, bearer(jwt), 84532, executionRef);
    expect(r.status).toBe(202);
    const b = await json(r);
    expect(b.data.status).toBe("pending_approval");
    expect(b.data.review.chainId).toBe(84532);
    const txId = b.data.txId as string;

    // A member of the tenant (not in the allowlist) cannot approve; the pinned owner can.
    const member = await call("POST", `/vault/${AGENT}/approve/${txId}`, bearer(memberToken), {
      reviewDigest: b.data.reviewDigest,
    });
    expect(member.status).toBe(403);
    const ok = await call("POST", `/vault/${AGENT}/approve/${txId}`, bearer(ownerToken), {
      reviewDigest: b.data.reviewDigest,
    });
    expect(ok.status).toBe(200);
    expect(signedBytes).toHaveLength(1);
    expect(signedBytes[0]!.chainId).toBe(84532);
    expect(signedBytes[0]!.to.toLowerCase()).toBe(TOKEN.toLowerCase());
    expect(signedBytes[0]!.value).toBe(0n);
    expect((await protectedRow())?.protected).toBe(true);
  });

  it("[T7] correct 8453 manifest pinned to the exact address: only the mainnet-authorized operation is possible", async () => {
    boundary.installProtectedMinterManifest(manifest(signerAddress, 8453));
    expect(await boundary.isQuarantinedProtectedAgent(AGENT)).toBe(false);
    const jwt = await freshAgentJwt();
    expect((await propose(AGENT, bearer(jwt), 84532)).status).toBe(403);
    expect((await propose(AGENT, rootHeaders(), 8453)).status).toBe(403);
    expect((await call("POST", `/vault/${AGENT}/export`, bearer(ownerToken), {})).status).toBe(403);

    const r = await propose(AGENT, bearer(jwt), 8453);
    expect(r.status).toBe(202);
    const b = await json(r);
    expect(b.data.review.chainId).toBe(8453);
    const ok = await call("POST", `/vault/${AGENT}/approve/${b.data.txId}`, bearer(adminToken), {
      reviewDigest: b.data.reviewDigest,
    });
    expect(ok.status).toBe(200);
    expect(signedBytes).toHaveLength(2);
    expect(signedBytes[1]!.chainId).toBe(8453);
    expect(signedBytes[1]!.to.toLowerCase()).toBe(TOKEN.toLowerCase());
  });

  it("[T10] manifest replacement invalidates approvals bound to the previous manifest", async () => {
    boundary.installProtectedMinterManifest(manifest(signerAddress, 8453));
    const digestA = boundary.getProtectedMinterManifestDigest();
    const jwt = await freshAgentJwt();
    const r = await propose(AGENT, bearer(jwt), 8453);
    expect(r.status).toBe(202);
    const b = await json(r);
    const txId = b.data.txId as string;
    const [qa] = await getDb().select().from(approvalQueue).where(eq(approvalQueue.txId, txId));
    expect(qa?.manifestDigest?.toLowerCase()).toBe(digestA.toLowerCase());

    // Same address, same chain, different pinned token provenance => new digest.
    boundary.installProtectedMinterManifest(
      manifest(signerAddress, 8453, {
        verifiedTokens: [{ address: TOKEN, provenance: "0xdeploytx:8453:re-verified" }],
      }),
    );
    expect(boundary.getProtectedMinterManifestDigest().toLowerCase()).not.toBe(
      digestA.toLowerCase(),
    );
    const stale = await call("POST", `/vault/${AGENT}/approve/${txId}`, bearer(ownerToken), {
      reviewDigest: b.data.reviewDigest,
    });
    expect(stale.status).toBe(403);
    expect((await json(stale)).error).toMatch(/manifest changed/);
    const [qb] = await getDb().select().from(approvalQueue).where(eq(approvalQueue.txId, txId));
    expect(qb?.status).toBe("pending");
    expect(signedBytes).toHaveLength(2);

    // Replacing with an address-mismatched manifest quarantines again, even
    // though the previous manifest was valid: approval and proposal both 403.
    boundary.installProtectedMinterManifest(manifest(`0x${"b".repeat(40)}`, 8453));
    expect(
      (
        await call("POST", `/vault/${AGENT}/approve/${txId}`, bearer(ownerToken), {
          reviewDigest: b.data.reviewDigest,
        })
      ).status,
    ).toBe(403);
    expect((await propose(AGENT, bearer(await freshAgentJwt()), 8453)).status).toBe(403);
    boundary.installProtectedMinterManifest(manifest(signerAddress, 8453));
  });

  it("[T8] an ordinary agent cannot get protected-minter authority through this endpoint", async () => {
    boundary.installProtectedMinterManifest(manifest(signerAddress, 8453));
    // Ordinary agent's credential: refused by the endpoint outright.
    expect(
      (await createProtected(bearer(ordinaryAgentJwt), { id: "ceremony-escalate" })).status,
    ).toBe(403);
    expect(await protectedRow("ceremony-escalate")).toBeNull();
    // Ordinary rows stay ordinary: marker false, and the manifest does not cover them.
    expect((await protectedRow(ORDINARY))?.protected).toBe(false);
    expect(boundary.isProtectedMinter(TENANT, ORDINARY)).toBe(false);
    expect(await boundary.isQuarantinedProtectedAgent(ORDINARY)).toBe(false);
    // A second protected row created by an owner under a different id is NOT
    // the manifest's signer: it is quarantined, not authorized.
    const second = await createProtected(bearer(ownerToken), { id: "ceremony-second" });
    expect(second.status).toBe(201);
    expect(await boundary.isQuarantinedProtectedAgent("ceremony-second")).toBe(true);
    expect(
      (await propose("ceremony-second", bearer(await freshAgentJwt("ceremony-second")), 8453))
        .status,
    ).toBe(403);
    expect((await propose("ceremony-second", rootHeaders(), 8453)).status).toBe(403);
    expect(
      (await call("POST", `/vault/ceremony-second/sign-message`, rootHeaders(), { message: "x" }))
        .status,
    ).toBe(403);
    // The ordinary agent itself cannot propose for the protected signer.
    expect((await propose(AGENT, bearer(ordinaryAgentJwt), 8453)).status).toBe(403);
  });

  it("[T9b] a tenant credential cannot use or activate the protected signer; no API or Vault path clears the marker", async () => {
    boundary.installProtectedMinterManifest(manifest(signerAddress, 8453));
    const key = rootHeaders();
    expect((await propose(AGENT, key, 8453)).status).toBe(403);
    expect((await call("POST", `/agents/${AGENT}/token`, key, {})).status).toBe(403);
    expect((await call("POST", `/vault/${AGENT}/export`, key, {})).status).toBe(403);
    expect((await call("POST", `/vault/${AGENT}/sign-message`, key, { message: "x" })).status).toBe(
      403,
    );
    expect((await call("DELETE", `/agents/${AGENT}`, key)).status).toBe(403);
    expect(
      (await call("POST", `/agents/${AGENT}/wallets`, key, { chainFamily: "evm" })).status,
    ).toBe(403);
    expect(
      (await call("POST", "/agents/batch", key, { agents: [{ id: AGENT, name: AGENT }] })).status,
    ).toBe(403);
    // Other tenant's owner/API key: no visibility, no activation.
    expect([403, 404]).toContain((await propose(AGENT, bearer(otherOwnerToken), 8453)).status);
    expect(
      (await createProtected(rootHeaders(otherRootKey, OTHER_TENANT), { id: AGENT })).status,
    ).toBe(403);
    // Agent ids are global: another tenant's owner cannot squat or rebind the protected id.
    expect((await createProtected(bearer(otherOwnerToken), { id: AGENT })).status).toBe(409);
    // Vault-level: import/export refuse; createAgent refuses the existing id.
    await expect(vault.importKey(TENANT, AGENT, `0x${"2".repeat(64)}`, "evm")).rejects.toThrow(
      /Protected signer:/,
    );
    await expect(vault.exportPrivateKey(TENANT, AGENT)).rejects.toThrow(/Protected signer:/);
    await expect(vault.createAgent(TENANT, AGENT, AGENT)).rejects.toThrow(/already exists/);
    const row = await protectedRow();
    expect(row?.protected).toBe(true);
    expect(row?.walletAddress.toLowerCase()).toBe(signerAddress.toLowerCase());
  });

  it("[T11] no Safe role / MINTER_ROLE after setup: no grant call, no funding, no network, no tx from the ceremony itself", async () => {
    // Everything signed in this suite came from explicit human approvals in
    // T6/T7 (one 84532 mint, one 8453 mint). The ceremony steps (create,
    // install, verify) produced nothing.
    expect(signedBytes).toHaveLength(2);
    expect(sendSpy).toHaveBeenCalledTimes(2);
    for (const tx of signedBytes) {
      // Neither signed tx is a Safe/role call: both are the approved mint to the verified token.
      expect(tx.to.toLowerCase()).toBe(TOKEN.toLowerCase());
      expect(tx.to.toLowerCase()).not.toBe(SAFE.toLowerCase());
      expect(tx.data?.slice(0, 10)).toBe(boundary.SELECTOR_MINT);
      expect(tx.value).toBe(0n);
    }
    // No tx rows exist for the ceremony-only rows; the approved mints are the only tx rows for AGENT.
    expect(await agentTxCount("ceremony-second")).toBe(0);
    const rows = await getDb().select().from(transactions).where(eq(transactions.agentId, AGENT));
    expect(rows.every((t) => t.toAddress?.toLowerCase() === TOKEN.toLowerCase())).toBe(true);
    // No outbound network at any point (RPC, Safe, faucet, grant): fetch never dialled.
    expect(fetchSpy).toHaveBeenCalledTimes(0);
    // The source of truth for the grant is the Safe, not Steward: nothing in
    // the API surface references a role grant for this signer.
    const r = await call("GET", `/agents/${AGENT}`, bearer(ownerToken));
    expect(r.status).toBe(200);
    const b = await json(r);
    for (const k of ["roles", "minterRole", "safe", "safeAdmin"])
      expect(b.data?.[k]).toBeUndefined();
  });
});
