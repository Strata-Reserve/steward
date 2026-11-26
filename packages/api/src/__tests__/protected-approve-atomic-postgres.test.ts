/**
 * STRATA-1673 r7 (verify-steward-43-r5 rows 1 and 3) on postgres:16, through
 * the real approve route.
 *  - H1: a refused human claim inside the approval transaction rolls the
 *    approval back (row stays pending, unapproved, unclaimed; zero key use).
 *    The refusal is injected by a test-database trigger that makes the claim
 *    UPDATE match no row, so the real claim code refuses inside the savepoint.
 *  - H2: two overlapping identical resumes by the same approver -> exactly one
 *    signer (200), the other is a replay (409) carrying the same tx hash; one
 *    key use.
 * Chain I/O goes through the vault's protected seams (no RPC). Skipped
 * without DATABASE_URL (admin URL).
 */
import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createPostgresClient } from "@stwd/db";
import { encodeFunctionData, keccak256, parseAbi } from "viem";

const SKIP = !process.env.DATABASE_URL;
const migrationsDir = fileURLToPath(new URL("../../../db/drizzle", import.meta.url));
const runId = crypto.randomUUID().replaceAll("-", "");
const sourceUrl = process.env.DATABASE_URL ?? "";
const DB = `steward_r7_${runId}`;
const dbUrl = (name: string) => {
  const url = new URL(sourceUrl);
  url.pathname = `/${name}`;
  return url.toString();
};
const q = (v: string) => `"${v.replaceAll('"', '""')}"`;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const TENANT = `r7-${runId.slice(0, 20)}`;
const AGENT = "r7-minter";
const OWNER_USER = crypto.randomUUID();
const TOKEN = "0x0000000000000000000000000000000000700007";
const SAFE = "0x3Ea77cDf3eC33603bF4135bb1a36712B5e21d721";
const FACTORY = "0x00000000000000000000000000000000000f0007";
const RECIPIENT = "0x00000000000000000000000000000000000000aa";
const mintData = (n: bigint) =>
  encodeFunctionData({
    abi: parseAbi(["function mint(address to, uint256 amount)"]),
    functionName: "mint",
    args: [RECIPIENT, n],
  });

type Sql = ReturnType<typeof createPostgresClient>;
let admin: Sql | undefined;
let db: Sql | undefined;
let app: any;
let vault: any;
let boundary: any;
let ownerToken: string;
let agentJwt: string;
let refN = 0;

const keyUses: string[] = [];
const sends: string[] = [];
const mined = new Set<string>();
let prepareDelayMs = 0;

const bearer = (t: string) => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${t}`,
});

async function proposeMint() {
  const executionRef = `r7:mint:${++refN}`;
  const res = await app.request(`/vault/${AGENT}/sign`, {
    method: "POST",
    headers: bearer(agentJwt),
    body: JSON.stringify({
      to: TOKEN,
      value: "0",
      data: mintData(BigInt(refN)),
      chainId: 8453,
      executionRef,
    }),
  });
  expect(res.status).toBe(202);
  const [t] = await db!.unsafe(`SELECT id FROM transactions WHERE execution_ref = $1`, [
    executionRef,
  ]);
  const [qr] = await db!.unsafe(`SELECT review_digest FROM approval_queue WHERE tx_id = $1`, [
    t!.id,
  ]);
  return { txId: t!.id as string, digest: qr!.review_digest as string };
}
const approve = (txId: string, digest: string) =>
  app.request(`/vault/${AGENT}/approve/${txId}`, {
    method: "POST",
    headers: bearer(ownerToken),
    body: JSON.stringify({ reviewDigest: digest }),
  });
async function state(txId: string) {
  const [t] = await db!.unsafe(
    `SELECT status, signed_raw, tx_hash FROM transactions WHERE id = $1`,
    [txId],
  );
  const [a] = await db!.unsafe(
    `SELECT status, approved_by_user_id, resolved_at, issuance_claimed_at FROM approval_queue WHERE tx_id = $1`,
    [txId],
  );
  return { tx: t!, q: a! };
}

beforeAll(async () => {
  if (SKIP) return;
  admin = createPostgresClient(sourceUrl);
  await admin.unsafe(`CREATE DATABASE ${q(DB)}`);
  db = createPostgresClient(dbUrl(DB));
  const files = (await Array.fromAsync(new Bun.Glob("*.sql").scan(migrationsDir)))
    .filter((f) => /^\d{4}.*\.sql$/.test(f))
    .sort();
  for (const f of files) {
    const source = await readFile(`${migrationsDir}/${f}`, "utf8");
    for (const s of source.split("--> statement-breakpoint")) {
      if (s.trim() && s.trim() !== "--") await db.unsafe(s.trim());
    }
  }
  process.env.DATABASE_URL = dbUrl(DB);
  process.env.STEWARD_MASTER_PASSWORD = "r7-master-password";
  process.env.STEWARD_AUDIT_HMAC_KEY = "r7-audit-key-32-bytes-minimum-aaaaaaaaaaaaaa";
  process.env.STEWARD_JWT_SECRET = "r7-jwt-secret-with-enough-bytes-aaaaaaaaaaaa";
  process.env.RPC_URL_8453 = "https://r7-tests.invalid/v2/UNUSED";

  const { generateApiKey, signAccessToken, signAgentToken } = await import("@stwd/auth");
  const k = generateApiKey();
  await db.unsafe(`INSERT INTO tenants (id, name, api_key_hash) VALUES ($1, 'R7', $2)`, [
    TENANT,
    k.hash,
  ]);
  await db.unsafe(`INSERT INTO users (id, email) VALUES ($1, $2)`, [
    OWNER_USER,
    `owner-${OWNER_USER}@example.test`,
  ]);
  await db.unsafe(`INSERT INTO user_tenants (user_id, tenant_id, role) VALUES ($1, $2, 'owner')`, [
    OWNER_USER,
    TENANT,
  ]);

  ({ app } = await import("../app"));
  ({ vault } = await import("../services/context"));
  boundary = await import("../services/prod-minter-boundary");
  (await import("../services/issuance-readback-client")).setIssuanceReadbackClient(null);

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
  const signerAddress = ((await r.json()) as any).data.walletAddress;
  boundary.installProtectedMinterManifest({
    tenantId: TENANT,
    agentId: AGENT,
    signerAddress,
    chainId: 8453,
    safeAdmin: SAFE,
    factories: [FACTORY],
    verifiedTokens: [{ address: TOKEN, provenance: "0xdeploy:r7" }],
    approvers: [OWNER_USER],
  });
  ownerToken = await signAccessToken(
    { address: `0x${"1".repeat(40)}`, tenantId: TENANT, userId: OWNER_USER } as never,
    "1h",
  );
  agentJwt = await signAgentToken({ agentId: AGENT, tenantId: TENANT }, "1h");

  // Protected chain seams. prepareProtectedEvm runs inside the signing
  // section right before the local key use: one call = one key use.
  spyOn(vault as never, "prepareProtectedEvm" as never).mockImplementation((async (
    _c: unknown,
    tx: { to: `0x${string}`; value: bigint; data?: `0x${string}`; chainId: number },
  ) => {
    keyUses.push(tx.to);
    if (prepareDelayMs) await sleep(prepareDelayMs);
    return {
      type: "eip1559",
      to: tx.to,
      value: tx.value,
      data: tx.data,
      gas: 100000n,
      nonce: mined.size,
      maxFeePerGas: 2_000_000_000n,
      maxPriorityFeePerGas: 1_000_000n,
      chainId: tx.chainId,
    };
  }) as never);
  spyOn(vault as never, "sendRawEvm" as never).mockImplementation((async (
    _c: unknown,
    raw: `0x${string}`,
  ) => {
    sends.push(raw);
    const h = keccak256(raw);
    mined.add(h);
    return h;
  }) as never);
  spyOn(vault as never, "observeProtectedTx" as never).mockImplementation((async (
    _chainId: number,
    hash: string,
  ) => {
    const known = mined.has(hash.toLowerCase());
    return { latestNonce: mined.size, receipt: known ? "success" : null, known, included: null };
  }) as never);
}, 180_000);

afterAll(async () => {
  if (SKIP) return;
  boundary?.installProtectedMinterManifest(null);
  const { closeDb } = await import("@stwd/db");
  await closeDb();
  await db?.end();
  await admin?.unsafe(`DROP DATABASE IF EXISTS ${q(DB)} WITH (FORCE)`);
  await admin?.end();
});

describe.skipIf(SKIP)("STRATA-1673 r7 approve atomicity + concurrent resume (postgres:16)", () => {
  it("[H1] claim refused inside the approval transaction -> approval rolled back, no claim, zero key use; normal path commits both", async () => {
    const { txId, digest } = await proposeMint();
    // Inject a claim refusal: the claim UPDATE (issuance_claimed_at NULL -> set)
    // silently matches no row, so the real claim code refuses in its savepoint.
    await db!.unsafe(`CREATE FUNCTION r7_refuse_claim() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        IF OLD.issuance_claimed_at IS NULL AND NEW.issuance_claimed_at IS NOT NULL THEN
          RETURN NULL;
        END IF;
        RETURN NEW;
      END $$`);
    await db!.unsafe(
      `CREATE TRIGGER r7_refuse_claim BEFORE UPDATE ON approval_queue FOR EACH ROW EXECUTE FUNCTION r7_refuse_claim()`,
    );
    const usesBefore = keyUses.length;
    let refused: Response;
    try {
      refused = await approve(txId, digest);
    } finally {
      await db!.unsafe(`DROP TRIGGER r7_refuse_claim ON approval_queue`);
      await db!.unsafe(`DROP FUNCTION r7_refuse_claim()`);
    }
    expect(refused.status).toBe(403);
    expect(((await refused.json()) as any).error).toMatch(/permit refused/);
    const after = await state(txId);
    expect(after.q.status).toBe("pending");
    expect(after.q.approved_by_user_id).toBeNull();
    expect(after.q.resolved_at).toBeNull();
    expect(after.q.issuance_claimed_at).toBeNull();
    expect(after.tx.status).toBe("pending");
    expect(after.tx.signed_raw).toBeNull();
    expect(keyUses.length - usesBefore).toBe(0);

    // Normal path: approval and claim commit together, signed once.
    const ok = await approve(txId, digest);
    expect(ok.status).toBe(200);
    const body = (await ok.json()) as any;
    const done = await state(txId);
    expect(done.q.status).toBe("approved");
    expect(done.q.approved_by_user_id).toBe(OWNER_USER);
    expect(done.q.issuance_claimed_at).not.toBeNull();
    expect(done.tx.signed_raw).not.toBeNull();
    expect(done.tx.tx_hash).toBe(body.data.txHash);
    expect(keyUses.length - usesBefore).toBe(1);
  });

  it("[H2] two overlapping identical resumes -> one 200 signer, one 409 replay, one key use, same hash", async () => {
    const { txId, digest } = await proposeMint();
    // Crash between the approval+claim commit and signing: key use never runs.
    let reached!: () => void;
    const atSign = new Promise<void>((res) => {
      reached = res;
    });
    const hang = spyOn(vault, "signTransaction").mockImplementationOnce((() => {
      reached();
      return new Promise<string>(() => {});
    }) as never);
    void approve(txId, digest);
    await atSign;
    hang.mockRestore();
    const crashed = await state(txId);
    expect(crashed.q.status).toBe("approved");
    expect(crashed.q.issuance_claimed_at).not.toBeNull();
    expect(crashed.tx.signed_raw).toBeNull();
    // The lost permit is past its TTL.
    await db!.unsafe(
      `UPDATE approval_queue SET issuance_claimed_at = now() - interval '5 minutes' WHERE tx_id = $1`,
      [txId],
    );

    const usesBefore = keyUses.length;
    prepareDelayMs = 300; // hold the signer inside the section so both overlap
    let results: Response[];
    try {
      results = await Promise.all([approve(txId, digest), approve(txId, digest)]);
    } finally {
      prepareDelayMs = 0;
    }
    const bodies = (await Promise.all(results.map((r) => r.json()))) as any[];
    const statuses = results.map((r) => r.status).sort();
    expect(statuses).toEqual([200, 409]);
    expect(keyUses.length - usesBefore).toBe(1);
    const final = await state(txId);
    expect(final.tx.tx_hash).toBeTruthy();
    for (const b of bodies) expect(b.data.txHash).toBe(final.tx.tx_hash);
    const loser = bodies[results.findIndex((r) => r.status === 409)];
    expect(loser.ok).toBe(false);
    expect(loser.data.replay).toBe(true);
    // A later, non-overlapping replay is also 409; still one key use.
    expect((await approve(txId, digest)).status).toBe(409);
    expect(keyUses.length - usesBefore).toBe(1);
  });
});
