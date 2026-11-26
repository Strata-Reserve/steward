/**
 * STRATA-1673 H1-nonce / H4 / (b): the protected signing critical section on
 * REAL postgres:16 (separate backends) + a local Anvil chain.
 *
 * Exercises the real `Vault.broadcastEvm` (prepare -> nonce -> local key use
 * -> signed-row write inside `runProtectedSigningSection`, send after commit)
 * with an http Anvil client. A third, independent connection observes locks.
 *   1. two different authorized mints concurrently -> distinct nonces, both mined;
 *   2. suspension attempted during key use -> blocks on the signer's lock
 *      until the signed row is durable, then the signed bytes are sent once;
 *   3. slow signer + a second permit on the same claim (TTL resume) -> the
 *      second waits on the lock, finds the signed row, never uses the key.
 * Skipped without DATABASE_URL (admin URL) and ANVIL_RPC_URL.
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createPostgresClient } from "@stwd/db";
import { sql } from "drizzle-orm";
import { createPublicClient, createWalletClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";

const ANVIL = process.env.ANVIL_RPC_URL ?? "";
const SKIP = !process.env.DATABASE_URL || !ANVIL;
const migrationsDir = fileURLToPath(new URL("../../../db/drizzle", import.meta.url));
const runId = crypto.randomUUID().replaceAll("-", "");
const sourceUrl = process.env.DATABASE_URL ?? "";
const DB = `steward_sect_${runId}`;
const dbUrl = (name: string) => {
  const url = new URL(sourceUrl);
  url.pathname = `/${name}`;
  return url.toString();
};
// Anvil's well-known public dev account #0 (not a secret).
const KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;
const account = privateKeyToAccount(KEY);
const SIGNER = account.address.toLowerCase();
const TENANT = `sect-${runId.slice(0, 20)}`;
const AGENT = "sect-agent";
const TOKEN = "0x00000000000000000000000000000000007000bb";
const DIGEST = `0x${"ab".repeat(32)}`;
const mintData = (n: number) =>
  `0x40c10f19${"0".repeat(24)}${"22".repeat(20)}${n.toString(16).padStart(64, "0")}` as const;

type Sql = ReturnType<typeof createPostgresClient>;
let admin: Sql | undefined;
let db: Sql | undefined; // seeding
let observer: Sql | undefined; // independent lock observer
let brake: Sql | undefined; // the incident brake, its own backend
let vaultLib: any;
let vault: any;

const q = (v: string) => `"${v.replaceAll('"', '""')}"`;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitFor(cond: () => Promise<boolean>, ms = 10_000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await cond()) return;
    await sleep(25);
  }
  throw new Error("timed out waiting for condition");
}
function gate() {
  let open!: () => void;
  const p = new Promise<void>((r) => {
    open = r;
  });
  return { p, open };
}

async function seedTx(id: string, n: number) {
  await db!.unsafe(
    `INSERT INTO transactions (id, agent_id, tenant_id, execution_ref, status, to_address, value, data, chain_id)
     VALUES ($1, $2, $3, $4, 'pending', $5, '0', $6, 8453)`,
    [id, AGENT, TENANT, `sect:${id}`, TOKEN, mintData(n)],
  );
  await db!.unsafe(
    `INSERT INTO approval_queue (id, tx_id, agent_id, status, approval_source, instruction_digest, review_digest, resolved_by, resolved_at, issuance_claimed_at)
     VALUES ($1, $2, $3, 'approved', 'issuance_readback', $4, $4, 'issuance_readback', now(), now())`,
    [`q-${id}`, id, AGENT, DIGEST],
  );
}
async function row(id: string) {
  const [r] = await db!.unsafe(
    `SELECT status, signed_raw, signed_nonce, tx_hash FROM transactions WHERE id = $1`,
    [id],
  );
  return r as {
    status: string;
    signed_raw: string | null;
    signed_nonce: string | null;
    tx_hash: string | null;
  };
}

const wallet = () => createWalletClient({ account, chain: base, transport: http(ANVIL) });
const pub = () => createPublicClient({ chain: base, transport: http(ANVIL) });

/**
 * The real protected broadcast with the section wired exactly as
 * Vault.signTransaction wires it, plus test hooks inside the section.
 */
async function protectedMint(
  txId: string,
  n: number,
  hooks: { inside?: (pid: number) => Promise<void>; keyUse?: () => void } = {},
) {
  const persist = (sign: (floor: number) => Promise<unknown>) =>
    vaultLib.runProtectedSigningSection(
      {
        tenantId: TENANT,
        agentId: AGENT,
        txId,
        chainId: 8453,
        to: TOKEN,
        data: mintData(n),
        signer: SIGNER,
      },
      async (exec: any, floor: number) => {
        const r = await exec.execute(sql`SELECT pg_backend_pid() AS pid`);
        const pidRows = r ? (Array.isArray(r) ? r : r.rows) : [];
        await hooks.inside?.(Number(pidRows[0]?.pid ?? 0));
        const signed = await sign(floor);
        hooks.keyUse?.();
        await vault.persistProtectedSigned(
          { tenantId: TENANT, agentId: AGENT, txId },
          signed,
          SIGNER,
          exec,
        );
        return signed;
      },
    );
  return vault.broadcastEvm(
    wallet(),
    { to: TOKEN, value: 0n, data: mintData(n), chainId: 8453 },
    persist,
  ) as Promise<`0x${string}`>;
}

async function blockedBy(pid: number): Promise<number[]> {
  const [r] = await observer!.unsafe(`SELECT pg_blocking_pids($1)::int[] AS b`, [pid]);
  return (r?.b as number[]) ?? [];
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
  await db.unsafe(`INSERT INTO tenants (id, name, api_key_hash) VALUES ($1, 'S', $2)`, [
    TENANT,
    "a".repeat(64),
  ]);
  await db.unsafe(
    `INSERT INTO agents (id, tenant_id, name, wallet_address) VALUES ($1, $2, 'A', $3)`,
    [AGENT, TENANT, account.address],
  );
  await db.unsafe(
    `INSERT INTO protected_minter_tokens (id, tenant_id, agent_id, chain_id, token_address, deploy_tx_hash, deploy_execution_ref)
     VALUES ('tok-sect', $1, $2, 8453, $3, $4, 'deploy:1')`,
    [TENANT, AGENT, TOKEN, `0x${"de".repeat(32)}`],
  );
  observer = createPostgresClient(dbUrl(DB));
  brake = createPostgresClient(dbUrl(DB));
  process.env.DATABASE_URL = dbUrl(DB);
  vaultLib = await import("@stwd/vault");
  vault = new vaultLib.Vault({ masterPassword: "section-test" });
}, 180_000);

afterAll(async () => {
  if (SKIP) return;
  const { closeDb } = await import("@stwd/db");
  await closeDb();
  await db?.end();
  await observer?.end();
  await brake?.end();
  await admin?.unsafe(`DROP DATABASE IF EXISTS ${q(DB)} WITH (FORCE)`);
  await admin?.end();
});

describe.skipIf(SKIP)("STRATA-1673 protected signing section (postgres:16 + Anvil)", () => {
  it("[H1-nonce] two different authorized mints signed concurrently -> distinct nonces, both included", async () => {
    await seedTx("n1", 1);
    await seedTx("n2", 2);
    const start = await pub().getTransactionCount({
      address: account.address,
      blockTag: "pending",
    });
    const pids: number[] = [];
    let waited = false;
    const first = gate();
    const a = protectedMint("n1", 1, {
      inside: async (pid) => {
        pids.push(pid);
        await first.p; // hold the section; b must wait on the advisory lock
      },
    });
    await waitFor(async () => pids.length === 1);
    const b = protectedMint("n2", 2, {
      inside: async (pid) => {
        pids.push(pid);
      },
    });
    // The second signer's backend is blocked by the first (advisory lock).
    await waitFor(async () => {
      const [r] = await observer!.unsafe(
        `SELECT count(*)::int AS n FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`,
      );
      waited = (r?.n as number) >= 1;
      return waited;
    });
    first.open();
    const [ha, hb] = await Promise.all([a, b]);
    expect(waited).toBe(true);
    expect(pids[0]).not.toBe(pids[1]);
    const ra = await row("n1");
    const rb = await row("n2");
    expect(new Set([Number(ra.signed_nonce), Number(rb.signed_nonce)])).toEqual(
      new Set([start, start + 1]),
    );
    const p = pub();
    const [xa, xb] = await Promise.all([
      p.waitForTransactionReceipt({ hash: ha }),
      p.waitForTransactionReceipt({ hash: hb }),
    ]);
    expect(xa.status).toBe("success");
    expect(xb.status).toBe("success");
    expect(await p.getTransactionCount({ address: account.address })).toBe(start + 2);
  }, 60_000);

  it("[H4] suspension attempted during key use blocks until the signed row is durable; signed work is sent once, not re-signed", async () => {
    await seedTx("b1", 3);
    const hold = gate();
    let signerPid = 0;
    let keyUses = 0;
    const mint = protectedMint("b1", 3, {
      inside: async (pid) => {
        signerPid = pid;
        await hold.p;
      },
      keyUse: () => {
        keyUses += 1;
      },
    });
    await waitFor(async () => signerPid !== 0);
    const brakeConn = await brake!.reserve();
    try {
      const [{ pid: brakePid }] = await brakeConn`SELECT pg_backend_pid() AS pid`;
      // postgres-js queries are lazy: start it now via then().
      const suspend = Promise.resolve().then(() =>
        brakeConn.unsafe(
          `INSERT INTO protected_minter_controls (tenant_id, agent_id, protected_minting_suspended_at, suspended_by, suspend_reason)
         VALUES ($1, $2, now(), 'user:incident', 'incident')
         ON CONFLICT (tenant_id, agent_id) DO UPDATE SET protected_minting_suspended_at = now()
         RETURNING clock_timestamp() AS at`,
          [TENANT, AGENT],
        ),
      );
      // PG observer: the brake backend is blocked BY the signer's backend
      // while the signer is inside the section (key use pending).
      await waitFor(async () => (await blockedBy(Number(brakePid))).includes(signerPid));
      expect((await row("b1")).signed_raw).toBeNull();
      hold.open();
      // Still blocked across key use + signed-row write, released only at commit.
      const hash = await mint;
      const [{ at }] = await suspend;
      const r = await row("b1");
      expect(r.signed_raw).not.toBeNull();
      expect(r.tx_hash).toBe(hash);
      const [{ signed_at }] = await db!.unsafe(
        `SELECT signed_at FROM transactions WHERE id = 'b1'`,
      );
      expect(new Date(at as string).getTime()).toBeGreaterThanOrEqual(
        new Date(signed_at as string).getTime(),
      );
      expect(keyUses).toBe(1);
      expect((await pub().waitForTransactionReceipt({ hash })).status).toBe("success");
      // Suspension now committed BEFORE the lock -> a new read-back mint is
      // refused before key use and handed off with its claim kept.
      await seedTx("b2", 4);
      let later = 0;
      await expect(
        protectedMint("b2", 4, {
          keyUse: () => {
            later += 1;
          },
        }),
      ).rejects.toBeInstanceOf(vaultLib.ProtectedKeyUseReleasedError);
      expect(later).toBe(0);
      const [h] = await db!.unsafe(
        `SELECT status, issuance_claimed_at FROM approval_queue WHERE tx_id = 'b2'`,
      );
      expect(h?.status).toBe("pending");
      expect(h?.issuance_claimed_at).not.toBeNull();
    } finally {
      hold.open();
      await mint.catch(() => undefined);
      brakeConn.release();
      await db!.unsafe(
        `UPDATE protected_minter_controls SET protected_minting_suspended_at = NULL WHERE tenant_id = $1 AND agent_id = $2`,
        [TENANT, AGENT],
      );
    }
  }, 60_000);

  it("[(b)] slow signer past TTL + second permit on the same claim -> one key use, one signed row, one mint", async () => {
    await seedTx("t1", 5);
    const slow = gate();
    let keyUses = 0;
    let inside = 0;
    const count = () => {
      keyUses += 1;
    };
    const first = protectedMint("t1", 5, {
      inside: async () => {
        inside += 1;
        await slow.p; // the original signer is still mid-signing past its TTL
      },
      keyUse: count,
    });
    await waitFor(async () => inside === 1);
    // A resumed second permit on the SAME claim/txId: waits on the lock.
    const second = protectedMint("t1", 5, { keyUse: count });
    await waitFor(async () => {
      const [r] = await observer!.unsafe(
        `SELECT count(*)::int AS n FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`,
      );
      return (r?.n as number) >= 1;
    });
    slow.open();
    const hash = await first;
    await expect(second).rejects.toThrow(/signed transaction already exists/);
    expect(keyUses).toBe(1);
    expect(inside).toBe(1);
    expect((await row("t1")).tx_hash).toBe(hash);
    expect((await pub().waitForTransactionReceipt({ hash })).status).toBe("success");
  }, 60_000);

  it("[F2] signer A commits signed bytes; signer B waiting sees suspension -> reconcile branch, never the human queue", async () => {
    await seedTx("h1", 6);
    let keyUses = 0;
    const count = () => {
      keyUses += 1;
    };
    // Signer A: signs and commits the signed row.
    const hash = await protectedMint("h1", 6, { keyUse: count });
    expect((await row("h1")).signed_raw).not.toBeNull();
    // A separate backend holds the per-signer section lock so B must wait.
    const holder = await brake!.reserve();
    try {
      await holder.unsafe("BEGIN");
      await holder.unsafe(`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, [
        `steward_protected_signer:8453:${SIGNER}`,
      ]);
      // Signer B (TTL resume on the same claim): waits on the section lock.
      const b = protectedMint("h1", 6, { keyUse: count });
      const bErr = b.then(
        () => null,
        (e: unknown) => e,
      );
      await waitFor(async () => {
        const [r] = await observer!.unsafe(
          `SELECT count(*)::int AS n FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`,
        );
        return (r?.n as number) >= 1;
      });
      // Suspension commits (third backend) while B is still waiting.
      await db!.unsafe(
        `INSERT INTO protected_minter_controls (tenant_id, agent_id, protected_minting_suspended_at, suspended_by, suspend_reason)
         VALUES ($1, $2, now(), 'user:incident', 'incident')
         ON CONFLICT (tenant_id, agent_id) DO UPDATE SET protected_minting_suspended_at = now()`,
        [TENANT, AGENT],
      );
      await holder.unsafe("COMMIT");
      const e = await bErr;
      expect(e).toBeInstanceOf(vaultLib.ProtectedSignerError);
      expect(e).not.toBeInstanceOf(vaultLib.ProtectedKeyUseReleasedError);
      expect(String((e as Error).message)).toMatch(/signed transaction already exists/);
      expect(keyUses).toBe(1);
      // No handoff: approval stays the read-back approval, no readbackHandoff.
      const [q] = await db!.unsafe(
        `SELECT status, approval_source, issuance_claimed_at, review_projection FROM approval_queue WHERE tx_id = 'h1'`,
      );
      expect(q?.status).toBe("approved");
      expect(q?.approval_source).toBe("issuance_readback");
      expect(q?.issuance_claimed_at).not.toBeNull();
      expect((q?.review_projection as any)?.readbackHandoff ?? null).toBeNull();
      // The signed row is untouched (reconcile branch: callers reconcile a
      // non-released refusal with signed bytes on record) and the original
      // bytes are the one inclusion. (Vault reconcile needs an https
      // RPC_URL_8453, not available against local Anvil.)
      expect((await pub().waitForTransactionReceipt({ hash })).status).toBe("success");
      const r = await row("h1");
      expect(r.status).toBe("signed");
      expect(r.signed_raw).not.toBeNull();
      expect(r.tx_hash).toBe(hash);
    } finally {
      await holder.unsafe("ROLLBACK").catch(() => undefined);
      holder.release();
      await db!.unsafe(
        `UPDATE protected_minter_controls SET protected_minting_suspended_at = NULL WHERE tenant_id = $1 AND agent_id = $2`,
        [TENANT, AGENT],
      );
    }
  }, 60_000);
});
