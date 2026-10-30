/**
 * STRATA-1515 exec-gap-a: migration 0031 against a LOCAL Postgres.
 * Gated on DATABASE_URL (local disposable server only). Creates a throwaway
 * database, applies every journaled migration, and proves the linkage table's
 * database-level guarantees: 84532-only, hash shape, FK to the proposal,
 * one row per proposal and per transaction, and immutability.
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createPostgresClient } from "@stwd/db";

const SKIP = !process.env.DATABASE_URL;
const sourceUrl = process.env.DATABASE_URL ?? "";
if (!SKIP) {
  const host = new URL(sourceUrl).hostname;
  if (host !== "127.0.0.1" && host !== "localhost") {
    throw new Error("execution postgres test runs against a local database only");
  }
}
const migrationsDir = fileURLToPath(new URL("../../../db/drizzle", import.meta.url));
const runId = crypto.randomUUID().replaceAll("-", "");
const databaseName = `steward_execgapa_${runId}`;
const databaseUrl = sourceUrl
  ? (() => {
      const url = new URL(sourceUrl);
      url.pathname = `/${databaseName}`;
      return url.toString();
    })()
  : "";

let admin: ReturnType<typeof createPostgresClient> | undefined;
let sql: ReturnType<typeof createPostgresClient> | undefined;

const T = "execgapa-tenant";
const P = `app_${"1".repeat(40)}`;
const K = `apk_${"1".repeat(24)}`;
const W = `aw_${"1".repeat(40)}`;
const A = "execgapa-agent";
const proposalId = (n: number) => `atp_${String(n).repeat(40).slice(0, 40)}`;
const hash = (c: string) => `0x${c.repeat(64)}`;

async function applyMigration(file: string) {
  const source = await readFile(`${migrationsDir}/${file}`, "utf8");
  for (const statement of source.split("--> statement-breakpoint")) {
    const trimmed = statement.trim();
    if (trimmed && trimmed !== "--") await sql!.unsafe(trimmed);
  }
}

async function seedProposal(n: number) {
  const intentId = `ati_${String(n).repeat(40).slice(0, 40)}`;
  await sql!.unsafe(
    `INSERT INTO application_transaction_intents
       (id, tenant_id, principal_id, credential_key_id, wallet_id, request_hash, intent, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, '{}', '2035-01-01T00:00:00Z')`,
    [intentId, T, P, K, W, "a".repeat(64)],
  );
  await sql!.unsafe(
    `INSERT INTO application_transaction_proposals
       (id, tenant_id, principal_id, credential_key_id, intent_id, request_hash)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [proposalId(n), T, P, K, intentId, "b".repeat(64)],
  );
  const txId = `tx-execgapa-${n}`;
  await sql!.unsafe(
    `INSERT INTO transactions (id, agent_id, tenant_id, status, to_address, value, chain_id, tx_hash)
     VALUES ($1, $2, $3, 'signed', $4, '0', 84532, $5)`,
    [txId, A, T, `0x${"ab".repeat(20)}`, hash(String(n))],
  );
  return txId;
}

/** postgres-js queries are lazy thenables; force a real Promise so expect().rejects runs them. */
async function q(text: string, params: unknown[] = []) {
  return await sql!.unsafe(text, params as never[]);
}

async function insertExecution(n: number, txId: string, chainId = 84532, txHash = hash(String(n))) {
  return await sql!.unsafe(
    `INSERT INTO application_proposal_executions
       (tenant_id, principal_id, proposal_id, transaction_id, chain_id, tx_hash, executed_by)
     VALUES ($1, $2, $3, $4, $5, $6, 'tenant:execgapa')`,
    [T, P, proposalId(n), txId, chainId, txHash],
  );
}

beforeAll(async () => {
  if (SKIP) return;
  admin = createPostgresClient(sourceUrl);
  await admin.unsafe(`CREATE DATABASE "${databaseName}"`);
  sql = createPostgresClient(databaseUrl);
  await sql.unsafe("SET statement_timeout = '10s'");
  const journal = JSON.parse(await readFile(`${migrationsDir}/meta/_journal.json`, "utf8")) as {
    entries: Array<{ tag: string }>;
  };
  for (const entry of journal.entries) await applyMigration(`${entry.tag}.sql`);
  await sql.unsafe(`INSERT INTO tenants (id, name, api_key_hash) VALUES ($1, 'exec-gap-a', $2)`, [
    T,
    "c".repeat(64),
  ]);
  await sql.unsafe(
    `INSERT INTO application_principals (id, tenant_id, name, capabilities, expires_at)
     VALUES ($1, $2, 'p', ARRAY['transaction:propose']::application_capability[], '2035-01-01T00:00:00Z')`,
    [P, T],
  );
  await sql.unsafe(
    `INSERT INTO application_principal_credentials (key_id, tenant_id, principal_id, secret_hash, expires_at)
     VALUES ($1, $2, $3, $4, '2035-01-01T00:00:00Z')`,
    [K, T, P, "d".repeat(64)],
  );
  await sql.unsafe(
    `INSERT INTO application_principal_resources (tenant_id, principal_id, resource_kind, resource_id)
     VALUES ($1, $2, 'wallet_owner', 'party_x')`,
    [T, P],
  );
  await sql.unsafe(
    `INSERT INTO agents (id, tenant_id, name, wallet_address) VALUES ($1, $2, 'a', $3)`,
    [A, T, `0x${"cd".repeat(20)}`],
  );
  await sql.unsafe(
    `INSERT INTO application_wallets (id, tenant_id, principal_id, resource_kind, resource_id, steward_agent_id, addresses)
     VALUES ($1, $2, $3, 'wallet_owner', 'party_x', $4, '{}')`,
    [W, T, P, A],
  );
}, 120000);

afterAll(async () => {
  if (SKIP) return;
  await sql?.end();
  await admin?.unsafe(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
  await admin?.end();
});

describe.skipIf(SKIP)("STRATA-1515 migration 0031 on local Postgres", () => {
  // DDL replay + FK checks on a cold database can exceed bun's 5s default.
  it("accepts one 84532 linkage per proposal and is immutable", async () => {
    const tx1 = await seedProposal(1);
    await insertExecution(1, tx1);
    await expect(insertExecution(1, tx1)).rejects.toThrow();
    await expect(
      q(`UPDATE application_proposal_executions SET tx_hash = $1`, [hash("f")]),
    ).rejects.toThrow(/immutable/);
    const rows = await sql!.unsafe(`SELECT chain_id, tx_hash FROM application_proposal_executions`);
    expect(rows.map((r) => ({ ...r }))).toEqual([{ chain_id: 84532, tx_hash: hash("1") }]);
  }, 30000);

  it("refuses chain 8453 and malformed hashes at the database", async () => {
    const tx2 = await seedProposal(2);
    await expect(insertExecution(2, tx2, 8453)).rejects.toThrow(/chain_chk/);
    await expect(insertExecution(2, tx2, 84532, "0xdead")).rejects.toThrow(/tx_hash_chk/);
  }, 30000);

  it("refuses linkage to an unknown proposal or reuse of a transaction", async () => {
    const tx3 = await seedProposal(3);
    await expect(
      q(
        `INSERT INTO application_proposal_executions
           (tenant_id, principal_id, proposal_id, transaction_id, chain_id, tx_hash, executed_by)
         VALUES ($1, $2, $3, $4, 84532, $5, 'x')`,
        [T, P, `atp_${"9".repeat(40)}`, tx3, hash("3")],
      ),
    ).rejects.toThrow(/proposal_fk/);
    const tx1 = "tx-execgapa-1";
    await expect(insertExecution(3, tx1)).rejects.toThrow(/transaction_idx|duplicate/);
  }, 30000);
});
