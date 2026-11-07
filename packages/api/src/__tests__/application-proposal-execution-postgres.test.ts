/**
 * STRATA-1515 exec gap A: real Postgres upgrade + 0031 constraint proof.
 *
 * Creates a disposable database, applies every migration up to 0030, seeds a
 * pre-0031 tenant/principal/proposal, then applies 0031 on top (the upgrade an
 * existing deployment performs). Asserts the 84532 hard pin and the
 * forward-only execution contract directly against the database, bypassing
 * application code entirely. Skipped without DATABASE_URL.
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createPostgresClient } from "@stwd/db";

const SKIP = !process.env.DATABASE_URL;
const migrationsDir = fileURLToPath(new URL("../../../db/drizzle", import.meta.url));
const runId = crypto.randomUUID().replaceAll("-", "");
const databaseName = `steward_exec31_${runId}`;
const sourceUrl = process.env.DATABASE_URL ?? "";
const databaseUrl = sourceUrl
  ? (() => {
      const url = new URL(sourceUrl);
      url.pathname = `/${databaseName}`;
      return url.toString();
    })()
  : "";

const TENANT = `exec31-${runId}`;
const PRINCIPAL = `app_${"a".repeat(40)}`;
const KEY_ID = `apk_${"a".repeat(24)}`;
const WALLET = "aw_exec31";
const INTENT = `ati_${"a".repeat(40)}`;
const PROPOSAL = `atp_${"a".repeat(40)}`;
const PROPOSAL_2 = `atp_${"b".repeat(40)}`;
const INTENT_2 = `ati_${"b".repeat(40)}`;
const SIGNER = "exec31-signer";
const TOKEN = "0x7045ee8bcd2f2bd5f04622829334faeb6129971b";

let admin: ReturnType<typeof createPostgresClient> | undefined;
let sql: ReturnType<typeof createPostgresClient> | undefined;

function quoteIdentifier(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

async function applyMigration(file: string) {
  const source = await readFile(`${migrationsDir}/${file}`, "utf8");
  for (const statement of source.split("--> statement-breakpoint")) {
    const trimmed = statement.trim();
    if (trimmed && trimmed !== "--") await sql!.unsafe(trimmed);
  }
}

async function migrationFiles(filter: (file: string) => boolean) {
  return (await Array.fromAsync(new Bun.Glob("*.sql").scan(migrationsDir)))
    .filter((file) => /^\d{4}.*\.sql$/.test(file) && filter(file))
    .sort();
}

async function refused(query: () => Promise<unknown>, pattern: RegExp) {
  try {
    await query();
  } catch (error) {
    const message = `${(error as { constraint_name?: string }).constraint_name ?? ""} ${
      (error as Error).message
    }`;
    expect(message).toMatch(pattern);
    return true;
  }
  return false;
}

async function insertTransaction(id: string, chainId: number, ref: string) {
  await sql!.unsafe(
    `INSERT INTO transactions (id, agent_id, tenant_id, execution_ref, status, to_address, value, chain_id)
     VALUES ($1, $2, $3, $4, 'approved', $5, '0', $6)`,
    [id, SIGNER, TENANT, ref, TOKEN, chainId],
  );
}

async function insertExecution(id: string, proposalId: string, txId: string, chainId: number) {
  await sql!.unsafe(
    `INSERT INTO application_proposal_executions
       (id, tenant_id, principal_id, proposal_id, signer_agent_id, chain_id, transaction_id,
        execution_ref, to_address, recipient_address, amount, approved_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, '1', 'user:exec31')`,
    [
      id,
      TENANT,
      PRINCIPAL,
      proposalId,
      SIGNER,
      chainId,
      txId,
      `application-proposal:${proposalId}`,
      TOKEN,
      `0x${"33".repeat(20)}`,
    ],
  );
}

beforeAll(async () => {
  if (SKIP) return;
  admin = createPostgresClient(sourceUrl);
  await admin.unsafe(`CREATE DATABASE ${quoteIdentifier(databaseName)}`);
  sql = createPostgresClient(databaseUrl);

  for (const file of await migrationFiles((f) => f < "0031")) await applyMigration(file);

  // Pre-0031 state: a deployment with live application proposals.
  await sql.unsafe(`INSERT INTO tenants (id, name, api_key_hash) VALUES ($1, 'exec31', $2)`, [
    TENANT,
    "a".repeat(64),
  ]);
  await sql.unsafe(
    `INSERT INTO agents (id, tenant_id, name, wallet_address) VALUES
       ($1, $2, 'signer', $3), ('exec31-app-wallet', $2, 'app wallet', $4)`,
    [SIGNER, TENANT, `0x${"11".repeat(20)}`, `0x${"33".repeat(20)}`],
  );
  await sql.unsafe(
    `INSERT INTO application_principals (id, tenant_id, name, capabilities, expires_at)
     VALUES ($1, $2, 'exec31', ARRAY['transaction:propose']::application_capability[], '2035-01-01T00:00:00Z')`,
    [PRINCIPAL, TENANT],
  );
  await sql.unsafe(
    `INSERT INTO application_principal_credentials (key_id, tenant_id, principal_id, secret_hash, expires_at)
     VALUES ($1, $2, $3, $4, '2035-01-01T00:00:00Z')`,
    [KEY_ID, TENANT, PRINCIPAL, "c".repeat(64)],
  );
  await sql.unsafe(
    `INSERT INTO application_principal_resources (tenant_id, principal_id, resource_kind, resource_id)
     VALUES ($1, $2, 'wallet_owner', 'resource:exec31')`,
    [TENANT, PRINCIPAL],
  );
  await sql.unsafe(
    `INSERT INTO application_wallets
       (id, tenant_id, principal_id, resource_kind, resource_id, steward_agent_id, addresses)
     VALUES ($1, $2, $3, 'wallet_owner', 'resource:exec31', 'exec31-app-wallet',
       '{"evm":"0x3333333333333333333333333333333333333333","solana":"11111111111111111111111111111111"}'::jsonb)`,
    [WALLET, TENANT, PRINCIPAL],
  );
  for (const [intent, proposal, suffix] of [
    [INTENT, PROPOSAL, "d"],
    [INTENT_2, PROPOSAL_2, "e"],
  ] as const) {
    await sql.unsafe(
      `INSERT INTO application_transaction_intents
         (id, tenant_id, principal_id, credential_key_id, wallet_id, request_hash, intent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, '{}', '2035-01-01T00:00:00Z')`,
      [intent, TENANT, PRINCIPAL, KEY_ID, WALLET, suffix.repeat(64)],
    );
    await sql.unsafe(
      `INSERT INTO application_transaction_proposals
         (id, tenant_id, principal_id, credential_key_id, intent_id, request_hash)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [proposal, TENANT, PRINCIPAL, KEY_ID, intent, suffix.repeat(64)],
    );
  }

  // The upgrade under test.
  for (const file of await migrationFiles((f) => f >= "0031")) await applyMigration(file);
}, 120_000);

afterAll(async () => {
  if (SKIP) return;
  await sql?.end();
  await admin?.unsafe(`DROP DATABASE IF EXISTS ${quoteIdentifier(databaseName)} WITH (FORCE)`);
  await admin?.end();
});

describe.skipIf(SKIP)("0031 application proposal execution on real Postgres", () => {
  it("upgrades a populated pre-0031 database without touching existing proposals", async () => {
    const proposals = await sql!.unsafe(
      `SELECT id, status FROM application_transaction_proposals WHERE tenant_id = $1 ORDER BY id`,
      [TENANT],
    );
    expect(proposals.map((p) => [p.id, p.status])).toEqual([
      [PROPOSAL, "proposed"],
      [PROPOSAL_2, "proposed"],
    ]);
    const executions = await sql!.unsafe(
      `SELECT count(*)::int AS n FROM application_proposal_executions`,
    );
    expect(executions[0]!.n).toBe(0);
    const checks = await sql!.unsafe(
      `SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
        WHERE conname IN ('application_executor_signers_chain_chk', 'application_executions_chain_chk')
        ORDER BY conname`,
    );
    expect(checks.map((c) => c.conname)).toEqual([
      "application_executions_chain_chk",
      "application_executor_signers_chain_chk",
    ]);
    for (const c of checks) expect(c.def).toContain("84532");
  });

  it("binding rows: only chain 84532 is admitted, and a binding is immutable", async () => {
    for (const chainId of [8453, 1, 0, -1, 11155111]) {
      expect(
        await refused(
          () =>
            sql!.unsafe(
              `INSERT INTO application_executor_signers
                 (tenant_id, principal_id, chain_id, signer_agent_id, allowed_targets, created_by)
               VALUES ($1, $2, $3, $4, ARRAY[$5], 'test')`,
              [TENANT, PRINCIPAL, chainId, SIGNER, TOKEN],
            ),
          /application_executor_signers_chain_chk/,
        ),
        `chain ${chainId}`,
      ).toBe(true);
    }
    await sql!.unsafe(
      `INSERT INTO application_executor_signers
         (tenant_id, principal_id, chain_id, signer_agent_id, allowed_targets, created_by)
       VALUES ($1, $2, 84532, $3, ARRAY[$4], 'test')`,
      [TENANT, PRINCIPAL, SIGNER, TOKEN],
    );
    expect(
      await refused(
        () =>
          sql!.unsafe(
            `UPDATE application_executor_signers SET chain_id = 8453 WHERE tenant_id = $1`,
            [TENANT],
          ),
        /immutable|application_executor_signers_chain_chk/,
      ),
    ).toBe(true);
  });

  it("execution rows: only chain 84532 is admitted; one per proposal; forward-only", async () => {
    await insertTransaction("exec31-tx-8453", 8453, "direct:8453");
    expect(
      await refused(
        () => insertExecution(`ape_${"8".repeat(40)}`, PROPOSAL, "exec31-tx-8453", 8453),
        /application_executions_chain_chk/,
      ),
    ).toBe(true);
    await insertTransaction("exec31-tx-1", 84532, "direct:84532");
    await insertExecution(`ape_${"1".repeat(40)}`, PROPOSAL, "exec31-tx-1", 84532);
    // Single execution per proposal.
    await insertTransaction("exec31-tx-dup", 84532, "direct:dup");
    expect(
      await refused(
        () => insertExecution(`ape_${"2".repeat(40)}`, PROPOSAL, "exec31-tx-dup", 84532),
        /application_executions_proposal_idx|duplicate key/,
      ),
    ).toBe(true);
    // Cannot be moved to 8453.
    expect(
      await refused(
        () =>
          sql!.unsafe(`UPDATE application_proposal_executions SET chain_id = 8453 WHERE id = $1`, [
            `ape_${"1".repeat(40)}`,
          ]),
        /immutable|application_executions_chain_chk/,
      ),
    ).toBe(true);
    // A hash without broadcast status, or broadcast without a hash, is refused.
    expect(
      await refused(
        () =>
          sql!.unsafe(
            `UPDATE application_proposal_executions SET status = 'broadcast' WHERE id = $1`,
            [`ape_${"1".repeat(40)}`],
          ),
        /application_executions_hash_chk/,
      ),
    ).toBe(true);
    // Ambiguity is terminal: indeterminate can never be re-armed or given a hash.
    await sql!.unsafe(
      `UPDATE application_proposal_executions SET status = 'indeterminate' WHERE id = $1`,
      [`ape_${"1".repeat(40)}`],
    );
    for (const set of [
      "status = 'executing'",
      `status = 'broadcast', tx_hash = '0x${"a".repeat(64)}'`,
    ]) {
      expect(
        await refused(
          () =>
            sql!.unsafe(`UPDATE application_proposal_executions SET ${set} WHERE id = $1`, [
              `ape_${"1".repeat(40)}`,
            ]),
          /terminal/,
        ),
        set,
      ).toBe(true);
    }
  });

  it("a broadcast row is permanent: its hash cannot change and it cannot be deleted", async () => {
    await insertTransaction("exec31-tx-2", 84532, "direct:84532-2");
    const id = `ape_${"3".repeat(40)}`;
    await insertExecution(id, PROPOSAL_2, "exec31-tx-2", 84532);
    await sql!.unsafe(
      `UPDATE application_proposal_executions SET status = 'broadcast', tx_hash = $2 WHERE id = $1`,
      [id, `0x${"b".repeat(64)}`],
    );
    expect(
      await refused(
        () =>
          sql!.unsafe(`UPDATE application_proposal_executions SET tx_hash = $2 WHERE id = $1`, [
            id,
            `0x${"c".repeat(64)}`,
          ]),
        /terminal/,
      ),
    ).toBe(true);
    expect(
      await refused(
        () => sql!.unsafe(`DELETE FROM application_proposal_executions WHERE id = $1`, [id]),
        /immutable|application/,
      ),
    ).toBe(true);
  });
});
