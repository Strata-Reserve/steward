/**
 * STRATA-1673 S1: migration 0032 on real Postgres.
 *
 * Two disposable databases:
 *   - upgrade: every migration up to 0031, seed a populated pre-0032 row set
 *     (agent, human-approved queue row, 84532 executor binding), then 0032;
 *   - fresh:   every migration including 0032 in one pass.
 * Asserts the new tables/constraints/trigger and the D5 chain CHECK relax
 * directly against the database. Skipped without DATABASE_URL.
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createPostgresClient } from "@stwd/db";

const SKIP = !process.env.DATABASE_URL;
const migrationsDir = fileURLToPath(new URL("../../../db/drizzle", import.meta.url));
const runId = crypto.randomUUID().replaceAll("-", "");
const sourceUrl = process.env.DATABASE_URL ?? "";
const dbUrl = (name: string) => {
  const url = new URL(sourceUrl);
  url.pathname = `/${name}`;
  return url.toString();
};
const UPGRADE_DB = `steward_rb32u_${runId}`;
const FRESH_DB = `steward_rb32f_${runId}`;

const TENANT = `rb32-${runId}`;
const AGENT = "rb32-agent";
const TOKEN = "0x00000000000000000000000000000000007000aa";
const HASH = `0x${"de".repeat(32)}`;
const DIGEST = `0x${"ab".repeat(32)}`;

type Sql = ReturnType<typeof createPostgresClient>;
let admin: Sql | undefined;
let upgrade: Sql | undefined;
let fresh: Sql | undefined;

const q = (v: string) => `"${v.replaceAll('"', '""')}"`;

async function apply(sql: Sql, file: string) {
  const source = await readFile(`${migrationsDir}/${file}`, "utf8");
  for (const statement of source.split("--> statement-breakpoint")) {
    const trimmed = statement.trim();
    if (trimmed && trimmed !== "--") await sql.unsafe(trimmed);
  }
}
async function files(filter: (f: string) => boolean) {
  return (await Array.fromAsync(new Bun.Glob("*.sql").scan(migrationsDir)))
    .filter((f) => /^\d{4}.*\.sql$/.test(f) && filter(f))
    .sort();
}
async function refused(run: () => Promise<unknown>, pattern: RegExp) {
  try {
    await run();
  } catch (error) {
    const message = `${(error as { constraint_name?: string }).constraint_name ?? ""} ${
      (error as Error).message
    }`;
    expect(message).toMatch(pattern);
    return true;
  }
  return false;
}

async function seedAgent(sql: Sql) {
  await sql.unsafe(`INSERT INTO tenants (id, name, api_key_hash) VALUES ($1, 'RB32', $2)`, [
    TENANT,
    "a".repeat(64),
  ]);
  await sql.unsafe(
    `INSERT INTO agents (id, tenant_id, name, wallet_address) VALUES ($1, $2, 'A', $3)`,
    [AGENT, TENANT, `0x${"11".repeat(20)}`],
  );
}

beforeAll(async () => {
  if (SKIP) return;
  admin = createPostgresClient(sourceUrl);
  await admin.unsafe(`CREATE DATABASE ${q(UPGRADE_DB)}`);
  await admin.unsafe(`CREATE DATABASE ${q(FRESH_DB)}`);
  upgrade = createPostgresClient(dbUrl(UPGRADE_DB));
  fresh = createPostgresClient(dbUrl(FRESH_DB));

  for (const f of await files((f) => f < "0032")) await apply(upgrade, f);
  await seedAgent(upgrade);
  await upgrade.unsafe(
    `INSERT INTO transactions (id, agent_id, tenant_id, execution_ref, status, to_address, value, chain_id)
     VALUES ('rb32-tx-old', $1, $2, 'old:1', 'pending', $3, '0', 8453)`,
    [AGENT, TENANT, TOKEN],
  );
  await upgrade.unsafe(
    `INSERT INTO approval_queue (id, tx_id, agent_id, status, approved_by_user_id)
     VALUES ('rb32-q-old', 'rb32-tx-old', $1, 'approved', 'some-user')`,
    [AGENT],
  );
  for (const f of await files((f) => f >= "0032")) await apply(upgrade, f);

  for (const f of await files(() => true)) await apply(fresh, f);
  await seedAgent(fresh);
}, 180_000);

afterAll(async () => {
  if (SKIP) return;
  await upgrade?.end();
  await fresh?.end();
  for (const name of [UPGRADE_DB, FRESH_DB]) {
    await admin?.unsafe(`DROP DATABASE IF EXISTS ${q(name)} WITH (FORCE)`);
  }
  await admin?.end();
});

describe.skipIf(SKIP)("0032 protected issuance readback on real Postgres", () => {
  it("upgrade from 0031 keeps existing approvals (source NULL = human) and adds the columns", async () => {
    const rows = await upgrade!.unsafe(
      `SELECT approval_source, instruction_digest, status FROM approval_queue WHERE id = 'rb32-q-old'`,
    );
    expect(rows[0]).toEqual({
      approval_source: null,
      instruction_digest: null,
      status: "approved",
    });
  });

  for (const which of ["upgrade", "fresh"] as const) {
    const db = () => (which === "upgrade" ? upgrade! : fresh!);

    it(`[${which}] approval_source CHECK + readback requires instruction_digest`, async () => {
      const sql = db();
      await sql.unsafe(
        `INSERT INTO transactions (id, agent_id, tenant_id, execution_ref, status, to_address, value, chain_id)
         VALUES ('rb32-tx-${which}', $1, $2, 'rb:${which}', 'pending', $3, '0', 8453)`,
        [AGENT, TENANT, TOKEN],
      );
      expect(
        await refused(
          () =>
            sql.unsafe(
              `INSERT INTO approval_queue (id, tx_id, agent_id, status, approval_source)
               VALUES ('rb32-q-bad', 'rb32-tx-${which}', $1, 'approved', 'robot')`,
              [AGENT],
            ),
          /approval_queue_source_chk/,
        ),
      ).toBe(true);
      expect(
        await refused(
          () =>
            sql.unsafe(
              `INSERT INTO approval_queue (id, tx_id, agent_id, status, approval_source)
               VALUES ('rb32-q-nodigest', 'rb32-tx-${which}', $1, 'approved', 'issuance_readback')`,
              [AGENT],
            ),
          /approval_queue_readback_digest_chk/,
        ),
      ).toBe(true);
      await sql.unsafe(
        `INSERT INTO approval_queue (id, tx_id, agent_id, status, approval_source, instruction_digest)
         VALUES ('rb32-q-ok-${which}', 'rb32-tx-${which}', $1, 'approved', 'issuance_readback', $2)`,
        [AGENT, DIGEST],
      );
    });

    it(`[${which}] protected_minter_tokens: unique scope, lowercase address, positive chain, one-way revoke`, async () => {
      const sql = db();
      const insert = (id: string, token: string, chain = 8453) =>
        sql.unsafe(
          `INSERT INTO protected_minter_tokens
             (id, tenant_id, agent_id, chain_id, token_address, deploy_tx_hash, deploy_execution_ref)
           VALUES ($1, $2, $3, $4, $5, $6, 'deploy:1')`,
          [id, TENANT, AGENT, chain, token, HASH],
        );
      await insert(`t1-${which}`, TOKEN);
      expect(
        await refused(
          () => insert(`t2-${which}`, TOKEN),
          /protected_minter_tokens_scope_idx|duplicate key/,
        ),
      ).toBe(true);
      expect(
        await refused(
          () => insert(`t3-${which}`, TOKEN.toUpperCase().replace("0X", "0x")),
          /protected_minter_tokens_address_chk/,
        ),
      ).toBe(true);
      expect(
        await refused(
          () => insert(`t4-${which}`, `0x${"22".repeat(20)}`, 0),
          /protected_minter_tokens_chain_chk/,
        ),
      ).toBe(true);
      // Same token on another chain is a separate admission.
      await insert(`t5-${which}`, TOKEN, 84532);
      // revoked without who/when is refused
      expect(
        await refused(
          () =>
            sql.unsafe(`UPDATE protected_minter_tokens SET status = 'revoked' WHERE id = $1`, [
              `t1-${which}`,
            ]),
          /protected_minter_tokens_revoke_chk/,
        ),
      ).toBe(true);
      // identity immutable
      expect(
        await refused(
          () =>
            sql.unsafe(`UPDATE protected_minter_tokens SET token_address = $2 WHERE id = $1`, [
              `t1-${which}`,
              `0x${"33".repeat(20)}`,
            ]),
          /immutable/,
        ),
      ).toBe(true);
      await sql.unsafe(
        `UPDATE protected_minter_tokens SET status = 'revoked', revoked_at = now(), revoked_by = 'user:x', revoke_reason = 'r' WHERE id = $1`,
        [`t1-${which}`],
      );
      // terminal
      expect(
        await refused(
          () =>
            sql.unsafe(
              `UPDATE protected_minter_tokens SET status = 'active', revoked_at = NULL, revoked_by = NULL WHERE id = $1`,
              [`t1-${which}`],
            ),
          /revoked \(terminal\)/,
        ),
      ).toBe(true);
    });

    it(`[${which}] protected_minter_controls: one row per agent, FK to agents`, async () => {
      const sql = db();
      await sql.unsafe(
        `INSERT INTO protected_minter_controls (tenant_id, agent_id, protected_minting_suspended_at, suspended_by)
         VALUES ($1, $2, now(), 'user:x')`,
        [TENANT, AGENT],
      );
      expect(
        await refused(
          () =>
            sql.unsafe(
              `INSERT INTO protected_minter_controls (tenant_id, agent_id) VALUES ($1, $2)`,
              [TENANT, AGENT],
            ),
          /protected_minter_controls_pk|duplicate key/,
        ),
      ).toBe(true);
      expect(
        await refused(
          () =>
            sql.unsafe(
              `INSERT INTO protected_minter_controls (tenant_id, agent_id) VALUES ($1, 'nobody')`,
              [TENANT],
            ),
          /protected_minter_controls_agent_fk/,
        ),
      ).toBe(true);
    });

    it(`[${which}] D5: 0031 chain CHECKs are relaxed to chain_id > 0`, async () => {
      const checks = await db().unsafe(
        `SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
          WHERE conname IN ('application_executor_signers_chain_chk', 'application_executions_chain_chk')
          ORDER BY conname`,
      );
      expect(checks).toHaveLength(2);
      for (const c of checks) {
        expect(c.def).toContain("> 0");
        expect(c.def).not.toContain("84532");
      }
    });
  }
});
