import { describe, expect, it } from "bun:test";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { PGlite } from "@electric-sql/pglite";

const migrationsDir = fileURLToPath(new URL("../../drizzle", import.meta.url));

async function applySql(client: PGlite, file: string) {
  const source = await readFile(`${migrationsDir}/${file}`, "utf8");
  const statements = source.includes("--> statement-breakpoint")
    ? source.split("--> statement-breakpoint")
    : [source];
  for (const statement of statements) {
    const sql = statement.trim();
    if (sql && sql !== "--") await client.exec(sql);
  }
}

describe("application-principal migrations", () => {
  it("applies additively over populated multi-tenant custody data", async () => {
    const client = new PGlite("memory://");
    try {
      const files = (await readdir(migrationsDir))
        .filter((file) => /^\d{4}.*\.sql$/.test(file) && file < "0025")
        .sort();
      for (const file of files) await applySql(client, file);

      await client.exec(`
        INSERT INTO tenants (id, name, api_key_hash) VALUES
          ('migration-tenant-a', 'Migration A', '${"a".repeat(64)}'),
          ('migration-tenant-b', 'Migration B', '${"b".repeat(64)}');
        INSERT INTO agents (id, tenant_id, name, wallet_address) VALUES
          ('migration-agent-a', 'migration-tenant-a', 'A', '0x${"11".repeat(20)}'),
          ('migration-agent-b', 'migration-tenant-b', 'B', '0x${"22".repeat(20)}');
        INSERT INTO transactions
          (id, agent_id, status, to_address, value, chain_id)
        VALUES
          ('migration-tx-a', 'migration-agent-a', 'pending', '0x${"33".repeat(20)}', '0', 8453),
          ('migration-tx-b', 'migration-agent-b', 'pending', '0x${"44".repeat(20)}', '0', 8453);
      `);

      await applySql(client, "0025_application_principals.sql");

      const tenants = await client.query<{ id: string }>("SELECT id FROM tenants ORDER BY id");
      const agents = await client.query<{ id: string }>("SELECT id FROM agents ORDER BY id");
      const transactions = await client.query<{ id: string }>(
        "SELECT id FROM transactions ORDER BY id",
      );
      expect(tenants.rows.map((row) => row.id)).toEqual([
        "migration-tenant-a",
        "migration-tenant-b",
      ]);
      expect(agents.rows.map((row) => row.id)).toEqual(["migration-agent-a", "migration-agent-b"]);
      expect(transactions.rows.map((row) => row.id)).toEqual(["migration-tx-a", "migration-tx-b"]);

      await client.exec(`
        INSERT INTO application_principals
          (id, tenant_id, name, capabilities, expires_at)
        VALUES
          ('app_migration_a', 'migration-tenant-a', 'App A', ARRAY['wallet:ensure']::application_capability[], '2030-01-01T00:00:00Z'),
          ('app_migration_b', 'migration-tenant-b', 'App B', ARRAY['transaction:propose']::application_capability[], '2030-01-01T00:00:00Z');
      `);
      const principals = await client.query<{ tenant_id: string }>(
        "SELECT tenant_id FROM application_principals ORDER BY tenant_id",
      );
      expect(principals.rows.map((row) => row.tenant_id)).toEqual([
        "migration-tenant-a",
        "migration-tenant-b",
      ]);

      let closedVocabularyError: unknown;
      try {
        await client.exec(`
          INSERT INTO application_principals
            (id, tenant_id, name, capabilities, expires_at)
          VALUES
            ('app_invalid', 'migration-tenant-a', 'Invalid', ARRAY['wallet:*']::application_capability[], '2030-01-01T00:00:00Z')
        `);
      } catch (error) {
        closedVocabularyError = error;
      }
      expect(closedVocabularyError).toBeDefined();
    } finally {
      await client.close();
    }
  });

  it("adds the proposal-read capability without rewriting existing principals or proposals", async () => {
    const client = new PGlite("memory://");
    try {
      const files = (await readdir(migrationsDir))
        .filter((file) => /^\d{4}.*\.sql$/.test(file) && file <= "0025_application_principals.sql")
        .sort();
      for (const file of files) await applySql(client, file);
      await client.exec(`
        INSERT INTO tenants (id, name, api_key_hash)
        VALUES ('migration-read', 'Migration Read', '${"c".repeat(64)}');
        INSERT INTO agents (id, tenant_id, name, wallet_address)
        VALUES ('agent_existing', 'migration-read', 'Existing agent', '0x${"11".repeat(20)}');
        INSERT INTO application_principals
          (id, tenant_id, name, capabilities, expires_at)
        VALUES
          ('app_existing', 'migration-read', 'Existing', ARRAY['transaction:propose']::application_capability[], '2030-01-01T00:00:00Z');
        INSERT INTO application_principal_credentials
          (key_id, tenant_id, principal_id, secret_hash, expires_at)
        VALUES
          ('apk_000000000000000000000001', 'migration-read', 'app_existing', '${"d".repeat(64)}', '2029-01-01T00:00:00Z');
        INSERT INTO application_principal_resources
          (tenant_id, principal_id, resource_kind, resource_id)
        VALUES
          ('migration-read', 'app_existing', 'wallet_owner', 'party_existing');
        INSERT INTO application_wallets
          (id, tenant_id, principal_id, resource_kind, resource_id, steward_agent_id, addresses)
        VALUES
          ('aw_existing', 'migration-read', 'app_existing', 'wallet_owner', 'party_existing', 'agent_existing',
           '{"evm":"0x1111111111111111111111111111111111111111","solana":"11111111111111111111111111111111"}');
        INSERT INTO application_transaction_intents
          (id, tenant_id, principal_id, credential_key_id, wallet_id, request_hash, intent, expires_at)
        VALUES
          ('ati_existing', 'migration-read', 'app_existing', 'apk_000000000000000000000001', 'aw_existing', '${"e".repeat(64)}', '{}', '2029-01-01T00:00:00Z');
        INSERT INTO application_transaction_proposals
          (id, tenant_id, principal_id, credential_key_id, intent_id, request_hash)
        VALUES
          ('atp_existing', 'migration-read', 'app_existing', 'apk_000000000000000000000001', 'ati_existing', '${"f".repeat(64)}');
      `);
      const proposalBefore = await client.query(
        "SELECT * FROM application_transaction_proposals WHERE id = 'atp_existing'",
      );

      await applySql(client, "0026_application_proposal_read.sql");
      await client.exec(`
        INSERT INTO application_principals
          (id, tenant_id, name, capabilities, expires_at)
        VALUES
          ('app_reader', 'migration-read', 'Reader', ARRAY['transaction:proposal:read']::application_capability[], '2030-01-01T00:00:00Z');
      `);

      const principals = await client.query<{ id: string; capabilities: string[] }>(
        "SELECT id, capabilities::text[] AS capabilities FROM application_principals ORDER BY id",
      );
      expect(principals.rows).toEqual([
        { id: "app_existing", capabilities: ["transaction:propose"] },
        { id: "app_reader", capabilities: ["transaction:proposal:read"] },
      ]);
      const proposalAfter = await client.query(
        "SELECT * FROM application_transaction_proposals WHERE id = 'atp_existing'",
      );
      expect(proposalAfter.rows).toEqual(proposalBefore.rows);
    } finally {
      await client.close();
    }
  });
});
