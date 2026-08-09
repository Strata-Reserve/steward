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

describe("0025 application-principal migration", () => {
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
});
