/**
 * PGLite adapter for Steward — runs Postgres in-process via WASM.
 *
 * Use this for local / desktop mode (Electrobun) where no external
 * PostgreSQL server is available.
 *
 * Environment detection:
 *   - STEWARD_DB_MODE=pglite  → always use PGLite
 *   - No DATABASE_URL set     → fall back to PGLite
 *   - STEWARD_PGLITE_PATH    → persistence directory (default ~/.steward/data)
 *   - STEWARD_PGLITE_MEMORY  → if "true", use in-memory (no persistence)
 *   - STEWARD_PGLITE_SNAPSHOT → test boot path only (NODE_ENV=test + memory://):
 *                               "0" disables the migrated-snapshot cache
 */

import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";

import * as schema from "./schema";
import * as schemaAuth from "./schema-auth";

export type PGLiteDb = ReturnType<typeof drizzle<typeof schema & typeof schemaAuth>>;

let globalPGLite: { client: PGlite; db: PGLiteDb } | undefined;

const MIGRATIONS_FOLDER = new URL("../drizzle", import.meta.url).pathname;
const MEMORY_TARGET = "memory://";

/**
 * Resolve the data directory for PGLite persistence.
 */
export function getDataDir(): string {
  if (process.env.STEWARD_PGLITE_PATH) {
    return resolve(process.env.STEWARD_PGLITE_PATH);
  }
  return join(homedir(), ".steward", "data");
}

/**
 * Determine whether PGLite should be used based on environment variables.
 */
export function shouldUsePGLite(): boolean {
  if (process.env.STEWARD_DB_MODE === "pglite") return true;
  if (!process.env.DATABASE_URL) return true;
  return false;
}

/**
 * Run all SQL migration files from the drizzle/ folder in lexicographic order.
 *
 * This reads every *.sql file (excluding meta/), splits on the Drizzle
 * statement-breakpoint marker, and executes each statement sequentially.
 * The `__steward_migrations` table tracks which files have already been applied
 * so restarts with a persistent data dir don't re-run migrations.
 */
async function listMigrationFiles(): Promise<string[]> {
  const files = await readdir(MIGRATIONS_FOLDER);
  return files.filter((f) => f.endsWith(".sql") && !f.startsWith(".")).sort();
}

async function runPGLiteMigrations(client: PGlite): Promise<void> {
  const migrationsFolder = MIGRATIONS_FOLDER;

  // Create tracking table
  await client.exec(`
    CREATE TABLE IF NOT EXISTS __steward_migrations (
      tag TEXT PRIMARY KEY,
      applied_at TIMESTAMP WITH TIME ZONE DEFAULT now()
    );
  `);

  // Get already-applied migrations
  const applied = await client.query<{ tag: string }>(
    "SELECT tag FROM __steward_migrations ORDER BY tag",
  );
  const appliedSet = new Set(applied.rows.map((r) => r.tag));

  // Read all SQL files (skip meta/ directory and non-.sql)
  const sqlFiles = await listMigrationFiles();

  for (const file of sqlFiles) {
    const tag = file.replace(/\.sql$/, "");
    if (appliedSet.has(tag)) continue;

    const filePath = join(migrationsFolder, file);
    const sql = await readFile(filePath, "utf-8");

    // Split on Drizzle's statement-breakpoint marker, or fall back to semicolons
    const statements = sql.includes("--> statement-breakpoint")
      ? sql.split("--> statement-breakpoint")
      : [sql];

    for (const stmt of statements) {
      const trimmed = stmt.trim();
      if (!trimmed || trimmed === "--") continue;
      try {
        await client.exec(trimmed);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        // Ignore "already exists" errors for idempotent migrations
        if (message.includes("already exists") || message.includes("duplicate key")) {
          continue;
        }
        throw new Error(
          `Migration ${file} failed: ${message}\nStatement: ${trimmed.slice(0, 200)}`,
        );
      }
    }

    await client.exec(`INSERT INTO __steward_migrations (tag) VALUES ('${tag}')`);
    console.log(`[pglite] Applied migration: ${file}`);
  }
}

// ─── Test boot path: migrated-snapshot cache ─────────────────────────────────
//
// Every in-memory PGLite boot pays for initdb (~2 s of WASM work) plus a full
// replay of drizzle/*.sql. Under `bun test --isolate` each test file boots its
// own instance, so with dozens of PGLite-backed files that cost dominates the
// per-file beforeAll. In tests we instead build the migrated data dir once,
// dump it to a tarball keyed by the migration contents + PGLite version, and
// boot every later instance from that tarball via `loadDataDir` (~0.25 s).
//
// The cache is only consulted for `memory://` targets when NODE_ENV=test (set
// by `bun test`); persistent/desktop boots are untouched. Migrations are still
// run after a snapshot load, so drizzle/*.sql stays the source of truth — on a
// warm snapshot that is a single SELECT against __steward_migrations.

function snapshotEnabled(connectionTarget: string): boolean {
  if (connectionTarget !== MEMORY_TARGET) return false;
  if (process.env.NODE_ENV !== "test") return false;
  return process.env.STEWARD_PGLITE_SNAPSHOT !== "0";
}

async function pgliteVersion(): Promise<string> {
  try {
    const pkgUrl = import.meta.resolve("@electric-sql/pglite/package.json");
    const pkg = JSON.parse(await readFile(new URL(pkgUrl), "utf-8")) as { version?: string };
    return pkg.version ?? "unknown";
  } catch {
    return "unknown";
  }
}

/** Content hash of every migration file + PGLite version: the snapshot key. */
async function snapshotPath(): Promise<string> {
  const hash = createHash("sha256");
  hash.update(`pglite:${await pgliteVersion()}\n`);
  for (const file of await listMigrationFiles()) {
    hash.update(`${file}\n`);
    hash.update(await readFile(join(MIGRATIONS_FOLDER, file)));
    hash.update("\n");
  }
  const dir = process.env.STEWARD_PGLITE_SNAPSHOT_DIR ?? tmpdir();
  return join(dir, `steward-pglite-snapshot-${hash.digest("hex").slice(0, 16)}.tar`);
}

/** Cold boot + migrate + dump. Written atomically so parallel workers never read a torn file. */
async function buildSnapshot(path: string): Promise<void> {
  const started = performance.now();
  const client = new PGlite(MEMORY_TARGET);
  try {
    await runPGLiteMigrations(client);
    await client.exec("CHECKPOINT");
    const dump = await client.dumpDataDir("none");
    const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
    await mkdir(resolve(path, ".."), { recursive: true });
    await writeFile(tmp, new Uint8Array(await dump.arrayBuffer()));
    await rename(tmp, path);
  } finally {
    await client.close();
  }
  console.log(
    `[pglite] Built migrated snapshot in ${Math.round(performance.now() - started)}ms: ${path}`,
  );
}

async function bootFromSnapshot(): Promise<PGlite> {
  const path = await snapshotPath();
  if (!existsSync(path)) {
    await buildSnapshot(path);
  }
  const bytes = await readFile(path);
  const loadDataDir = new Blob([new Uint8Array(bytes)], { type: "application/x-tar" });
  return new PGlite({ dataDir: MEMORY_TARGET, loadDataDir });
}

/**
 * Create a PGLite-backed Drizzle instance.
 *
 * @param dataDir - directory for persistence, or "memory://" for in-memory
 */
export async function createPGLiteDb(dataDir?: string): Promise<{ client: PGlite; db: PGLiteDb }> {
  const useMemory = process.env.STEWARD_PGLITE_MEMORY === "true";

  let connectionTarget: string;
  if (useMemory) {
    connectionTarget = "memory://";
  } else {
    const dir = dataDir ?? getDataDir();
    // Ensure data directory exists
    if (!existsSync(dir)) {
      await mkdir(dir, { recursive: true });
      console.log(`[pglite] Created data directory: ${dir}`);
    }
    connectionTarget = dir;
  }

  console.log(`[pglite] Initializing PGLite at: ${connectionTarget}`);
  const started = performance.now();
  const client = snapshotEnabled(connectionTarget)
    ? await bootFromSnapshot()
    : new PGlite(connectionTarget);

  // Run migrations (no-op after a snapshot load: every tag is already recorded)
  await runPGLiteMigrations(client);
  console.log(`[pglite] Ready in ${Math.round(performance.now() - started)}ms`);

  const db = drizzle(client, {
    schema: { ...schema, ...schemaAuth },
  });

  return { client, db };
}

/**
 * Get or create the global PGLite DB singleton.
 * Mirrors the getDb() / getSql() pattern from client.ts.
 */
export async function getPGLiteDb(): Promise<PGLiteDb> {
  if (!globalPGLite) {
    globalPGLite = await createPGLiteDb();
  }
  return globalPGLite.db;
}

export async function getPGLiteClient(): Promise<PGlite> {
  if (!globalPGLite) {
    globalPGLite = await createPGLiteDb();
  }
  return globalPGLite.client;
}

export async function closePGLiteDb(): Promise<void> {
  if (!globalPGLite) return;
  await globalPGLite.client.close();
  globalPGLite = undefined;
}
