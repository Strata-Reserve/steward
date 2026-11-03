/**
 * Re-apply the env-resolved user-wallet rate-limit policy to existing
 * user-wallet-* agents in the given tenants.
 *
 * Usage:
 *   bun packages/vault/scripts/reapply-user-wallet-ratelimit.ts --tenants <id>[,<id>...] [--apply]
 *
 * Dry-run by default. Reads USER_WALLET_MAX_TX_PER_HOUR / USER_WALLET_MAX_TX_PER_DAY
 * and DATABASE_URL from env. Prints counts only.
 */

import { closeDb } from "@stwd/db";
import { reapplyUserWalletRateLimit } from "../src/user-wallet-reapply";

function parseArgs(argv: string[]): { tenantIds: string[]; apply: boolean } {
  let tenantIds: string[] = [];
  let apply = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--apply") apply = true;
    else if (arg === "--tenants") tenantIds = (argv[++i] ?? "").split(",");
    else if (arg.startsWith("--tenants=")) tenantIds = arg.slice("--tenants=".length).split(",");
    else throw new Error(`Unknown argument: ${arg}`);
  }
  tenantIds = tenantIds.map((t) => t.trim()).filter(Boolean);
  if (tenantIds.length === 0) throw new Error("--tenants <id>[,<id>...] is required");
  return { tenantIds, apply };
}

async function main(): Promise<void> {
  const { tenantIds, apply } = parseArgs(process.argv.slice(2));
  try {
    const r = await reapplyUserWalletRateLimit({ tenantIds, apply });
    console.log(
      `mode=${r.mode} tenants=${tenantIds.length} maxTxPerHour=${r.maxTxPerHour} maxTxPerDay=${r.maxTxPerDay} scanned=${r.scanned} inserted=${r.inserted} updated=${r.updated} unchanged=${r.unchanged}`,
    );
  } finally {
    await closeDb();
  }
}

main().catch((err) => {
  console.error(
    `reapply-user-wallet-ratelimit failed: ${err instanceof Error ? err.message : String(err)}`,
  );
  process.exit(1);
});
