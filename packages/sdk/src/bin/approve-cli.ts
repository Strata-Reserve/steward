#!/usr/bin/env bun
/**
 * Entry point: `bun packages/sdk/src/bin/approve-cli.ts pending <agentId>`
 *                                        `approve <agentId> <txId>`
 * Config via env only (see ../approve-cli.ts). Secrets are read from the
 * terminal with echo disabled and are never written anywhere.
 */
import { createInterface } from "node:readline/promises";
import { runApproveCli } from "../approve-cli.ts";

const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
const code = await runApproveCli(
  process.argv.slice(2),
  {
    STEWARD_API_URL: process.env.STEWARD_API_URL,
    STEWARD_TENANT_ID: process.env.STEWARD_TENANT_ID,
    STEWARD_APPROVER_ALLOWLIST: process.env.STEWARD_APPROVER_ALLOWLIST,
    STEWARD_APPROVER_EMAIL: process.env.STEWARD_APPROVER_EMAIL,
    STEWARD_APPROVER_USER_ID: process.env.STEWARD_APPROVER_USER_ID,
  },
  {
    out: (l) => console.log(l),
    err: (l) => console.error(l),
    ask: (q) => rl.question(q),
    askSecret: async (q) => {
      // Suppress echo while the secret is typed; readline keeps the prompt visible.
      const w = process.stdout.write.bind(process.stdout);
      process.stdout.write = ((s: string | Uint8Array) =>
        typeof s === "string" && s.startsWith(q) ? w(s) : true) as typeof process.stdout.write;
      try {
        return await rl.question(q);
      } finally {
        process.stdout.write = w;
        w("\n");
      }
    },
    fetch: globalThis.fetch,
  },
);
rl.close();
process.exit(code);
