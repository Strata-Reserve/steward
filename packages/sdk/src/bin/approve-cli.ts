#!/usr/bin/env bun
/**
 * Entry point: `bun packages/sdk/src/bin/approve-cli.ts pending <agentId>`
 *                                        `approve <agentId> <txId>`
 * Config via env only (see ../approve-cli.ts).
 *
 * Secret input: the magic-link token is read by a dedicated readline interface
 * whose `output` is a muted sink. Readline never holds a reference to the real
 * terminal while a secret is being typed, so nothing it emits (per-key echo,
 * Backspace/Ctrl-U/arrow redraws, line-wrap redraws, which all write
 * `prompt + typed line`) can reach stdout. The CLI writes the prompt and the
 * trailing newline itself. Every interface has `historySize: 0` and is closed
 * after one answer, so no prompt can replay an earlier answer via ↑.
 * `process.stdout.write` is never patched.
 */
import { createInterface } from "node:readline/promises";
import { Writable } from "node:stream";
import { type ApproveCliIo, runApproveCli } from "../approve-cli.ts";

export interface TerminalStreams {
  input: NodeJS.ReadableStream;
  output: NodeJS.WritableStream;
  error: NodeJS.WritableStream;
  fetch?: typeof fetch;
}

/** Sink for everything readline wants to draw while a secret is being typed. */
const MUTED: NodeJS.WritableStream = new Writable({
  write(_chunk, _encoding, callback) {
    callback();
  },
});

/** Build the terminal IO for the CLI. Exported so tests can drive the real prompts. */
export function makeIo(streams: TerminalStreams): ApproveCliIo {
  const { input, output, error } = streams;

  // One interface per prompt: exactly one readline is ever attached to `input`
  // (two live ones would both echo), and each starts with an empty history.
  async function ask(question: string): Promise<string> {
    const rl = createInterface({ input, output, terminal: true, historySize: 0 });
    try {
      return await rl.question(question);
    } finally {
      rl.close();
    }
  }

  async function askSecret(question: string): Promise<string> {
    const rl = createInterface({ input, output: MUTED, terminal: true, historySize: 0 });
    output.write(question);
    try {
      return await rl.question(question);
    } finally {
      rl.close();
      output.write("\n");
    }
  }

  return {
    out: (line) => {
      output.write(`${line}\n`);
    },
    err: (line) => {
      error.write(`${line}\n`);
    },
    ask,
    askSecret,
    fetch: streams.fetch ?? globalThis.fetch,
  };
}

if (import.meta.main) {
  const code = await runApproveCli(
    process.argv.slice(2),
    {
      STEWARD_API_URL: process.env.STEWARD_API_URL,
      STEWARD_TENANT_ID: process.env.STEWARD_TENANT_ID,
      STEWARD_APPROVER_ALLOWLIST: process.env.STEWARD_APPROVER_ALLOWLIST,
      STEWARD_APPROVER_EMAIL: process.env.STEWARD_APPROVER_EMAIL,
      STEWARD_APPROVER_USER_ID: process.env.STEWARD_APPROVER_USER_ID,
    },
    makeIo({ input: process.stdin, output: process.stdout, error: process.stderr }),
  );
  process.exit(code);
}
