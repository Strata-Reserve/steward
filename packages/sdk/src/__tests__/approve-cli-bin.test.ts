/**
 * Bin-level secrecy tests for packages/sdk/src/bin/approve-cli.ts.
 *
 * The real bin is spawned on a real pseudo-terminal (Bun.Terminal, 40 columns)
 * against a local in-test HTTP server. Keystrokes are typed exactly as an
 * operator would: the secret, Backspace, a line long enough to wrap, Ctrl-U, and
 * ↑ (history) at the following visible prompt. Every byte the terminal receives
 * is captured and must never contain the secret, or any prefix of it that
 * readline could have drawn.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { fileURLToPath } from "node:url";

const BIN = fileURLToPath(new URL("../bin/approve-cli.ts", import.meta.url));
const COLS = 40;
const SECRET_PROMPT = "magic-link token: ";
// Both long enough that prompt (18) + line > 40 columns, which forces a readline redraw.
const DRAFT_SECRET = "DRAFT-SECRET-TYPED-THEN-CLEARED-0123456789";
const MAGIC = "MAGIC-LINK-SECRET-DO-NOT-ECHO-abcdef0123456789";
const SESSION = "eyJ.SESSION-SECRET-DO-NOT-LEAK.sig";
const DIGEST = "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const AGENT = "agent-1";
const TX = "tx-1";
const BS = "\x7f";
const CTRL_U = "\x15";
const UP = "\x1b[A";
const ENTER = "\r";

type Seen = { url: string; method: string; body: unknown };
const seen: Seen[] = [];
let verifyTokens: string[] = [];
let server: ReturnType<typeof Bun.serve>;

function pendingBody() {
  return {
    ok: true,
    data: [
      {
        queueId: "q1",
        status: "pending",
        transaction: { id: TX, agentId: AGENT, status: "pending", executionRef: "exec-1" },
        protected: true,
        reviewDigest: DIGEST,
        requestedBy: "agent:agent-1",
        executionRef: "exec-1",
        review: { kind: "mint", chainId: 84532, to: "0xToken", value: "0" },
      },
    ],
  };
}

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    async fetch(req) {
      const url = new URL(req.url);
      const body = req.method === "POST" ? await req.json().catch(() => null) : null;
      seen.push({ url: url.pathname, method: req.method, body });
      const json = (status: number, b: unknown) => Response.json(b, { status });
      if (url.pathname === "/auth/email/send") return json(200, { ok: true });
      if (url.pathname === "/auth/email/verify") {
        const token = (body as { token?: string } | null)?.token ?? "";
        verifyTokens.push(token);
        if (token !== MAGIC) return json(401, { ok: false, error: "bad token" });
        return json(200, {
          ok: true,
          token: SESSION,
          refreshToken: "refresh-secret",
          user: { id: "u1", email: "owner@example.com" },
        });
      }
      if (req.headers.get("authorization") !== `Bearer ${SESSION}`) {
        return json(401, { ok: false });
      }
      if (url.pathname === `/vault/${AGENT}/pending`) return json(200, pendingBody());
      if (url.pathname === `/vault/${AGENT}/approve/${TX}`) {
        return json(200, {
          ok: true,
          data: { txId: TX, txHash: "0xhash", executionRef: "exec-1" },
        });
      }
      return json(404, { ok: false });
    },
  });
});

afterAll(() => {
  server.stop(true);
});

/** Spawn the real bin on a PTY and return helpers to drive it. */
function spawnBin(argv: string[]) {
  const decoder = new TextDecoder();
  let output = "";
  const term = new Bun.Terminal({
    cols: COLS,
    rows: 24,
    data(_t, chunk) {
      output += decoder.decode(chunk, { stream: true });
    },
  });
  const proc = Bun.spawn(["bun", BIN, ...argv], {
    terminal: term,
    env: {
      PATH: process.env.PATH ?? "",
      HOME: process.env.HOME ?? "",
      TERM: "xterm",
      STEWARD_API_URL: `http://127.0.0.1:${server.port}`,
      STEWARD_TENANT_ID: "tenant-1",
      STEWARD_APPROVER_ALLOWLIST: "owner@example.com",
      STEWARD_APPROVER_EMAIL: "owner@example.com",
    },
  });
  async function waitFor(text: string, timeoutMs = 10_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!output.includes(text)) {
      if (Date.now() > deadline) {
        throw new Error(
          `timed out waiting for ${JSON.stringify(text)}; got ${JSON.stringify(output)}`,
        );
      }
      if (proc.exitCode !== null) {
        throw new Error(
          `bin exited ${proc.exitCode} before ${JSON.stringify(text)}; got ${JSON.stringify(output)}`,
        );
      }
      await Bun.sleep(10);
    }
  }
  async function type(keys: string): Promise<void> {
    term.write(keys);
    // Let readline process the keystrokes (and draw whatever it is going to draw).
    await Bun.sleep(60);
  }
  async function finish(): Promise<number> {
    const code = await proc.exited;
    await Bun.sleep(50);
    term.close();
    return code;
  }
  return { waitFor, type, finish, output: () => output };
}

/** Every substring readline could draw from the secret: the whole and all prefixes ≥ 6 chars. */
function leakFragments(secret: string): string[] {
  const frags: string[] = [];
  for (let n = 6; n <= secret.length; n++) frags.push(secret.slice(0, n));
  return frags;
}

function expectNoSecretBytes(out: string) {
  for (const secret of [DRAFT_SECRET, MAGIC, SESSION, "refresh-secret"]) {
    for (const frag of leakFragments(secret)) {
      expect(out).not.toContain(frag);
    }
  }
}

describe("bin/approve-cli secret input (real PTY)", () => {
  test("secret with Backspace, wrap, Ctrl-U, retype, and ↑ at the next prompt never reaches the terminal", async () => {
    seen.length = 0;
    verifyTokens = [];
    const bin = spawnBin(["approve", AGENT, TX]);
    await bin.waitFor(SECRET_PROMPT);

    // A draft long enough to wrap at 40 columns, corrected with Backspace, then abandoned with Ctrl-U.
    await bin.type(DRAFT_SECRET);
    await bin.type(BS);
    await bin.type("Z");
    await bin.type(CTRL_U);
    // The real secret, also wrap-length, with a Backspace correction of the last character.
    await bin.type(`${MAGIC.slice(0, -1)}X`);
    await bin.type(BS);
    await bin.type(MAGIC.slice(-1));
    await bin.type(ENTER);

    // Next visible prompt: ↑ must not replay the secret; then approve for real.
    await bin.waitFor("to approve: ");
    await bin.type(UP);
    await bin.type(CTRL_U);
    await bin.type(DIGEST.slice(2, 10));
    await bin.type(ENTER);

    const code = await bin.finish();
    const out = bin.output();

    expect(out).toContain(SECRET_PROMPT);
    expectNoSecretBytes(out);
    // The edits above were actually applied: the server saw exactly the corrected secret, once.
    expect(verifyTokens).toEqual([MAGIC]);
    expect(seen.map((c) => `${c.method} ${c.url}`)).toEqual([
      "POST /auth/email/send",
      "POST /auth/email/verify",
      `GET /vault/${AGENT}/pending`,
      `GET /vault/${AGENT}/pending`,
      `POST /vault/${AGENT}/approve/${TX}`,
    ]);
    expect(seen[4]?.body).toEqual({ reviewDigest: DIGEST });
    expect(out).toContain(`approved txId=${TX}`);
    expect(code).toBe(0);
  }, 30_000);

  test("plain typing of a wrap-length secret (no edits) never reaches the terminal", async () => {
    seen.length = 0;
    verifyTokens = [];
    const bin = spawnBin(["pending", AGENT]);
    await bin.waitFor(SECRET_PROMPT);
    await bin.type(MAGIC);
    await bin.type(ENTER);
    const code = await bin.finish();
    const out = bin.output();
    expectNoSecretBytes(out);
    expect(verifyTokens).toEqual([MAGIC]);
    expect(out).toContain("--- pending #1 ---");
    expect(code).toBe(0);
  }, 30_000);

  test("wrong secret: failure path prints status only, never the secret", async () => {
    seen.length = 0;
    verifyTokens = [];
    const bin = spawnBin(["pending", AGENT]);
    await bin.waitFor(SECRET_PROMPT);
    await bin.type(DRAFT_SECRET);
    await bin.type(ENTER);
    const code = await bin.finish();
    const out = bin.output();
    expectNoSecretBytes(out);
    expect(verifyTokens).toEqual([DRAFT_SECRET]);
    expect(out).toContain("login (verify) failed: HTTP 401");
    expect(code).toBe(1);
  }, 30_000);
});
