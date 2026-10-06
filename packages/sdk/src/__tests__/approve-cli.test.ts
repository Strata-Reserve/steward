import { describe, expect, test } from "bun:test";
import { EXIT, type PendingItem, renderPending, runApproveCli } from "../approve-cli.ts";

const SECRET_TOKEN = "eyJ.SESSION-SECRET-DO-NOT-LEAK.sig";
const MAGIC = "magic-link-secret-token";
const DIGEST = "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const DIGEST2 = "0x1111111123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const AGENT = "agent-1";
const TX = "tx-1";

type Call = { url: string; method: string; headers: Record<string, string>; body: unknown };

function pendingRow(digest = DIGEST) {
  return {
    queueId: "q1",
    status: "pending",
    requestedAt: "2026-10-06T09:00:00.000Z",
    transaction: { id: TX, agentId: AGENT, status: "pending", executionRef: "exec-1" },
    protected: true,
    reviewDigest: digest,
    manifestDigest: "0xmanifest",
    requestedBy: "agent:agent-1",
    executionRef: "exec-1",
    review: {
      kind: "mint",
      chainId: 84532,
      to: "0xToken",
      value: "0",
      selector: "0x40c10f19",
      executionRef: "exec-1",
      signer: "0xSigner",
      token: "0xToken",
      recipient: "0xRecipient",
      amount: "1000",
    },
  };
}

function harness(opts: {
  allowlist?: string;
  email?: string;
  answers?: string[];
  pendingSequence?: Array<Array<ReturnType<typeof pendingRow>>>;
  approveStatus?: number;
  verifyStatus?: number;
  sendStatus?: number;
  user?: Record<string, unknown>;
}) {
  const calls: Call[] = [];
  const out: string[] = [];
  const err: string[] = [];
  const answers = [...(opts.answers ?? [])];
  const pendings = [...(opts.pendingSequence ?? [[pendingRow()]])];
  const json = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  const fetchMock = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const headers = Object.fromEntries(new Headers(init?.headers).entries());
    calls.push({
      url,
      method: init?.method ?? "GET",
      headers,
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    });
    if (url.endsWith("/auth/email/send"))
      return json(opts.sendStatus ?? 200, { ok: true, data: {} });
    if (url.endsWith("/auth/email/verify")) {
      const st = opts.verifyStatus ?? 200;
      if (st !== 200) return json(st, { ok: false, error: "Invalid or expired magic link" });
      return json(200, {
        ok: true,
        token: SECRET_TOKEN,
        refreshToken: "refresh-secret",
        user: opts.user ?? { id: "user-1", email: "owner@example.com" },
      });
    }
    if (url.endsWith(`/vault/${AGENT}/pending`)) {
      const rows = pendings.length > 1 ? pendings.shift() : pendings[0];
      return json(200, { ok: true, data: rows });
    }
    if (url.endsWith(`/vault/${AGENT}/approve/${TX}`)) {
      const st = opts.approveStatus ?? 200;
      if (st !== 200) return json(st, { ok: false, error: "Protected signer: refused" });
      return json(200, { ok: true, data: { txId: TX, txHash: "0xhash", executionRef: "exec-1" } });
    }
    return json(404, { ok: false, error: "not found" });
  }) as unknown as typeof fetch;
  const io = {
    out: (l: string) => out.push(l),
    err: (l: string) => err.push(l),
    ask: async () => answers.shift() ?? "",
    askSecret: async () => MAGIC,
    fetch: fetchMock,
  };
  const env = {
    STEWARD_API_URL: "http://steward.test",
    STEWARD_TENANT_ID: "tenant-1",
    STEWARD_APPROVER_ALLOWLIST: opts.allowlist,
    STEWARD_APPROVER_EMAIL: opts.email ?? "owner@example.com",
  };
  const captured = () => [...out, ...err].join("\n");
  return { calls, out, err, io, env, captured };
}

const PREFIX = DIGEST.slice(2, 10);

describe("approve-cli allowlist gate", () => {
  test("empty allowlist refuses before any network call", async () => {
    const h = harness({ allowlist: "" });
    const code = await runApproveCli(["pending", AGENT], h.env, h.io);
    expect(code).toBe(EXIT.REFUSED);
    expect(h.calls.length).toBe(0);
    expect(h.err.join("\n")).toContain("refused");
  });

  test("missing allowlist refuses before any network call", async () => {
    const h = harness({ allowlist: undefined });
    const code = await runApproveCli(["approve", AGENT, TX], h.env, h.io);
    expect(code).toBe(EXIT.REFUSED);
    expect(h.calls.length).toBe(0);
  });

  test("non-allowlisted identity refused before any network call", async () => {
    const h = harness({
      allowlist: "someone-else@example.com, user-99",
      email: "owner@example.com",
    });
    const code = await runApproveCli(["pending", AGENT], h.env, h.io);
    expect(code).toBe(EXIT.REFUSED);
    expect(h.calls.length).toBe(0);
  });

  test("signed-in identity not matching the allowlist is refused after login, no vault calls", async () => {
    const h = harness({
      allowlist: "owner@example.com",
      user: { id: "user-1", email: "impostor@example.com" },
    });
    const code = await runApproveCli(["pending", AGENT], h.env, h.io);
    expect(code).toBe(EXIT.REFUSED);
    expect(h.calls.some((c) => c.url.includes("/vault/"))).toBe(false);
  });
});

describe("approve-cli pending", () => {
  test("renders txId, executionRef, projection and reviewDigest", async () => {
    const h = harness({ allowlist: "owner@example.com" });
    const code = await runApproveCli(["pending", AGENT], h.env, h.io);
    expect(code).toBe(EXIT.OK);
    const text = h.out.join("\n");
    expect(text).toContain(`txId:          ${TX}`);
    expect(text).toContain("executionRef:  exec-1");
    expect(text).toContain("target:        0xToken");
    expect(text).toContain("selector:      0x40c10f19");
    expect(text).toContain("chain:         84532");
    expect(text).toContain("recipient: 0xRecipient");
    expect(text).toContain("amount: 1000");
    expect(text).toContain(`reviewDigest:  ${DIGEST}`);
    const pendingCall = h.calls.find((c) => c.url.endsWith("/pending"));
    expect(pendingCall?.headers.authorization).toBe(`Bearer ${SECRET_TOKEN}`);
    expect(pendingCall?.headers["x-steward-tenant"]).toBe("tenant-1");
  });

  test("renderPending is pure and lists decoded args", () => {
    const item: PendingItem = {
      txId: "t",
      executionRef: "e",
      reviewDigest: "0xd",
      review: {
        kind: "createDealToken",
        chainId: 1,
        to: "0xF",
        selector: "0x1",
        name: "Deal",
        symbol: "DL",
      },
    };
    const lines = renderPending(item);
    expect(lines).toContain("  name: Deal");
    expect(lines).toContain("  symbol: DL");
    expect(lines[lines.length - 1]).toBe("reviewDigest:  0xd");
  });
});

describe("approve-cli approve", () => {
  test("echoes exactly the displayed digest after confirmation", async () => {
    const h = harness({ allowlist: "owner@example.com", answers: [PREFIX] });
    const code = await runApproveCli(["approve", AGENT, TX], h.env, h.io);
    expect(code).toBe(EXIT.OK);
    const approve = h.calls.find((c) => c.method === "POST" && c.url.includes("/approve/"));
    expect(approve).toBeDefined();
    expect(approve?.body).toEqual({ reviewDigest: DIGEST });
    expect(approve?.headers.authorization).toBe(`Bearer ${SECRET_TOKEN}`);
    expect(h.out.join("\n")).toContain(`reviewDigest:  ${DIGEST}`);
    expect(h.out.join("\n")).toContain("approved txId=tx-1 txHash=0xhash");
  });

  test("wrong confirmation aborts without POSTing", async () => {
    const h = harness({ allowlist: "owner@example.com", answers: ["nope"] });
    const code = await runApproveCli(["approve", AGENT, TX], h.env, h.io);
    expect(code).toBe(EXIT.ABORTED);
    expect(h.calls.some((c) => c.url.includes("/approve/"))).toBe(false);
  });

  test("digest changed between display and approve is refused", async () => {
    const h = harness({
      allowlist: "owner@example.com",
      answers: [PREFIX],
      pendingSequence: [[pendingRow(DIGEST)], [pendingRow(DIGEST2)]],
    });
    const code = await runApproveCli(["approve", AGENT, TX], h.env, h.io);
    expect(code).toBe(EXIT.ABORTED);
    expect(h.err.join("\n")).toContain("reviewDigest changed");
    expect(h.calls.some((c) => c.url.includes("/approve/"))).toBe(false);
  });

  test("item no longer pending on re-fetch is refused", async () => {
    const h = harness({
      allowlist: "owner@example.com",
      answers: [PREFIX],
      pendingSequence: [[pendingRow(DIGEST)], []],
    });
    const code = await runApproveCli(["approve", AGENT, TX], h.env, h.io);
    expect(code).toBe(EXIT.ABORTED);
    expect(h.calls.some((c) => c.url.includes("/approve/"))).toBe(false);
  });

  test("unknown txId fails without POSTing", async () => {
    const h = harness({ allowlist: "owner@example.com", answers: [PREFIX] });
    const code = await runApproveCli(["approve", AGENT, "tx-other"], h.env, h.io);
    expect(code).toBe(EXIT.FAIL);
    expect(h.calls.some((c) => c.url.includes("/approve/"))).toBe(false);
  });

  test("non-2xx approve prints only the status code", async () => {
    const h = harness({ allowlist: "owner@example.com", answers: [PREFIX], approveStatus: 403 });
    const code = await runApproveCli(["approve", AGENT, TX], h.env, h.io);
    expect(code).toBe(EXIT.FAIL);
    expect(h.err).toContain("approve failed: HTTP 403");
    expect(h.captured()).not.toContain("Protected signer");
  });

  test("non-2xx login prints only the status code", async () => {
    const h = harness({ allowlist: "owner@example.com", verifyStatus: 401 });
    const code = await runApproveCli(["pending", AGENT], h.env, h.io);
    expect(code).toBe(EXIT.FAIL);
    expect(h.err).toContain("login (verify) failed: HTTP 401");
    expect(h.calls.some((c) => c.url.includes("/vault/"))).toBe(false);
  });

  test("only GET pending and POST approve hit /vault — no other mutations", async () => {
    const h = harness({ allowlist: "owner@example.com", answers: [PREFIX] });
    await runApproveCli(["approve", AGENT, TX], h.env, h.io);
    const vaultCalls = h.calls.filter((c) => c.url.includes("/vault/"));
    expect(vaultCalls.map((c) => `${c.method} ${new URL(c.url).pathname}`)).toEqual([
      `GET /vault/${AGENT}/pending`,
      `GET /vault/${AGENT}/pending`,
      `POST /vault/${AGENT}/approve/${TX}`,
    ]);
  });
});

describe("approve-cli secrecy", () => {
  test("session token and magic token never appear in stdout/stderr (success path)", async () => {
    const h = harness({ allowlist: "owner@example.com", answers: [PREFIX] });
    await runApproveCli(["approve", AGENT, TX], h.env, h.io);
    expect(h.captured()).not.toContain(SECRET_TOKEN);
    expect(h.captured()).not.toContain("SESSION-SECRET");
    expect(h.captured()).not.toContain(MAGIC);
    expect(h.captured()).not.toContain("refresh-secret");
  });

  test("session token never appears in output on failure paths", async () => {
    for (const opts of [
      { approveStatus: 500 },
      { user: { id: "x", email: "impostor@example.com" } },
      { pendingSequence: [[pendingRow(DIGEST)], [pendingRow(DIGEST2)]] },
    ]) {
      const h = harness({ allowlist: "owner@example.com", answers: [PREFIX], ...opts });
      await runApproveCli(["approve", AGENT, TX], h.env, h.io);
      expect(h.captured()).not.toContain(SECRET_TOKEN);
      expect(h.captured()).not.toContain(MAGIC);
    }
  });

  test("magic token travels only in the verify body, never in argv or URLs", async () => {
    const h = harness({ allowlist: "owner@example.com", answers: [PREFIX] });
    await runApproveCli(["approve", AGENT, TX], h.env, h.io);
    for (const c of h.calls) expect(c.url).not.toContain(MAGIC);
    const verify = h.calls.find((c) => c.url.endsWith("/auth/email/verify"));
    expect(verify?.body).toEqual({
      token: MAGIC,
      email: "owner@example.com",
      tenantId: "tenant-1",
    });
  });
});
