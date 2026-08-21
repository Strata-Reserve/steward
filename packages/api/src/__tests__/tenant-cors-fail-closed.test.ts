/**
 * STRATA-1115 — tenant CORS must FAIL CLOSED.
 *
 * The middleware previously initialised `allowOrigin = "*"` and reached that
 * value on two distinct paths: an empty `allowed_origins` list, and a THROWN
 * error from the config lookup. Both emitted `Access-Control-Allow-Origin: *`.
 * The second is the sharper defect — a transient database failure silently
 * downgraded a security control for a tenant that HAD configured an allowlist.
 *
 * These are pure middleware tests: no database, no server. `@stwd/db` is mocked
 * so the lookup can be made to return an empty list or throw ON DEMAND, which is
 * the only way to exercise the failure path deterministically. Waiting for a
 * real database outage is not a test strategy.
 *
 * Note each test uses a DISTINCT tenant id. The middleware caches origin lists
 * for 60s, so sharing an id across cases would let one test's cached result
 * decide another's outcome — a false pass that looks like coverage.
 */
import { beforeEach, describe, expect, it, mock } from "bun:test";

// ─── Mock the config lookup ───────────────────────────────────────────────────
// `behaviour` is reassigned per test to select the scenario under exercise.

type Behaviour = { kind: "origins"; origins: string[] } | { kind: "throw"; error: Error };

let behaviour: Behaviour = { kind: "origins", origins: [] };
let selectCalls = 0;

const db = {
  select: () => ({
    from: () => ({
      where: () => {
        selectCalls += 1;
        if (behaviour.kind === "throw") return Promise.reject(behaviour.error);
        return Promise.resolve([{ allowedOrigins: behaviour.origins }]);
      },
    }),
  }),
};

mock.module("@stwd/db", () => ({
  getDb: () => db,
  tenantConfigs: { tenantId: "tenantId", allowedOrigins: "allowedOrigins" },
  eq: () => true,
}));

const { tenantCors } = await import("../middleware/tenant-cors");

// ─── Minimal Hono-shaped context ──────────────────────────────────────────────

interface Invocation {
  status: number | undefined;
  headers: Record<string, string>;
  nextCalled: boolean;
  returnedResponse: boolean;
}

async function invoke(opts: {
  method: string;
  origin?: string;
  tenantId?: string;
}): Promise<Invocation> {
  const headers: Record<string, string> = {};
  let nextCalled = false;
  let status: number | undefined;

  const requestHeaders: Record<string, string> = {};
  if (opts.origin !== undefined) requestHeaders.origin = opts.origin;
  if (opts.tenantId !== undefined) requestHeaders["X-Steward-Tenant"] = opts.tenantId;

  const c = {
    req: {
      method: opts.method,
      header: (name: string) => requestHeaders[name] ?? requestHeaders[name.toLowerCase()],
    },
    header: (name: string, value: string) => {
      headers[name] = value;
    },
    newResponse: (_body: null, code: number) => {
      status = code;
      return { __response: true, status: code } as unknown as Response;
    },
  };

  const next = async () => {
    nextCalled = true;
  };

  const result = await tenantCors(c as never, next as never);
  return { status, headers, nextCalled, returnedResponse: result !== undefined };
}

const acao = (inv: Invocation) => inv.headers["Access-Control-Allow-Origin"];

beforeEach(() => {
  selectCalls = 0;
});

describe("STRATA-1115: empty allowedOrigins must DENY, not wildcard", () => {
  it("preflight from an arbitrary origin gets 403 and NO CORS headers", async () => {
    behaviour = { kind: "origins", origins: [] };
    const inv = await invoke({
      method: "OPTIONS",
      origin: "https://evil.example.com",
      tenantId: "t-empty-preflight",
    });

    expect(inv.status).toBe(403);
    expect(acao(inv)).toBeUndefined();
    // The pre-fix behaviour was 204 + ACAO:*. Assert the wildcard is gone
    // explicitly, not merely that the status changed.
    expect(Object.keys(inv.headers)).toHaveLength(0);
  });

  it("actual request still reaches the handler but carries NO CORS headers", async () => {
    behaviour = { kind: "origins", origins: [] };
    const inv = await invoke({
      method: "GET",
      origin: "https://evil.example.com",
      tenantId: "t-empty-get",
    });

    // Denial is a BROWSER-enforced read block, not an API refusal: the handler
    // must still run so non-browser behaviour is unchanged.
    expect(inv.nextCalled).toBe(true);
    expect(acao(inv)).toBeUndefined();
  });
});

describe("STRATA-1115: config lookup failure must DENY, not wildcard", () => {
  it("a thrown DB error denies the preflight instead of falling back to *", async () => {
    behaviour = { kind: "throw", error: new Error("connection terminated unexpectedly") };
    const inv = await invoke({
      method: "OPTIONS",
      origin: "https://evil.example.com",
      tenantId: "t-throw-preflight",
    });

    expect(inv.status).toBe(403);
    expect(acao(inv)).toBeUndefined();
  });

  it("a thrown DB error denies a request from an origin that WOULD be allowed", async () => {
    // The critical case: a correctly-configured tenant during a database blip.
    // Pre-fix this returned `*` — strictly WEAKER than the tenant's own policy.
    // We cannot verify the origin is permitted, so we must not claim it is.
    behaviour = { kind: "throw", error: new Error("pool exhausted") };
    const inv = await invoke({
      method: "OPTIONS",
      origin: "https://app.stratareserve.co",
      tenantId: "t-throw-allowed-origin",
    });

    expect(inv.status).toBe(403);
    expect(acao(inv)).toBeUndefined();
  });

  it("a lookup failure is NOT cached — the next request retries", async () => {
    behaviour = { kind: "throw", error: new Error("transient") };
    await invoke({ method: "GET", origin: "https://x.example.com", tenantId: "t-no-neg-cache" });
    const afterFirst = selectCalls;

    behaviour = { kind: "origins", origins: ["https://x.example.com"] };
    const recovered = await invoke({
      method: "OPTIONS",
      origin: "https://x.example.com",
      tenantId: "t-no-neg-cache",
    });

    // A cached failure would pin the tenant into denial for the whole 60s TTL,
    // turning a blip into an outage.
    expect(selectCalls).toBeGreaterThan(afterFirst);
    expect(recovered.status).toBe(204);
    expect(acao(recovered)).toBe("https://x.example.com");
  });
});

describe("explicit allowlist behaviour is PRESERVED", () => {
  it("an approved origin is echoed back with Vary: Origin", async () => {
    behaviour = {
      kind: "origins",
      origins: ["https://app.stratareserve.co", "https://staging.stratareserve.co"],
    };
    const inv = await invoke({
      method: "OPTIONS",
      origin: "https://staging.stratareserve.co",
      tenantId: "t-allowed",
    });

    expect(inv.status).toBe(204);
    expect(acao(inv)).toBe("https://staging.stratareserve.co");
    // Selective allow is Origin-dependent; without Vary a shared cache could
    // serve one origin's allowed response to a different origin.
    expect(inv.headers.Vary).toBe("Origin");
  });

  it("an arbitrary origin is denied when the allowlist is populated", async () => {
    behaviour = { kind: "origins", origins: ["https://app.stratareserve.co"] };
    const inv = await invoke({
      method: "OPTIONS",
      origin: "https://evil.example.com",
      tenantId: "t-arbitrary",
    });

    expect(inv.status).toBe(403);
    expect(acao(inv)).toBeUndefined();
  });

  it("a tenant's EXPLICIT wildcard is still honoured", async () => {
    // Distinguishes a deliberate operator decision from the absence of one.
    // The defect was inferring "*" from absence and from errors, not honouring
    // it when actually configured.
    behaviour = { kind: "origins", origins: ["*"] };
    const inv = await invoke({
      method: "OPTIONS",
      origin: "https://anything.example.com",
      tenantId: "t-explicit-wildcard",
    });

    expect(inv.status).toBe(204);
    expect(acao(inv)).toBe("https://anything.example.com");
    expect(inv.headers.Vary).toBe("Origin");
  });
});

describe("CONTROLS: unchanged paths must stay unchanged", () => {
  it("no Origin header => permissive, and the config is never consulted", async () => {
    behaviour = { kind: "origins", origins: [] };
    const inv = await invoke({ method: "GET", tenantId: "t-no-origin" });

    // Server-to-server callers are not subject to same-origin policy.
    // Tightening here would break every non-browser integration for no gain.
    expect(acao(inv)).toBe("*");
    expect(selectCalls).toBe(0);
    expect(inv.nextCalled).toBe(true);
  });

  it("Origin but NO tenant header => permissive (documented narrow exception)", async () => {
    behaviour = { kind: "origins", origins: [] };
    const inv = await invoke({ method: "GET", origin: "https://dash.example.com" });

    // /health and the /user/me/tenants session routes are called without a
    // tenant header. With no tenant there is no allowlist to consult, so there
    // is nothing to fail closed against. Tracked separately; closing it needs a
    // platform-origin allowlist.
    expect(acao(inv)).toBe("*");
    expect(selectCalls).toBe(0);
  });

  it("wildcard responses do NOT set Vary: Origin", async () => {
    behaviour = { kind: "origins", origins: [] };
    const inv = await invoke({ method: "GET", origin: "https://dash.example.com" });
    expect(inv.headers.Vary).toBeUndefined();
  });

  it("allowed responses still advertise the full header/method contract", async () => {
    // Guards against a fail-closed change accidentally narrowing the working
    // path: a fix that breaks legitimate clients is not a fix.
    behaviour = { kind: "origins", origins: ["https://app.stratareserve.co"] };
    const inv = await invoke({
      method: "OPTIONS",
      origin: "https://app.stratareserve.co",
      tenantId: "t-contract",
    });

    expect(inv.headers["Access-Control-Allow-Methods"]).toContain("POST");
    expect(inv.headers["Access-Control-Allow-Headers"]).toContain("X-Steward-Tenant");
    expect(inv.headers["Access-Control-Allow-Headers"]).toContain("Authorization");
    expect(inv.headers["Access-Control-Expose-Headers"]).toContain("X-Request-Id");
    expect(inv.headers["Access-Control-Max-Age"]).toBe("86400");
  });
});
