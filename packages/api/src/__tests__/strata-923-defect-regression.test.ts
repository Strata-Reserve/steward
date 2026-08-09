import { beforeAll, beforeEach, describe, expect, it } from "bun:test";
import type { z as Zod } from "zod";

// The route module transitively imports `services/context`, which throws at
// module-evaluation time unless the runtime env is present. Set it BEFORE the
// dynamic import, exactly as the boundary suite does.
process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.DATABASE_URL ??= "postgres://test:test@localhost:5432/steward";
process.env.STEWARD_MASTER_PASSWORD ??= "strata-923-regression-master-password-value";
process.env.STEWARD_AUDIT_HMAC_KEY ??= "strata-923-regression-audit-hmac-key-minimum";

let __resetApplicationAuthRateLimiterForTests: () => void;
let applicationAuthRateLimited: (selector: string, nowMs?: number) => boolean;
let clearApplicationSelectorKnownGood: (selector: string) => void;
let markApplicationSelectorKnownGood: (selector: string) => void;
let prepareApplicationTransactionSchema: Zod.ZodTypeAny;

beforeAll(async () => {
  const mw = await import("../middleware/application-principal");
  __resetApplicationAuthRateLimiterForTests = mw.__resetApplicationAuthRateLimiterForTests;
  applicationAuthRateLimited = mw.applicationAuthRateLimited;
  clearApplicationSelectorKnownGood = mw.clearApplicationSelectorKnownGood;
  markApplicationSelectorKnownGood = mw.markApplicationSelectorKnownGood;
  ({ prepareApplicationTransactionSchema } = await import("../routes/application"));
});

/**
 * Regression tests for the defects found by independent security review of the
 * STRATA-923 application-principal boundary, AND for the defects a delta review
 * then found in the first remediation.
 *
 * THESE BIND TO THE REAL EXPORTED CODE. The first version of this suite tested
 * private re-implementations of the limiter and the schema. That was worthless:
 * a delta review showed reverting both source files left every test green, and
 * the suite failed to notice when I later rewrote the limiter's ceiling model
 * outright. Faithful-but-unbound is a subtler form of the vacuously-green
 * defect family this codebase keeps producing. Import the real symbols or the
 * test proves nothing.
 *
 * `applicationAuthRateLimited` takes an optional `nowMs` so windows are
 * controlled deterministically instead of by wall clock.
 */

const KEY = (c: string) => `apk_${c.repeat(24)}`;
const LEGIT = KEY("a");
const FRESH = KEY("b");
const junk = (i: number) => `apk_${i.toString(16).padStart(24, "0")}`;

const WINDOW_MS = 60_000;
const SELECTOR_MAX = 600;
const GLOBAL_MAX = 10_000;
const MAX_TRACKED = 10_000;

beforeEach(() => {
  __resetApplicationAuthRateLimiterForTests();
});

describe("defect 1 — EVM value/data must be bounded (authenticated CPU DoS)", () => {
  const valid = {
    walletId: "aw_1",
    network: { type: "evm" as const, chainId: 84532 },
    transaction: { to: `0x${"a".repeat(40)}`, value: "1000000" },
  };

  it("rejects an oversized decimal value, so BigInt() is never reached", () => {
    const attack = { ...valid, transaction: { ...valid.transaction, value: "9".repeat(200_000) } };
    expect(prepareApplicationTransactionSchema.safeParse(attack).success).toBe(false);
  });

  it("still accepts uint256 max (78 digits) — the bound must not reject legitimate values", () => {
    const uint256Max = (2n ** 256n - 1n).toString();
    expect(uint256Max.length).toBe(78);
    const ok = { ...valid, transaction: { ...valid.transaction, value: uint256Max } };
    expect(prepareApplicationTransactionSchema.safeParse(ok).success).toBe(true);
  });

  it("rejects 79 digits — the boundary is exactly at uint256 max", () => {
    const over = { ...valid, transaction: { ...valid.transaction, value: "9".repeat(79) } };
    expect(prepareApplicationTransactionSchema.safeParse(over).success).toBe(false);
  });

  it("bounds calldata too", () => {
    const big = {
      ...valid,
      transaction: { ...valid.transaction, data: `0x${"ab".repeat(200_000)}` },
    };
    expect(prepareApplicationTransactionSchema.safeParse(big).success).toBe(false);
  });
});

describe("defect 2 — a junk flood must not lock out an established principal", () => {
  it("serves a known-good principal after the unknown-selector ceiling is exhausted", () => {
    const now = 1_000_000;
    expect(applicationAuthRateLimited(LEGIT, now)).toBe(false);
    markApplicationSelectorKnownGood(LEGIT);

    for (let i = 0; i < GLOBAL_MAX + 1; i++) applicationAuthRateLimited(junk(i), now);

    // The unknown budget is spent; the known-good budget is independent.
    expect(applicationAuthRateLimited(junk(999_999), now)).toBe(true);
    expect(applicationAuthRateLimited(LEGIT, now)).toBe(false);
  });

  it("admits a brand-new principal when the tracked-selector map is full", () => {
    const now = 2_000_000;
    for (let i = 0; i < MAX_TRACKED; i++) applicationAuthRateLimited(junk(i), now);
    markApplicationSelectorKnownGood(FRESH);
    // Known-good draws on its own ceiling, so map fullness alone must not deny.
    expect(applicationAuthRateLimited(FRESH, now)).toBe(false);
  });
});

describe("defect 2 must not become a resource-exhaustion hole (delta-review finding)", () => {
  it("known-good traffic is PRIORITISED but still bounded — not exempt", () => {
    const now = 3_000_000;
    // Spread across many known-good selectors so the per-selector cap is not
    // what stops us; only the known-good AGGREGATE ceiling can.
    let denied = false;
    outer: for (let s = 0; s < 200; s++) {
      const sel = junk(500_000 + s);
      markApplicationSelectorKnownGood(sel);
      for (let i = 0; i < SELECTOR_MAX; i++) {
        if (applicationAuthRateLimited(sel, now)) {
          denied = true;
          break outer;
        }
      }
    }
    expect(denied).toBe(true);
  });

  it("still rate-limits a single abusive known-good selector", () => {
    const now = 4_000_000;
    markApplicationSelectorKnownGood(LEGIT);
    let limited = false;
    for (let i = 0; i < SELECTOR_MAX + 5; i++) {
      if (applicationAuthRateLimited(LEGIT, now)) {
        limited = true;
        break;
      }
    }
    expect(limited).toBe(true);
  });

  it("a revoked/rotated selector loses known-good standing", () => {
    const now = 5_000_000;
    markApplicationSelectorKnownGood(LEGIT);
    clearApplicationSelectorKnownGood(LEGIT);
    // Now charged to the unknown ceiling: exhaust it and LEGIT is shed too.
    for (let i = 0; i < GLOBAL_MAX + 1; i++) applicationAuthRateLimited(junk(i), now);
    expect(applicationAuthRateLimited(LEGIT, now)).toBe(true);
  });
});

describe("defect 3 (delta review) — per-selector cap must not be resettable by forcing eviction", () => {
  it("a live bucket is never evicted, so the 600/min cap holds across a map cycle", () => {
    const w1 = 10_000_000;
    // Window 1: insert junk LATE so those buckets carry resetAt into window 2.
    for (let i = 0; i < MAX_TRACKED; i++) applicationAuthRateLimited(junk(i), w1);

    // Window 2 begins before those buckets expire.
    const w2 = w1 + WINDOW_MS - 1;
    markApplicationSelectorKnownGood(LEGIT);
    let served = 0;
    while (!applicationAuthRateLimited(LEGIT, w2)) served += 1;
    expect(served).toBe(SELECTOR_MAX);

    // Try to cycle LEGIT out of the map with fresh selectors, then return.
    for (let i = 0; i < MAX_TRACKED + 100; i++) {
      applicationAuthRateLimited(junk(700_000 + i), w2);
    }
    // If eviction had discarded LEGIT's LIVE bucket, this would be false (a
    // fresh count). It must stay limited for the remainder of the window.
    expect(applicationAuthRateLimited(LEGIT, w2)).toBe(true);
  });

  it("the cap does reset once the window genuinely elapses", () => {
    const t = 20_000_000;
    markApplicationSelectorKnownGood(LEGIT);
    while (!applicationAuthRateLimited(LEGIT, t)) {
      /* burn the budget */
    }
    expect(applicationAuthRateLimited(LEGIT, t + WINDOW_MS + 1)).toBe(false);
  });
});
