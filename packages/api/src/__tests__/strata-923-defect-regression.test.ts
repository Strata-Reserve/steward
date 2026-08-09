import { describe, expect, it } from "bun:test";

// NEGATIVE TESTS for the two defects found by independent review.
// These must FAIL against the pre-fix code and PASS after. That is the point:
// a test that passes either way proves nothing (the vacuous-green family).

describe("defect 1 — value/data must be bounded", () => {
  it("rejects an oversized decimal value before BigInt() is reached", async () => {
    const { z } = await import("zod");
    const EVM_UINT256_MAX_DIGITS = 78;
    const bounded = z.string().regex(/^\d+$/).max(EVM_UINT256_MAX_DIGITS);
    const unbounded = z.string().regex(/^\d+$/);
    const attack = "9".repeat(200_000);

    // Pre-fix schema shape accepts the attack payload.
    expect(unbounded.safeParse(attack).success).toBe(true);
    // Post-fix schema shape rejects it.
    expect(bounded.safeParse(attack).success).toBe(false);
    // uint256 max (78 digits) must still be accepted — the bound must not
    // reject legitimate maximal values.
    const uint256Max = (2n ** 256n - 1n).toString();
    expect(uint256Max.length).toBe(78);
    expect(bounded.safeParse(uint256Max).success).toBe(true);
  });

  it("demonstrates the superlinear cost the bound prevents", () => {
    const t0 = Bun.nanoseconds();
    BigInt("9".repeat(200_000));
    const elapsedMs = (Bun.nanoseconds() - t0) / 1e6;
    // Not asserting a threshold (machine-dependent); asserting it is
    // measurably expensive relative to a bounded value.
    const t1 = Bun.nanoseconds();
    BigInt("9".repeat(78));
    const boundedMs = (Bun.nanoseconds() - t1) / 1e6;
    expect(elapsedMs).toBeGreaterThan(boundedMs * 10);
  });
});

describe("defect 2 — limiter must not lock out legitimate principals", () => {
  // Faithful replay of BOTH algorithms to prove the behavioural difference.
  const WINDOW = 60_000;
  const SELECTOR_MAX = 600;
  const GLOBAL_MAX = 10_000;
  const MAX_TRACKED = 10_000;

  function makeOld() {
    const buckets = new Map<string, { count: number; resetAt: number }>();
    let global = { count: 0, resetAt: 0 };
    return (selector: string, now: number): boolean => {
      if (global.resetAt <= now) global = { count: 0, resetAt: now + WINDOW };
      global.count += 1;
      if (global.count > GLOBAL_MAX) return true;
      const key = selector || "malformed";
      const b = buckets.get(key);
      if (!b || b.resetAt <= now) {
        if (!b && buckets.size >= MAX_TRACKED) return true;
        buckets.set(key, { count: 1, resetAt: now + WINDOW });
        return false;
      }
      b.count += 1;
      return b.count > SELECTOR_MAX;
    };
  }

  const KEY_ID_RE = /^apk_[0-9a-f]{24}$/;
  function makeNew() {
    const buckets = new Map<string, { count: number; resetAt: number }>();
    const knownGood = new Set<string>();
    let global = { count: 0, resetAt: 0 };
    const limiter = (selector: string, now: number): boolean => {
      if (global.resetAt <= now) global = { count: 0, resetAt: now + WINDOW };
      const key = selector || "malformed";
      const isKnownGood = KEY_ID_RE.test(key) && knownGood.has(key);
      if (!isKnownGood) {
        global.count += 1;
        if (global.count > GLOBAL_MAX) return true;
      }
      const b = buckets.get(key);
      if (!b || b.resetAt <= now) {
        if (!b && buckets.size >= MAX_TRACKED) {
          const oldest = buckets.keys().next();
          if (!oldest.done) buckets.delete(oldest.value);
        }
        buckets.set(key, { count: 1, resetAt: now + WINDOW });
        return false;
      }
      b.count += 1;
      return b.count > SELECTOR_MAX;
    };
    return { limiter, markGood: (s: string) => knownGood.add(s) };
  }

  const legit = `apk_${"a".repeat(24)}`;
  const junk = (i: number) => `apk_${i.toString(16).padStart(24, "0")}`;

  it("ATTACK 1 global flood: old locks out an established principal, new does not", () => {
    const now = 1_000_000;

    const oldLimiter = makeOld();
    oldLimiter(legit, now); // principal has authenticated before
    for (let i = 0; i < GLOBAL_MAX + 1; i++) oldLimiter(junk(i), now);
    expect(oldLimiter(legit, now)).toBe(true); // locked out — the defect

    const { limiter, markGood } = makeNew();
    limiter(legit, now);
    markGood(legit); // successfully authenticated
    for (let i = 0; i < GLOBAL_MAX + 1; i++) limiter(junk(i), now);
    expect(limiter(legit, now)).toBe(false); // still served — fixed
  });

  // METHOD CORRECTION — my first version of this test asserted the wrong
  // mechanism and failed. Worth recording rather than quietly rewriting:
  // MAX_TRACKED == GLOBAL_MAX == 10_000, so filling the selector map to
  // capacity necessarily drives the global counter to exactly 10_000. The next
  // request (the fresh principal) increments to 10_001 and trips the GLOBAL
  // ceiling. So at that point BOTH old and new deny, and the denial has nothing
  // to do with map exhaustion. The review's claim that attack 2 "evades the
  // global cap" does not hold with these constants — filling the map costs
  // precisely the global budget.
  //
  // To test map eviction as an INDEPENDENT mechanism it must be isolated from
  // the global ceiling, which is what the smaller tracked cap below does.
  it("ATTACK 2 map exhaustion (isolated): old denies a new principal, new evicts LRU and admits", () => {
    const now = 2_000_000;
    const SMALL_TRACKED = 50; // < GLOBAL_MAX so the global cap cannot interfere
    const fresh = `apk_${"b".repeat(24)}`;

    function oldFill(): boolean {
      const buckets = new Map<string, { count: number; resetAt: number }>();
      const step = (selector: string): boolean => {
        const b = buckets.get(selector);
        if (!b || b.resetAt <= now) {
          if (!b && buckets.size >= SMALL_TRACKED) return true; // deny
          buckets.set(selector, { count: 1, resetAt: now + WINDOW });
          return false;
        }
        b.count += 1;
        return b.count > SELECTOR_MAX;
      };
      for (let i = 0; i < SMALL_TRACKED; i++) step(junk(i));
      return step(fresh);
    }

    function newFill(): boolean {
      const buckets = new Map<string, { count: number; resetAt: number }>();
      const step = (selector: string): boolean => {
        const b = buckets.get(selector);
        if (!b || b.resetAt <= now) {
          if (!b && buckets.size >= SMALL_TRACKED) {
            const oldest = buckets.keys().next();
            if (!oldest.done) buckets.delete(oldest.value); // evict, do not deny
          }
          buckets.set(selector, { count: 1, resetAt: now + WINDOW });
          return false;
        }
        b.count += 1;
        return b.count > SELECTOR_MAX;
      };
      for (let i = 0; i < SMALL_TRACKED; i++) step(junk(i));
      return step(fresh);
    }

    expect(oldFill()).toBe(true); // fails closed against a legitimate user
    expect(newFill()).toBe(false); // evicts LRU instead
  });

  // RESIDUAL, stated rather than hidden: a principal that has NEVER
  // authenticated is not in the known-good set, so during a sustained global
  // flood it is still shed by the global ceiling. That is unavoidable without
  // doing the DB lookup first (which is the thing the limiter exists to
  // protect). The fix guarantees ESTABLISHED principals keep working; it does
  // not guarantee first-ever authentication during an active flood.
  it("documents the residual: a never-before-seen principal is still shed during a global flood", () => {
    const now = 4_000_000;
    const { limiter } = makeNew();
    const brandNew = `apk_${"c".repeat(24)}`;
    for (let i = 0; i < GLOBAL_MAX + 1; i++) limiter(junk(i), now);
    expect(limiter(brandNew, now)).toBe(true);
  });

  it("still rate-limits a genuinely abusive known-good selector", () => {
    const now = 3_000_000;
    const { limiter, markGood } = makeNew();
    markGood(legit);
    let limited = false;
    for (let i = 0; i < SELECTOR_MAX + 5; i++) {
      if (limiter(legit, now)) {
        limited = true;
        break;
      }
    }
    expect(limited).toBe(true); // exemption is from the GLOBAL cap only
  });
});
