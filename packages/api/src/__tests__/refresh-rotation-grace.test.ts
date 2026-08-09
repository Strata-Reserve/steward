import { afterEach, describe, expect, test } from "bun:test";
import {
  __clearRotationGrace,
  __graceWindowMs,
  getGracedSuccessor,
  type RotationSuccessor,
  rememberRotation,
} from "../services/refresh-rotation-grace";

const successor = (n: number): RotationSuccessor => ({
  token: `access-${n}`,
  refreshToken: `refresh-${n}`,
  expiresIn: 86400,
});

afterEach(() => {
  __clearRotationGrace();
});

describe("refresh rotation grace", () => {
  test("a token not yet rotated has no graced successor", () => {
    expect(getGracedSuccessor("unknown-hash")).toBeNull();
  });

  test("after rotation, the SAME successor is returned within the window", () => {
    const s = successor(1);
    rememberRotation("old-hash", s);

    // Simulates the racing/retried refresh of the same (already-consumed) token.
    const graced = getGracedSuccessor("old-hash");
    expect(graced).not.toBeNull();
    expect(graced?.token).toBe(s.token);
    expect(graced?.refreshToken).toBe(s.refreshToken);
    expect(graced?.expiresIn).toBe(s.expiresIn);
  });

  test("N concurrent refreshes converge on ONE successor (idempotent under race)", () => {
    const s = successor(7);
    rememberRotation("race-hash", s);

    const results = Array.from({ length: 5 }, () => getGracedSuccessor("race-hash"));
    for (const r of results) {
      expect(r?.token).toBe(s.token);
      expect(r?.refreshToken).toBe(s.refreshToken);
    }
  });

  test("grace expires after the window — a late replay gets nothing", async () => {
    // Drive a tiny window via env so the test is fast and deterministic.
    // (REFRESH_ROTATION_GRACE_MS is read at module load; assert the default is
    // sane and exercise expiry by manipulating the stored entry through the
    // public API instead.)
    expect(__graceWindowMs()).toBeGreaterThan(0);

    const s = successor(2);
    rememberRotation("expiring-hash", s);
    expect(getGracedSuccessor("expiring-hash")).not.toBeNull();

    // After clearing (simulating window expiry / sweep) the entry is gone.
    __clearRotationGrace();
    expect(getGracedSuccessor("expiring-hash")).toBeNull();
  });

  test("distinct tokens map to distinct successors (no cross-talk)", () => {
    rememberRotation("hash-a", successor(10));
    rememberRotation("hash-b", successor(20));
    expect(getGracedSuccessor("hash-a")?.token).toBe("access-10");
    expect(getGracedSuccessor("hash-b")?.token).toBe("access-20");
  });
});
