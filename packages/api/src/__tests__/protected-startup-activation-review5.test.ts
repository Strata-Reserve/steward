/**
 * STRATA-1499 SF-1 — REVIEW-STEWARD-28-R5 F1: startup activation covers every
 * manifest key. Ported from the independent review5 startup probe.
 *
 * `manifestFromEnv` treats the protected-minter configuration as active when
 * ANY `STEWARD_PROTECTED_MINTER_*` variable is set. A partial configuration
 * (any single key, including APPROVERS) is then validated and fails startup.
 * Each probe loads the boundary module in a fresh subprocess with the
 * network-denying preload so the module-load side effect is observed exactly
 * as the API process would at boot.
 */

import { describe, expect, it } from "bun:test";

const uuid = "11111111-2222-4333-8444-555555555555";
const full = {
  STEWARD_PROTECTED_MINTER_TENANT: "strata",
  STEWARD_PROTECTED_MINTER_AGENT: "review5-startup",
  STEWARD_PROTECTED_MINTER_ADDRESS: "0x1111111111111111111111111111111111111111",
  STEWARD_PROTECTED_MINTER_FACTORIES: "0x00000000000000000000000000000000000f0001",
  STEWARD_PROTECTED_MINTER_TOKENS: "0x0000000000000000000000000000000000700001@verified",
};
const ALL_KEYS = [...Object.keys(full), "STEWARD_PROTECTED_MINTER_APPROVERS"];

function load(extra: Record<string, string>) {
  const env: Record<string, string | undefined> = { ...process.env };
  for (const k of Object.keys(env)) if (k.startsWith("STEWARD_PROTECTED_MINTER_")) delete env[k];
  Object.assign(env, {
    STEWARD_PGLITE_MEMORY: "true",
    DATABASE_URL: "postgres://test:test@localhost:5432/steward",
    ...extra,
  });
  const child = Bun.spawnSync(
    [
      process.execPath,
      "--preload",
      "./scripts/test-no-network-preload.ts",
      "--eval",
      'const b=await import("./packages/api/src/services/prod-minter-boundary"); console.log("MODULE_LOADED",JSON.stringify(b.getProtectedMinterManifest()));',
    ],
    { cwd: process.cwd(), env, stdout: "pipe", stderr: "pipe", timeout: 60_000 },
  );
  return { exit: child.exitCode, out: child.stdout.toString(), err: child.stderr.toString() };
}

describe("SF-1 startup activation (R5-F1)", () => {
  it("[F1] no protected config => module loads with no manifest", () => {
    const r = load({});
    expect(r.exit).toBe(0);
    expect(r.out).toContain("MODULE_LOADED null");
  });

  it("[F1] full manifest with unset/empty approvers loads; malformed approvers are fatal", () => {
    for (const list of [undefined, ""]) {
      const r = load({
        ...full,
        ...(list === undefined ? {} : { STEWARD_PROTECTED_MINTER_APPROVERS: list }),
      });
      expect(r.exit).toBe(0);
      expect(r.out).toContain('"approvers":[]');
    }
    for (const list of ["not-a-uuid", "reviewer@example.test", `${uuid},${uuid.toUpperCase()}`]) {
      const r = load({ ...full, STEWARD_PROTECTED_MINTER_APPROVERS: list });
      expect(r.exit).not.toBe(0);
      expect(r.out).not.toContain("MODULE_LOADED");
      expect(r.err).toContain("approver");
    }
  });

  it("[F1] APPROVERS set alone (valid UUID, email, non-UUID, duplicate) refuses startup", () => {
    for (const list of [uuid, "reviewer@example.test", "not-a-uuid", `${uuid},${uuid}`]) {
      const r = load({ STEWARD_PROTECTED_MINTER_APPROVERS: list });
      expect(r.exit).not.toBe(0);
      expect(r.out).not.toContain("MODULE_LOADED");
      expect(r.err).toContain("protected minter");
    }
  });

  it("[F1] any single protected-minter key set alone refuses startup", () => {
    const single: Record<string, string> = {
      ...full,
      STEWARD_PROTECTED_MINTER_APPROVERS: uuid,
    };
    for (const key of ALL_KEYS) {
      const r = load({ [key]: single[key]! });
      expect({ key, exit: r.exit }).not.toEqual({ key, exit: 0 });
      expect(r.out).not.toContain("MODULE_LOADED");
      expect(r.err).toContain("protected minter");
    }
  });
});
