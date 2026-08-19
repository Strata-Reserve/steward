import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { isPersistedPolicyType, policyTypeEnum } from "../index";

const migration = readFileSync(
  fileURLToPath(new URL("../../drizzle/0091_manual_approval_policy.sql", import.meta.url)),
  "utf8",
);
const journal = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../drizzle/meta/_journal.json", import.meta.url)), "utf8"),
) as { entries: Array<{ idx: number; tag: string }> };

describe("STRATA-1097 manual-approval policy persistence", () => {
  test("schema vocabulary and runtime persisted-type guard include the primitive", () => {
    expect(policyTypeEnum.enumValues).toContain("manual-approval");
    expect(isPersistedPolicyType("manual-approval")).toBe(true);
  });

  test("migration is additive/idempotent and journaled at the next monotonic index", () => {
    expect(migration).toContain("ALTER TYPE");
    expect(migration).toContain("ADD VALUE IF NOT EXISTS 'manual-approval'");
    expect(journal.entries.at(-1)).toMatchObject({
      idx: 91,
      tag: "0091_manual_approval_policy",
    });
  });
});
