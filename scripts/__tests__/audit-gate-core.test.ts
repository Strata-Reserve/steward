/**
 * STRATA-926 — adversarial tests for the dependency-audit exception gate.
 *
 * These tests exist because a gate that has only ever been observed PASSING is
 * unproven. Each case below is an attack the reviewer was asked to attempt:
 * every one must BLOCK, and the assertions bind to the specific reason, not
 * merely to `ok === false` (a test that only checks `ok` would still pass if
 * the gate blocked for an unrelated reason).
 */
import { describe, expect, it } from "bun:test";
import type { AuditException } from "../security/audit-exceptions.ts";
import { AUDIT_EXCEPTIONS } from "../security/audit-exceptions.ts";
import { evaluate, type Finding } from "../security/audit-gate-core.ts";

/** A fixed "now" so expiry tests never depend on the wall clock. */
const NOW = new Date("2026-08-11T00:00:00Z");

const VALID_PROSE = `## Known accepted CVEs

| Package | CVE / advisory | Disposition | Class | Owner | Accepted | Review by |
|---|---|---|---|---|---|---|
| \`demo-pkg\` (<=1.0.0) | GHSA-aaaa-bbbb-cccc — demo | \`accepted_absent_from_production_closure\` | A | JJ Joseph | 2026-08-11 | 2026-11-11 |

#### \`demo-pkg\` — CLASS A
- Absent from the production closure.
`;

function baseException(overrides: Partial<AuditException> = {}): AuditException {
  return {
    package: "demo-pkg",
    advisories: ["GHSA-aaaa-bbbb-cccc"],
    authorizesSeverity: ["high"],
    reachabilityClass: "A",
    disposition: "accepted_absent_from_production_closure",
    qualifiers: [],
    owner: "JJ Joseph",
    rationale:
      "Demo rationale long enough to satisfy the minimum-length requirement for a real justification.",
    entryPath: "workspace demo -> demo-pkg",
    acceptedOn: "2026-08-01",
    reviewBy: "2026-11-11",
    reconsiderIf: ["a fixed release appears"],
    expectedAbsentFromAudit: false,
    ...overrides,
  };
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    package: "demo-pkg",
    advisoryId: "GHSA-aaaa-bbbb-cccc",
    severity: "high",
    title: "demo advisory",
    vulnerableVersions: "<=1.0.0",
    ...overrides,
  };
}

/** Assert the verdict blocked AND that some message matches `reason`. */
function expectBlockedBecause(verdict: ReturnType<typeof evaluate>, reason: RegExp): void {
  expect(verdict.ok).toBe(false);
  const all = [
    ...verdict.problems,
    ...verdict.unallowlisted.map((f) => `unallowlisted ${f.package} ${f.advisoryId}`),
  ];
  expect(all.some((m) => reason.test(m))).toBe(true);
}

describe("baseline: a well-formed exception passes", () => {
  it("accepts a high finding with a complete, active exception", () => {
    const v = evaluate([finding()], [baseException()], VALID_PROSE, NOW);
    expect(v.ok).toBe(true);
    expect(v.accepted).toHaveLength(1);
    expect(v.unallowlisted).toHaveLength(0);
    expect(v.problems).toEqual([]);
  });
});

describe("attack: advisory-ID mismatch", () => {
  it("BLOCKS a different advisory in a package that has an accepted one", () => {
    // The package is allowlisted; this specific GHSA is not.
    const v = evaluate(
      [finding({ advisoryId: "GHSA-zzzz-yyyy-xxxx" })],
      [baseException()],
      VALID_PROSE,
      NOW,
    );
    expectBlockedBecause(v, /unallowlisted demo-pkg GHSA-zzzz-yyyy-xxxx/);
    expect(v.accepted).toHaveLength(0);
  });

  it("BLOCKS when the exception's advisory is not what the audit reports", () => {
    const v = evaluate(
      [finding({ advisoryId: "GHSA-1111-2222-3333" })],
      [baseException({ advisories: ["GHSA-aaaa-bbbb-cccc"] })],
      VALID_PROSE,
      NOW,
    );
    // Blocks twice over: the finding is unallowlisted AND the registry entry is stale.
    expect(v.ok).toBe(false);
    expect(v.unallowlisted).toHaveLength(1);
    expectBlockedBecause(v, /no longer reports/);
  });
});

describe("attack: stale / expired exception", () => {
  it("BLOCKS an exception whose reviewBy is in the past", () => {
    const v = evaluate([finding()], [baseException({ reviewBy: "2026-08-10" })], VALID_PROSE, NOW);
    expectBlockedBecause(v, /EXPIRED — review was due 2026-08-10/);
  });

  it("BLOCKS on the day AFTER expiry, and passes on the expiry day itself", () => {
    const expiring = baseException({ reviewBy: "2026-08-11" });
    expect(evaluate([finding()], [expiring], VALID_PROSE, NOW).ok).toBe(true);
    const dayAfter = new Date("2026-08-12T00:00:00Z");
    expectBlockedBecause(evaluate([finding()], [expiring], VALID_PROSE, dayAfter), /EXPIRED/);
  });

  it("BLOCKS a reviewBy that precedes acceptedOn", () => {
    const v = evaluate(
      [finding()],
      [baseException({ acceptedOn: "2026-08-01", reviewBy: "2026-07-01" })],
      VALID_PROSE,
      NOW,
    );
    expectBlockedBecause(v, /reviewBy must be after acceptedOn/);
  });
});

describe("attack: new unallowlisted high", () => {
  it("BLOCKS a high in a package with no exception at all", () => {
    const v = evaluate(
      [finding({ package: "brand-new-pkg", advisoryId: "GHSA-9999-8888-7777" })],
      [baseException()],
      VALID_PROSE,
      NOW,
    );
    // Also flags the now-unreferenced demo-pkg entry as stale — both are correct.
    expect(v.unallowlisted.map((f) => f.package)).toEqual(["brand-new-pkg"]);
    expect(v.ok).toBe(false);
  });
});

describe("attack: new CRITICAL sharing a package with an allowed HIGH", () => {
  it("BLOCKS a critical on the SAME advisory as an accepted high", () => {
    // The exception authorizes ["high"] only. Severity escalating to critical
    // must not ride along on it.
    const v = evaluate([finding({ severity: "critical" })], [baseException()], VALID_PROSE, NOW);
    expectBlockedBecause(v, /CRITICAL .* authorizes only \[high\]/);
    expect(v.accepted).toHaveLength(0);
  });

  it("BLOCKS a critical on a DIFFERENT advisory in the same package", () => {
    const v = evaluate(
      [finding({ advisoryId: "GHSA-crit-crit-crit", severity: "critical" })],
      [baseException()],
      VALID_PROSE,
      NOW,
    );
    expect(v.ok).toBe(false);
    expect(v.accepted).toHaveLength(0);
  });

  it("BLOCKS a critical-scoped exception that lacks criticalApproval", () => {
    const v = evaluate(
      [finding({ severity: "critical" })],
      [baseException({ authorizesSeverity: ["high", "critical"] })],
      VALID_PROSE,
      NOW,
    );
    expectBlockedBecause(v, /authorizes CRITICAL but has no complete criticalApproval/);
  });

  it("BLOCKS an incomplete criticalApproval (missing justification)", () => {
    const v = evaluate(
      [finding({ severity: "critical" })],
      [
        baseException({
          authorizesSeverity: ["high", "critical"],
          criticalApproval: {
            approvedBy: "JJ Joseph",
            approvedOn: "2026-08-11",
            justification: "",
          },
        }),
      ],
      VALID_PROSE,
      NOW,
    );
    expectBlockedBecause(v, /no complete criticalApproval/);
  });

  it("ALLOWS a critical only with a complete, explicit critical approval", () => {
    const v = evaluate(
      [finding({ severity: "critical" })],
      [
        baseException({
          authorizesSeverity: ["high", "critical"],
          criticalApproval: {
            approvedBy: "JJ Joseph",
            approvedOn: "2026-08-11",
            justification: "Explicitly reviewed and accepted for this specific critical advisory.",
          },
        }),
      ],
      VALID_PROSE,
      NOW,
    );
    expect(v.ok).toBe(true);
    expect(v.accepted).toHaveLength(1);
  });

  it("BLOCKS a criticalApproval attached without listing critical (ambiguous intent)", () => {
    const v = evaluate(
      [finding()],
      [
        baseException({
          criticalApproval: {
            approvedBy: "JJ Joseph",
            approvedOn: "2026-08-11",
            justification: "dangling approval",
          },
        }),
      ],
      VALID_PROSE,
      NOW,
    );
    expectBlockedBecause(v, /does not list "critical" in authorizesSeverity/);
  });
});

describe("attack: exception for a package that disappears", () => {
  it("BLOCKS a registry entry the audit no longer reports", () => {
    const v = evaluate([], [baseException()], VALID_PROSE, NOW);
    expectBlockedBecause(v, /references GHSA-aaaa-bbbb-cccc, which the audit no longer reports/);
  });

  it("reports it as REMEDIATED when explicitly marked for cleanup", () => {
    const v = evaluate([], [baseException({ expectedAbsentFromAudit: true })], VALID_PROSE, NOW);
    expect(v.ok).toBe(true);
    expect(v.remediated).toEqual([{ package: "demo-pkg", advisoryId: "GHSA-aaaa-bbbb-cccc" }]);
  });

  it("BLOCKS a cleanup-marked entry that the audit STILL reports", () => {
    // Guards the inverse mistake: marking something cleaned up while it is live.
    const v = evaluate(
      [finding()],
      [baseException({ expectedAbsentFromAudit: true })],
      VALID_PROSE,
      NOW,
    );
    expectBlockedBecause(v, /marked `expectedAbsentFromAudit`.*but the audit STILL reports it/s);
  });
});

describe("attack: missing evidence fields", () => {
  it("BLOCKS an exception with no owner", () => {
    expectBlockedBecause(
      evaluate([finding()], [baseException({ owner: "" })], VALID_PROSE, NOW),
      /owner is missing or a placeholder/,
    );
  });

  it("BLOCKS placeholder owners", () => {
    for (const owner of ["TBD", "unknown", "team", "n/a"]) {
      expectBlockedBecause(
        evaluate([finding()], [baseException({ owner })], VALID_PROSE, NOW),
        /owner is missing or a placeholder/,
      );
    }
  });

  it("BLOCKS an exception with no rationale", () => {
    expectBlockedBecause(
      evaluate([finding()], [baseException({ rationale: "" })], VALID_PROSE, NOW),
      /rationale is missing or too short/,
    );
  });

  it("BLOCKS a trivially short rationale", () => {
    expectBlockedBecause(
      evaluate([finding()], [baseException({ rationale: "not exploitable" })], VALID_PROSE, NOW),
      /rationale is missing or too short/,
    );
  });

  it("BLOCKS an exception with no re-review triggers", () => {
    expectBlockedBecause(
      evaluate([finding()], [baseException({ reconsiderIf: [] })], VALID_PROSE, NOW),
      /at least one condition mandating re-review/,
    );
  });

  it("BLOCKS a malformed advisory identifier", () => {
    expectBlockedBecause(
      evaluate(
        [finding({ advisoryId: "just-trust-me" })],
        [baseException({ advisories: ["just-trust-me"] })],
        VALID_PROSE,
        NOW,
      ),
      /not a well-formed GHSA or CVE identifier/,
    );
  });

  it("BLOCKS a class/disposition mismatch", () => {
    expectBlockedBecause(
      evaluate(
        [finding()],
        [
          baseException({
            reachabilityClass: "B",
            disposition: "accepted_absent_from_production_closure",
          }),
        ],
        VALID_PROSE,
        NOW,
      ),
      /CLASS B must use disposition/,
    );
  });
});

describe("attack: bypass by editing only the Markdown", () => {
  it("BLOCKS prose that documents an advisory with no registry entry", () => {
    const proseWithSmuggledCve = `${VALID_PROSE}
| \`sneaky\` | GHSA-dead-beef-cafe — smuggled in via prose | accepted | A | JJ | 2026-08-11 | 2026-11-11 |
`;
    const v = evaluate([finding()], [baseException()], proseWithSmuggledCve, NOW);
    expectBlockedBecause(
      v,
      /GHSA-dead-beef-cafe.*no entry in scripts\/security\/audit-exceptions/s,
    );
  });

  it("does NOT let prose alone authorize a live finding", () => {
    // The finding is real; only the Markdown mentions it. Registry is empty.
    const prose = `## Known accepted CVEs

| Package | CVE / advisory | Disposition | Class | Owner | Accepted | Review by |
|---|---|---|---|---|---|---|
| \`demo-pkg\` | GHSA-aaaa-bbbb-cccc — totally fine, promise | accepted | A | JJ | 2026-08-11 | 2026-11-11 |
`;
    const v = evaluate([finding()], [], prose, NOW);
    expect(v.ok).toBe(false);
    expect(v.unallowlisted).toHaveLength(1);
  });

  it("BLOCKS a registry entry with no matching prose", () => {
    const v = evaluate(
      [finding()],
      [baseException()],
      "## Known accepted CVEs\n\nnothing here.\n",
      NOW,
    );
    expectBlockedBecause(v, /threat model does not document advisory GHSA-aaaa-bbbb-cccc/);
  });

  it("BLOCKS when the threat model is missing entirely", () => {
    expectBlockedBecause(
      evaluate([finding()], [baseException()], null, NOW),
      /threat model not found/,
    );
  });

  it("BLOCKS when the accepted-CVE section is absent", () => {
    expectBlockedBecause(
      evaluate([finding()], [baseException()], "# Some doc\n\nno such section\n", NOW),
      /no `## Known accepted CVEs` section/,
    );
  });
});

describe("attack: image-size silently reverted to ABSENT / CLASS A", () => {
  const imageSizeException = baseException({
    package: "image-size",
    advisories: ["GHSA-w3rx-r6r6-pgpr"],
    reachabilityClass: "B",
    disposition: "accepted_present_but_not_imported_by_runtime",
    qualifiers: ["no_fix_available"],
    rationale:
      "Present in the production closure; accepted on non-reachability by runtime import, not absence.",
  });
  const imageSizeFinding = finding({
    package: "image-size",
    advisoryId: "GHSA-w3rx-r6r6-pgpr",
  });

  const classBProse = `## Known accepted CVEs

| Package | CVE / advisory | Disposition | Class | Owner | Accepted | Review by |
|---|---|---|---|---|---|---|
| \`image-size\` (<=2.0.2) | GHSA-w3rx-r6r6-pgpr — DoS | \`accepted_present_but_not_imported_by_runtime\` | **B** | JJ Joseph | 2026-08-11 | 2026-09-11 |

#### \`image-size\` — CLASS B, weaker basis, shorter expiry
- **It IS present in the production dependency closure**.
- Accepted on non-reachability by runtime import.
`;

  it("passes when documented as CLASS B with present-tense presence", () => {
    const v = evaluate([imageSizeFinding], [imageSizeException], classBProse, NOW);
    expect(v.ok).toBe(true);
  });

  it("BLOCKS when the registry flips image-size to CLASS A but prose says B", () => {
    const v = evaluate(
      [imageSizeFinding],
      [
        baseException({
          package: "image-size",
          advisories: ["GHSA-w3rx-r6r6-pgpr"],
          reachabilityClass: "A",
          disposition: "accepted_absent_from_production_closure",
        }),
      ],
      classBProse,
      NOW,
    );
    expectBlockedBecause(v, /does not record `image-size` as CLASS A/);
  });

  it("BLOCKS prose that reverts image-size to ABSENCE language", () => {
    const absentProse = `## Known accepted CVEs

| Package | CVE / advisory | Disposition | Class | Owner | Accepted | Review by |
|---|---|---|---|---|---|---|
| \`image-size\` (<=2.0.2) | GHSA-w3rx-r6r6-pgpr — DoS | \`accepted_present_but_not_imported_by_runtime\` | **B** | JJ Joseph | 2026-08-11 | 2026-09-11 |

#### \`image-size\` — CLASS B
- **Absent** from the deployed production dependency closure (verified by script).
`;
    const v = evaluate([imageSizeFinding], [imageSizeException], absentProse, NOW);
    expectBlockedBecause(v, /using ABSENCE language/);
  });

  it("BLOCKS 'is absent' phrasing for a CLASS B package", () => {
    const sneaky = classBProse.replace(
      "- **It IS present in the production dependency closure**.",
      "- The package is absent from the production dependency closure.",
    );
    expectBlockedBecause(
      evaluate([imageSizeFinding], [imageSizeException], sneaky, NOW),
      /using ABSENCE language/,
    );
  });

  it("still ALLOWS the deferred-remediation wording about becoming absent", () => {
    const withDeferred = `${classBProse}
- **Standing remediation option**: stub packages/react so the closure drops and image-size becomes genuinely absent, promoting this to CLASS A.
`;
    expect(evaluate([imageSizeFinding], [imageSizeException], withDeferred, NOW).ok).toBe(true);
  });
});

describe("severity filtering", () => {
  it("ignores non-gated severities entirely", () => {
    const v = evaluate(
      [finding({ package: "low-pkg", advisoryId: "GHSA-0000-0000-0001", severity: "moderate" })],
      [],
      "## Known accepted CVEs\n",
      NOW,
    );
    expect(v.ok).toBe(true);
    expect(v.unallowlisted).toHaveLength(0);
  });
});

describe("the REAL shipped registry", () => {
  it("is internally valid and mirrors the real threat model", async () => {
    const doc = await Bun.file(
      new URL("../../docs/security/threat-model.mdx", import.meta.url),
    ).text();
    const v = evaluate([], AUDIT_EXCEPTIONS, doc, NOW);
    // No findings supplied, so every entry reads as "no longer reported"; we are
    // asserting only that there are no VALIDITY or BINDING defects.
    const validity = v.problems.filter((p) => !/no longer reports/.test(p));
    expect(validity).toEqual([]);
  });

  it("keeps image-size as CLASS B with the non-reachability disposition", () => {
    const e = AUDIT_EXCEPTIONS.find((x) => x.package === "image-size");
    expect(e).toBeDefined();
    expect(e?.reachabilityClass).toBe("B");
    expect(e?.disposition).toBe("accepted_present_but_not_imported_by_runtime");
    expect(e?.qualifiers).toContain("no_fix_available");
  });

  it("keeps vite and next as CLASS A absent-from-closure", () => {
    for (const pkg of ["vite", "next"]) {
      const e = AUDIT_EXCEPTIONS.find((x) => x.package === pkg);
      expect(e?.reachabilityClass).toBe("A");
      expect(e?.disposition).toBe("accepted_absent_from_production_closure");
    }
  });

  it("authorizes NO critical anywhere — no standing critical acceptance exists", () => {
    for (const e of AUDIT_EXCEPTIONS) {
      expect(e.authorizesSeverity).not.toContain("critical");
    }
  });

  it("gives image-size the shorter 30-day-class review window", () => {
    const img = AUDIT_EXCEPTIONS.find((x) => x.package === "image-size");
    const vite = AUDIT_EXCEPTIONS.find((x) => x.package === "vite");
    const days = (e?: AuditException) =>
      e ? (Date.parse(e.reviewBy) - Date.parse(e.acceptedOn)) / 86_400_000 : Number.NaN;
    expect(days(img)).toBeLessThanOrEqual(31);
    expect(days(img)).toBeLessThan(days(vite));
  });
  it("requires image-size to name its four mandatory reconsideration triggers", () => {
    const e = AUDIT_EXCEPTIONS.find((x) => x.package === "image-size");
    const joined = (e?.reconsiderIf ?? []).join(" | ").toLowerCase();
    expect(joined).toContain("fixed image-size release");
    expect(joined).toContain("@stwd/react");
    expect(joined).toContain("composition changes");
    expect(joined).toContain("reachability checker");
  });

  it("does not describe image-size with absence language in its rationale", () => {
    const e = AUDIT_EXCEPTIONS.find((x) => x.package === "image-size");
    expect(e?.rationale ?? "").toMatch(/IS PRESENT/);
    expect(e?.rationale ?? "").not.toMatch(/\bis absent\b/i);
  });
});
