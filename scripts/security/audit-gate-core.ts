/**
 * STRATA-926 — pure evaluation core for the dependency-audit exception gate.
 *
 * WHY THIS IS SEPARATE FROM THE CLI
 * ---------------------------------
 * The decision logic here is a pure function of (findings, registry, prose). It
 * performs no IO. That matters for two reasons:
 *
 *  1. It is testable adversarially — the suite feeds synthetic findings such as
 *     "a CRITICAL in a package that has an accepted HIGH" and asserts the gate
 *     BLOCKS. No env-var fixture hook is needed, so there is no test-only
 *     escape hatch that could be set in CI to feed the gate a clean audit.
 *  2. The CLI cannot accidentally soften a verdict: it runs `bun audit`, hands
 *     the parsed findings here, and does exactly what the verdict says.
 *
 * Every helper below fails CLOSED: unknown/missing/malformed input produces a
 * blocking problem, never a pass.
 */
import type { AuditException, AuditSeverity, ReachabilityClass } from "./audit-exceptions.ts";
import { GATED_SEVERITIES } from "./audit-exceptions.ts";

export interface Finding {
  package: string;
  advisoryId: string;
  severity: AuditSeverity;
  title: string;
  vulnerableVersions: string;
}

export interface AcceptedFinding {
  finding: Finding;
  exception: AuditException;
}

export interface RemediatedEntry {
  package: string;
  advisoryId: string;
}

export interface Verdict {
  /** Findings covered by a valid, active, correctly-scoped exception. */
  accepted: AcceptedFinding[];
  /** Registry entries whose advisory the audit no longer reports (cleanup-marked). */
  remediated: RemediatedEntry[];
  /** Gated findings with no active exception. Always blocking. */
  unallowlisted: Finding[];
  /** Registry/prose defects. Always blocking. */
  problems: string[];
  /** True iff nothing blocks. */
  ok: boolean;
}

/** Minimum characters for a rationale to count as a rationale and not a shrug. */
export const MIN_RATIONALE_CHARS = 40;

const PLACEHOLDER_OWNERS = new Set([
  "",
  "-",
  "tbd",
  "todo",
  "unknown",
  "n/a",
  "na",
  "none",
  "team",
  "security",
  "someone",
]);

const DISPOSITION_FOR_CLASS: Record<ReachabilityClass, string> = {
  A: "accepted_absent_from_production_closure",
  B: "accepted_present_but_not_imported_by_runtime",
};

export function isIsoDate(value: unknown): boolean {
  return (
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}$/.test(value) &&
    !Number.isNaN(Date.parse(value))
  );
}

/** UTC-midnight "today", so expiry comparisons are timezone-stable. */
export function utcMidnight(d: Date): Date {
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
}

export function isWellFormedAdvisoryId(id: string): boolean {
  return /^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/.test(id) || /^CVE-\d{4}-\d+$/.test(id);
}

/**
 * Validate the registry in isolation. A malformed registry must never be able to
 * authorize anything, so every defect here is blocking.
 */
export function validateRegistry(exceptions: readonly AuditException[], now: Date): string[] {
  const problems: string[] = [];
  const seen = new Set<string>();
  const today = utcMidnight(now);

  for (const e of exceptions) {
    const label = `exception \`${e.package}\``;

    if (!e.package || e.package.trim() === "") {
      problems.push(`${label}: empty package name.`);
    }

    if (!Array.isArray(e.advisories) || e.advisories.length === 0) {
      problems.push(`${label}: must list at least one advisory identifier.`);
    }
    for (const id of e.advisories ?? []) {
      if (!isWellFormedAdvisoryId(id)) {
        problems.push(`${label}: \`${id}\` is not a well-formed GHSA or CVE identifier.`);
      }
      const key = `${e.package}::${id}`;
      if (seen.has(key)) {
        problems.push(`${label}: duplicate entry for ${id}. Merge the entries.`);
      }
      seen.add(key);
    }

    if (
      PLACEHOLDER_OWNERS.has(
        String(e.owner ?? "")
          .trim()
          .toLowerCase(),
      )
    ) {
      problems.push(
        `${label}: owner is missing or a placeholder (\`${e.owner}\`). An exception needs a named accountable human.`,
      );
    }

    if (!e.rationale || e.rationale.trim().length < MIN_RATIONALE_CHARS) {
      problems.push(
        `${label}: rationale is missing or too short (< ${MIN_RATIONALE_CHARS} chars). State why the risk is acceptable.`,
      );
    }

    if (!e.disposition) {
      problems.push(`${label}: no disposition.`);
    } else {
      const expected = DISPOSITION_FOR_CLASS[e.reachabilityClass];
      if (expected === undefined) {
        problems.push(`${label}: unknown reachability class \`${e.reachabilityClass}\`.`);
      } else if (e.disposition !== expected) {
        problems.push(
          `${label}: CLASS ${e.reachabilityClass} must use disposition \`${expected}\`, got \`${e.disposition}\`.`,
        );
      }
    }

    if (!isIsoDate(e.acceptedOn)) {
      problems.push(`${label}: acceptedOn \`${e.acceptedOn}\` is not a YYYY-MM-DD date.`);
    }
    if (!isIsoDate(e.reviewBy)) {
      problems.push(`${label}: reviewBy \`${e.reviewBy}\` is not a YYYY-MM-DD date.`);
    }
    if (isIsoDate(e.acceptedOn) && isIsoDate(e.reviewBy)) {
      if (Date.parse(e.reviewBy) <= Date.parse(e.acceptedOn)) {
        problems.push(`${label}: reviewBy must be after acceptedOn.`);
      }
      if (new Date(`${e.reviewBy}T00:00:00Z`) < today) {
        problems.push(
          `${label}: EXPIRED — review was due ${e.reviewBy}. Re-review and re-date, or remediate. Expiry is not a formality.`,
        );
      }
    }

    if (!Array.isArray(e.reconsiderIf) || e.reconsiderIf.length === 0) {
      problems.push(`${label}: must declare at least one condition mandating re-review.`);
    }

    if (!Array.isArray(e.authorizesSeverity) || e.authorizesSeverity.length === 0) {
      problems.push(`${label}: authorizesSeverity must be non-empty.`);
    }
    if ((e.authorizesSeverity ?? []).includes("critical")) {
      const a = e.criticalApproval;
      if (!a || !a.approvedBy?.trim() || !a.approvedOn?.trim() || !a.justification?.trim()) {
        problems.push(
          `${label}: authorizes CRITICAL but has no complete criticalApproval (approvedBy/approvedOn/justification). ` +
            "Critical acceptance requires an explicit, separately approved disposition.",
        );
      } else if (!isIsoDate(a.approvedOn)) {
        problems.push(
          `${label}: criticalApproval.approvedOn \`${a.approvedOn}\` is not a YYYY-MM-DD date.`,
        );
      }
    } else if (e.criticalApproval) {
      problems.push(
        `${label}: carries a criticalApproval but does not list "critical" in authorizesSeverity. Ambiguous — make the intent explicit.`,
      );
    }
  }

  return problems;
}

/**
 * Enforce the registry <-> prose binding in BOTH directions.
 *
 * Forward:  every registry entry must be documented (advisory id, package, class).
 * Reverse:  no advisory may be documented as accepted without a registry entry.
 *
 * The reverse direction is what closes the "edit only the Markdown" bypass.
 */
export function checkProseBinding(
  exceptions: readonly AuditException[],
  threatModel: string | null,
): string[] {
  const problems: string[] = [];

  if (threatModel === null) {
    problems.push("threat model not found. The registry must have a documented mirror.");
    return problems;
  }

  const anchor = threatModel.indexOf("## Known accepted CVEs");
  if (anchor === -1) {
    problems.push("threat model has no `## Known accepted CVEs` section to mirror the registry.");
    return problems;
  }
  const section = threatModel.slice(anchor);

  for (const e of exceptions) {
    for (const id of e.advisories ?? []) {
      if (!section.includes(id)) {
        problems.push(
          `threat model does not document advisory ${id} (\`${e.package}\`). Every registry entry needs a matching human-readable entry.`,
        );
      }
    }
    if (!section.includes(`\`${e.package}\``)) {
      problems.push(
        `threat model does not mention package \`${e.package}\` in the accepted-CVE section.`,
      );
    }

    // The class letter must agree, so prose cannot restate a CLASS B
    // (present, unimported) acceptance as a CLASS A (absent) one.
    const escaped = e.package.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const classRow = new RegExp(
      `\`${escaped}\`[^\\n]*\\|[^\\n|]*\\*{0,2}${e.reachabilityClass}\\*{0,2}\\s*\\|`,
    );
    if (!classRow.test(section)) {
      problems.push(
        `threat model does not record \`${e.package}\` as CLASS ${e.reachabilityClass} in the accepted-CVE table. Registry and prose disagree about the strength of the claim.`,
      );
    }
  }

  const registryIds = new Set(exceptions.flatMap((e) => e.advisories ?? []));
  for (const match of section.matchAll(/GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/g)) {
    if (!registryIds.has(match[0])) {
      problems.push(
        `threat model documents ${match[0]} as an accepted CVE, but it has no entry in scripts/security/audit-exceptions.ts. Prose cannot authorize a vulnerability.`,
      );
    }
  }

  // A CLASS B package must never be described with present-tense absence language.
  for (const e of exceptions) {
    if (e.reachabilityClass !== "B") continue;
    const heading = `#### \`${e.package}\``;
    const idx = section.indexOf(heading);
    if (idx === -1) {
      problems.push(`threat model has no \`${heading}\` subsection for CLASS B package.`);
      continue;
    }
    const next = section.indexOf("\n#### ", idx + 1);
    const body = section.slice(idx, next === -1 ? section.length : next);
    for (const line of body.split("\n")) {
      if (!/\babsent\b/i.test(line)) continue;
      // The deferred remediation option legitimately says it WOULD become absent.
      if (/becomes genuinely absent|would become absent|promoting (this|it) to/i.test(line)) {
        continue;
      }
      if (/\bis\s+(genuinely\s+)?absent\b|\*\*absent\*\*/i.test(line)) {
        problems.push(
          `threat model describes CLASS B package \`${e.package}\` using ABSENCE language ("${line.trim().slice(0, 120)}"). ` +
            "It is PRESENT in the closure and accepted on non-reachability by runtime import.",
        );
      }
    }
  }

  return problems;
}

/**
 * The core decision. Given gated findings, the registry and the prose, decide
 * what is accepted, what is remediated, and what blocks.
 */
export function evaluate(
  findings: readonly Finding[],
  exceptions: readonly AuditException[],
  threatModel: string | null,
  now: Date,
): Verdict {
  const problems = [
    ...validateRegistry(exceptions, now),
    ...checkProseBinding(exceptions, threatModel),
  ];

  const byKey = new Map<string, AuditException>();
  for (const e of exceptions) {
    for (const id of e.advisories ?? []) byKey.set(`${e.package}::${id}`, e);
  }

  const accepted: AcceptedFinding[] = [];
  const unallowlisted: Finding[] = [];

  for (const f of findings) {
    // Defence in depth: re-filter rather than trusting --audit-level semantics.
    if (!GATED_SEVERITIES.includes(f.severity)) continue;

    // Keyed by package AND advisory. An exception for a different advisory in
    // the same package is NOT coverage — advisory-ID mismatch fails closed.
    const exception = byKey.get(`${f.package}::${f.advisoryId}`);

    if (!exception) {
      unallowlisted.push(f);
      continue;
    }

    // Severity escalation. A high-only exception NEVER covers a critical.
    if (!exception.authorizesSeverity.includes(f.severity)) {
      problems.push(
        `${f.severity.toUpperCase()} ${f.advisoryId} in \`${f.package}\` is NOT covered: its exception authorizes only [${exception.authorizesSeverity.join(", ")}]. ` +
          (f.severity === "critical"
            ? "A critical requires its own explicitly approved critical disposition; a high exception never escalates automatically."
            : "Widen authorizesSeverity deliberately, with review."),
      );
      continue;
    }

    if (exception.expectedAbsentFromAudit) {
      problems.push(
        `\`${f.package}\` ${f.advisoryId} is marked \`expectedAbsentFromAudit\` (pending cleanup) but the audit STILL reports it. Un-mark it or remediate.`,
      );
      continue;
    }

    accepted.push({ finding: f, exception });
  }

  // Stale entries: the registry references an advisory the audit no longer reports.
  const auditKeys = new Set(findings.map((f) => `${f.package}::${f.advisoryId}`));
  const remediated: RemediatedEntry[] = [];
  for (const e of exceptions) {
    for (const id of e.advisories ?? []) {
      if (auditKeys.has(`${e.package}::${id}`)) continue;
      if (e.expectedAbsentFromAudit) {
        remediated.push({ package: e.package, advisoryId: id });
        continue;
      }
      problems.push(
        `exception \`${e.package}\` references ${id}, which the audit no longer reports. ` +
          "Either it was remediated (delete the entry) or the package left the tree. " +
          "Set `expectedAbsentFromAudit: true` only as a deliberate cleanup marker — a stale exception must not sit here unnoticed.",
      );
    }
  }

  return {
    accepted,
    remediated,
    unallowlisted,
    problems,
    ok: problems.length === 0 && unallowlisted.length === 0,
  };
}
