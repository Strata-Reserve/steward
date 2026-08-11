#!/usr/bin/env bun
/**
 * STRATA-926 — fail-closed dependency-audit gate (CLI).
 *
 *   1. runs `bun audit --audit-level=high --json`
 *   2. parses every high/critical advisory
 *   3. matches each against the structured registry, keyed by (package, advisory id)
 *   4. FAILS if any high/critical finding has no active exception
 *   5. FAILS if an exception is expired / ownerless / rationale-less / disposition-less,
 *      or references an advisory no longer present (unless marked for cleanup)
 *   6. FAILS on any critical not covered by an explicitly critical-scoped, approved
 *      disposition — a generic high exception never auto-covers a future critical
 *   7. prints which findings were REMEDIATED vs ACCEPTED
 *
 * All decision logic lives in ./audit-gate-core.ts as a pure function, which the
 * test suite drives with synthetic findings. This file only does IO: run the
 * audit, parse it, hand it to the core, print the verdict, set the exit code.
 * There is deliberately NO fixture/override env var — nothing a CI config could
 * set to feed this gate a fake clean audit.
 *
 * Exit 0 = every gated finding is remediated or explicitly, validly accepted.
 * Exit 1 = anything else, including "the gate could not trust its own inputs".
 */
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { AUDIT_EXCEPTIONS, type AuditSeverity, GATED_SEVERITIES } from "./audit-exceptions.ts";
import { evaluate, type Finding } from "./audit-gate-core.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const THREAT_MODEL = join(repoRoot, "docs", "security", "threat-model.mdx");

interface RawAdvisory {
  id: number;
  url: string;
  title: string;
  severity: string;
  vulnerable_versions: string;
}

/** Hard stop. Used only where continuing would mean certifying from bad input. */
function abort(message: string): never {
  console.error(`\n[FAIL] ${message}`);
  process.exit(1);
}

function runAudit(): Map<string, RawAdvisory[]> {
  const res = spawnSync("bun", ["audit", "--audit-level=high", "--json"], {
    cwd: repoRoot,
    encoding: "utf8",
    timeout: 600_000,
    maxBuffer: 64 * 1024 * 1024,
  });

  if (res.error) {
    abort(`could not execute \`bun audit\`: ${res.error.message}`);
  }

  const stdout = (res.stdout ?? "").trim();

  // `bun audit` exits non-zero WHEN FINDINGS EXIST, so non-zero is not itself an
  // error. But empty stdout with a non-zero status means the command genuinely
  // failed, and that must never be read as "no vulnerabilities".
  if (stdout === "") {
    if (res.status === 0) return new Map();
    abort(
      `\`bun audit\` exited ${res.status} with no JSON on stdout. Refusing to treat a broken audit as a clean one.\n${(res.stderr ?? "").slice(-800)}`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch (err) {
    abort(
      `could not parse \`bun audit --json\` output: ${(err as Error).message}. Refusing to certify from unparseable audit output.`,
    );
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    abort(
      "unexpected `bun audit --json` shape (expected an object keyed by package name). The audit format may have changed; update this gate before trusting it.",
    );
  }

  const out = new Map<string, RawAdvisory[]>();
  for (const [pkg, advisories] of Object.entries(parsed as Record<string, unknown>)) {
    if (!Array.isArray(advisories)) {
      abort(`advisory list for \`${pkg}\` is not an array. Unexpected audit shape.`);
    }
    out.set(pkg, advisories as RawAdvisory[]);
  }
  return out;
}

/** Extract the GHSA/CVE identifier from an advisory URL, falling back to numeric id. */
function advisoryIdOf(a: RawAdvisory): string {
  const fromUrl = (a.url ?? "").trim().replace(/\/+$/, "").split("/").pop() ?? "";
  if (/^(GHSA-|CVE-)/i.test(fromUrl)) return fromUrl;
  return String(a.id ?? "");
}

function collectGatedFindings(raw: Map<string, RawAdvisory[]>): Finding[] {
  const findings: Finding[] = [];
  for (const [pkg, advisories] of raw) {
    for (const a of advisories) {
      const severity = String(a.severity ?? "").toLowerCase() as AuditSeverity;
      if (!GATED_SEVERITIES.includes(severity)) continue;
      findings.push({
        package: pkg,
        advisoryId: advisoryIdOf(a),
        severity,
        title: a.title ?? "(no title)",
        vulnerableVersions: a.vulnerable_versions ?? "(unspecified)",
      });
    }
  }
  return findings.sort(
    (x, y) => x.package.localeCompare(y.package) || x.advisoryId.localeCompare(y.advisoryId),
  );
}

// ---------------------------------------------------------------------------
console.log("STRATA-926 dependency-audit exception gate\n");

const findings = collectGatedFindings(runAudit());
const threatModel = existsSync(THREAT_MODEL) ? readFileSync(THREAT_MODEL, "utf8") : null;
const verdict = evaluate(findings, AUDIT_EXCEPTIONS, threatModel, new Date());

console.log(`gated severities: ${GATED_SEVERITIES.join(", ")}`);
console.log(
  `audit reported ${findings.length} gated finding(s) across ${new Set(findings.map((f) => f.package)).size} package(s)\n`,
);

if (verdict.remediated.length > 0) {
  console.log("REMEDIATED / no longer reported (exception pending cleanup):");
  for (const r of verdict.remediated) {
    console.log(`  [remediated] ${r.package.padEnd(14)} ${r.advisoryId}`);
  }
  console.log();
}

if (verdict.accepted.length > 0) {
  console.log("ACCEPTED — explicitly dispositioned, NOT fixed:");
  for (const { finding, exception } of verdict.accepted) {
    console.log(
      `  [accepted]   ${finding.severity.toUpperCase().padEnd(8)} ${finding.package.padEnd(14)} ${finding.advisoryId}`,
    );
    console.log(
      `               class ${exception.reachabilityClass} · ${exception.disposition}${
        exception.qualifiers.length > 0 ? ` (+${exception.qualifiers.join(", ")})` : ""
      }`,
    );
    console.log(`               owner ${exception.owner} · review by ${exception.reviewBy}`);
  }
  console.log();
}

if (verdict.unallowlisted.length > 0) {
  console.error("UNALLOWLISTED — no active exception:");
  for (const f of verdict.unallowlisted) {
    console.error(
      `  [BLOCKED]    ${f.severity.toUpperCase().padEnd(8)} ${f.package.padEnd(14)} ${f.advisoryId}  ${f.title}`,
    );
    console.error(`               vulnerable: ${f.vulnerableVersions}`);
  }
  console.error();
}

if (verdict.problems.length > 0) {
  console.error("EXCEPTION-REGISTRY PROBLEMS:");
  for (const p of verdict.problems) console.error(`  [BLOCKED]    ${p}`);
  console.error();
}

if (!verdict.ok) {
  console.error(
    `[FAIL] ${verdict.unallowlisted.length} unallowlisted finding(s), ${verdict.problems.length} registry/binding problem(s).\n` +
      "Remediate the vulnerability, or add a complete exception to scripts/security/audit-exceptions.ts\n" +
      "WITH owner, rationale, disposition, dated expiry and re-review triggers — and mirror it in\n" +
      "docs/security/threat-model.mdx. Editing the prose alone will not authorize anything.",
  );
  process.exit(1);
}

console.log(
  `[OK] ${verdict.accepted.length} accepted with valid dispositions, ${verdict.remediated.length} remediated, 0 unallowlisted.`,
);
console.log("     Accepted findings are NOT fixed. They are time-boxed and owned.");
