/**
 * STRATA-926 — MACHINE SOURCE OF TRUTH for dependency-audit exceptions.
 *
 * READ THIS BEFORE EDITING
 * ------------------------
 * This file — not the threat model prose — is what authorizes a high/critical
 * `bun audit` finding to pass CI. The invariant the gate enforces is:
 *
 *     Changing prose alone MUST NOT silently authorize a vulnerability.
 *     Adding a vulnerability here MUST carry the full evidence set below.
 *
 * `docs/security/threat-model.mdx` is REQUIRED to carry a matching
 * human-readable section for every entry here, and is FORBIDDEN from carrying
 * an accepted-CVE row that does not exist here. Both directions are checked by
 * `scripts/security/check-audit-exceptions.ts`. The document renders/mirrors
 * this data; it never overrides it.
 *
 * FAIL-CLOSED BY CONSTRUCTION
 * ---------------------------
 *  - An advisory with no entry here fails the build.
 *  - An entry missing owner / rationale / disposition / expiry fails the build.
 *  - An expired entry fails the build.
 *  - An entry whose advisory has vanished from the audit fails the build,
 *    UNLESS it is explicitly marked `expectedAbsentFromAudit` for cleanup.
 *  - A CRITICAL finding is NEVER covered by a high-only exception. Escalation
 *    requires `authorizesSeverity` to include "critical" AND a populated
 *    `criticalApproval`. This is deliberate: a package with an accepted high
 *    must not silently absorb a future critical in the same package.
 */

export type AuditSeverity = "low" | "moderate" | "high" | "critical";

/** Severities the CI gate blocks on. Anything below is informational. */
export const GATED_SEVERITIES: readonly AuditSeverity[] = ["high", "critical"] as const;

/**
 * CLASS A — the vulnerable package is ABSENT from the production dependency
 *           closure. Strongest claim: the code is not installed at all.
 * CLASS B — the vulnerable package IS PRESENT in the production closure and is
 *           accepted only because no runtime-shipped package can import it.
 *           Strictly weaker. "Accepted" must never be read as "not installed".
 */
export type ReachabilityClass = "A" | "B";

export type Disposition =
  /** CLASS A basis: not in the production dependency closure. */
  | "accepted_absent_from_production_closure"
  /** CLASS B basis: in the closure, but unreachable by runtime import. */
  | "accepted_present_but_not_imported_by_runtime";

/** Additional qualifiers. Not a substitute for a disposition. */
export type Qualifier = "no_fix_available";

/** Escalation record required before any exception may cover a CRITICAL. */
export interface CriticalApproval {
  approvedBy: string;
  approvedOn: string;
  justification: string;
}

export interface AuditException {
  /** Package name exactly as `bun audit --json` keys it. */
  package: string;
  /**
   * Advisory identifiers (GHSA). Matching is EXACT and per-advisory: an
   * exception for one GHSA in a package does not cover a different GHSA in
   * that same package.
   */
  advisories: string[];
  /**
   * Severities this exception is authorized to cover. Including "critical"
   * additionally requires `criticalApproval`.
   */
  authorizesSeverity: AuditSeverity[];
  criticalApproval?: CriticalApproval;
  reachabilityClass: ReachabilityClass;
  disposition: Disposition;
  qualifiers: Qualifier[];
  /** Accountable human. Empty/placeholder values fail the gate. */
  owner: string;
  /** Why this risk is acceptable. Empty or trivially short fails the gate. */
  rationale: string;
  /** How the package enters the tree. Must be accurate; reviewed evidence. */
  entryPath: string;
  /**
   * The workspace package through which the vulnerable package enters, stated
   * EXPLICITLY rather than parsed out of `entryPath` prose.
   *
   * Required for CLASS B, where the whole acceptance rests on "no runtime-shipped
   * package can reach THIS workspace". It was previously recovered with a regex
   * that took the first scoped token in `entryPath`; that captured the right
   * value only by luck of word order. Reordering the prose while keeping every
   * fact identical made it verify `@solana/wallet-adapter-react` instead — an
   * unrelated package. Evidence a reviewer trusts must not depend on word order.
   */
  entryWorkspace?: string;
  /** ISO date the exception was accepted. */
  acceptedOn: string;
  /** ISO date after which the exception is EXPIRED and fails the gate. */
  reviewBy: string;
  /** Conditions that mandate re-review before `reviewBy`. */
  reconsiderIf: string[];
  /**
   * Cleanup marker. Set true ONLY when the advisory is expected to have
   * disappeared from audit output and this entry is pending removal.
   * Without it, a stale entry referencing a vanished advisory fails the gate.
   */
  expectedAbsentFromAudit: boolean;
}

const OWNER_JJ = "JJ Joseph";

export const AUDIT_EXCEPTIONS: readonly AuditException[] = [
  {
    package: "vite",
    advisories: ["GHSA-fx2h-pf6j-xcff"],
    authorizesSeverity: ["high"],
    reachabilityClass: "A",
    disposition: "accepted_absent_from_production_closure",
    qualifiers: [],
    owner: OWNER_JJ,
    rationale:
      "`server.fs.deny` bypass via Windows alternate data streams in the Vite dev server. " +
      "Vite is a test/build-time dependency only: it is ABSENT from the production dependency " +
      "closure, reaches the tree exclusively through devDependencies, and no dev server is ever " +
      "started in the deployed signing service. Verified mechanically by " +
      "scripts/verify-production-reachability.ts.",
    entryPath: "@stwd/eliza-plugin -> vitest -> vite (devDependency edge only)",
    entryWorkspace: "@stwd/eliza-plugin",
    acceptedOn: "2026-08-11",
    reviewBy: "2026-11-11",
    reconsiderIf: [
      "@stwd/eliza-plugin, Vitest, or Vite build output is added to the production runtime image",
      "vite appears in the production dependency closure for any reason",
      "the runtime image package allowlist changes",
      "the reachability checker changes or fails",
    ],
    expectedAbsentFromAudit: false,
  },
  {
    // STRATA-1494. TEMPORARY CLASS B acceptance approved by JJ (#development,
    // 2026-10-04). This exception does NOT authorize other unpatched dependencies.
    package: "braces",
    advisories: ["GHSA-vfj7-8cjw-p6xm"],
    authorizesSeverity: ["high"],
    reachabilityClass: "B",
    disposition: "accepted_present_but_not_imported_by_runtime",
    qualifiers: ["no_fix_available"],
    owner: OWNER_JJ,
    rationale:
      "Stack-exhaustion DoS when braces expands an attacker-controlled glob pattern with deep " +
      "nesting. No patched release exists at any version (latest is 3.0.3, vulnerable range " +
      "<= 3.0.3), so there is nothing to upgrade or override to. braces reaches the tree only " +
      "through build/tooling parents: tailwindcss@3 (devDependency of @stwd/web, stubbed out of " +
      "the runtime stage, ABSENT from the production closure) and metro-file-map via the " +
      "react-native subtree pulled in by optional peers of @stwd/react's wallet connectors. The " +
      "metro chain IS PRESENT in the production closure (hence CLASS B, not A), but no " +
      "runtime-shipped package imports braces, micromatch, metro or react-native " +
      "(import-reachability from the 12 runtime roots: not reachable, verified by " +
      "scripts/verify-production-reachability.ts). Nothing in Steward executes metro or " +
      "tailwind at runtime, and no Steward API accepts a glob pattern from a client, so there " +
      "is no attacker-controlled input to the vulnerable function. Standing remediation: stub " +
      "packages/react out of the runtime image stage (separate hardening ticket), which would " +
      "move the whole react-native/metro subtree out of the closure.",
    entryPath:
      "@stwd/react -> wagmi -> @wagmi/connectors -> porto (optional peer react-native) | " +
      "@stwd/react -> @solana/wallet-adapter-react -> @solana-mobile/wallet-adapter-mobile | " +
      "@solana-mobile/wallet-standard-mobile (optional) | @trezor/env-utils (optional peer) | " +
      "@walletconnect/keyvaluestorage -> @react-native-async-storage/async-storage (optional peer) " +
      "-> react-native -> @react-native/community-cli-plugin -> metro-config -> metro -> " +
      "metro-file-map -> micromatch -> braces; " +
      "plus dev-only @stwd/web -> tailwindcss@3 -> micromatch | fast-glob -> micromatch | " +
      "chokidar@3 -> braces (devDependency edge only, not in the production closure)",
    entryWorkspace: "@stwd/react",
    acceptedOn: "2026-10-04",
    reviewBy: "2026-11-03",
    reconsiderIf: [
      "a braces release marked as the first patched version for GHSA-vfj7-8cjw-p6xm appears (re-review IMMEDIATELY; do not wait for expiry)",
      "the reachability classification changes: @stwd/react or any package on its chain becomes import-reachable from a runtime-shipped package",
      "Steward begins executing tailwind or metro tooling at runtime, or any runtime code path imports micromatch/braces",
      "any Steward endpoint begins accepting glob patterns from clients",
      "the runtime image or package composition changes (including packages/react being stubbed, which should re-class this as A or remove it)",
      "the reachability checker changes or fails",
      "expiry (reviewBy) is reached without a fixed release",
    ],
    expectedAbsentFromAudit: false,
  },
];
