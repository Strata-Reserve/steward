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
    package: "next",
    advisories: ["GHSA-89xv-2m56-2m9x", "GHSA-m99w-x7hq-7vfj", "GHSA-p9j2-gv94-2wf4"],
    authorizesSeverity: ["high"],
    reachabilityClass: "A",
    disposition: "accepted_absent_from_production_closure",
    qualifiers: [],
    owner: OWNER_JJ,
    rationale:
      "SSRF in Server Actions on custom servers, DoS in the App Router, and SSRF in rewrites. " +
      "Next.js enters solely through the `web` workspace, which the runtime stage STUBS rather " +
      "than ships. Next is ABSENT from the production dependency closure and no web application " +
      "output is deployed with the signing service. Verified mechanically by " +
      "scripts/verify-production-reachability.ts.",
    entryPath: "workspace `web` -> next (web is stubbed in the runtime image stage)",
    entryWorkspace: "@stwd/web",
    acceptedOn: "2026-08-11",
    reviewBy: "2026-11-11",
    reconsiderIf: [
      "@stwd/web, Next.js, or web build output is added to the production image",
      "next appears in the production dependency closure for any reason",
      "the runtime image package allowlist changes",
      "the reachability checker changes or fails",
    ],
    expectedAbsentFromAudit: false,
  },
  {
    package: "image-size",
    advisories: ["GHSA-w3rx-r6r6-pgpr", "GHSA-5p2g-fcmc-qvqq"],
    authorizesSeverity: ["high"],
    reachabilityClass: "B",
    disposition: "accepted_present_but_not_imported_by_runtime",
    qualifiers: ["no_fix_available"],
    owner: OWNER_JJ,
    rationale:
      "Denial of service via infinite loops in the ICNS and JXL/HEIF parsers. This is a CLASS B " +
      "acceptance and the distinction is material: image-size IS PRESENT in the production " +
      "dependency closure at 1.2.1 — it is NOT absent. No patched release exists at any version " +
      "(the advisory covers <=2.0.2 and the latest published version IS 2.0.2), so there is " +
      "nothing to upgrade to. The acceptance rests on NON-REACHABILITY BY RUNTIME IMPORT: no " +
      "package whose build output is copied into the runtime image has any import path, direct " +
      "or transitive, to the workspace that pulls image-size in. Steward's signing service " +
      "decodes no images, and both advisories require attacker-controlled image input.",
    entryPath:
      "@stwd/react -> wagmi | @solana/wallet-adapter-* | @rainbow-me/rainbowkit -> " +
      "(porto | @walletconnect/keyvaluestorage | @trezor/env-utils) -> react-native -> " +
      "@react-native/community-cli-plugin -> metro -> image-size. The proximate parent is " +
      "`metro`, the React Native bundler; image-size is not a direct wagmi/Solana dependency.",
    entryWorkspace: "@stwd/react",
    acceptedOn: "2026-08-11",
    reviewBy: "2026-09-11",
    reconsiderIf: [
      "a fixed image-size release appears (re-review IMMEDIATELY, do not wait for expiry)",
      "@stwd/react or its dependency chain becomes imported by a runtime-copied package",
      "runtime image or package composition changes",
      "the reachability checker changes or fails",
    ],
    expectedAbsentFromAudit: false,
  },
];
