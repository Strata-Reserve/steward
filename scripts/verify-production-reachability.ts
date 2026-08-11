#!/usr/bin/env bun
import { spawnSync } from "node:child_process";
/**
 * STRATA-926 — rerunnable production-image reachability check.
 *
 * WHY THIS EXISTS
 * ---------------
 * Three dependency-audit findings (`vite`, `next`, `image-size`) are accepted on the
 * basis that the vulnerable package is NOT present in the dependency closure copied
 * into the Steward production runtime image. That claim was originally produced by an
 * ad hoc probe — and during that work TWO probes confidently reported "ABSENT" while
 * inspecting an installation that had actually failed and contained ZERO packages.
 *
 * An exception justified by a probe that cannot fail is not an exception; it is a
 * narrative. This script exists so the claim is re-verifiable and FAILS LOUDLY when it
 * stops being true.
 *
 * THE THREE WAYS THIS CHECK REFUSES TO FAIL-OPEN
 * ----------------------------------------------
 *  1. INSTALL LIVENESS. A `--production` install is performed into a scratch tree and
 *     the resulting closure MUST contain more than MIN_EXPECTED_PACKAGES entries. An
 *     empty or failed install aborts with a hard error instead of reporting "ABSENT"
 *     for everything. This is the exact defect that motivated the script.
 *  2. POSITIVE CONTROL. Packages that MUST be present in a correct production closure
 *     (`hono`, `drizzle-orm`, ...) are asserted PRESENT. If those go missing, the probe
 *     is measuring the wrong tree and says so, rather than emitting a clean bill of
 *     health.
 *  3. COMPOSITION PIN. The runtime image's package allowlist is parsed out of the
 *     Dockerfile and compared against a pinned expected set. If a future change copies
 *     `packages/web`, `packages/react` or `packages/eliza-plugin` into the runtime
 *     stage, the reachability basis for all three exceptions collapses — and this check
 *     goes red at that moment rather than at the next audit.
 *
 * USAGE
 *   bun scripts/verify-production-reachability.ts
 *   exit 0 = every accepted-CVE package is genuinely absent from the production closure
 *            AND the runtime composition is unchanged.
 *   exit 1 = an exception basis no longer holds, or the probe could not trust itself.
 *
 * This is deliberately NOT a general SBOM tool. It answers exactly one question:
 * "is the vulnerable package in the dependency closure the production image installs?"
 */
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadGraph, reachableFrom } from "./security/runtime-import-closure.ts";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * CLASS A — accepted because the package is ABSENT from the production dependency
 * closure. The strongest form of the claim: the vulnerable code is not installed.
 * Keep in sync with docs/security/threat-model.mdx#known-accepted-cves.
 */
const ACCEPTED_MUST_BE_ABSENT = ["vite", "next"] as const;

/**
 * CLASS B — accepted on the WEAKER ground that the package IS installed in the
 * production closure but nothing in the runtime image imports it.
 *
 * `image-size` is here because the first version of this check caught the author
 * asserting it was absent when it is not. The runtime stage stubs only `web`; it
 * copies the REAL `packages/react/package.json`, so react's transitive dependencies
 * (wagmi, the Solana wallet adapters) are installed into the image closure even
 * though react's build output is never copied. Absence was the wrong claim.
 *
 * This class is deliberately separate so nobody can read "accepted" and assume
 * "not installed". Both facts are asserted below: it IS present, and no
 * runtime-shipped workspace package depends on the workspace that pulls it in.
 */
const ACCEPTED_PRESENT_BUT_UNIMPORTED = [
  { pkg: "image-size", viaWorkspace: "@stwd/react" },
] as const;

/**
 * Positive control: a correct production closure certainly contains these. If any is
 * missing we are inspecting the wrong/broken tree and every ABSENT result is worthless.
 */
const MUST_BE_PRESENT = ["hono", "drizzle-orm"] as const;

/** A real production closure is thousands of packages. Anything near zero is a failed install. */
const MIN_EXPECTED_PACKAGES = 500;

/**
 * Positive controls for the IMPORT-GRAPH probe (distinct from the install probe
 * above). These MUST be reachable from the runtime-shipped workspace roots. If they
 * are not, the graph walk is inspecting the wrong roots or the lockfile parse broke,
 * and every "not reachable" result it produces is worthless.
 */
const MUST_BE_IMPORT_REACHABLE = ["hono", "drizzle-orm"] as const;

/**
 * Floor on the import-reachable set. The real runtime closure is ~148 packages; a
 * handful would mean the walk terminated early and is silently under-reporting.
 */
const MIN_IMPORT_REACHABLE = 50;

/**
 * The runtime image copies build output for exactly these workspace packages.
 * Derived from the `COPY --from=build /app/packages/<name>` lines in the runtime stage.
 * If this set changes, the reachability basis for the accepted CVEs must be re-derived.
 */
const EXPECTED_RUNTIME_PACKAGES = [
  "api",
  "auth",
  "db",
  "policy-engine",
  "proxy",
  "redis",
  "sdk",
  "shared",
  "trade-sessions",
  "vault",
  "venue-hyperliquid",
  "webhooks",
].sort();

/** Workspace packages that introduce the accepted CVEs; must NOT reach the runtime image. */
const MUST_NOT_BE_IN_RUNTIME = ["web", "react", "eliza-plugin"] as const;

function fail(message: string): never {
  console.error(`\n[FAIL] ${message}`);
  process.exit(1);
}

/** Parse the runtime stage's package allowlist straight out of the Dockerfile. */
function runtimePackagesFromDockerfile(): string[] {
  const dockerfile = readFileSync(join(repoRoot, "Dockerfile"), "utf8");
  const runtimeStart = dockerfile.indexOf("FROM oven/bun:1.3-alpine AS runtime");
  if (runtimeStart === -1) {
    fail(
      "Could not locate the `runtime` stage in the Dockerfile. Image composition changed — re-derive the exception basis before editing this check.",
    );
  }
  const runtimeStage = dockerfile.slice(runtimeStart);
  const names = new Set<string>();
  for (const match of runtimeStage.matchAll(/COPY --from=build \/app\/packages\/([a-z0-9-]+)/g)) {
    names.add(match[1]!);
  }
  if (names.size === 0) {
    fail(
      "Parsed ZERO `COPY --from=build /app/packages/*` lines from the runtime stage. Either the Dockerfile changed shape or this parser is broken — refusing to report a clean result from a parse that found nothing.",
    );
  }
  return [...names].sort();
}

/** Build the production dependency closure exactly as the runtime stage does. */
function productionClosure(): string[] {
  const scratch = mkdtempSync(join(tmpdir(), "strata-926-reach-"));
  try {
    for (const file of ["package.json", "turbo.json", "tsconfig.json"]) {
      cpSync(join(repoRoot, file), join(scratch, file));
    }
    // EVERY workspace manifest must be copied or the install aborts with an unresolved
    // workspace and leaves an empty tree — one of the two original false-ABSENT probes.
    for (const group of ["packages", join("packages", "examples")]) {
      const dir = join(repoRoot, group);
      if (!existsSync(dir)) continue;
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (!entry.isDirectory()) continue;
        const manifest = join(dir, entry.name, "package.json");
        if (!existsSync(manifest)) continue;
        mkdirSync(join(scratch, group, entry.name), { recursive: true });
        cpSync(manifest, join(scratch, group, entry.name, "package.json"));
      }
    }
    // The runtime stage stubs `web` rather than shipping it.
    mkdirSync(join(scratch, "web"), { recursive: true });
    writeFileSync(
      join(scratch, "web", "package.json"),
      JSON.stringify({ name: "web", version: "0.0.0", private: true }),
    );

    const install = spawnSync("bun", ["install", "--production", "--ignore-scripts"], {
      cwd: scratch,
      encoding: "utf8",
      env: { ...process.env, CI: "false" },
      timeout: 600_000,
    });
    if (install.status !== 0) {
      fail(
        `production install failed (exit ${install.status}). A failed install yields an EMPTY tree, which would make every package look absent. Refusing to certify.\n${(install.stderr || "").slice(-800)}`,
      );
    }

    const store = join(scratch, "node_modules", ".bun");
    if (!existsSync(store)) {
      fail(
        "production install produced no `node_modules/.bun` store. Refusing to certify absence from a tree that does not exist.",
      );
    }
    return readdirSync(store);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

/** `.bun` store entries are `name@version` (scoped: `@scope+name@version`). */
function isPresent(closure: string[], pkg: string): string | null {
  const hit = closure.find((entry) => entry.startsWith(`${pkg}@`));
  return hit ?? null;
}

console.log("STRATA-926 production-image reachability check\n");

// ---- 1. Composition pin -----------------------------------------------------
const runtimePackages = runtimePackagesFromDockerfile();
console.log(`runtime image ships build output for ${runtimePackages.length} package(s):`);
console.log(`  ${runtimePackages.join(", ")}\n`);

const added = runtimePackages.filter((p) => !EXPECTED_RUNTIME_PACKAGES.includes(p));
const removed = EXPECTED_RUNTIME_PACKAGES.filter((p) => !runtimePackages.includes(p));
if (added.length > 0 || removed.length > 0) {
  fail(
    `runtime image composition CHANGED (added: ${added.join(", ") || "none"}; removed: ${removed.join(", ") || "none"}).\n` +
      "The accepted-CVE exceptions in docs/security/threat-model.mdx rest on this exact composition. " +
      "Re-derive reachability and update the exceptions before changing this pin.",
  );
}
for (const forbidden of MUST_NOT_BE_IN_RUNTIME) {
  if (runtimePackages.includes(forbidden)) {
    fail(
      `workspace package \`${forbidden}\` is now copied into the runtime image. It introduces an accepted CVE; the exception no longer holds.`,
    );
  }
}
console.log("composition pin: OK (unchanged, and no CVE-introducing workspace package ships)\n");

// ---- 2. Install liveness + positive control ---------------------------------
const closure = productionClosure();
console.log(`production dependency closure: ${closure.length} packages`);
if (closure.length < MIN_EXPECTED_PACKAGES) {
  fail(
    `closure has only ${closure.length} packages (expected >= ${MIN_EXPECTED_PACKAGES}). This is the empty/partial-install failure mode that previously produced false ABSENT results.`,
  );
}
for (const pkg of MUST_BE_PRESENT) {
  const hit = isPresent(closure, pkg);
  if (hit === null) {
    fail(
      `positive control \`${pkg}\` is MISSING from the production closure. The probe is inspecting the wrong tree; its ABSENT results cannot be trusted.`,
    );
  }
  console.log(`  positive control ${pkg}: PRESENT (${hit})`);
}
console.log("install liveness: OK\n");

// ---- 3. Import-graph liveness + positive control ----------------------------
// Distinct probe, distinct failure modes, so it gets its OWN controls. The
// install probe above proves the tree exists; this one proves the graph walk is
// actually traversing the modelled runtime roots rather than terminating early.
const importReachable = reachableFrom(
  loadGraph(join(repoRoot, "bun.lock")),
  EXPECTED_RUNTIME_PACKAGES.map((p) => `packages/${p}`),
);
console.log(
  `import graph: ${importReachable.keys.size} package(s) transitively reachable from the ${EXPECTED_RUNTIME_PACKAGES.length} runtime-shipped roots`,
);
if (importReachable.keys.size < MIN_IMPORT_REACHABLE) {
  fail(
    `only ${importReachable.keys.size} packages are import-reachable (expected >= ${MIN_IMPORT_REACHABLE}). The graph walk terminated early or the lockfile parse is broken; its "not reachable" results cannot be trusted.`,
  );
}
for (const pkg of MUST_BE_IMPORT_REACHABLE) {
  if (!importReachable.names.has(pkg)) {
    fail(
      `import-graph positive control \`${pkg}\` is NOT reachable from the runtime-shipped roots. The walk is inspecting the wrong graph; every "not reachable" result is worthless.`,
    );
  }
  console.log(`  positive control ${pkg}: import-REACHABLE`);
}
// Negative control: something that must NOT be reachable, proving the walk can
// actually answer "no" and does not simply mark everything reachable.
if (importReachable.names.has("@stwd/web")) {
  fail(
    "import-graph negative control failed: `@stwd/web` is reachable from the runtime roots, but the runtime stage stubs it. The walk is over-reporting.",
  );
}
console.log("  negative control @stwd/web: correctly NOT reachable");
console.log("import-graph liveness: OK\n");

// ---- 4. The actual question -------------------------------------------------
let broken = 0;

console.log("CLASS A — must be ABSENT from the production closure:");
for (const pkg of ACCEPTED_MUST_BE_ABSENT) {
  const hit = isPresent(closure, pkg);
  if (hit === null) {
    console.log(`  ${pkg.padEnd(12)} ABSENT — exception basis holds`);
  } else {
    console.error(`  ${pkg.padEnd(12)} PRESENT (${hit}) — EXCEPTION BASIS BROKEN`);
    broken++;
  }
}

console.log(
  "\nCLASS B — present in the closure, accepted only because nothing shipped imports them:",
);
for (const { pkg, viaWorkspace } of ACCEPTED_PRESENT_BUT_UNIMPORTED) {
  const hit = isPresent(closure, pkg);
  if (hit === null) {
    // Not a failure, but the documented basis is now stale and must be corrected:
    // an absent package should be promoted to CLASS A rather than left overstated.
    console.log(
      `  ${pkg.padEnd(12)} ABSENT — basis is now STRONGER than documented; promote to CLASS A.`,
    );
    continue;
  }
  console.log(
    `  ${pkg.padEnd(12)} PRESENT (${hit}) via ${viaWorkspace} — verifying nothing shipped imports it`,
  );

  // The whole exception rests on this: no package whose build output ships in the
  // runtime image may reach the CVE-bearing package.
  //
  // This is a FULL TRANSITIVE walk, not a one-hop manifest check. The earlier
  // version only asked "does a shipped package DIRECTLY declare @stwd/react",
  // which a path like `api -> agent-trader -> react` would have walked straight
  // through. Depth is exactly where this claim was weakest, so depth is what the
  // check now covers.
  if (!importReachable.names.has(viaWorkspace) && !importReachable.names.has(pkg)) {
    console.log(
      `  ${"".padEnd(12)} OK — no transitive import path from any runtime-shipped root to ${viaWorkspace} or ${pkg}`,
    );
    continue;
  }

  if (importReachable.names.has(pkg)) {
    console.error(
      `  ${"".padEnd(12)} ${pkg} IS transitively reachable from the runtime-shipped roots — CLASS B basis BROKEN.`,
    );
  }
  if (importReachable.names.has(viaWorkspace)) {
    console.error(
      `  ${"".padEnd(12)} ${viaWorkspace} IS transitively reachable from the runtime-shipped roots — CLASS B basis BROKEN.`,
    );
  }
  broken++;
}

if (broken > 0) {
  fail(
    `${broken} accepted-CVE disposition(s) no longer hold. Remediate or re-disposition before shipping.`,
  );
}

console.log(
  "\n[OK] every accepted-CVE disposition still holds, and runtime composition is unchanged.",
);
console.log("NOTE: CLASS B is a weaker claim than CLASS A. `image-size` IS installed in the");
console.log(
  "      production image closure; it is accepted only because nothing shipped imports it.",
);
