/**
 * STRATA-926 — binding tests for the transitive import-closure walk.
 *
 * These exist because hostile review found the walk was blind to exactly the
 * path its own docstring advertised. In `bun.lock`, a workspace package is a
 * ONE-ELEMENT array with no dependency metadata, so every workspace package
 * looked like a leaf and the walk dead-ended at the first workspace hop.
 *
 * The `@stwd/web` negative control could not have caught it: it was vacuous,
 * unreachable regardless of the truth. A control that cannot fail is not a
 * control. These tests bind the fix so it cannot silently regress.
 */
import { describe, expect, it } from "bun:test";
import { buildGraph, reachableFrom } from "../security/runtime-import-closure.ts";

/**
 * Minimal lock in bun's real shape:
 *  - workspaces carry `name` + dependency fields
 *  - workspace packages appear in `packages` as ONE-ELEMENT arrays (no deps!)
 *  - registry packages are 4-element arrays with deps at index 2
 */
const LOCK = JSON.stringify({
  lockfileVersion: 1,
  workspaces: {
    "": { name: "root" },
    "packages/api": { name: "@stwd/api", dependencies: { "@stwd/mid": "workspace:*", hono: "^4" } },
    "packages/mid": { name: "@stwd/mid", dependencies: { "@stwd/leaf": "workspace:*" } },
    "packages/leaf": { name: "@stwd/leaf", dependencies: { "vuln-pkg": "^1" } },
    "packages/unshipped": { name: "@stwd/unshipped", dependencies: { "other-pkg": "^1" } },
  },
  packages: {
    // Workspace entries: one-element, dependency-less. This is the trap.
    "@stwd/api": ["@stwd/api@workspace:packages/api"],
    "@stwd/mid": ["@stwd/mid@workspace:packages/mid"],
    "@stwd/leaf": ["@stwd/leaf@workspace:packages/leaf"],
    "@stwd/unshipped": ["@stwd/unshipped@workspace:packages/unshipped"],
    hono: ["hono@4.13.1", "", {}, "sha512-x"],
    "vuln-pkg": ["vuln-pkg@1.0.0", "", { dependencies: { "deep-transitive": "^1" } }, "sha512-y"],
    "deep-transitive": ["deep-transitive@1.0.0", "", {}, "sha512-z"],
    "other-pkg": ["other-pkg@1.0.0", "", {}, "sha512-w"],
  },
});

describe("workspace-to-workspace traversal (the blind spot)", () => {
  const graph = buildGraph(LOCK);

  it("maps workspace package names to their workspace paths", () => {
    expect(graph.workspaceNameToPath.get("@stwd/api")).toBe("packages/api");
    expect(graph.workspaceNameToPath.get("@stwd/leaf")).toBe("packages/leaf");
  });

  it("traverses api -> mid -> leaf across TWO workspace hops", () => {
    const r = reachableFrom(graph, ["packages/api"]);
    expect(r.names.has("@stwd/mid")).toBe(true);
    // The hop that used to be lost: a workspace reached FROM another workspace.
    expect(r.names.has("@stwd/leaf")).toBe(true);
  });

  it("reaches a CVE that is only visible through a multi-hop workspace chain", () => {
    // Before the fix this was FALSE: the walk stopped at the first workspace
    // package and silently reported the vulnerable package as unreachable.
    const r = reachableFrom(graph, ["packages/api"]);
    expect(r.names.has("vuln-pkg")).toBe(true);
    expect(r.names.has("deep-transitive")).toBe(true);
  });

  it("still reaches ordinary registry dependencies", () => {
    expect(reachableFrom(graph, ["packages/api"]).names.has("hono")).toBe(true);
  });

  it("does NOT reach workspaces that are not in the root set (control can fail)", () => {
    // This is the non-vacuous negative control: `@stwd/unshipped` IS a workspace
    // with real deps and COULD be reached — it simply is not, from this root.
    const r = reachableFrom(graph, ["packages/api"]);
    expect(r.names.has("@stwd/unshipped")).toBe(false);
    expect(r.names.has("other-pkg")).toBe(false);
    // Proof the control is capable of being true: seed from it directly.
    const direct = reachableFrom(graph, ["packages/unshipped"]);
    expect(direct.names.has("other-pkg")).toBe(true);
  });

  it("refuses to compute from a root that does not exist", () => {
    expect(() => reachableFrom(graph, ["packages/nope"])).toThrow(/not present in bun.lock/);
  });

  it("terminates on cyclic workspace dependencies", () => {
    const cyclic = JSON.stringify({
      workspaces: {
        "packages/a": { name: "@x/a", dependencies: { "@x/b": "workspace:*" } },
        "packages/b": { name: "@x/b", dependencies: { "@x/a": "workspace:*" } },
      },
      packages: {
        "@x/a": ["@x/a@workspace:packages/a"],
        "@x/b": ["@x/b@workspace:packages/b"],
      },
    });
    const r = reachableFrom(buildGraph(cyclic), ["packages/a"]);
    expect(r.names.has("@x/b")).toBe(true);
  });
});

describe("the REAL lockfile", () => {
  it("keeps image-size and @stwd/react unreachable from the runtime roots", async () => {
    const lock = await Bun.file(new URL("../../bun.lock", import.meta.url)).text();
    const graph = buildGraph(lock);
    const roots = [
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
    ].map((p) => `packages/${p}`);
    const r = reachableFrom(graph, roots);

    // Positive controls: the walk is genuinely traversing.
    expect(r.names.has("hono")).toBe(true);
    expect(r.names.has("drizzle-orm")).toBe(true);
    // Workspace traversal specifically must be live on the real graph.
    expect(r.names.has("@stwd/shared")).toBe(true);
    expect(r.names.has("@stwd/db")).toBe(true);

    // The actual CLASS B claim.
    expect(r.names.has("@stwd/react")).toBe(false);
    expect(r.names.has("image-size")).toBe(false);
  });
});

/**
 * Round-2 findings. Each of these was "correct by luck" before the fix, so each
 * test is written to fail against the pre-fix behaviour, not merely to describe
 * the current one.
 */
describe("R2 F1 — workspace optionalDependencies are traversed", () => {
  const LOCK_OPT = JSON.stringify({
    workspaces: {
      "packages/api": { name: "@stwd/api", optionalDependencies: { "vuln-opt": "^1" } },
    },
    packages: {
      "@stwd/api": ["@stwd/api@workspace:packages/api"],
      "vuln-opt": ["vuln-opt@1.0.0", "", {}, "sha512-a"],
    },
  });

  it("follows a workspace optionalDependencies edge (was silently dropped)", () => {
    const r = reachableFrom(buildGraph(LOCK_OPT), ["packages/api"]);
    expect(r.names.has("vuln-opt")).toBe(true);
  });
});

describe("R2 F2 — runtime roots are inside their own closure", () => {
  const LOCK_SELF = JSON.stringify({
    workspaces: { "packages/api": { name: "@stwd/api", dependencies: { hono: "^4" } } },
    packages: {
      "@stwd/api": ["@stwd/api@workspace:packages/api"],
      hono: ["hono@4.13.1", "", {}, "sha512-b"],
    },
  });

  it("reports a shipped root as reachable from itself", () => {
    // Previously false: a CLASS B exception whose entry workspace IS a shipped
    // root would have been reported as having "no import path".
    const r = reachableFrom(buildGraph(LOCK_SELF), ["packages/api"]);
    expect(r.names.has("@stwd/api")).toBe(true);
    expect(r.names.has("hono")).toBe(true);
  });

  it("holds on the real lockfile for every shipped root", async () => {
    const lock = await Bun.file(new URL("../../bun.lock", import.meta.url)).text();
    const roots = [
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
    ];
    const r = reachableFrom(
      buildGraph(lock),
      roots.map((p) => `packages/${p}`),
    );
    for (const p of roots) expect(r.names.has(`@stwd/${p}`)).toBe(true);
    // and the CVE claims must survive the larger closure
    expect(r.names.has("image-size")).toBe(false);
    expect(r.names.has("@stwd/react")).toBe(false);
  });
});
