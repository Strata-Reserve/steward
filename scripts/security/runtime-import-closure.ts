/**
 * STRATA-926 — transitive import-reachability over the declared dependency graph.
 *
 * WHAT THIS PROVES, AND WHAT IT DOES NOT
 * --------------------------------------
 * The CLASS B acceptance for `image-size` rests on the claim that no package whose
 * build output is copied into the runtime image can reach it. The original check
 * tested only ONE HOP: "does a runtime-shipped package DIRECTLY declare `@stwd/react`".
 * That is too weak — `@stwd/api -> @stwd/agent-trader -> @stwd/react` would have
 * slipped straight through it.
 *
 * This module computes the FULL TRANSITIVE CLOSURE of the declared dependency graph
 * starting from the runtime-shipped workspace roots, so a path of any length is caught.
 *
 * PRECISION ABOUT THE CLAIM (do not overstate this):
 *   PROVEN here — no path exists from the runtime-shipped workspace roots to the
 *     vulnerable package through *declared* dependency edges (dependencies +
 *     peerDependencies, plus optionalDependencies for transitives) in `bun.lock`.
 *   NOT PROVEN here — that no source file performs an undeclared or dynamic import
 *     (`require(someVariable)`, deep path escapes, phantom deps resolved from a
 *     hoisted tree). A package cannot be imported by a runtime package without a
 *     declared edge *under normal resolution*, but phantom/hoisted resolution is a
 *     real failure mode and this module does not rule it out.
 *
 * That residual gap is carried as independently reviewed evidence in the threat
 * model, not as a machine-proven fact. See docs/security/threat-model.mdx.
 */
import { readFileSync } from "node:fs";

export interface LockGraph {
  /** Workspace path -> declared deps of that workspace. */
  workspaces: Map<string, Record<string, string>>;
  /** Lock key -> declared deps of that package. */
  packages: Map<string, Record<string, string>>;
  /** Every lock key, for resolution. */
  keys: Set<string>;
}

interface RawLock {
  workspaces?: Record<string, Record<string, unknown>>;
  packages?: Record<string, unknown[]>;
}

/**
 * `bun.lock` is JSONC with trailing commas. Strip them conservatively — only commas
 * immediately preceding a closing brace/bracket, never inside string literals.
 */
export function parseBunLock(text: string): RawLock {
  let out = "";
  let inString = false;
  let escaped = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;

    if (inString) {
      out += ch;
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }

    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }

    if (ch === ",") {
      // Look ahead past whitespace for a closer.
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j]!)) j++;
      if (j < text.length && (text[j] === "}" || text[j] === "]")) continue; // drop it
    }
    out += ch;
  }

  return JSON.parse(out) as RawLock;
}

const DEP_FIELDS_WORKSPACE = ["dependencies", "peerDependencies"] as const;
const DEP_FIELDS_TRANSITIVE = ["dependencies", "peerDependencies", "optionalDependencies"] as const;

export function buildGraph(lockText: string): LockGraph {
  const lock = parseBunLock(lockText);

  const workspaces = new Map<string, Record<string, string>>();
  for (const [path, meta] of Object.entries(lock.workspaces ?? {})) {
    const deps: Record<string, string> = {};
    for (const field of DEP_FIELDS_WORKSPACE) {
      Object.assign(deps, (meta as Record<string, unknown>)[field] ?? {});
    }
    workspaces.set(path, deps);
  }

  const packages = new Map<string, Record<string, string>>();
  for (const [key, entry] of Object.entries(lock.packages ?? {})) {
    const meta =
      Array.isArray(entry) && entry.length > 2 && typeof entry[2] === "object"
        ? (entry[2] as Record<string, unknown>)
        : {};
    const deps: Record<string, string> = {};
    for (const field of DEP_FIELDS_TRANSITIVE) {
      Object.assign(deps, (meta[field] as Record<string, string>) ?? {});
    }
    packages.set(key, deps);
  }

  return { workspaces, packages, keys: new Set(packages.keys()) };
}

/**
 * Resolve a dependency name as bun does: prefer the nested `<parent>/<name>` entry,
 * else the hoisted top-level `<name>` entry.
 */
function resolveKey(graph: LockGraph, name: string, parent: string): string | null {
  if (parent !== "") {
    const nested = `${parent}/${name}`;
    if (graph.keys.has(nested)) return nested;
  }
  return graph.keys.has(name) ? name : null;
}

/**
 * Every package transitively reachable from the given workspace roots through
 * declared dependency edges. Returns the set of resolved lock keys AND the set of
 * bare package names (a lock key may be nested, e.g. `foo/bar`).
 */
export function reachableFrom(
  graph: LockGraph,
  roots: readonly string[],
): { keys: Set<string>; names: Set<string> } {
  const seen = new Set<string>();
  const queue: string[] = [];

  for (const root of roots) {
    const deps = graph.workspaces.get(root);
    if (deps === undefined) {
      throw new Error(
        `workspace root \`${root}\` is not present in bun.lock. Refusing to compute reachability from a root that does not exist — that would silently under-report.`,
      );
    }
    for (const name of Object.keys(deps)) {
      const key = resolveKey(graph, name, "");
      if (key !== null && !seen.has(key)) {
        seen.add(key);
        queue.push(key);
      }
    }
  }

  while (queue.length > 0) {
    const current = queue.pop()!;
    for (const name of Object.keys(graph.packages.get(current) ?? {})) {
      const key = resolveKey(graph, name, current);
      if (key !== null && !seen.has(key)) {
        seen.add(key);
        queue.push(key);
      }
    }
  }

  // A nested key `a/b/c` denotes package `c`; reduce to bare names for lookups.
  const names = new Set<string>();
  for (const key of seen) names.add(key.split("/").pop()!);
  // Scoped packages keep their scope: `@scope/name` must not reduce to `name`.
  for (const key of seen) {
    const m = key.match(/(@[^/]+\/[^/]+)$/);
    if (m) names.add(m[1]!);
  }

  return { keys: seen, names };
}

export function loadGraph(lockPath: string): LockGraph {
  return buildGraph(readFileSync(lockPath, "utf8"));
}
