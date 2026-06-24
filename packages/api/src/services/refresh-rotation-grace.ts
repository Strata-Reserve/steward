/**
 * Refresh-token rotation grace cache.
 *
 * PROBLEM (the "keeps logging me out" bug):
 * Refresh tokens are single-use — `consumeRefreshToken` deletes the row on
 * consume and the handler mints a rotated successor. That is correct for
 * replay protection, but it makes CONCURRENT refreshes fatal: when two
 * refreshes present the SAME refresh token at nearly the same instant — which
 * happens routinely in real use (multiple browser tabs sharing one stored
 * refresh token; a tab waking from sleep firing both a proactive scheduler
 * refresh AND a reactive 401-retry refresh; two parallel API calls each
 * crossing the staleness boundary) — the first consume wins and ROTATES, and
 * every other concurrent attempt finds the row already deleted, gets
 * `401 Invalid or expired refresh token`, and the client treats that as a
 * genuine logout. The session dies for no real reason.
 *
 * FIX:
 * When a refresh succeeds and rotates, we briefly remember the successor it
 * minted, keyed by the OLD token's hash, for a short grace window. A racing /
 * retried refresh that presents the just-rotated old token gets handed back the
 * EXACT SAME successor (same new access token + same new refresh token) instead
 * of a 401. The result is idempotent under races: N concurrent refreshes of the
 * same token all converge on ONE successor, and nobody is logged out.
 *
 * SECURITY:
 * - The grace window is tiny (default 20s) and bound to the EXACT prior token
 *   hash, so this does not weaken single-use semantics in any meaningful way:
 *   an attacker replaying a stolen-and-already-rotated token more than ~20s
 *   later still gets 401. Within the window they could only ever receive the
 *   same successor the legitimate client already holds — no new authority.
 * - We store only what `/refresh` already returns to the caller (token,
 *   refreshToken, expiresIn). Nothing extra is exposed.
 *
 * DEPLOYMENT NOTE:
 * This is an in-process cache. It is correct because the prod Steward runs a
 * SINGLE replica (numReplicas: 1). If Steward is ever scaled to >1 replica,
 * promote this to a shared store (Redis) keyed identically, or move the
 * successor mapping into the refresh_tokens table (replaced_by columns). The
 * public contract (getGracedSuccessor / rememberRotation) stays the same.
 */

export interface RotationSuccessor {
  token: string;
  refreshToken: string;
  expiresIn: number;
}

interface GraceEntry extends RotationSuccessor {
  expiresAtMs: number;
}

/** Grace window in milliseconds. Overridable via env for tests / tuning. */
const GRACE_WINDOW_MS = (() => {
  const raw = (process.env.REFRESH_ROTATION_GRACE_MS ?? "").trim();
  const parsed = raw.length > 0 ? Number.parseInt(raw, 10) : NaN;
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 20_000;
})();

/** Hard cap on entries so a burst can never grow memory unbounded. */
const MAX_ENTRIES = 5_000;

// Keyed by the OLD (pre-rotation) token hash.
const cache = new Map<string, GraceEntry>();

function sweep(now: number): void {
  for (const [key, entry] of cache) {
    if (entry.expiresAtMs <= now) cache.delete(key);
  }
}

/**
 * Record the successor minted for a just-rotated token, so a racing refresh of
 * the same token can be served the SAME successor within the grace window.
 *
 * @param oldTokenHash hash of the token that was just consumed/rotated
 * @param successor    the access+refresh pair returned to the winning caller
 */
export function rememberRotation(oldTokenHash: string, successor: RotationSuccessor): void {
  const now = Date.now();
  // Opportunistic cleanup; cheap because the map is small and short-lived.
  if (cache.size >= MAX_ENTRIES) sweep(now);
  if (cache.size >= MAX_ENTRIES) {
    // Still full after sweep (pathological burst): drop the oldest entry.
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(oldTokenHash, { ...successor, expiresAtMs: now + GRACE_WINDOW_MS });
}

/**
 * If the given (already-consumed) token was rotated within the grace window,
 * return the successor that was minted for it. Otherwise null.
 *
 * @param oldTokenHash hash of the token the caller presented
 */
export function getGracedSuccessor(oldTokenHash: string): RotationSuccessor | null {
  const now = Date.now();
  const entry = cache.get(oldTokenHash);
  if (entry === undefined) return null;
  if (entry.expiresAtMs <= now) {
    cache.delete(oldTokenHash);
    return null;
  }
  return { token: entry.token, refreshToken: entry.refreshToken, expiresIn: entry.expiresIn };
}

/** Test/maintenance helper: clear all grace entries. */
export function __clearRotationGrace(): void {
  cache.clear();
}

/** Test helper: current grace window in ms. */
export function __graceWindowMs(): number {
  return GRACE_WINDOW_MS;
}
