/**
 * approve-cli.ts — attended canary approval for ONE pending protected-minter
 * action (STRATA-1499 SF-1). Stacked on Steward PR #28, which introduces the
 * `reviewDigest` + review projection on GET /vault/:agentId/pending and the
 * digest-echo contract on POST /vault/:agentId/approve/:txId.
 *
 * Commands:
 *   pending <agentId>          list pending actions with projection + reviewDigest
 *   approve <agentId> <txId>   re-fetch one item, show it, confirm, echo its digest
 *
 * Guarantees:
 *   - Allowlist (STEWARD_APPROVER_ALLOWLIST, comma-separated emails / user IDs)
 *     is checked client-side BEFORE any network call. Empty = refuse everything.
 *   - Session login via email magic link (POST /auth/email/send, then the token
 *     from the link is pasted interactively → POST /auth/email/verify). Tokens
 *     live only in a closure: never printed, logged, persisted, or in argv.
 *   - Approve echoes exactly the digest the operator just confirmed; if the
 *     server's digest changed between display and approve, refuse.
 *   - No other mutations exist here (no reject, no policy edits, no batch).
 *   - Non-2xx responses print the HTTP status code only.
 *
 * All IO is injected so tests run offline with a mocked fetch.
 */

export interface ApproveCliIo {
  out(line: string): void;
  err(line: string): void;
  /** Plain interactive prompt (echoed). */
  ask(question: string): Promise<string>;
  /** Interactive prompt for a secret (not echoed by the CLI). */
  askSecret(question: string): Promise<string>;
  fetch: typeof fetch;
}

export interface ApproveCliEnv {
  STEWARD_API_URL?: string;
  STEWARD_TENANT_ID?: string;
  STEWARD_APPROVER_ALLOWLIST?: string;
  STEWARD_APPROVER_EMAIL?: string;
  /** Optional claimed user ID, for allowlists pinned by ID; re-verified against the session after login. */
  STEWARD_APPROVER_USER_ID?: string;
}

export interface PendingItem {
  txId: string;
  executionRef: string;
  reviewDigest: string;
  requestedBy?: string;
  requestedAt?: string;
  review: Record<string, unknown>;
}

/** Exit codes: 0 ok, 1 request/usage failure, 2 refused by allowlist, 3 aborted/digest mismatch. */
export const EXIT = { OK: 0, FAIL: 1, REFUSED: 2, ABORTED: 3 } as const;

/** Keys of the review projection that are rendered as headline fields, not "decoded args". */
const HEADLINE_KEYS = new Set([
  "kind",
  "chainId",
  "to",
  "value",
  "selector",
  "executionRef",
  "signer",
]);

export function parseAllowlist(raw: string | undefined): Set<string> {
  return new Set(
    (raw ?? "")
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter((s) => s.length > 0),
  );
}

export function isAllowlisted(
  allow: Set<string>,
  ...identities: Array<string | undefined>
): boolean {
  if (allow.size === 0) return false;
  return identities.some((id) => typeof id === "string" && allow.has(id.trim().toLowerCase()));
}

export function renderPending(item: PendingItem): string[] {
  const r = item.review ?? {};
  const lines = [
    `txId:          ${item.txId}`,
    `executionRef:  ${item.executionRef}`,
    `kind:          ${String(r.kind ?? "?")}`,
    `chain:         ${String(r.chainId ?? "?")}`,
    `target:        ${String(r.to ?? "?")}`,
    `selector:      ${String(r.selector ?? "?")}`,
    `value:         ${String(r.value ?? "0")}`,
    `signer:        ${String(r.signer ?? "?")}`,
    "decoded args:",
  ];
  for (const [k, v] of Object.entries(r)) {
    if (HEADLINE_KEYS.has(k) || v === undefined) continue;
    lines.push(`  ${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`);
  }
  if (item.requestedBy) lines.push(`requestedBy:   ${item.requestedBy}`);
  lines.push(`reviewDigest:  ${item.reviewDigest}`);
  return lines;
}

function toPendingItem(raw: Record<string, unknown>): PendingItem | null {
  const tx = raw.transaction as Record<string, unknown> | undefined;
  const txId = typeof tx?.id === "string" ? tx.id : null;
  const reviewDigest = typeof raw.reviewDigest === "string" ? raw.reviewDigest : null;
  if (!txId || !reviewDigest) return null;
  return {
    txId,
    reviewDigest,
    executionRef: String(raw.executionRef ?? tx?.executionRef ?? "?"),
    requestedBy: typeof raw.requestedBy === "string" ? raw.requestedBy : undefined,
    requestedAt: typeof raw.requestedAt === "string" ? raw.requestedAt : undefined,
    review: (raw.review as Record<string, unknown>) ?? {},
  };
}

export async function runApproveCli(
  argv: string[],
  env: ApproveCliEnv,
  io: ApproveCliIo,
): Promise<number> {
  const [cmd, agentId, txIdArg] = argv;
  if (!(cmd === "pending" && agentId) && !(cmd === "approve" && agentId && txIdArg)) {
    io.err("usage: approve-cli pending <agentId> | approve <agentId> <txId>");
    return EXIT.FAIL;
  }

  // 1. Allowlist gate — strictly before any network call.
  const allow = parseAllowlist(env.STEWARD_APPROVER_ALLOWLIST);
  if (allow.size === 0) {
    io.err("refused: STEWARD_APPROVER_ALLOWLIST is empty or missing");
    return EXIT.REFUSED;
  }
  const email = (env.STEWARD_APPROVER_EMAIL ?? (await io.ask("approver email: ")))
    .trim()
    .toLowerCase();
  if (!isAllowlisted(allow, email, env.STEWARD_APPROVER_USER_ID)) {
    io.err("refused: identity is not in the approver allowlist");
    return EXIT.REFUSED;
  }

  const baseUrl = (env.STEWARD_API_URL ?? "http://localhost:3000").replace(/\/+$/, "");
  const tenantId = env.STEWARD_TENANT_ID;
  let session: string | null = null; // the only place the token ever lives

  async function api(
    path: string,
    init: { method?: string; body?: unknown } = {},
  ): Promise<{ status: number; json: Record<string, unknown> | null }> {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (init.body !== undefined) headers["Content-Type"] = "application/json";
    if (session) headers.Authorization = `Bearer ${session}`;
    if (tenantId) headers["X-Steward-Tenant"] = tenantId;
    let res: Response;
    try {
      res = await io.fetch(`${baseUrl}${path}`, {
        method: init.method ?? "GET",
        headers,
        body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
      });
    } catch {
      return { status: 0, json: null };
    }
    let json: Record<string, unknown> | null = null;
    try {
      json = (await res.json()) as Record<string, unknown>;
    } catch {
      json = null;
    }
    return { status: res.status, json };
  }

  function fail(label: string, status: number): number {
    io.err(`${label} failed: HTTP ${status}`);
    return EXIT.FAIL;
  }

  // 2. Session login (magic link). Token read interactively, never from argv.
  const send = await api("/auth/email/send", { method: "POST", body: { email, tenantId } });
  if (send.status < 200 || send.status >= 300) return fail("login (send)", send.status);
  io.out("magic link sent; paste the `token` query value from the link (input hidden)");
  const magicToken = (await io.askSecret("magic-link token: ")).trim();
  const verify = await api("/auth/email/verify", {
    method: "POST",
    body: { token: magicToken, email, tenantId },
  });
  if (verify.status < 200 || verify.status >= 300 || typeof verify.json?.token !== "string") {
    return fail("login (verify)", verify.status);
  }
  session = verify.json.token;
  const user = (verify.json.user as Record<string, unknown> | undefined) ?? {};
  const userId = typeof user.id === "string" ? user.id : undefined;
  const userEmail = typeof user.email === "string" ? user.email : undefined;
  if (!isAllowlisted(allow, userId, userEmail)) {
    session = null;
    io.err("refused: signed-in identity is not in the approver allowlist");
    return EXIT.REFUSED;
  }
  io.out(`signed in as ${userEmail ?? email}`);

  async function fetchPending(): Promise<PendingItem[] | number> {
    const res = await api(`/vault/${encodeURIComponent(agentId)}/pending`);
    if (res.status < 200 || res.status >= 300) return fail("pending", res.status);
    const data = Array.isArray(res.json?.data) ? (res.json.data as Record<string, unknown>[]) : [];
    return data.map(toPendingItem).filter((x): x is PendingItem => x !== null);
  }

  // 3. pending
  const first = await fetchPending();
  if (typeof first === "number") return first;
  if (cmd === "pending") {
    if (first.length === 0) io.out("no pending protected actions");
    first.forEach((item, i) => {
      io.out(`--- pending #${i + 1} ---`);
      for (const line of renderPending(item)) io.out(line);
    });
    return EXIT.OK;
  }

  // 4. approve <txId>
  const item = first.find((p) => p.txId === txIdArg);
  if (!item) {
    io.err(`txId ${txIdArg} is not pending for agent ${agentId}`);
    return EXIT.FAIL;
  }
  for (const line of renderPending(item)) io.out(line);
  const shown = item.reviewDigest;
  const prefix = shown.replace(/^0x/i, "").slice(0, 8).toLowerCase();
  const typed = (
    await io.ask(`type the first 8 hex chars of reviewDigest (${prefix}) to approve: `)
  )
    .trim()
    .replace(/^0x/i, "")
    .toLowerCase();
  if (typed !== prefix) {
    io.err("aborted: confirmation did not match the displayed digest");
    return EXIT.ABORTED;
  }
  const again = await fetchPending();
  if (typeof again === "number") return again;
  const current = again.find((p) => p.txId === txIdArg);
  if (!current || current.reviewDigest.toLowerCase() !== shown.toLowerCase()) {
    io.err("refused: reviewDigest changed (or item left pending) between display and approve");
    return EXIT.ABORTED;
  }
  const approve = await api(
    `/vault/${encodeURIComponent(agentId)}/approve/${encodeURIComponent(txIdArg)}`,
    { method: "POST", body: { reviewDigest: shown } },
  );
  if (approve.status < 200 || approve.status >= 300) return fail("approve", approve.status);
  const data = (approve.json?.data as Record<string, unknown> | undefined) ?? {};
  io.out(`approved txId=${String(data.txId ?? txIdArg)} txHash=${String(data.txHash ?? "?")}`);
  return EXIT.OK;
}
