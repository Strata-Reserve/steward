/**
 * STRATA-1673 E7 S1: read back the authoritative issuance instruction from
 * Strata before the protected minter signs a mint without a human.
 *
 * Contract (Strata S2 must match exactly; also recorded in the PR body):
 *
 *   GET  ${STRATA_ISSUANCE_READBACK_URL}/internal/steward/issuance-instructions/:executionRef
 *        Authorization: Bearer ${STRATA_ISSUANCE_READBACK_TOKEN}
 *        Accept: application/json
 *
 *   200  {
 *          "tenantRef": string,             // Strata tenant reference
 *          "chainId": number,               // positive integer
 *          "token": "0x" + 40 hex,          // deal token contract (mint target)
 *          "recipient": "0x" + 40 hex,      // frozen destination snapshot
 *          "amount": string,                // base units, decimal integer, > 0
 *          "participationId": string,
 *          "mintId": string,
 *          "executionRef": string,          // must equal the path parameter
 *          "status": "authorized",          // the only accepted value
 *          "instructionDigest": "0x" + 64 hex
 *        }
 *   409  { "reason": string }               // not authorized (any §1.1 condition fails)
 *   any other status, timeout, network error, non-JSON or schema mismatch
 *        => unavailable (never signs).
 *
 * Unset URL or token => readback disabled: the protected path behaves exactly
 * as before S1 (every mint queues for a human).
 *
 * The client never decides; it only reports. The caller compares the
 * instruction with the decoded calldata field for field and falls back to the
 * human queue on anything other than an exact match.
 */

export const STRATA_ISSUANCE_READBACK_URL_ENV = "STRATA_ISSUANCE_READBACK_URL";
export const STRATA_ISSUANCE_READBACK_TOKEN_ENV = "STRATA_ISSUANCE_READBACK_TOKEN";
export const STRATA_ISSUANCE_READBACK_TIMEOUT_ENV = "STRATA_ISSUANCE_READBACK_TIMEOUT_MS";
export const DEFAULT_READBACK_TIMEOUT_MS = 5_000;
export const ISSUANCE_READBACK_PATH = "/internal/steward/issuance-instructions/";

export interface IssuanceInstruction {
  tenantRef: string;
  chainId: number;
  token: string;
  recipient: string;
  amount: string;
  participationId: string;
  mintId: string;
  executionRef: string;
  status: "authorized";
  instructionDigest: string;
}

export type ReadbackResult =
  | { kind: "disabled" }
  | { kind: "authorized"; instruction: IssuanceInstruction }
  | { kind: "refused"; reason: string }
  | { kind: "unavailable"; reason: string };

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export interface ReadbackConfig {
  baseUrl: string;
  token: string;
  timeoutMs: number;
}

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const DIGEST_RE = /^0x[0-9a-fA-F]{64}$/;
const AMOUNT_RE = /^[1-9][0-9]{0,77}$/;
const REASON_RE = /^[A-Za-z0-9_.:-]{1,128}$/;

/** Read config from env. Missing URL or token => null (feature off, fail-closed). */
export function readbackConfigFromEnv(
  env: Record<string, string | undefined> = process.env,
): ReadbackConfig | null {
  const baseUrl = env[STRATA_ISSUANCE_READBACK_URL_ENV]?.trim();
  const token = env[STRATA_ISSUANCE_READBACK_TOKEN_ENV]?.trim();
  if (!baseUrl || !token) return null;
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch {
    return null;
  }
  // https only, except loopback for local development.
  const loopback = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) return null;
  const rawTimeout = Number(env[STRATA_ISSUANCE_READBACK_TIMEOUT_ENV]);
  const timeoutMs =
    Number.isInteger(rawTimeout) && rawTimeout > 0 && rawTimeout <= 30_000
      ? rawTimeout
      : DEFAULT_READBACK_TIMEOUT_MS;
  return { baseUrl: baseUrl.replace(/\/+$/, ""), token, timeoutMs };
}

const EXPECTED_KEYS = [
  "tenantRef",
  "chainId",
  "token",
  "recipient",
  "amount",
  "participationId",
  "mintId",
  "executionRef",
  "status",
  "instructionDigest",
] as const;

/** Strict schema: exact key set, exact types. Returns null on any deviation. */
export function parseIssuanceInstruction(body: unknown): IssuanceInstruction | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  const o = body as Record<string, unknown>;
  const keys = Object.keys(o).sort();
  const expected = [...EXPECTED_KEYS].sort();
  if (keys.length !== expected.length || keys.some((k, i) => k !== expected[i])) return null;
  const str = (k: string) => typeof o[k] === "string" && (o[k] as string).length > 0;
  if (!str("tenantRef") || !str("participationId") || !str("mintId") || !str("executionRef"))
    return null;
  if (typeof o.chainId !== "number" || !Number.isSafeInteger(o.chainId) || o.chainId <= 0)
    return null;
  if (typeof o.token !== "string" || !ADDRESS_RE.test(o.token)) return null;
  if (typeof o.recipient !== "string" || !ADDRESS_RE.test(o.recipient)) return null;
  if (typeof o.amount !== "string" || !AMOUNT_RE.test(o.amount)) return null;
  if (o.status !== "authorized") return null;
  if (typeof o.instructionDigest !== "string" || !DIGEST_RE.test(o.instructionDigest)) return null;
  return o as unknown as IssuanceInstruction;
}

export class IssuanceReadbackClient {
  constructor(
    private readonly config: ReadbackConfig | null,
    private readonly fetchImpl: FetchLike = (input, init) => fetch(input, init),
  ) {}

  get enabled(): boolean {
    return this.config !== null;
  }

  async read(executionRef: string): Promise<ReadbackResult> {
    const cfg = this.config;
    if (!cfg) return { kind: "disabled" };
    const url = `${cfg.baseUrl}${ISSUANCE_READBACK_PATH}${encodeURIComponent(executionRef)}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), cfg.timeoutMs);
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method: "GET",
        headers: { Authorization: `Bearer ${cfg.token}`, Accept: "application/json" },
        signal: controller.signal,
        redirect: "error",
      });
    } catch (e) {
      clearTimeout(timer);
      const aborted = controller.signal.aborted || (e instanceof Error && e.name === "AbortError");
      return { kind: "unavailable", reason: aborted ? "readback_timeout" : "readback_unreachable" };
    }
    try {
      if (res.status === 409) {
        let reason = "readback_refused";
        try {
          const b = (await res.json()) as { reason?: unknown };
          if (typeof b?.reason === "string" && REASON_RE.test(b.reason)) reason = b.reason;
        } catch {
          // keep generic reason
        }
        return { kind: "refused", reason };
      }
      if (res.status !== 200) {
        return { kind: "unavailable", reason: `readback_http_${res.status}` };
      }
      let body: unknown;
      try {
        body = await res.json();
      } catch {
        return { kind: "unavailable", reason: "readback_malformed" };
      }
      const instruction = parseIssuanceInstruction(body);
      if (!instruction) return { kind: "unavailable", reason: "readback_malformed" };
      if (instruction.executionRef !== executionRef) {
        return { kind: "refused", reason: "readback_execution_ref_mismatch" };
      }
      return { kind: "authorized", instruction };
    } catch (e) {
      const aborted = controller.signal.aborted || (e instanceof Error && e.name === "AbortError");
      return { kind: "unavailable", reason: aborted ? "readback_timeout" : "readback_unreachable" };
    } finally {
      clearTimeout(timer);
    }
  }
}

export type CalldataMintFields = {
  chainId: number;
  token: string;
  recipient: string;
  amount: bigint;
};

/**
 * Exact match on (chainId, token, recipient, amount). Addresses compare
 * case-insensitively (same 20 bytes); amount compares as an integer.
 * Returns null on match, otherwise the first mismatching field.
 */
export function compareInstruction(
  instruction: IssuanceInstruction,
  calldata: CalldataMintFields,
): null | "chainId" | "token" | "recipient" | "amount" {
  if (instruction.chainId !== calldata.chainId) return "chainId";
  if (instruction.token.toLowerCase() !== calldata.token.toLowerCase()) return "token";
  if (instruction.recipient.toLowerCase() !== calldata.recipient.toLowerCase()) return "recipient";
  if (BigInt(instruction.amount) !== calldata.amount) return "amount";
  return null;
}

let activeClient: IssuanceReadbackClient = new IssuanceReadbackClient(readbackConfigFromEnv());

export function getIssuanceReadbackClient(): IssuanceReadbackClient {
  return activeClient;
}

/** Tests only: install a client (e.g. with a typed fake fetch). Null => from env. */
export function setIssuanceReadbackClient(client: IssuanceReadbackClient | null): void {
  activeClient = client ?? new IssuanceReadbackClient(readbackConfigFromEnv());
}
