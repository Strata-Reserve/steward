/**
 * STRATA-1499 (SF-1): protected production-minter boundary.
 *
 * One deployment-controlled manifest, fixed outside Avera, defines the only
 * signer this module protects and the only two call shapes it may ever sign:
 *
 *   createDealToken(string,string,address,address,bytes32)  0x2217bc2d
 *     to      = an approved factory
 *     admin   = the manifest Safe (DEFAULT_ADMIN_ROLE)
 *     minter  = the protected signer's own address (MINTER_ROLE)
 *   mint(address,uint256)                                   0x40c10f19
 *     to      = a manifest-verified Avera deal token
 *
 * chainId must be exactly the manifest's single pinned chain (8453 production;
 * 84532 only for a separately deployed rehearsal), value exactly 0, calldata
 * canonical with no trailing bytes. Everything else is refused. No API route
 * can change the manifest; changing it is a Steward release/config change.
 *
 * Chain binding (B1): one manifest == one signer == ONE chain. A process
 * installs exactly one manifest, so a protected signer can never sign or
 * propose for any chain but the one its manifest names. The chainId is part
 * of the manifest digest, so an 84532 manifest can never consume an 8453
 * review/permit or vice versa. There is no multi-chain manifest and no
 * per-request chain selection.
 *
 * Manifest source (env, read once at startup; absence == no protected signer):
 *   STEWARD_PROTECTED_MINTER_TENANT     tenant id (e.g. "strata")
 *   STEWARD_PROTECTED_MINTER_AGENT      immutable agent id
 *   STEWARD_PROTECTED_MINTER_ADDRESS    expected EVM address of the signer
 *   STEWARD_PROTECTED_MINTER_FACTORIES  comma-separated approved factory addresses
 *   STEWARD_PROTECTED_MINTER_TOKENS     comma-separated verified deal tokens,
 *                                       each `address@provenance` where
 *                                       provenance is the independently
 *                                       verified deploy tx hash / receipt ref
 *   STEWARD_PROTECTED_MINTER_CHAIN_ID   OPTIONAL. Unset => 8453 (production,
 *                                       byte-identical to before this knob
 *                                       existed). If set it must be exactly
 *                                       "8453" or "84532"; any other value
 *                                       (empty, a list, another chain, hex)
 *                                       is a malformed manifest and refuses
 *                                       startup.
 *   STEWARD_PROTECTED_MINTER_APPROVERS  comma-separated stable user IDs (the
 *                                       `users.id` UUID) of the ONLY humans who
 *                                       may approve for this signer. Email is
 *                                       not an identity here. Empty/unset =>
 *                                       NO approver (zero approve capability,
 *                                       fail-closed); a malformed entry is a
 *                                       malformed manifest and refuses startup.
 *                                       Part of the manifest digest, so any
 *                                       change invalidates pending reviews.
 *   (Safe admin is fixed in code: 0x3Ea77cDf3eC33603bF4135bb1a36712B5e21d721)
 *
 * If any of these is set, all of the required ones must be valid or startup
 * fails. There is no "protected but unconfigured" posture.
 *
 * Approver authority (STRATA-1499 SF-1, REVIEW-STEWARD-28-R3 platform finding):
 * tenant membership (owner/admin) is necessary but NOT sufficient to approve
 * for the protected signer. Platform membership administration can promote a
 * user to owner/admin; it cannot put that user in this allowlist, because the
 * allowlist lives only in the deployment-controlled manifest and no API route
 * reaches it.
 */

import {
  agents,
  approvalQueue,
  getDb,
  protectedMinterControls,
  protectedMinterTokens,
  transactions,
} from "@stwd/db";
import {
  chainRpcUrlsFromEnv,
  computeProtectedReviewDigest,
  isUndefinedColumn,
  type ProtectedSignerGuard,
  type ProtectedTransactionShape,
  type ProtectedValidation,
  registerProtectedSignerGuard,
  resolveEvmRpcUrl,
} from "@stwd/vault";
import { and, desc, eq, inArray, isNotNull, like, sql } from "drizzle-orm";
import {
  createPublicClient,
  decodeEventLog,
  decodeFunctionData,
  encodeFunctionData,
  http,
  keccak256,
  parseAbi,
  stringToHex,
  toFunctionSelector,
} from "viem";

// ─── Fixed constants ─────────────────────────────────────────────────────────

/** 2-of-3 Safe that holds DEFAULT_ADMIN_ROLE on every deal token. Fixed. */
export const PROTECTED_MINTER_SAFE_ADMIN = "0x3Ea77cDf3eC33603bF4135bb1a36712B5e21d721";
/** Production chain. The default and the only chain when no chain is configured. */
export const PROTECTED_MINTER_CHAIN_ID = 8453;
/** Base Sepolia rehearsal chain. Only reachable via an explicit, separately deployed manifest. */
export const PROTECTED_MINTER_REHEARSAL_CHAIN_ID = 84532;
export type ProtectedMinterChainId =
  | typeof PROTECTED_MINTER_CHAIN_ID
  | typeof PROTECTED_MINTER_REHEARSAL_CHAIN_ID;
export const PROTECTED_MINTER_ALLOWED_CHAIN_IDS: readonly ProtectedMinterChainId[] = Object.freeze([
  PROTECTED_MINTER_CHAIN_ID,
  PROTECTED_MINTER_REHEARSAL_CHAIN_ID,
]);

export function isProtectedMinterChainId(v: unknown): v is ProtectedMinterChainId {
  return (
    typeof v === "number" &&
    Number.isInteger(v) &&
    (PROTECTED_MINTER_ALLOWED_CHAIN_IDS as readonly number[]).includes(v)
  );
}

export const SELECTOR_CREATE_DEAL_TOKEN = toFunctionSelector(
  "createDealToken(string,string,address,address,bytes32)",
);
export const SELECTOR_MINT = toFunctionSelector("mint(address,uint256)");
/**
 * STRATA-1673 H2: the trusted RestrictedDealTokenFactory surface (Strata
 * contracts-core IRestrictedDealTokenFactory @ 9d5ecb8d2). Only tokens it
 * produced, from Steward's own protected deploy, are admitted for auto-sign.
 */
export const SELECTOR_CREATE_RESTRICTED_DEAL_TOKEN = toFunctionSelector(
  "createRestrictedDealToken(string,string,uint8,(address,address,address,address),bytes32)",
);
export const RESTRICTED_FACTORY_VERSION = "RestrictedDealTokenFactory/1.0.0";
export const RESTRICTED_FACTORY_VERSION_ID = keccak256(stringToHex(RESTRICTED_FACTORY_VERSION));
export const DEFAULT_ADMIN_ROLE = `0x${"0".repeat(64)}` as `0x${string}`;
export const ISSUER_ROLE = keccak256(stringToHex("STRATA_ISSUER_ROLE"));
/** Blocks on top of the deploy receipt's block before admission. */
export const PROTECTED_ADMISSION_MIN_CONFIRMATIONS = 10n;

if (SELECTOR_CREATE_DEAL_TOKEN !== "0x2217bc2d" || SELECTOR_MINT !== "0x40c10f19") {
  throw new Error("protected minter: selector constants do not match DealTokenFactory/DealTokenV1");
}

// ─── Manifest ────────────────────────────────────────────────────────────────

export interface VerifiedToken {
  address: string;
  /** Independently verified provenance (deploy tx hash / receipt reference). */
  provenance: string;
}

export interface ProtectedMinterManifest {
  tenantId: string;
  agentId: string;
  signerAddress: string;
  /** Exactly ONE chain. 8453 in production; 84532 only in the rehearsal deployment. */
  chainId: ProtectedMinterChainId;
  safeAdmin: string;
  factories: string[];
  verifiedTokens: VerifiedToken[];
  /**
   * Pinned approver allowlist: stable user IDs (`users.id` UUIDs) of the only
   * humans allowed to approve for this signer. Empty => nobody can approve.
   */
  approvers: string[];
}

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const USER_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;

function lower(a: string): string {
  return a.toLowerCase();
}

export function validateManifest(m: ProtectedMinterManifest): void {
  if (!m.tenantId || !m.agentId) throw new Error("protected minter: tenantId/agentId required");
  if (!ADDRESS_RE.test(m.signerAddress)) throw new Error("protected minter: bad signerAddress");
  if (lower(m.signerAddress) === ZERO_ADDRESS)
    throw new Error("protected minter: signerAddress is zero");
  // B1: exactly one chain, and it must be a member of the fixed allowlist. A
  // missing chain, an array ("two chains"), a string or any other chain id is
  // a malformed manifest.
  if (!isProtectedMinterChainId(m.chainId))
    throw new Error(
      `protected minter: chainId must be exactly one of ${PROTECTED_MINTER_ALLOWED_CHAIN_IDS.join("|")}`,
    );
  if (lower(m.safeAdmin) !== lower(PROTECTED_MINTER_SAFE_ADMIN))
    throw new Error("protected minter: safeAdmin is not the fixed Safe");
  if (lower(m.safeAdmin) === lower(m.signerAddress))
    throw new Error("protected minter: safeAdmin must differ from signer");
  if (!Array.isArray(m.factories) || m.factories.some((f) => !ADDRESS_RE.test(f)))
    throw new Error("protected minter: bad factories");
  if (!Array.isArray(m.verifiedTokens)) throw new Error("protected minter: bad verifiedTokens");
  for (const t of m.verifiedTokens) {
    if (!ADDRESS_RE.test(t.address)) throw new Error("protected minter: bad verified token");
    if (!t.provenance || typeof t.provenance !== "string")
      throw new Error(`protected minter: token ${t.address} lacks verified provenance`);
    if (m.factories.some((f) => lower(f) === lower(t.address)))
      throw new Error("protected minter: a factory cannot also be a mint target");
  }
  // Approver allowlist: required field; may be empty (fail-closed: no approver),
  // but every entry must be a stable user ID and entries must be unique.
  if (!Array.isArray(m.approvers)) throw new Error("protected minter: bad approvers");
  const seen = new Set<string>();
  for (const a of m.approvers) {
    if (typeof a !== "string" || !USER_ID_RE.test(a))
      throw new Error("protected minter: approvers must be stable user IDs (uuid)");
    if (seen.has(lower(a))) throw new Error("protected minter: duplicate approver");
    seen.add(lower(a));
  }
}

export function computeManifestDigest(m: ProtectedMinterManifest): `0x${string}` {
  const canonical = JSON.stringify({
    v: 1,
    tenantId: m.tenantId,
    agentId: m.agentId,
    signerAddress: lower(m.signerAddress),
    chainId: m.chainId,
    safeAdmin: lower(m.safeAdmin),
    factories: [...m.factories].map(lower).sort(),
    verifiedTokens: [...m.verifiedTokens]
      .map((t) => ({ address: lower(t.address), provenance: t.provenance }))
      .sort((a, b) => (a.address < b.address ? -1 : 1)),
    approvers: [...m.approvers].map(lower).sort(),
  });
  return keccak256(stringToHex(canonical));
}

function parseList(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * B1: unset => production 8453 (unchanged behaviour). Set => must be the exact
 * decimal string of ONE allowed chain. Anything else throws (malformed
 * manifest => startup refused). Validation runs again in validateManifest.
 */
export function parseChainIdEnv(raw: string | undefined): ProtectedMinterChainId {
  if (raw === undefined) return PROTECTED_MINTER_CHAIN_ID;
  const allowed = PROTECTED_MINTER_ALLOWED_CHAIN_IDS.join("|");
  if (!/^\d+$/.test(raw)) {
    throw new Error(
      `protected minter: STEWARD_PROTECTED_MINTER_CHAIN_ID must be exactly one of ${allowed}`,
    );
  }
  const n = Number(raw);
  if (!isProtectedMinterChainId(n) || String(n) !== raw) {
    throw new Error(
      `protected minter: STEWARD_PROTECTED_MINTER_CHAIN_ID must be exactly one of ${allowed}`,
    );
  }
  return n;
}

export function manifestFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): ProtectedMinterManifest | null {
  const keys = [
    "STEWARD_PROTECTED_MINTER_TENANT",
    "STEWARD_PROTECTED_MINTER_AGENT",
    "STEWARD_PROTECTED_MINTER_ADDRESS",
    "STEWARD_PROTECTED_MINTER_FACTORIES",
    "STEWARD_PROTECTED_MINTER_TOKENS",
    // REVIEW-STEWARD-28-R5 F1: every manifest field activates validation, so
    // an approvers-only (partial or malformed) config is fatal, never ignored.
    "STEWARD_PROTECTED_MINTER_APPROVERS",
  ];
  // B1 / REVIEW-SF1-DELTA F1: the chain knob is an exact-string contract, so
  // mere presence (even "" or whitespace) activates validation and is fatal
  // when malformed. Only a truly unset key keeps the 8453 default. A chain-only
  // env is a partial manifest and fatal, never ignored.
  const chainPresent = env.STEWARD_PROTECTED_MINTER_CHAIN_ID !== undefined;
  if (!chainPresent && !keys.some((k) => env[k] !== undefined && env[k] !== "")) return null;
  const tokens = parseList(env.STEWARD_PROTECTED_MINTER_TOKENS).map((entry) => {
    const [address, provenance] = entry.split("@");
    return { address: address ?? "", provenance: provenance ?? "" };
  });
  const manifest: ProtectedMinterManifest = {
    tenantId: env.STEWARD_PROTECTED_MINTER_TENANT ?? "",
    agentId: env.STEWARD_PROTECTED_MINTER_AGENT ?? "",
    signerAddress: env.STEWARD_PROTECTED_MINTER_ADDRESS ?? "",
    chainId: parseChainIdEnv(env.STEWARD_PROTECTED_MINTER_CHAIN_ID),
    safeAdmin: PROTECTED_MINTER_SAFE_ADMIN,
    factories: parseList(env.STEWARD_PROTECTED_MINTER_FACTORIES),
    verifiedTokens: tokens,
    // Unset/empty => [] => no approver (fail-closed). Malformed => throws.
    approvers: parseList(env.STEWARD_PROTECTED_MINTER_APPROVERS),
  };
  validateManifest(manifest);
  return manifest;
}

// ─── Strict calldata decoding ────────────────────────────────────────────────
//
// Adapted from draft #25 (237dcbd7) calldata.ts with the factory ABI corrected
// to five arguments (admin=arg3, minter=arg4). Every branch is fail-closed:
// exact canonical length, zero address padding, in-range word-aligned offsets,
// tails laid out back to back with no stray bytes.

const CREATE_DEAL_TOKEN_ABI = parseAbi([
  "function createDealToken(string name, string symbol, address admin, address minter, bytes32 salt) returns (address)",
]);
const SELECTOR_HEX = 8;
const WORD_HEX = 64;

export interface DecodedCreateDealToken {
  kind: "createDealToken";
  selector: string;
  name: string;
  symbol: string;
  admin: string;
  minter: string;
  salt: string;
}

export interface DecodedMint {
  kind: "mint";
  selector: string;
  recipient: string;
  amount: bigint;
}

export interface DecodedCreateRestrictedDealToken {
  kind: "createRestrictedDealToken";
  selector: string;
  name: string;
  symbol: string;
  decimals: number;
  admin: string;
  issuer: string;
  operator: string;
  pauser: string;
  salt: string;
}

export type DecodedProtectedCall =
  | DecodedCreateDealToken
  | DecodedCreateRestrictedDealToken
  | DecodedMint;

const CREATE_RESTRICTED_DEAL_TOKEN_ABI = parseAbi([
  "struct RoleConfig { address admin; address issuer; address operator; address pauser; }",
  "function createRestrictedDealToken(string name, string symbol, uint8 decimals, RoleConfig roles, bytes32 salt) returns (address token)",
]);

/** Strict: ABI decode, then the re-encoding must reproduce the input bytes. */
export function decodeCreateRestrictedDealToken(
  data: unknown,
): DecodedCreateRestrictedDealToken | null {
  if (typeof data !== "string" || !/^0x[0-9a-fA-F]*$/.test(data)) return null;
  const hex = data.toLowerCase() as `0x${string}`;
  if (!hex.startsWith(SELECTOR_CREATE_RESTRICTED_DEAL_TOKEN)) return null;
  try {
    const d = decodeFunctionData({ abi: CREATE_RESTRICTED_DEAL_TOKEN_ABI, data: hex });
    const [name, symbol, decimals, roles, salt] = d.args as unknown as [
      string,
      string,
      number,
      { admin: string; issuer: string; operator: string; pauser: string },
      `0x${string}`,
    ];
    const re = encodeFunctionData({
      abi: CREATE_RESTRICTED_DEAL_TOKEN_ABI,
      functionName: "createRestrictedDealToken",
      args: [name, symbol, decimals, roles as never, salt],
    }).toLowerCase();
    if (re !== hex) return null;
    return {
      kind: "createRestrictedDealToken",
      selector: SELECTOR_CREATE_RESTRICTED_DEAL_TOKEN,
      name,
      symbol,
      decimals,
      admin: lower(roles.admin),
      issuer: lower(roles.issuer),
      operator: lower(roles.operator),
      pauser: lower(roles.pauser),
      salt: lower(salt),
    };
  } catch {
    return null;
  }
}

function normalizeHex(data: unknown): string | null {
  if (typeof data !== "string") return null;
  if (!(data.startsWith("0x") || data.startsWith("0X"))) return null;
  const body = data.slice(2);
  if (body.length % 2 !== 0) return null;
  if (!/^[0-9a-fA-F]*$/.test(body)) return null;
  return body.toLowerCase();
}

function readWord(hex: string, index: number): string | null {
  const start = SELECTOR_HEX + index * WORD_HEX;
  const end = start + WORD_HEX;
  if (end > hex.length) return null;
  return hex.slice(start, end);
}

function readAddressWord(hex: string, index: number): string | null {
  const word = readWord(hex, index);
  if (word === null) return null;
  if (!/^0{24}[0-9a-f]{40}$/.test(word)) return null;
  return `0x${word.slice(24)}`;
}

function readUint256Word(hex: string, index: number): bigint | null {
  const word = readWord(hex, index);
  if (word === null) return null;
  return BigInt(`0x${word}`);
}

function readOffsetWord(hex: string, index: number, argsLength: number): number | null {
  const word = readWord(hex, index);
  if (word === null) return null;
  const offset = BigInt(`0x${word}`);
  if (offset % 32n !== 0n) return null;
  if (offset >= BigInt(argsLength)) return null;
  return Number(offset);
}

/** Returns {end, value} for a dynamic string tail at `offset` bytes into args, or null. */
function readDynamicString(argsHex: string, offset: number): { end: number; value: string } | null {
  const lenStart = offset * 2;
  const lenEnd = lenStart + WORD_HEX;
  if (lenEnd > argsHex.length) return null;
  const length = BigInt(`0x${argsHex.slice(lenStart, lenEnd)}`);
  if (length > 4096n) return null;
  const len = Number(length);
  const paddedLen = Math.ceil(len / 32) * 32;
  const dataStart = lenEnd;
  const dataEnd = dataStart + paddedLen * 2;
  if (dataEnd > argsHex.length) return null;
  const payload = argsHex.slice(dataStart, dataStart + len * 2);
  const padding = argsHex.slice(dataStart + len * 2, dataEnd);
  if (!/^0*$/.test(padding)) return null;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = parseInt(payload.slice(i * 2, i * 2 + 2), 16);
  let value: string;
  try {
    value = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
  return { end: offset + 32 + paddedLen, value };
}

export function decodeCreateDealToken(data: unknown): DecodedCreateDealToken | null {
  const hex = normalizeHex(data);
  if (hex === null || hex.length < SELECTOR_HEX) return null;
  const selector = `0x${hex.slice(0, SELECTOR_HEX)}`;
  if (selector !== SELECTOR_CREATE_DEAL_TOKEN) return null;
  const argsHex = hex.slice(SELECTOR_HEX);
  const argsLength = argsHex.length / 2;
  // Head (5 words) + at least one length word per string.
  if (argsLength < 7 * 32 || argsLength % 32 !== 0) return null;

  const nameOffset = readOffsetWord(hex, 0, argsLength);
  const symbolOffset = readOffsetWord(hex, 1, argsLength);
  const admin = readAddressWord(hex, 2);
  const minter = readAddressWord(hex, 3);
  const salt = readWord(hex, 4);
  if (
    nameOffset === null ||
    symbolOffset === null ||
    admin === null ||
    minter === null ||
    salt === null
  )
    return null;
  if (nameOffset < 5 * 32 || symbolOffset < 5 * 32) return null;

  const name = readDynamicString(argsHex, nameOffset);
  const symbol = readDynamicString(argsHex, symbolOffset);
  if (name === null || symbol === null) return null;

  const [first, second] =
    nameOffset <= symbolOffset
      ? [
          { start: nameOffset, end: name.end },
          { start: symbolOffset, end: symbol.end },
        ]
      : [
          { start: symbolOffset, end: symbol.end },
          { start: nameOffset, end: name.end },
        ];
  if (first.start !== 5 * 32) return null;
  if (second.start !== first.end) return null;
  if (second.end !== argsLength) return null;

  // Canonical encoding: decode -> re-encode must reproduce the input bytes
  // exactly (name tail before symbol tail, no swapped tails, no slack).
  const reencoded = encodeFunctionData({
    abi: CREATE_DEAL_TOKEN_ABI,
    functionName: "createDealToken",
    args: [name.value, symbol.value, admin as `0x${string}`, minter as `0x${string}`, `0x${salt}`],
  }).toLowerCase();
  if (reencoded !== `0x${hex}`) return null;

  return {
    kind: "createDealToken",
    selector,
    name: name.value,
    symbol: symbol.value,
    admin,
    minter,
    salt: `0x${salt}`,
  };
}

export function decodeMint(data: unknown): DecodedMint | null {
  const hex = normalizeHex(data);
  if (hex === null || hex.length < SELECTOR_HEX) return null;
  const selector = `0x${hex.slice(0, SELECTOR_HEX)}`;
  if (selector !== SELECTOR_MINT) return null;
  if (hex.length !== SELECTOR_HEX + 2 * WORD_HEX) return null;
  const recipient = readAddressWord(hex, 0);
  const amount = readUint256Word(hex, 1);
  if (recipient === null || amount === null) return null;
  return { kind: "mint", selector, recipient, amount };
}

// ─── Validation + review projection ──────────────────────────────────────────

export interface ProtectedReviewProjection {
  kind: "createDealToken" | "createRestrictedDealToken" | "mint";
  chainId: number;
  to: string;
  value: string;
  selector: string;
  executionRef: string;
  signer: string;
  /** createDealToken */
  factory?: string;
  name?: string;
  symbol?: string;
  salt?: string;
  adminSafe?: string;
  minter?: string;
  /** createRestrictedDealToken (H2) */
  issuer?: string;
  operator?: string;
  pauser?: string;
  decimals?: number;
  predictedTokenAddress?: string | null;
  predictedTokenAddressNote?: string;
  /** mint */
  token?: string;
  tokenProvenance?: string;
  recipient?: string;
  amount?: string;
}

export type ProtectedShapeResult =
  | { ok: true; decoded: DecodedProtectedCall; projection: ProtectedReviewProjection }
  | { ok: false; reason: string };

/**
 * STRATA-1673 S1: the mint target set is manifest tokens UNION the active
 * `protected_minter_tokens` rows for this (tenant, agent, manifest chain),
 * passed in by the caller (the lookup is async; see `listAdmittedTokens`).
 */
export function validateProtectedShape(
  manifest: ProtectedMinterManifest,
  tx: ProtectedTransactionShape & { executionRef?: string },
  admittedTokens: readonly VerifiedToken[] = [],
  revokedTokens: readonly string[] = [],
): ProtectedShapeResult {
  // B1: bound to the manifest's single chain, never to a global constant.
  if (typeof tx.chainId !== "number" || tx.chainId !== manifest.chainId) {
    return { ok: false, reason: `chainId must be exactly ${manifest.chainId}` };
  }
  // STRATA-1673 H3: a revoked admission overrides manifest membership, for
  // every path (auto, human, key use).
  if (typeof tx.to === "string" && revokedTokens.some((t) => lower(t) === lower(tx.to))) {
    return { ok: false, reason: "token admission is revoked" };
  }
  let value: bigint;
  try {
    value = BigInt(String(tx.value));
  } catch {
    return { ok: false, reason: "value must be a decimal integer" };
  }
  if (value !== 0n || !/^0+$/.test(String(tx.value).trim())) {
    return { ok: false, reason: "value must be exactly 0" };
  }
  if (typeof tx.to !== "string" || !ADDRESS_RE.test(tx.to)) {
    return { ok: false, reason: "to must be an EVM address" };
  }
  const to = lower(tx.to);
  const data = tx.data;
  if (typeof data !== "string" || normalizeHex(data) === null || normalizeHex(data)!.length < 8) {
    return { ok: false, reason: "calldata is missing or malformed" };
  }
  const selector = `0x${normalizeHex(data)!.slice(0, 8)}`;
  const base = {
    chainId: tx.chainId,
    to: tx.to,
    value: "0",
    selector,
    executionRef: tx.executionRef ?? "",
    signer: manifest.signerAddress,
  };

  const factory = manifest.factories.find((f) => lower(f) === to);
  if (factory && selector === SELECTOR_CREATE_RESTRICTED_DEAL_TOKEN) {
    const d = decodeCreateRestrictedDealToken(data);
    if (!d) return { ok: false, reason: "createRestrictedDealToken calldata is not canonical" };
    const signer = lower(manifest.signerAddress);
    if (d.admin !== lower(manifest.safeAdmin)) {
      return { ok: false, reason: "createRestrictedDealToken admin must be the manifest Safe" };
    }
    if (d.issuer !== signer) {
      return { ok: false, reason: "createRestrictedDealToken issuer must be the protected signer" };
    }
    for (const [k, v] of [
      ["operator", d.operator],
      ["pauser", d.pauser],
    ] as const) {
      if (v === ZERO_ADDRESS || v === signer || v === lower(factory)) {
        return {
          ok: false,
          reason: `createRestrictedDealToken ${k} must be nonzero and not the signer`,
        };
      }
    }
    if (d.name.length === 0 || d.symbol.length === 0) {
      return { ok: false, reason: "createRestrictedDealToken name/symbol must be non-empty" };
    }
    return {
      ok: true,
      decoded: d,
      projection: {
        ...base,
        kind: "createRestrictedDealToken",
        factory,
        name: d.name,
        symbol: d.symbol,
        decimals: d.decimals,
        salt: d.salt,
        adminSafe: manifest.safeAdmin,
        issuer: manifest.signerAddress,
        operator: d.operator,
        pauser: d.pauser,
        predictedTokenAddress: null,
        predictedTokenAddressNote:
          "RestrictedDealTokenFactory deploys with CREATE; the token address is read from the RestrictedDealTokenDeployed receipt at admission.",
      },
    };
  }
  if (factory) {
    if (selector !== SELECTOR_CREATE_DEAL_TOKEN) {
      return {
        ok: false,
        reason: "factory target permits only createRestrictedDealToken or createDealToken",
      };
    }
    const decoded = decodeCreateDealToken(data);
    if (!decoded) return { ok: false, reason: "createDealToken calldata is not canonical" };
    if (lower(decoded.admin) !== lower(manifest.safeAdmin)) {
      return { ok: false, reason: "createDealToken admin must be the manifest Safe" };
    }
    if (lower(decoded.minter) !== lower(manifest.signerAddress)) {
      return { ok: false, reason: "createDealToken minter must be the protected signer" };
    }
    if (decoded.name.length === 0 || decoded.symbol.length === 0) {
      return { ok: false, reason: "createDealToken name/symbol must be non-empty" };
    }
    return {
      ok: true,
      decoded,
      projection: {
        ...base,
        kind: "createDealToken",
        factory,
        name: decoded.name,
        symbol: decoded.symbol,
        salt: decoded.salt,
        adminSafe: manifest.safeAdmin,
        minter: manifest.signerAddress,
        predictedTokenAddress: null,
        predictedTokenAddressNote:
          "DealTokenFactory deploys with CREATE (factory nonce), not CREATE2; address is not computable offline. Verify from the DealTokenDeployed receipt.",
      },
    };
  }

  const token =
    manifest.verifiedTokens.find((t) => lower(t.address) === to) ??
    admittedTokens.find((t) => lower(t.address) === to);
  if (token) {
    if (selector !== SELECTOR_MINT) {
      return { ok: false, reason: "verified token target permits only mint (0x40c10f19)" };
    }
    const decoded = decodeMint(data);
    if (!decoded) return { ok: false, reason: "mint calldata is not canonical (68 bytes)" };
    if (lower(decoded.recipient) === ZERO_ADDRESS) {
      return { ok: false, reason: "mint recipient must be nonzero" };
    }
    if (decoded.amount <= 0n) return { ok: false, reason: "mint amount must be positive" };
    return {
      ok: true,
      decoded,
      projection: {
        ...base,
        kind: "mint",
        token: token.address,
        tokenProvenance: token.provenance,
        recipient: decoded.recipient,
        amount: decoded.amount.toString(),
      },
    };
  }

  return { ok: false, reason: "target is neither an approved factory nor a verified deal token" };
}

// ─── Runtime registry ────────────────────────────────────────────────────────

let activeManifest: ProtectedMinterManifest | null = null;
let activeDigest = "";

function buildGuard(manifest: ProtectedMinterManifest, digest: string): ProtectedSignerGuard {
  return {
    isProtected: (tenantId, agentId) =>
      tenantId === manifest.tenantId && agentId === manifest.agentId,
    expectedAddress: (tenantId, agentId) =>
      tenantId === manifest.tenantId && agentId === manifest.agentId
        ? manifest.signerAddress
        : null,
    manifestDigest: () => digest,
    validateTransaction: async (tx, scope): Promise<ProtectedValidation> => {
      // STRATA-1673 S1: admitted tokens are re-read at key-use time, so a
      // revocation between approval and signing refuses the signature.
      const ts =
        scope && scope.tenantId === manifest.tenantId && scope.agentId === manifest.agentId
          ? await loadTokenScope(scope.tenantId, scope.agentId, manifest.chainId)
          : { admitted: [], revoked: [] };
      const r = validateProtectedShape(manifest, tx, ts.admitted, ts.revoked);
      return r.ok ? { ok: true } : { ok: false, reason: r.reason };
    },
    // REVIEW-STEWARD-28-R5 N1: the vault verifies the recorded approver at
    // permit issuance against this same pinned allowlist.
    isApprover: (userId) =>
      Boolean(userId) && manifest.approvers.some((a) => lower(a) === lower(userId as string)),
  };
}

/**
 * Install a manifest. Called once at startup from env; tests may call it
 * directly. Passing null removes protection (tests only; production never
 * calls this at runtime because no route reaches it).
 */
export function installProtectedMinterManifest(manifest: ProtectedMinterManifest | null): void {
  if (!manifest) {
    activeManifest = null;
    activeDigest = "";
    registerProtectedSignerGuard(null);
    return;
  }
  validateManifest(manifest);
  activeManifest = Object.freeze({
    ...manifest,
    factories: Object.freeze([...manifest.factories]) as string[],
    verifiedTokens: Object.freeze(
      manifest.verifiedTokens.map((t) => Object.freeze({ ...t })),
    ) as VerifiedToken[],
    approvers: Object.freeze([...manifest.approvers]) as string[],
  });
  activeDigest = computeManifestDigest(activeManifest);
  registerProtectedSignerGuard(buildGuard(activeManifest, activeDigest));
}

export function getProtectedMinterManifest(): ProtectedMinterManifest | null {
  return activeManifest;
}

export function getProtectedMinterManifestDigest(): string {
  return activeDigest;
}

export function isProtectedMinter(tenantId: string, agentId: string): boolean {
  return (
    activeManifest !== null &&
    activeManifest.tenantId === tenantId &&
    activeManifest.agentId === agentId
  );
}

/**
 * True when `userId` is a pinned approver in the installed manifest. No
 * manifest, empty allowlist or any other user => false (fail-closed). Tenant
 * role is checked separately by the caller; both are required.
 */
export function isProtectedMinterApprover(userId: string | null | undefined): boolean {
  if (!activeManifest || !userId) return false;
  return activeManifest.approvers.some((a) => lower(a) === lower(userId));
}

/** True when the agent id is the protected minter in any tenant (for id-only routes). */
export function isProtectedMinterAgentId(agentId: string): boolean {
  return activeManifest !== null && activeManifest.agentId === agentId;
}

export function protectedReviewDigest(input: {
  tenantId: string;
  agentId: string;
  chainId: number;
  to: string;
  value: string;
  data: string | null | undefined;
  executionRef: string;
}): `0x${string}` {
  if (!activeManifest) throw new Error("protected minter manifest not installed");
  return computeProtectedReviewDigest({
    ...input,
    signerAddress: activeManifest.signerAddress,
    manifestDigest: activeDigest,
  });
}

/**
 * REVIEW-STEWARD-28-R2 R2-2: a persisted-protected row is covered ONLY when
 * the manifest names its tenant and agent AND pins exactly its persisted
 * wallet address. A wrong-address manifest is not coverage.
 */
export function isProtectedMinterCovered(row: {
  tenantId: string;
  id: string;
  walletAddress: string;
}): boolean {
  return (
    isProtectedMinter(row.tenantId, row.id) &&
    activeManifest !== null &&
    lower(activeManifest.signerAddress) === lower(row.walletAddress)
  );
}

export type ProtectedQuarantineReason =
  | "no-manifest"
  | "tenant-or-agent-mismatch"
  | "address-mismatch";

export interface ProtectedQuarantineEntry {
  tenantId: string;
  agentId: string;
  reason: ProtectedQuarantineReason;
}

function quarantineReason(row: {
  tenantId: string;
  id: string;
  walletAddress: string;
}): ProtectedQuarantineReason | null {
  if (activeManifest === null) return "no-manifest";
  if (!isProtectedMinter(row.tenantId, row.id)) return "tenant-or-agent-mismatch";
  if (lower(activeManifest.signerAddress) !== lower(row.walletAddress)) return "address-mismatch";
  return null;
}

let startupQuarantine: ProtectedQuarantineEntry[] = [];

/**
 * REVIEW-STEWARD-28-R2 N1: per-agent quarantine instead of whole-process
 * refusal. Steward boots and serves unrelated tenants; every persisted-
 * protected agent that is not exactly covered (tenant, agent AND address)
 * has zero capability. That fencing is enforced on every request by
 * `protectedAgentDispatch` / the global bearer guard and inside the Vault
 * (`assertProtectedPostureIntact`), all of which re-read the persisted row
 * and compare it to the installed manifest at call time. This startup hook
 * is therefore diagnostic only: it reports loudly and sets the health flag;
 * there is no window in which an uncovered agent is usable, before or
 * after it runs.
 *
 * A MALFORMED manifest (bad syntax / invalid values) still refuses startup:
 * `manifestFromEnv()` throws at module load, so the process never serves.
 *
 * Returns the quarantine list (empty when every protected row is covered).
 */
export async function assertProtectedPostureAtStartup(): Promise<ProtectedQuarantineEntry[]> {
  let rows: Array<{ id: string; tenantId: string; walletAddress: string }>;
  try {
    rows = await getDb()
      .select({ id: agents.id, tenantId: agents.tenantId, walletAddress: agents.walletAddress })
      .from(agents)
      .where(eq(agents.protected, true));
  } catch (e) {
    if (isUndefinedColumn(e)) {
      // Pre-0029 schema: marker column absent => no persisted-protected agent can exist.
      console.warn("[steward] agents.protected column absent (migration 0029 not applied)");
      startupQuarantine = [];
      return [];
    }
    throw e;
  }
  const quarantined: ProtectedQuarantineEntry[] = [];
  for (const r of rows) {
    const reason = quarantineReason(r);
    if (reason) quarantined.push({ tenantId: r.tenantId, agentId: r.id, reason });
  }
  startupQuarantine = quarantined;
  if (quarantined.length > 0) {
    console.error(
      `[steward] PROTECTED POSTURE DEGRADED: ${quarantined.length} persisted-protected agent(s) are QUARANTINED (zero capability) because no valid manifest exactly covers them: ${quarantined
        .map((q) => `${q.tenantId}/${q.agentId} (${q.reason})`)
        .join(", ")}. Unrelated tenants continue to be served.`,
    );
  }
  return quarantined;
}

/** Health flag: quarantined protected agents as of the last startup posture check. */
export function getProtectedQuarantine(): ProtectedQuarantineEntry[] {
  return startupQuarantine;
}

/** Persisted-protected row for an agent id (any tenant), or null. */
export async function persistedProtectedAgentRow(
  agentId: string,
): Promise<{ id: string; tenantId: string; walletAddress: string } | null> {
  try {
    const [row] = await getDb()
      .select({
        id: agents.id,
        tenantId: agents.tenantId,
        walletAddress: agents.walletAddress,
        protected: agents.protected,
      })
      .from(agents)
      .where(eq(agents.id, agentId));
    if (row?.protected !== true) return null;
    return { id: row.id, tenantId: row.tenantId, walletAddress: row.walletAddress };
  } catch (e) {
    if (isUndefinedColumn(e)) return null; // pre-0029 schema: marker cannot exist
    throw e;
  }
}

/** Persisted-marker lookup for route guards (deny-by-default when manifest absent). */
export async function isPersistedProtectedAgent(agentId: string): Promise<boolean> {
  return (await persistedProtectedAgentRow(agentId)) !== null;
}

/**
 * True when `agentId` is persisted-protected and NOT exactly covered by the
 * installed manifest (tenant, agent and address). Such an agent has zero
 * capability everywhere.
 */
export async function isQuarantinedProtectedAgent(agentId: string): Promise<boolean> {
  const row = await persistedProtectedAgentRow(agentId);
  return row !== null && !isProtectedMinterCovered(row);
}

// ─── STRATA-1673 S1: admitted tokens, suspension, self-admission ─────────────

/** Active admitted tokens for (tenant, agent, chain). Revoked rows are never returned. */
export async function listAdmittedTokens(
  tenantId: string,
  agentId: string,
  chainId: number,
): Promise<VerifiedToken[]> {
  const rows = await getDb()
    .select({
      tokenAddress: protectedMinterTokens.tokenAddress,
      deployTxHash: protectedMinterTokens.deployTxHash,
    })
    .from(protectedMinterTokens)
    .where(
      and(
        eq(protectedMinterTokens.tenantId, tenantId),
        eq(protectedMinterTokens.agentId, agentId),
        eq(protectedMinterTokens.chainId, chainId),
        eq(protectedMinterTokens.status, "active"),
      ),
    );
  return rows.map((r) => ({ address: r.tokenAddress, provenance: `admitted:${r.deployTxHash}` }));
}

/**
 * STRATA-1673 H3: active admissions AND revoked tokens for (tenant, agent,
 * chain), one read. Revoked addresses override manifest membership.
 */
export async function loadTokenScope(
  tenantId: string,
  agentId: string,
  chainId: number,
): Promise<{ admitted: VerifiedToken[]; revoked: string[] }> {
  const rows = await getDb()
    .select({
      tokenAddress: protectedMinterTokens.tokenAddress,
      deployTxHash: protectedMinterTokens.deployTxHash,
      status: protectedMinterTokens.status,
    })
    .from(protectedMinterTokens)
    .where(
      and(
        eq(protectedMinterTokens.tenantId, tenantId),
        eq(protectedMinterTokens.agentId, agentId),
        eq(protectedMinterTokens.chainId, chainId),
      ),
    );
  return {
    admitted: rows
      .filter((r) => r.status === "active")
      .map((r) => ({ address: r.tokenAddress, provenance: `admitted:${r.deployTxHash}` })),
    revoked: rows.filter((r) => r.status === "revoked").map((r) => lower(r.tokenAddress)),
  };
}

/**
 * STRATA-1673 H3: automatic (read-back) signing requires an ACTIVE admission
 * row for the token. Manifest membership alone keeps the existing human path.
 */
export async function hasActiveAdmission(
  tenantId: string,
  agentId: string,
  chainId: number,
  token: string,
): Promise<boolean> {
  const [row] = await getDb()
    .select({ status: protectedMinterTokens.status })
    .from(protectedMinterTokens)
    .where(
      and(
        eq(protectedMinterTokens.tenantId, tenantId),
        eq(protectedMinterTokens.agentId, agentId),
        eq(protectedMinterTokens.chainId, chainId),
        eq(protectedMinterTokens.tokenAddress, lower(token)),
      ),
    );
  return row?.status === "active";
}

/** True when automatic (read-back) signing is suspended for the agent. */
export async function isProtectedMintingSuspended(
  tenantId: string,
  agentId: string,
): Promise<boolean> {
  const [row] = await getDb()
    .select({ at: protectedMinterControls.protectedMintingSuspendedAt })
    .from(protectedMinterControls)
    .where(
      and(
        eq(protectedMinterControls.tenantId, tenantId),
        eq(protectedMinterControls.agentId, agentId),
      ),
    );
  return Boolean(row?.at);
}

export interface ChainReceiptLog {
  address: string;
  topics: readonly `0x${string}`[];
  data: `0x${string}`;
}
export interface ChainReceipt {
  status: "success" | "reverted";
  to: string | null;
  /** H2: the transaction sender; must be the protected signer. */
  from: string;
  blockNumber: bigint;
  logs: readonly ChainReceiptLog[];
}
/** Read-only chain access used for admission (and H1 reconciliation). Injectable for tests. */
export interface ProtectedChainReader {
  getReceipt(chainId: number, txHash: `0x${string}`): Promise<ChainReceipt | null>;
  getBlockNumber(chainId: number): Promise<bigint | null>;
  hasRole(chainId: number, token: string, role: `0x${string}`, account: string): Promise<boolean>;
}

/** Legacy DealTokenV1 role; never sufficient for admission (H2). */
export const MINTER_ROLE = keccak256(stringToHex("MINTER_ROLE"));
const RESTRICTED_DEPLOYED_ABI = parseAbi([
  "event RestrictedDealTokenDeployed(address indexed token, address indexed admin, address indexed issuer, address operator, address pauser, address deployer, bytes32 salt, bytes32 versionId)",
]);
const HAS_ROLE_ABI = parseAbi([
  "function hasRole(bytes32 role, address account) view returns (bool)",
]);

function rpcClient(chainId: number) {
  const url = resolveEvmRpcUrl(chainId, {
    rpcUrl: process.env.RPC_URL,
    chainRpcUrls: chainRpcUrlsFromEnv(),
  });
  if (!url) throw new Error(`no RPC endpoint for chainId ${chainId}`);
  return createPublicClient({ transport: http(url) });
}

const viemChainReader: ProtectedChainReader = {
  async getReceipt(chainId, txHash) {
    try {
      const r = await rpcClient(chainId).getTransactionReceipt({ hash: txHash });
      return {
        status: r.status,
        to: r.to ?? null,
        from: r.from,
        blockNumber: r.blockNumber,
        logs: r.logs,
      };
    } catch {
      return null;
    }
  },
  async getBlockNumber(chainId) {
    try {
      return await rpcClient(chainId).getBlockNumber();
    } catch {
      return null;
    }
  },
  async hasRole(chainId, token, role, account) {
    // Fail closed: an RPC error is "role not proven". Callers that need a
    // proven ABSENCE treat an error as failure too (see admission).
    return rpcClient(chainId).readContract({
      address: token as `0x${string}`,
      abi: HAS_ROLE_ABI,
      functionName: "hasRole",
      args: [role, account as `0x${string}`],
    });
  },
};

let chainReader: ProtectedChainReader = viemChainReader;

/** Tests only. Null restores the viem reader. */
export function setProtectedChainReader(reader: ProtectedChainReader | null): void {
  chainReader = reader ?? viemChainReader;
}
export function getProtectedChainReader(): ProtectedChainReader {
  return chainReader;
}

export type AdmissionResult =
  | { ok: true; token: VerifiedToken; admitted: boolean }
  | { ok: false; reason: string };

/**
 * STRATA-1673 H2: admit `tokenAddress` for protected (auto) mint iff it was
 * produced by Steward's OWN protected deployment through the trusted
 * RestrictedDealTokenFactory, and its live roles are what that deploy set:
 *
 *  1. Binding: a transactions row of THIS protected agent on the manifest
 *     chain whose approval_queue row is an approved, claimed protected review
 *     (review_digest present, issuance claimed) -- i.e. the deploy went
 *     through the protected signing path -- to a manifest factory, with
 *     canonical createRestrictedDealToken calldata (admin = Safe, issuer =
 *     signer). No rolling history window: every such deploy row that has not
 *     yet produced an admission is eligible (deploys are few; MEDIUM fix).
 *  2. Receipt: success, to = that factory, from = the signer, and at least
 *     PROTECTED_ADMISSION_MIN_CONFIRMATIONS blocks deep.
 *  3. Event: RestrictedDealTokenDeployed emitted BY the factory naming exactly
 *     this token, admin = Safe, issuer = signer, deployer = signer, the
 *     calldata's operator/pauser/salt, and versionId = the trusted version.
 *  4. Live roles: hasRole(DEFAULT_ADMIN_ROLE, Safe), hasRole(ISSUER_ROLE,
 *     signer); signer and factory do NOT hold DEFAULT_ADMIN_ROLE.
 *
 * Legacy DealToken (createDealToken / MINTER_ROLE) is never admitted. A
 * revoked admission is terminal. Any RPC/decoding problem => not admitted.
 */
export async function admitOwnDeployedToken(
  tenantId: string,
  agentId: string,
  tokenAddress: string,
): Promise<AdmissionResult> {
  const manifest = activeManifest;
  if (!manifest || manifest.tenantId !== tenantId || manifest.agentId !== agentId) {
    return { ok: false, reason: "no manifest covers this agent" };
  }
  if (!ADDRESS_RE.test(tokenAddress)) return { ok: false, reason: "token is not an address" };
  const token = lower(tokenAddress);
  if (manifest.factories.some((f) => lower(f) === token)) {
    return { ok: false, reason: "a factory cannot be a mint target" };
  }
  const db = getDb();
  const existing = async () =>
    (
      await db
        .select()
        .from(protectedMinterTokens)
        .where(
          and(
            eq(protectedMinterTokens.tenantId, tenantId),
            eq(protectedMinterTokens.agentId, agentId),
            eq(protectedMinterTokens.chainId, manifest.chainId),
            eq(protectedMinterTokens.tokenAddress, token),
          ),
        )
    )[0];
  const prior = await existing();
  if (prior) {
    if (prior.status !== "active") return { ok: false, reason: "token admission is revoked" };
    return {
      ok: true,
      admitted: false,
      token: { address: prior.tokenAddress, provenance: `admitted:${prior.deployTxHash}` },
    };
  }

  const signer = lower(manifest.signerAddress);
  const safe = lower(manifest.safeAdmin);
  const factories = manifest.factories.map(lower);
  if (factories.length === 0) return { ok: false, reason: "no trusted factory configured" };

  // (1) Steward's own protected deploy rows (exact shape; no time window).
  const candidates = await db
    .select({
      txHash: transactions.txHash,
      toAddress: transactions.toAddress,
      data: transactions.data,
      executionRef: transactions.executionRef,
    })
    .from(transactions)
    .innerJoin(approvalQueue, eq(approvalQueue.txId, transactions.id))
    .where(
      and(
        eq(transactions.tenantId, tenantId),
        eq(transactions.agentId, agentId),
        eq(transactions.chainId, manifest.chainId),
        isNotNull(transactions.txHash),
        isNotNull(transactions.executionRef),
        inArray(transactions.status, ["signed", "broadcast", "confirmed"]),
        inArray(sql`lower(${transactions.toAddress})`, factories),
        like(sql`lower(${transactions.data})`, `${SELECTOR_CREATE_RESTRICTED_DEAL_TOKEN}%`),
        eq(approvalQueue.agentId, agentId),
        eq(approvalQueue.status, "approved"),
        isNotNull(approvalQueue.reviewDigest),
        isNotNull(approvalQueue.issuanceClaimedAt),
        sql`lower(${transactions.txHash}) NOT IN (SELECT lower(${protectedMinterTokens.deployTxHash}) FROM ${protectedMinterTokens} WHERE ${protectedMinterTokens.tenantId} = ${tenantId} AND ${protectedMinterTokens.agentId} = ${agentId})`,
      ),
    )
    .orderBy(desc(transactions.createdAt));

  const lastReason = "token was not produced by Steward's own protected RestrictedDealToken deploy";
  for (const cand of candidates) {
    const factory = lower(cand.toAddress);
    if (!cand.txHash || !cand.executionRef || !/^0x[0-9a-fA-F]{64}$/.test(cand.txHash)) continue;
    const d = decodeCreateRestrictedDealToken(cand.data);
    if (!d || d.admin !== safe || d.issuer !== signer) continue;

    // (2) Receipt identity and depth.
    const receipt = await chainReader.getReceipt(manifest.chainId, cand.txHash as `0x${string}`);
    if (!receipt || receipt.status !== "success") continue;
    if (!receipt.to || lower(receipt.to) !== factory) continue;
    if (lower(receipt.from) !== signer) continue;

    // (3) The factory's own event names this token with the expected roles.
    const match = receipt.logs.some((log) => {
      if (lower(log.address) !== factory) return false;
      try {
        const ev = decodeEventLog({
          abi: RESTRICTED_DEPLOYED_ABI,
          topics: log.topics as [`0x${string}`, ...`0x${string}`[]],
          data: log.data,
        });
        return (
          ev.eventName === "RestrictedDealTokenDeployed" &&
          lower(ev.args.token) === token &&
          lower(ev.args.admin) === safe &&
          lower(ev.args.issuer) === signer &&
          lower(ev.args.deployer) === signer &&
          lower(ev.args.operator) === d.operator &&
          lower(ev.args.pauser) === d.pauser &&
          lower(ev.args.salt) === d.salt &&
          lower(ev.args.versionId) === lower(RESTRICTED_FACTORY_VERSION_ID)
        );
      } catch {
        return false;
      }
    });
    if (!match) continue;

    const head = await chainReader.getBlockNumber(manifest.chainId);
    if (head === null || head - receipt.blockNumber + 1n < PROTECTED_ADMISSION_MIN_CONFIRMATIONS) {
      return { ok: false, reason: "deploy receipt is not yet confirmed" };
    }

    // (4) Live roles, read now.
    try {
      const [safeAdmin, signerIssuer, signerAdmin, factoryAdmin] = await Promise.all([
        chainReader.hasRole(manifest.chainId, token, DEFAULT_ADMIN_ROLE, safe),
        chainReader.hasRole(manifest.chainId, token, ISSUER_ROLE, signer),
        chainReader.hasRole(manifest.chainId, token, DEFAULT_ADMIN_ROLE, signer),
        chainReader.hasRole(manifest.chainId, token, DEFAULT_ADMIN_ROLE, factory),
      ]);
      if (!safeAdmin) return { ok: false, reason: "Safe does not hold DEFAULT_ADMIN_ROLE" };
      if (!signerIssuer) return { ok: false, reason: "signer does not hold ISSUER_ROLE" };
      if (signerAdmin || factoryAdmin) {
        return { ok: false, reason: "signer or factory holds DEFAULT_ADMIN_ROLE" };
      }
    } catch {
      return { ok: false, reason: "role read failed" };
    }

    await db
      .insert(protectedMinterTokens)
      .values({
        id: crypto.randomUUID(),
        tenantId,
        agentId,
        chainId: manifest.chainId,
        tokenAddress: token,
        deployTxHash: lower(cand.txHash),
        deployExecutionRef: cand.executionRef,
      })
      .onConflictDoNothing();
    const row = await existing();
    if (!row || row.status !== "active") return { ok: false, reason: "token admission is revoked" };
    return {
      ok: true,
      admitted: true,
      token: { address: row.tokenAddress, provenance: `admitted:${row.deployTxHash}` },
    };
  }
  return { ok: false, reason: lastReason };
}

// Startup: read env once. Fail closed on invalid configuration.
installProtectedMinterManifest(manifestFromEnv());
