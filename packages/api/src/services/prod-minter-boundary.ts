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

import { agents, getDb } from "@stwd/db";
import {
  computeProtectedReviewDigest,
  isUndefinedColumn,
  type ProtectedSignerGuard,
  type ProtectedTransactionShape,
  type ProtectedValidation,
  registerProtectedSignerGuard,
} from "@stwd/vault";
import { eq } from "drizzle-orm";
import { encodeFunctionData, keccak256, parseAbi, stringToHex, toFunctionSelector } from "viem";

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

export type DecodedProtectedCall = DecodedCreateDealToken | DecodedMint;

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
  kind: "createDealToken" | "mint";
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

export function validateProtectedShape(
  manifest: ProtectedMinterManifest,
  tx: ProtectedTransactionShape & { executionRef?: string },
): ProtectedShapeResult {
  // B1: bound to the manifest's single chain, never to a global constant.
  if (typeof tx.chainId !== "number" || tx.chainId !== manifest.chainId) {
    return { ok: false, reason: `chainId must be exactly ${manifest.chainId}` };
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
  if (factory) {
    if (selector !== SELECTOR_CREATE_DEAL_TOKEN) {
      return { ok: false, reason: "factory target permits only createDealToken (0x2217bc2d)" };
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

  const token = manifest.verifiedTokens.find((t) => lower(t.address) === to);
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
    validateTransaction: (tx): ProtectedValidation => {
      const r = validateProtectedShape(manifest, tx);
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

// Startup: read env once. Fail closed on invalid configuration.
installProtectedMinterManifest(manifestFromEnv());
