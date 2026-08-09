import { randomBytes } from "node:crypto";

import { hashSha256Hex } from "./crypto";
import type { EmailProvider } from "./email-provider";
import { ConsoleProvider } from "./email-provider";
import {
  renderTemplate as defaultTemplateRenderer,
  type MagicLinkTemplateData,
  type RenderedMagicLinkTemplate,
  renderOtpTemplate,
} from "./email-templates";
import { TokenStore } from "./token-store";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface EmailAuthConfig {
  /** Sender address, e.g. "login@steward.fi" */
  from: string;
  /** Base URL for building the callback link, e.g. "https://steward.fi" */
  baseUrl: string;
  /**
   * Pluggable email provider.
   * Defaults to ConsoleProvider so nothing breaks without API credentials.
   */
  provider?: EmailProvider;
  /** Token TTL in milliseconds. Default: 10 minutes. */
  tokenTtlMs?: number;
  /** Path that receives the magic-link callback. Default: "/auth/callback/email" */
  callbackPath?: string;
  /**
   * Optional external TokenStore to use for magic-link tokens.
   * Defaults to a fresh TokenStore backed by in-memory storage.
   * Pass a store configured with a Redis or Postgres backend for
   * restart-safe / multi-instance deployments.
   */
  tokenStore?: TokenStore;
  /** Override the magic-link template renderer. */
  templateRenderer?: (
    templateId: string | undefined,
    data: MagicLinkTemplateData,
  ) => RenderedMagicLinkTemplate;
  /** Template ID to render for outgoing magic-link emails. */
  templateId?: string;
  /** Override the rendered subject line. */
  subjectOverride?: string;
  /** Optional reply-to address to pass through to the provider. */
  replyTo?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TOKEN_BYTES = 32;
const DEFAULT_TTL_MS = 10 * 60 * 1000; // 10 min
const DEFAULT_CALLBACK = "/auth/callback/email";
const OTP_DIGITS = 6;

function generateToken(): string {
  // URL-safe hex token (64 chars from 32 bytes)
  return randomBytes(TOKEN_BYTES).toString("hex");
}

/**
 * Crypto-random 6-digit one-time code with rejection sampling to avoid
 * modulo bias. Draws a uniform 32-bit value and rejects any draw at or above
 * the largest multiple of 10^6 that fits in 2^32, so the surviving range maps
 * to [0, 10^6) with no bias before the `% max` reduction.
 */
export function generateOtpCode(): string {
  const max = 10 ** OTP_DIGITS;
  const limit = Math.floor(0x1_0000_0000 / max) * max;
  for (;;) {
    const bytes = randomBytes(4);
    const draw =
      ((bytes[0] << 24) >>> 0) + ((bytes[1] << 16) >>> 0) + ((bytes[2] << 8) >>> 0) + bytes[3];
    if (draw < limit) {
      return String(draw % max).padStart(OTP_DIGITS, "0");
    }
  }
}

/**
 * Hash binds the code to {email, tenant} so a code minted for one address or
 * tenant can never verify for another. The hashed key is what we persist, so
 * the raw code is never written to the store.
 */
function otpStoreKey(email: string, tenantId: string | undefined, code: string): string {
  return hashSha256Hex(`email-otp:${tenantId ?? ""}:${email}:${code}`);
}

type OtpPayload = { email: string; tenantId?: string };

function encodeOtpPayload(payload: OtpPayload): string {
  return JSON.stringify(payload);
}

function decodeOtpPayload(value: string): OtpPayload {
  try {
    const parsed = JSON.parse(value) as OtpPayload;
    if (typeof parsed.email === "string") return parsed;
  } catch {
    // Fall through to legacy raw-email form.
  }
  return { email: value };
}

function hashToken(token: string): string {
  return hashSha256Hex(token);
}

function buildMagicLink(
  baseUrl: string,
  callbackPath: string,
  token: string,
  email: string,
): string {
  const url = new URL(callbackPath, baseUrl);
  url.searchParams.set("token", token);
  url.searchParams.set("email", email);
  return url.toString();
}

// ---------------------------------------------------------------------------
// EmailAuth
// ---------------------------------------------------------------------------

export class EmailAuth {
  private provider: EmailProvider;
  private tokenStore: TokenStore;
  private baseUrl: string;
  private callbackPath: string;
  private tokenTtlMs: number;
  private from: string;
  private replyTo?: string;
  private templateId?: string;
  private subjectOverride?: string;
  private templateRenderer: (
    templateId: string | undefined,
    data: MagicLinkTemplateData,
  ) => RenderedMagicLinkTemplate;

  constructor(config: EmailAuthConfig) {
    this.from = config.from;
    this.baseUrl = config.baseUrl.replace(/\/$/, ""); // strip trailing slash
    this.callbackPath = config.callbackPath ?? DEFAULT_CALLBACK;
    this.tokenTtlMs = config.tokenTtlMs ?? DEFAULT_TTL_MS;
    this.provider = config.provider ?? new ConsoleProvider();
    this.tokenStore = config.tokenStore ?? new TokenStore();
    this.replyTo = config.replyTo;
    this.templateId = config.templateId;
    this.subjectOverride = config.subjectOverride;
    this.templateRenderer = config.templateRenderer ?? defaultTemplateRenderer;
  }

  /**
   * Generate a magic link token, persist its hash, and send the email.
   * Returns the token hash (for verification lookup) and the expiry date.
   */
  async sendMagicLink(email: string): Promise<{ tokenHash: string; expiresAt: Date }> {
    const token = generateToken();
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + this.tokenTtlMs);

    // Persist hash → email with TTL
    this.tokenStore.store(tokenHash, email, this.tokenTtlMs);

    // Build and send the email
    const magicLink = buildMagicLink(this.baseUrl, this.callbackPath, token, email);
    const rendered = this.templateRenderer(this.templateId, {
      magicLink,
      email,
      expiresInMinutes: Math.floor(this.tokenTtlMs / (60 * 1000)),
      tenantName: undefined,
    });
    const subject = this.subjectOverride || rendered.subject;
    const body = rendered.text;
    const html = rendered.html;

    await this.provider.send(email, subject, body, html, { replyTo: this.replyTo });

    return { tokenHash, expiresAt };
  }

  /**
   * Generate a 6-digit one-time code, persist its hash bound to {email,tenant},
   * and email it. Privy-style email verification: the code proves address
   * ownership and is exchanged for a short-lived verified-email grant by the
   * API layer. The grant is what unlocks first-time passkey registration, so a
   * brand-new email cannot be squatted with a passkey before its real owner
   * proves control of the inbox.
   */
  async sendOtp(
    email: string,
    context: { tenantId?: string; tenantName?: string } = {},
  ): Promise<{ expiresAt: Date }> {
    const code = generateOtpCode();
    const expiresAt = new Date(Date.now() + this.tokenTtlMs);

    // Store the HASH of {email,tenant,code} -> payload, single-use on verify.
    this.tokenStore.store(
      otpStoreKey(email, context.tenantId, code),
      encodeOtpPayload({ email, tenantId: context.tenantId }),
      this.tokenTtlMs,
    );

    const minutes = Math.floor(this.tokenTtlMs / (60 * 1000));
    const brand = context.tenantName || "Steward";
    // Render the code email through the same per-tenant templateId used for
    // magic links, so a branded tenant (e.g. templateId "strata") gets its
    // branded code card instead of the generic dark fallback.
    const rendered = renderOtpTemplate(this.templateId, {
      code,
      expiresInMinutes: minutes,
      brand,
    });
    // NOTE: deliberately do NOT apply `this.subjectOverride` here. That override
    // is the tenant's MAGIC-LINK subject (e.g. "Sign in to ..."), which is wrong
    // for a verification-code email. The OTP subject must carry the code, so we
    // always use the rendered OTP subject.
    await this.provider.send(email, rendered.subject, rendered.text, rendered.html, {
      replyTo: this.replyTo,
    });

    return { expiresAt };
  }

  /**
   * Verify a 6-digit code for {email, tenantId}. One-time use: the entry is
   * consumed (atomically read-and-deleted) on success so a code cannot be
   * replayed. Returns false for malformed / unknown / expired / mismatched
   * codes.
   */
  async verifyOtp(email: string, code: string, tenantId?: string): Promise<boolean> {
    if (!/^\d{6}$/.test(code)) return false;
    const stored = await this.tokenStore.consume(otpStoreKey(email, tenantId, code));
    if (!stored) return false;
    const payload = decodeOtpPayload(stored);
    return payload.email === email && (payload.tenantId ?? undefined) === (tenantId ?? undefined);
  }

  /**
   * Verify a raw token received from the callback URL.
   * One-time use: deletes the token after successful verification.
   */
  async verifyMagicLink(token: string): Promise<{ email: string; valid: boolean }> {
    const tokenHash = hashToken(token);
    const email = await this.tokenStore.verify(tokenHash);

    if (!email) {
      return { email: "", valid: false };
    }

    // Consume the token (one-time use)
    this.tokenStore.delete(tokenHash);

    return { email, valid: true };
  }

  /**
   * Clean up background timers.  Call in tests after each suite.
   */
  destroy(): void {
    this.tokenStore.destroy();
  }
}
