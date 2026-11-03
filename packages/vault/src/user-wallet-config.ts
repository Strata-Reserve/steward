/**
 * user-wallet-config.ts - Env-driven configuration for user-wallet defaults.
 *
 * Rate-limit policy for user wallets:
 *   USER_WALLET_MAX_TX_PER_HOUR  (default 10)
 *   USER_WALLET_MAX_TX_PER_DAY   (default 50)
 *
 * Values must be positive integers. Anything else (zero, negative,
 * non-integer, garbage) falls back to the default and emits a warning.
 * Unset or empty falls back to the default silently.
 */

export const USER_WALLET_MAX_TX_PER_HOUR_ENV = "USER_WALLET_MAX_TX_PER_HOUR";
export const USER_WALLET_MAX_TX_PER_DAY_ENV = "USER_WALLET_MAX_TX_PER_DAY";

export const DEFAULT_USER_WALLET_MAX_TX_PER_HOUR = 10;
export const DEFAULT_USER_WALLET_MAX_TX_PER_DAY = 50;

export type EnvSource = Record<string, string | undefined>;
export type WarnFn = (message: string) => void;

export interface UserWalletRateLimitConfig {
  maxTxPerHour: number;
  maxTxPerDay: number;
}

const defaultWarn: WarnFn = (message) => console.warn(message);

/**
 * Parse a positive integer from an env var. Returns `fallback` (and warns)
 * when the value is present but not a positive integer.
 */
export function parsePositiveIntEnv(
  env: EnvSource,
  name: string,
  fallback: number,
  warn: WarnFn = defaultWarn,
): number {
  const raw = env[name];
  if (raw === undefined) return fallback;
  const trimmed = raw.trim();
  if (trimmed === "") return fallback;

  if (!/^\d+$/.test(trimmed)) {
    warn(`[UserWallet] ${name} is not a positive integer; using default ${fallback}`);
    return fallback;
  }
  const value = Number(trimmed);
  if (!Number.isSafeInteger(value) || value <= 0) {
    warn(`[UserWallet] ${name} must be a positive integer; using default ${fallback}`);
    return fallback;
  }
  return value;
}

/** Resolve the user-wallet rate-limit policy config from env. */
export function getUserWalletRateLimitConfig(
  env: EnvSource = process.env,
  warn: WarnFn = defaultWarn,
): UserWalletRateLimitConfig {
  return {
    maxTxPerHour: parsePositiveIntEnv(
      env,
      USER_WALLET_MAX_TX_PER_HOUR_ENV,
      DEFAULT_USER_WALLET_MAX_TX_PER_HOUR,
      warn,
    ),
    maxTxPerDay: parsePositiveIntEnv(
      env,
      USER_WALLET_MAX_TX_PER_DAY_ENV,
      DEFAULT_USER_WALLET_MAX_TX_PER_DAY,
      warn,
    ),
  };
}
