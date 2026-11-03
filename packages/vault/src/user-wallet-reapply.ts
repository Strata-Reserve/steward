/**
 * user-wallet-reapply.ts - Re-apply the env-resolved rate-limit policy to
 * existing user-wallet agents.
 *
 * Scope: agents whose id starts with `user-wallet-` inside the given tenant
 * set. Only the `user-rate-limit-<userId>` policy row is touched; spending
 * limits and any other policies are left as they are.
 *
 * Dry-run by default (no writes). Idempotent: a second apply with the same
 * env reports every agent as unchanged.
 */

import { agents, getDb, policies } from "@stwd/db";
import { and, eq, inArray, like } from "drizzle-orm";
import { buildUserWalletRateLimitPolicy, USER_WALLET_RATE_LIMIT_POLICY_ID } from "./user-wallet";
import type { EnvSource, WarnFn } from "./user-wallet-config";

const USER_WALLET_AGENT_PREFIX = "user-wallet-";

export interface ReapplyRateLimitOptions {
  tenantIds: string[];
  apply?: boolean;
  env?: EnvSource;
  warn?: WarnFn;
}

export interface ReapplyRateLimitResult {
  mode: "dry-run" | "apply";
  maxTxPerHour: number;
  maxTxPerDay: number;
  scanned: number;
  inserted: number;
  updated: number;
  unchanged: number;
}

function sameRateLimit(config: Record<string, unknown>, hour: number, day: number): boolean {
  return config.maxTxPerHour === hour && config.maxTxPerDay === day;
}

export async function reapplyUserWalletRateLimit(
  options: ReapplyRateLimitOptions,
): Promise<ReapplyRateLimitResult> {
  const tenantIds = [...new Set(options.tenantIds.map((t) => t.trim()).filter(Boolean))];
  if (tenantIds.length === 0) {
    throw new Error("reapplyUserWalletRateLimit: at least one tenant id is required");
  }
  const apply = options.apply === true;
  const rule = buildUserWalletRateLimitPolicy(options.env ?? process.env, options.warn);
  const hour = rule.config.maxTxPerHour as number;
  const day = rule.config.maxTxPerDay as number;

  const result: ReapplyRateLimitResult = {
    mode: apply ? "apply" : "dry-run",
    maxTxPerHour: hour,
    maxTxPerDay: day,
    scanned: 0,
    inserted: 0,
    updated: 0,
    unchanged: 0,
  };

  const db = getDb();
  const rows = await db
    .select({ id: agents.id })
    .from(agents)
    .where(
      and(inArray(agents.tenantId, tenantIds), like(agents.id, `${USER_WALLET_AGENT_PREFIX}%`)),
    );

  for (const { id: agentId } of rows) {
    result.scanned += 1;
    const userId = agentId.slice(USER_WALLET_AGENT_PREFIX.length);
    const policyId = `${USER_WALLET_RATE_LIMIT_POLICY_ID}-${userId}`;

    const [existing] = await db
      .select({ id: policies.id, enabled: policies.enabled, config: policies.config })
      .from(policies)
      .where(and(eq(policies.id, policyId), eq(policies.agentId, agentId)));

    if (!existing) {
      result.inserted += 1;
      if (apply) {
        await db.insert(policies).values({
          id: policyId,
          agentId,
          type: rule.type,
          enabled: rule.enabled,
          config: rule.config,
        });
      }
      continue;
    }

    if (existing.enabled === rule.enabled && sameRateLimit(existing.config ?? {}, hour, day)) {
      result.unchanged += 1;
      continue;
    }

    result.updated += 1;
    if (apply) {
      await db
        .update(policies)
        .set({
          enabled: rule.enabled,
          config: { ...(existing.config ?? {}), maxTxPerHour: hour, maxTxPerDay: day },
          updatedAt: new Date(),
        })
        .where(eq(policies.id, policyId));
    }
  }

  return result;
}
