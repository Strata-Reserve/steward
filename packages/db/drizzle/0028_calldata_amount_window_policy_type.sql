-- STRATA-1499 (SF-1): calldata-amount-window policy type (rolling cap on a
-- decoded calldata amount per contract + selector).
-- Additive enum value only; no table changes. Idempotent on re-run.
-- Rollback: Postgres cannot drop a single enum value in place. Leaving the
-- value present is harmless once no policies rows reference it:
--   DELETE FROM policies WHERE type = 'calldata-amount-window';
ALTER TYPE "policy_type" ADD VALUE IF NOT EXISTS 'calldata-amount-window';
