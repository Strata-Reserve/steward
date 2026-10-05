-- STRATA-1499 (SF-1): contract-allowlist policy type.
-- Additive enum value only; no table changes. Idempotent on re-run.
-- Rollback: Postgres cannot drop a single enum value in place. Leaving the
-- value present is harmless once no policies rows reference it:
--   DELETE FROM policies WHERE type = 'contract-allowlist';
ALTER TYPE "policy_type" ADD VALUE IF NOT EXISTS 'contract-allowlist';
