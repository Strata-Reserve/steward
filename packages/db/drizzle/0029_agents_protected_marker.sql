-- STRATA-1499 (SF-1, REVIEW-STEWARD-28 F1): persisted, env-independent
-- protected marker. Set once at protected creation; no API route clears it.
-- Additive. Existing agents keep false (legacy posture).
-- Rollback: ALTER TABLE agents DROP COLUMN protected;
ALTER TABLE "agents" ADD COLUMN IF NOT EXISTS "protected" boolean NOT NULL DEFAULT false;
