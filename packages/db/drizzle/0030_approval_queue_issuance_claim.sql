-- STRATA-1499 (SF-1, REVIEW-STEWARD-28-R2 R2-1): durable single-use issuance
-- claim. An internal signing permit may be issued for an approved row exactly
-- once; the claim is taken by CAS (status='approved' AND issuance_claimed_at IS NULL)
-- before any key use, so a second issuance (or one racing an in-flight signing)
-- is refused. Additive. Ordinary approvals keep NULL.
-- Rollback: ALTER TABLE approval_queue DROP COLUMN issuance_claimed_at;
ALTER TABLE "approval_queue" ADD COLUMN IF NOT EXISTS "issuance_claimed_at" timestamp with time zone;
