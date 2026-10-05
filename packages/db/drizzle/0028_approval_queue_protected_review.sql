-- STRATA-1499 (SF-1): protected production-minter review evidence.
-- Additive. Ordinary approvals keep NULLs.
-- Rollback SQL: ALTER TABLE approval_queue DROP COLUMN review_digest, DROP COLUMN manifest_digest,
--               DROP COLUMN review_projection, DROP COLUMN requested_by, DROP COLUMN approved_by_user_id;
-- Rollback is NOT authorization-safe after any protected use (REVIEW-STEWARD-28-R4 N1):
-- it drops the frozen review evidence (digests, projection, requester, approver) that the
-- protected approve path depends on, and re-applying this additive migration does not
-- restore it. Only roll back BEFORE any protected proposal has been queued, or together
-- with revoking MINTER_ROLE from the signer via the Safe (0x3Ea77cDf3eC33603bF4135bb1a36712B5e21d721).
ALTER TABLE "approval_queue" ADD COLUMN IF NOT EXISTS "review_digest" varchar(66);
--> statement-breakpoint
ALTER TABLE "approval_queue" ADD COLUMN IF NOT EXISTS "manifest_digest" varchar(66);
--> statement-breakpoint
ALTER TABLE "approval_queue" ADD COLUMN IF NOT EXISTS "review_projection" jsonb;
--> statement-breakpoint
ALTER TABLE "approval_queue" ADD COLUMN IF NOT EXISTS "requested_by" varchar(255);
--> statement-breakpoint
ALTER TABLE "approval_queue" ADD COLUMN IF NOT EXISTS "approved_by_user_id" varchar(64);
