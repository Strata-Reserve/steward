-- STRATA-1499 (SF-1): protected production-minter review evidence.
-- Additive. Ordinary approvals keep NULLs.
-- Rollback: ALTER TABLE approval_queue DROP COLUMN review_digest, DROP COLUMN manifest_digest,
--           DROP COLUMN review_projection, DROP COLUMN requested_by, DROP COLUMN approved_by_user_id;
ALTER TABLE "approval_queue" ADD COLUMN IF NOT EXISTS "review_digest" varchar(66);
--> statement-breakpoint
ALTER TABLE "approval_queue" ADD COLUMN IF NOT EXISTS "manifest_digest" varchar(66);
--> statement-breakpoint
ALTER TABLE "approval_queue" ADD COLUMN IF NOT EXISTS "review_projection" jsonb;
--> statement-breakpoint
ALTER TABLE "approval_queue" ADD COLUMN IF NOT EXISTS "requested_by" varchar(255);
--> statement-breakpoint
ALTER TABLE "approval_queue" ADD COLUMN IF NOT EXISTS "approved_by_user_id" varchar(64);
