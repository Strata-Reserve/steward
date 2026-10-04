-- STRATA-1486: stable execution reference on vault sign actions.
-- Additive. Legacy rows keep NULL tenant_id/execution_ref and are untouched.
-- Rollback: DROP INDEX transactions_tenant_agent_execution_ref_idx;
--           ALTER TABLE transactions DROP CONSTRAINT transactions_execution_ref_chk;
--           ALTER TABLE transactions DROP COLUMN execution_ref, DROP COLUMN tenant_id;
ALTER TABLE "transactions" ADD COLUMN IF NOT EXISTS "tenant_id" varchar(64);
--> statement-breakpoint
ALTER TABLE "transactions" ADD COLUMN IF NOT EXISTS "execution_ref" varchar(128);
--> statement-breakpoint
ALTER TABLE "transactions" DROP CONSTRAINT IF EXISTS "transactions_execution_ref_chk";
--> statement-breakpoint
ALTER TABLE "transactions"
  ADD CONSTRAINT "transactions_execution_ref_chk"
  CHECK ("execution_ref" IS NULL OR ("tenant_id" IS NOT NULL AND length("execution_ref") BETWEEN 1 AND 128));
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "transactions_tenant_agent_execution_ref_idx"
  ON "transactions" ("tenant_id", "agent_id", "execution_ref");
