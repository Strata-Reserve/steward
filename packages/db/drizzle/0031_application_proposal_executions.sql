-- STRATA-1515 exec-gap-a: canonical application-proposal -> execution linkage.
-- Additive. One immutable row per executed application proposal, written only
-- by the tenant-level executor (POST /vault/application-proposals/:id/execute)
-- after policy evaluation and a Vault broadcast. Application principals never
-- write here. chain_id is pinned to Base Sepolia (84532) for this lane.
-- Rollback (only before any row exists): DROP TABLE application_proposal_executions;
CREATE TABLE IF NOT EXISTS "application_proposal_executions" (
  "tenant_id" varchar(64) NOT NULL,
  "principal_id" varchar(64) NOT NULL,
  "proposal_id" varchar(64) NOT NULL,
  "transaction_id" varchar(64) NOT NULL REFERENCES "transactions" ("id") ON DELETE restrict,
  "chain_id" integer NOT NULL,
  "tx_hash" varchar(66) NOT NULL,
  "executed_by" varchar(255) NOT NULL,
  "created_at" timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT "application_proposal_executions_pk" PRIMARY KEY ("tenant_id", "principal_id", "proposal_id"),
  CONSTRAINT "application_proposal_executions_proposal_fk"
    FOREIGN KEY ("tenant_id", "principal_id", "proposal_id")
    REFERENCES "application_transaction_proposals" ("tenant_id", "principal_id", "id") ON DELETE cascade,
  CONSTRAINT "application_proposal_executions_chain_chk" CHECK ("chain_id" = 84532),
  CONSTRAINT "application_proposal_executions_tx_hash_chk" CHECK ("tx_hash" ~ '^0x[0-9a-f]{64}$')
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "application_proposal_executions_transaction_idx"
  ON "application_proposal_executions" ("transaction_id");
--> statement-breakpoint
DROP TRIGGER IF EXISTS application_proposal_executions_immutable ON application_proposal_executions;
--> statement-breakpoint
CREATE TRIGGER application_proposal_executions_immutable
  BEFORE UPDATE ON application_proposal_executions
  FOR EACH ROW EXECUTE FUNCTION steward_reject_application_immutable_update();
