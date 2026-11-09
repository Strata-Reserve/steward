-- STRATA-1515 exec gap (option A): Steward executes an approved application
-- proposal. Additive. No existing row, enum value, or contract changes.
--
-- Two tables:
--   application_executor_signers   immutable binding: which tenant signer agent
--                                  may execute which principal's proposals on
--                                  which chain, and against which contracts.
--   application_proposal_executions one row per executed proposal. The unique
--                                  (tenant, principal, proposal) key is the
--                                  single-execution arbiter: a proposal can be
--                                  signed at most once, ever.
--
--   application_proposal_rejections one row per rejected proposal. A human
--                                  owner/admin refusal is a durable terminal
--                                  decision (rejector, reason, timestamp).
--
-- Execution and rejection are mutually exclusive per proposal. Both inserts run
-- a BEFORE INSERT guard that locks the proposal row and refuses if the other
-- decision already exists, so exactly one of a concurrent reject/execute pair
-- can commit, whatever the application code does.
--
-- Rollback (only BEFORE any execution has been broadcast; afterwards it drops
-- the only Steward linkage from proposal to chain transaction):
--   DROP TABLE application_proposal_rejections;
--   DROP TABLE application_proposal_executions;
--   DROP TABLE application_executor_signers;
--   DROP FUNCTION steward_guard_application_execution_update();
--   DROP FUNCTION steward_guard_application_proposal_decision();
--   DROP FUNCTION steward_guard_application_rejection_delete();
--   DROP TYPE application_execution_status;
CREATE TYPE "application_execution_status" AS ENUM (
  'executing',
  'broadcast',
  'indeterminate'
);
--> statement-breakpoint
CREATE TABLE "application_executor_signers" (
  "tenant_id" varchar(64) NOT NULL,
  "principal_id" varchar(64) NOT NULL,
  "chain_id" integer NOT NULL,
  "signer_agent_id" varchar(64) NOT NULL,
  "allowed_targets" text[] NOT NULL,
  "created_by" varchar(255) NOT NULL,
  "created_at" timestamp with time zone NOT NULL DEFAULT now(),
  -- Hard pin: Base Sepolia only. 8453 and every other chain are refused by
  -- the database even if application code or env were wrong.
  CONSTRAINT "application_executor_signers_chain_chk" CHECK ("chain_id" = 84532),
  CONSTRAINT "application_executor_signers_targets_chk"
    CHECK (cardinality("allowed_targets") BETWEEN 1 AND 100),
  CONSTRAINT "application_executor_signers_principal_fk"
    FOREIGN KEY ("tenant_id", "principal_id")
    REFERENCES "application_principals" ("tenant_id", "id") ON DELETE cascade,
  CONSTRAINT "application_executor_signers_agent_fk"
    FOREIGN KEY ("tenant_id", "signer_agent_id")
    REFERENCES "agents" ("tenant_id", "id") ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX "application_executor_signers_scope_idx"
  ON "application_executor_signers" ("tenant_id", "principal_id", "chain_id");
--> statement-breakpoint
CREATE TRIGGER application_executor_signers_immutable
  BEFORE UPDATE ON application_executor_signers
  FOR EACH ROW EXECUTE FUNCTION steward_reject_application_immutable_update();
--> statement-breakpoint
CREATE TABLE "application_proposal_executions" (
  "id" varchar(64) PRIMARY KEY NOT NULL,
  "tenant_id" varchar(64) NOT NULL,
  "principal_id" varchar(64) NOT NULL,
  "proposal_id" varchar(64) NOT NULL,
  "signer_agent_id" varchar(64) NOT NULL,
  "chain_id" integer NOT NULL,
  "transaction_id" varchar(64) NOT NULL REFERENCES "transactions"("id") ON DELETE restrict,
  "execution_ref" varchar(128) NOT NULL,
  "to_address" varchar(42) NOT NULL,
  "recipient_address" varchar(42) NOT NULL,
  "amount" text NOT NULL,
  "approved_by" varchar(255) NOT NULL,
  "status" application_execution_status NOT NULL DEFAULT 'executing',
  "tx_hash" varchar(128),
  "failure_reason" text,
  "policy_results" jsonb NOT NULL DEFAULT '[]'::jsonb,
  "created_at" timestamp with time zone NOT NULL DEFAULT now(),
  "updated_at" timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT "application_executions_chain_chk" CHECK ("chain_id" = 84532),
  CONSTRAINT "application_executions_hash_chk"
    CHECK (("status" = 'broadcast') = ("tx_hash" IS NOT NULL)),
  CONSTRAINT "application_executions_proposal_fk"
    FOREIGN KEY ("tenant_id", "principal_id", "proposal_id")
    REFERENCES "application_transaction_proposals" ("tenant_id", "principal_id", "id")
    ON DELETE cascade,
  CONSTRAINT "application_executions_agent_fk"
    FOREIGN KEY ("tenant_id", "signer_agent_id")
    REFERENCES "agents" ("tenant_id", "id") ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX "application_executions_proposal_idx"
  ON "application_proposal_executions" ("tenant_id", "principal_id", "proposal_id");
--> statement-breakpoint
CREATE UNIQUE INDEX "application_executions_transaction_idx"
  ON "application_proposal_executions" ("transaction_id");
--> statement-breakpoint
-- Forward-only status machine. Identity is immutable; the only legal update is
-- one transition out of 'executing'. A broadcast hash can never be replaced,
-- and a terminal row can never be re-armed for a second signature.
CREATE OR REPLACE FUNCTION steward_guard_application_execution_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.principal_id <> OLD.principal_id
     OR NEW.proposal_id <> OLD.proposal_id OR NEW.signer_agent_id <> OLD.signer_agent_id
     OR NEW.chain_id <> OLD.chain_id OR NEW.transaction_id <> OLD.transaction_id
     OR NEW.execution_ref <> OLD.execution_ref OR NEW.to_address <> OLD.to_address
     OR NEW.recipient_address <> OLD.recipient_address OR NEW.amount <> OLD.amount
     OR NEW.approved_by <> OLD.approved_by OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'application execution identity is immutable';
  END IF;
  IF OLD.status <> 'executing' THEN
    RAISE EXCEPTION 'application execution is terminal';
  END IF;
  IF NEW.status = 'executing' THEN
    RAISE EXCEPTION 'application execution must leave executing';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
--> statement-breakpoint
CREATE TRIGGER application_executions_forward_only
  BEFORE UPDATE ON application_proposal_executions
  FOR EACH ROW EXECUTE FUNCTION steward_guard_application_execution_update();
--> statement-breakpoint
CREATE TRIGGER application_executions_no_delete
  BEFORE DELETE ON application_proposal_executions
  FOR EACH ROW WHEN (OLD.status = 'broadcast')
  EXECUTE FUNCTION steward_reject_application_immutable_update();
--> statement-breakpoint
-- Durable human rejection. Immutable once written; it can only disappear
-- together with its proposal (cascade), never on its own, so a rejected
-- proposal can never be reopened for execution.
CREATE TABLE "application_proposal_rejections" (
  "id" varchar(64) PRIMARY KEY NOT NULL,
  "tenant_id" varchar(64) NOT NULL,
  "principal_id" varchar(64) NOT NULL,
  "proposal_id" varchar(64) NOT NULL,
  "rejected_by" varchar(255) NOT NULL,
  "reason" text NOT NULL,
  "created_at" timestamp with time zone NOT NULL DEFAULT now(),
  -- Only a human user can reject (the route records user:<id>).
  CONSTRAINT "application_rejections_human_chk" CHECK ("rejected_by" ~ '^user:.+$'),
  CONSTRAINT "application_rejections_reason_chk"
    CHECK (char_length(btrim("reason")) BETWEEN 1 AND 1000),
  CONSTRAINT "application_rejections_proposal_fk"
    FOREIGN KEY ("tenant_id", "principal_id", "proposal_id")
    REFERENCES "application_transaction_proposals" ("tenant_id", "principal_id", "id")
    ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX "application_rejections_proposal_idx"
  ON "application_proposal_rejections" ("tenant_id", "principal_id", "proposal_id");
--> statement-breakpoint
CREATE TRIGGER application_rejections_immutable
  BEFORE UPDATE ON application_proposal_rejections
  FOR EACH ROW EXECUTE FUNCTION steward_reject_application_immutable_update();
--> statement-breakpoint
CREATE OR REPLACE FUNCTION steward_guard_application_rejection_delete() RETURNS trigger AS $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM application_transaction_proposals
     WHERE tenant_id = OLD.tenant_id AND principal_id = OLD.principal_id AND id = OLD.proposal_id
  ) THEN
    RAISE EXCEPTION 'application proposal rejection is permanent';
  END IF;
  RETURN OLD;
END;
$$ LANGUAGE plpgsql;
--> statement-breakpoint
CREATE TRIGGER application_rejections_no_delete
  BEFORE DELETE ON application_proposal_rejections
  FOR EACH ROW EXECUTE FUNCTION steward_guard_application_rejection_delete();
--> statement-breakpoint
-- One decision per proposal: lock the proposal row, then refuse the insert if
-- the opposite decision exists. Under READ COMMITTED the check runs after the
-- lock is granted, so it sees the competing transaction's commit.
CREATE OR REPLACE FUNCTION steward_guard_application_proposal_decision() RETURNS trigger AS $$
BEGIN
  PERFORM 1 FROM application_transaction_proposals
   WHERE tenant_id = NEW.tenant_id AND principal_id = NEW.principal_id AND id = NEW.proposal_id
   FOR UPDATE;
  IF TG_TABLE_NAME = 'application_proposal_executions' THEN
    IF EXISTS (
      SELECT 1 FROM application_proposal_rejections
       WHERE tenant_id = NEW.tenant_id AND principal_id = NEW.principal_id AND proposal_id = NEW.proposal_id
    ) THEN
      RAISE EXCEPTION 'application proposal is rejected';
    END IF;
  ELSIF EXISTS (
    SELECT 1 FROM application_proposal_executions
     WHERE tenant_id = NEW.tenant_id AND principal_id = NEW.principal_id AND proposal_id = NEW.proposal_id
  ) THEN
    RAISE EXCEPTION 'application proposal execution already started';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
--> statement-breakpoint
CREATE TRIGGER application_executions_decision_guard
  BEFORE INSERT ON application_proposal_executions
  FOR EACH ROW EXECUTE FUNCTION steward_guard_application_proposal_decision();
--> statement-breakpoint
CREATE TRIGGER application_rejections_decision_guard
  BEFORE INSERT ON application_proposal_rejections
  FOR EACH ROW EXECUTE FUNCTION steward_guard_application_proposal_decision();
