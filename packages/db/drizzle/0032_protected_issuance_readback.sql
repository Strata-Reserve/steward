-- STRATA-1673 E7 S1: protected minter auto-signs read-back-validated issuance.
-- Authority: JJ 2026-11-25T02:45Z/02:53Z (option 1). Additive except the
-- relaxation of the two 0031 chain pins (D5).
--
--   protected_minter_tokens    deal tokens admitted for protected mint, written
--                              by Steward itself after verifying the receipt of
--                              its own protected createDealToken (admin = Safe,
--                              minter = signer, hasRole(MINTER_ROLE, signer)).
--                              Revocable at runtime; no manifest edit, no restart.
--   protected_minter_controls  one row per protected agent; non-NULL
--                              protected_minting_suspended_at => nothing is
--                              auto-signed (every mint falls back to the human queue).
--   transactions.signed_raw / signed_nonce / signer_address / sent_at (H1)
--                              protected signer only: exact signed bytes, nonce
--                              and signer persisted BEFORE the send, so an
--                              uncertain outcome is reconciled and the SAME
--                              bytes retransmitted; never re-signed.
--   approval_queue.approval_source / instruction_digest
--                              'issuance_readback' rows were approved by a live
--                              Strata read-back match, not by a human. The vault
--                              permit accepts such a row only with a non-NULL
--                              instruction_digest and an unsuspended agent.
--
-- Rollback (only BEFORE any issuance_readback row was signed; afterwards it
-- erases the evidence of why those transactions were signed):
--   ALTER TABLE transactions DROP CONSTRAINT transactions_signed_raw_chk;
--   ALTER TABLE transactions DROP COLUMN sent_at, DROP COLUMN signer_address,
--     DROP COLUMN signed_nonce, DROP COLUMN signed_raw;
--   ALTER TABLE approval_queue DROP CONSTRAINT approval_queue_source_chk;
--   ALTER TABLE approval_queue DROP CONSTRAINT approval_queue_readback_digest_chk;
--   ALTER TABLE approval_queue DROP COLUMN instruction_digest;
--   ALTER TABLE approval_queue DROP COLUMN approval_source;
--   DROP TABLE protected_minter_controls;
--   DROP TABLE protected_minter_tokens;
--   DROP TYPE protected_minter_token_status;
--   and re-add the 0031 pins (refused if a non-84532 row exists):
--   ALTER TABLE application_executor_signers DROP CONSTRAINT application_executor_signers_chain_chk,
--     ADD CONSTRAINT application_executor_signers_chain_chk CHECK (chain_id = 84532);
--   ALTER TABLE application_proposal_executions DROP CONSTRAINT application_executions_chain_chk,
--     ADD CONSTRAINT application_executions_chain_chk CHECK (chain_id = 84532);
CREATE TYPE "protected_minter_token_status" AS ENUM ('active', 'revoked');
--> statement-breakpoint
CREATE TABLE "protected_minter_tokens" (
  "id" varchar(64) PRIMARY KEY NOT NULL,
  "tenant_id" varchar(64) NOT NULL,
  "agent_id" varchar(64) NOT NULL,
  "chain_id" integer NOT NULL,
  "token_address" varchar(42) NOT NULL,
  "deploy_tx_hash" varchar(66) NOT NULL,
  "deploy_execution_ref" varchar(128) NOT NULL,
  "admitted_at" timestamp with time zone NOT NULL DEFAULT now(),
  "status" protected_minter_token_status NOT NULL DEFAULT 'active',
  "revoked_by" varchar(255),
  "revoked_at" timestamp with time zone,
  "revoke_reason" text,
  CONSTRAINT "protected_minter_tokens_chain_chk" CHECK ("chain_id" > 0),
  CONSTRAINT "protected_minter_tokens_address_chk" CHECK ("token_address" ~ '^0x[0-9a-f]{40}$'),
  CONSTRAINT "protected_minter_tokens_hash_chk" CHECK ("deploy_tx_hash" ~ '^0x[0-9a-f]{64}$'),
  CONSTRAINT "protected_minter_tokens_revoke_chk" CHECK (
    ("status" = 'active' AND "revoked_at" IS NULL AND "revoked_by" IS NULL)
    OR ("status" = 'revoked' AND "revoked_at" IS NOT NULL AND "revoked_by" IS NOT NULL)
  ),
  CONSTRAINT "protected_minter_tokens_agent_fk"
    FOREIGN KEY ("tenant_id", "agent_id")
    REFERENCES "agents" ("tenant_id", "id") ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX "protected_minter_tokens_scope_idx"
  ON "protected_minter_tokens" ("tenant_id", "agent_id", "chain_id", "token_address");
--> statement-breakpoint
-- Revocation is one-way: a revoked admission can never be re-activated by an
-- UPDATE (re-admission needs a new deploy, i.e. a new token address).
CREATE OR REPLACE FUNCTION steward_guard_protected_minter_token_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.agent_id <> OLD.agent_id
     OR NEW.chain_id <> OLD.chain_id OR NEW.token_address <> OLD.token_address
     OR NEW.deploy_tx_hash <> OLD.deploy_tx_hash
     OR NEW.deploy_execution_ref <> OLD.deploy_execution_ref
     OR NEW.admitted_at <> OLD.admitted_at THEN
    RAISE EXCEPTION 'protected minter token admission identity is immutable';
  END IF;
  IF OLD.status = 'revoked' THEN
    RAISE EXCEPTION 'protected minter token admission is revoked (terminal)';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
--> statement-breakpoint
CREATE TRIGGER protected_minter_tokens_guard
  BEFORE UPDATE ON protected_minter_tokens
  FOR EACH ROW EXECUTE FUNCTION steward_guard_protected_minter_token_update();
--> statement-breakpoint
CREATE TABLE "protected_minter_controls" (
  "tenant_id" varchar(64) NOT NULL,
  "agent_id" varchar(64) NOT NULL,
  "protected_minting_suspended_at" timestamp with time zone,
  "suspended_by" varchar(255),
  "suspend_reason" text,
  "updated_at" timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT "protected_minter_controls_pk" PRIMARY KEY ("tenant_id", "agent_id"),
  CONSTRAINT "protected_minter_controls_agent_fk"
    FOREIGN KEY ("tenant_id", "agent_id")
    REFERENCES "agents" ("tenant_id", "id") ON DELETE cascade
);
--> statement-breakpoint
ALTER TABLE "approval_queue" ADD COLUMN IF NOT EXISTS "approval_source" varchar(32);
--> statement-breakpoint
ALTER TABLE "approval_queue" ADD COLUMN IF NOT EXISTS "instruction_digest" varchar(66);
--> statement-breakpoint
ALTER TABLE "approval_queue" ADD CONSTRAINT "approval_queue_source_chk"
  CHECK ("approval_source" IS NULL OR "approval_source" IN ('human', 'issuance_readback'));
--> statement-breakpoint
ALTER TABLE "approval_queue" ADD CONSTRAINT "approval_queue_readback_digest_chk"
  CHECK ("approval_source" IS DISTINCT FROM 'issuance_readback' OR "instruction_digest" IS NOT NULL);
--> statement-breakpoint
-- D5: remove the arbitrary Base Sepolia pin. The chain derives from the
-- binding + configured network (STEWARD_APPLICATION_EXECUTION_CHAIN_IDS).
ALTER TABLE "application_executor_signers" DROP CONSTRAINT "application_executor_signers_chain_chk";
--> statement-breakpoint
ALTER TABLE "application_executor_signers" ADD CONSTRAINT "application_executor_signers_chain_chk"
  CHECK ("chain_id" > 0);
--> statement-breakpoint
ALTER TABLE "application_proposal_executions" DROP CONSTRAINT "application_executions_chain_chk";
--> statement-breakpoint
ALTER TABLE "application_proposal_executions" ADD CONSTRAINT "application_executions_chain_chk"
  CHECK ("chain_id" > 0);
--> statement-breakpoint
ALTER TABLE "transactions" ADD COLUMN IF NOT EXISTS "signed_raw" text;
--> statement-breakpoint
ALTER TABLE "transactions" ADD COLUMN IF NOT EXISTS "signed_nonce" bigint;
--> statement-breakpoint
ALTER TABLE "transactions" ADD COLUMN IF NOT EXISTS "signer_address" varchar(42);
--> statement-breakpoint
ALTER TABLE "transactions" ADD COLUMN IF NOT EXISTS "sent_at" timestamp with time zone;
--> statement-breakpoint
ALTER TABLE "transactions" ADD CONSTRAINT "transactions_signed_raw_chk"
  CHECK ("signed_raw" IS NULL OR ("tx_hash" IS NOT NULL AND "signed_nonce" IS NOT NULL AND "signer_address" IS NOT NULL));
