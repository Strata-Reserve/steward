ALTER TYPE "application_capability" ADD VALUE IF NOT EXISTS 'transaction:proposal:read';
--> statement-breakpoint
ALTER TABLE "application_principals"
  DROP CONSTRAINT IF EXISTS "application_principals_capabilities_nonempty_chk";
--> statement-breakpoint
ALTER TABLE "application_principals"
  ADD CONSTRAINT "application_principals_capabilities_nonempty_chk"
  CHECK (cardinality("capabilities") BETWEEN 1 AND 5);
--> statement-breakpoint
-- The compatibility snapshot is deliberately proposal-specific. A principal-
-- wide grant would let a pre-0026 proposer read sibling proposals created
-- after this migration. The existence guard is also security-significant:
-- replay may recreate the trigger, but must never snapshot later proposals.
DO $migration$
BEGIN
  IF to_regclass('public.application_proposal_read_compatibility') IS NULL THEN
    CREATE TABLE "application_proposal_read_compatibility" (
      "tenant_id" varchar(64) NOT NULL,
      "principal_id" varchar(64) NOT NULL,
      "proposal_id" varchar(64) NOT NULL,
      "resource_kind" application_resource_kind NOT NULL,
      "resource_id" varchar(255) NOT NULL,
      "source" varchar(48) NOT NULL,
      "created_at" timestamp with time zone NOT NULL DEFAULT now(),
      CONSTRAINT "application_proposal_read_compatibility_source_chk"
        CHECK ("source" = 'pre_0026_transaction_proposal')
    );

    CREATE UNIQUE INDEX "application_proposal_read_compatibility_idx"
      ON "application_proposal_read_compatibility"
      ("tenant_id", "principal_id", "proposal_id", "resource_kind", "resource_id");

    INSERT INTO "application_proposal_read_compatibility"
      ("tenant_id", "principal_id", "proposal_id", "resource_kind", "resource_id", "source")
    SELECT
      proposal."tenant_id",
      proposal."principal_id",
      proposal."id",
      wallet."resource_kind",
      wallet."resource_id",
      'pre_0026_transaction_proposal'
    FROM "application_transaction_proposals" proposal
    INNER JOIN "application_principals" principal
      ON principal."tenant_id" = proposal."tenant_id"
     AND principal."id" = proposal."principal_id"
    INNER JOIN "application_transaction_intents" intent
      ON intent."tenant_id" = proposal."tenant_id"
     AND intent."principal_id" = proposal."principal_id"
     AND intent."id" = proposal."intent_id"
    INNER JOIN "application_wallets" wallet
      ON wallet."tenant_id" = intent."tenant_id"
     AND wallet."principal_id" = intent."principal_id"
     AND wallet."id" = intent."wallet_id"
    INNER JOIN "application_principal_resources" resource
      ON resource."tenant_id" = wallet."tenant_id"
     AND resource."principal_id" = wallet."principal_id"
     AND resource."resource_kind" = wallet."resource_kind"
     AND resource."resource_id" = wallet."resource_id"
    WHERE 'transaction:propose'::application_capability = ANY(principal."capabilities");
  END IF;
END
$migration$;
--> statement-breakpoint
CREATE OR REPLACE FUNCTION steward_reject_application_proposal_read_compatibility_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'application proposal read compatibility assignments are immutable';
END;
$$ LANGUAGE plpgsql;
--> statement-breakpoint
DROP TRIGGER IF EXISTS application_proposal_read_compatibility_immutable
  ON "application_proposal_read_compatibility";
--> statement-breakpoint
CREATE TRIGGER application_proposal_read_compatibility_immutable
  BEFORE INSERT OR UPDATE OR DELETE ON "application_proposal_read_compatibility"
  FOR EACH ROW EXECUTE FUNCTION steward_reject_application_proposal_read_compatibility_mutation();
