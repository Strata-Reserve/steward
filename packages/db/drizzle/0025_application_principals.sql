CREATE TYPE "application_capability" AS ENUM (
  'wallet:ensure',
  'wallet:address:read',
  'transaction:prepare',
  'transaction:propose'
);
CREATE TYPE "application_resource_kind" AS ENUM ('wallet_owner');
CREATE TYPE "application_operation" AS ENUM (
  'wallet_ensure',
  'transaction_prepare',
  'transaction_propose'
);
CREATE TYPE "application_proposal_status" AS ENUM ('proposed');

CREATE UNIQUE INDEX IF NOT EXISTS "agents_tenant_id_id_idx" ON "agents" ("tenant_id", "id");

CREATE TABLE "application_principals" (
  "id" varchar(64) PRIMARY KEY NOT NULL,
  "tenant_id" varchar(64) NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "name" varchar(255) NOT NULL,
  "capabilities" application_capability[] NOT NULL,
  "expires_at" timestamp with time zone NOT NULL,
  "revoked_at" timestamp with time zone,
  "created_at" timestamp with time zone NOT NULL DEFAULT now(),
  "updated_at" timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT "application_principals_capabilities_nonempty_chk"
    CHECK (cardinality("capabilities") BETWEEN 1 AND 4)
);
CREATE UNIQUE INDEX "application_principals_tenant_id_idx"
  ON "application_principals" ("tenant_id", "id");
CREATE INDEX "application_principals_active_idx"
  ON "application_principals" ("tenant_id", "expires_at") WHERE "revoked_at" IS NULL;

CREATE TABLE "application_principal_credentials" (
  "key_id" varchar(64) PRIMARY KEY NOT NULL,
  "tenant_id" varchar(64) NOT NULL,
  "principal_id" varchar(64) NOT NULL,
  "secret_hash" varchar(64) NOT NULL,
  "expires_at" timestamp with time zone NOT NULL,
  "revoked_at" timestamp with time zone,
  "created_at" timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT "application_credentials_key_id_chk" CHECK ("key_id" ~ '^apk_[0-9a-f]{24}$'),
  CONSTRAINT "application_credentials_secret_hash_chk" CHECK ("secret_hash" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "application_credentials_expiry_chk" CHECK ("expires_at" > "created_at"),
  CONSTRAINT "application_credentials_tenant_principal_fk"
    FOREIGN KEY ("tenant_id", "principal_id")
    REFERENCES "application_principals" ("tenant_id", "id") ON DELETE cascade
);
CREATE UNIQUE INDEX "application_credentials_tenant_principal_key_idx"
  ON "application_principal_credentials" ("tenant_id", "principal_id", "key_id");
CREATE INDEX "application_credentials_active_idx"
  ON "application_principal_credentials" ("tenant_id", "principal_id", "expires_at")
  WHERE "revoked_at" IS NULL;

CREATE TABLE "application_principal_resources" (
  "tenant_id" varchar(64) NOT NULL,
  "principal_id" varchar(64) NOT NULL,
  "resource_kind" application_resource_kind NOT NULL,
  "resource_id" varchar(255) NOT NULL,
  "created_at" timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT "application_principal_resources_id_chk" CHECK (length("resource_id") > 0),
  CONSTRAINT "application_principal_resources_tenant_principal_fk"
    FOREIGN KEY ("tenant_id", "principal_id")
    REFERENCES "application_principals" ("tenant_id", "id") ON DELETE cascade
);
CREATE UNIQUE INDEX "application_principal_resources_scope_idx"
  ON "application_principal_resources" ("tenant_id", "principal_id", "resource_kind", "resource_id");

CREATE TABLE "application_wallets" (
  "id" varchar(64) PRIMARY KEY NOT NULL,
  "tenant_id" varchar(64) NOT NULL,
  "principal_id" varchar(64) NOT NULL,
  "resource_kind" application_resource_kind NOT NULL,
  "resource_id" varchar(255) NOT NULL,
  "steward_agent_id" varchar(64) NOT NULL,
  "addresses" jsonb NOT NULL,
  "created_at" timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT "application_wallets_addresses_chk" CHECK (
    jsonb_typeof("addresses") = 'object'
    AND jsonb_typeof("addresses"->'evm') = 'string'
    AND jsonb_typeof("addresses"->'solana') = 'string'
    AND ("addresses"->>'evm') ~ '^0x[0-9a-fA-F]{40}$'
    AND length("addresses"->>'solana') BETWEEN 32 AND 44
  ),
  CONSTRAINT "application_wallets_assigned_resource_fk"
    FOREIGN KEY ("tenant_id", "principal_id", "resource_kind", "resource_id")
    REFERENCES "application_principal_resources" ("tenant_id", "principal_id", "resource_kind", "resource_id")
    ON DELETE cascade,
  CONSTRAINT "application_wallets_tenant_agent_fk"
    FOREIGN KEY ("tenant_id", "steward_agent_id") REFERENCES "agents" ("tenant_id", "id")
    ON DELETE cascade
);
CREATE UNIQUE INDEX "application_wallets_scope_idx"
  ON "application_wallets" ("tenant_id", "principal_id", "resource_kind", "resource_id");
CREATE UNIQUE INDEX "application_wallets_tenant_principal_id_idx"
  ON "application_wallets" ("tenant_id", "principal_id", "id");
CREATE UNIQUE INDEX "application_wallets_agent_idx" ON "application_wallets" ("steward_agent_id");

CREATE TABLE "application_idempotency_records" (
  "tenant_id" varchar(64) NOT NULL,
  "principal_id" varchar(64) NOT NULL,
  "operation" application_operation NOT NULL,
  "idempotency_key" varchar(128) NOT NULL,
  "request_hash" varchar(64) NOT NULL,
  "response_id" varchar(64) NOT NULL,
  "created_at" timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT "application_idempotency_key_chk" CHECK (length("idempotency_key") BETWEEN 1 AND 128),
  CONSTRAINT "application_idempotency_hash_chk" CHECK ("request_hash" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "application_idempotency_tenant_principal_fk"
    FOREIGN KEY ("tenant_id", "principal_id")
    REFERENCES "application_principals" ("tenant_id", "id") ON DELETE cascade
);
CREATE UNIQUE INDEX "application_idempotency_scope_idx"
  ON "application_idempotency_records" ("tenant_id", "principal_id", "operation", "idempotency_key");

CREATE TABLE "application_transaction_intents" (
  "id" varchar(64) PRIMARY KEY NOT NULL,
  "tenant_id" varchar(64) NOT NULL,
  "principal_id" varchar(64) NOT NULL,
  "credential_key_id" varchar(64) NOT NULL,
  "wallet_id" varchar(64) NOT NULL,
  "request_hash" varchar(64) NOT NULL,
  "intent" jsonb NOT NULL,
  "expires_at" timestamp with time zone NOT NULL,
  "created_at" timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT "application_intents_hash_chk" CHECK ("request_hash" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "application_intents_expiry_chk" CHECK ("expires_at" > "created_at"),
  CONSTRAINT "application_intents_wallet_fk"
    FOREIGN KEY ("tenant_id", "principal_id", "wallet_id")
    REFERENCES "application_wallets" ("tenant_id", "principal_id", "id") ON DELETE cascade,
  CONSTRAINT "application_intents_credential_fk"
    FOREIGN KEY ("tenant_id", "principal_id", "credential_key_id")
    REFERENCES "application_principal_credentials" ("tenant_id", "principal_id", "key_id") ON DELETE cascade
);
CREATE UNIQUE INDEX "application_intents_tenant_principal_id_idx"
  ON "application_transaction_intents" ("tenant_id", "principal_id", "id");
CREATE INDEX "application_intents_tenant_principal_idx"
  ON "application_transaction_intents" ("tenant_id", "principal_id");

CREATE TABLE "application_transaction_proposals" (
  "id" varchar(64) PRIMARY KEY NOT NULL,
  "tenant_id" varchar(64) NOT NULL,
  "principal_id" varchar(64) NOT NULL,
  "credential_key_id" varchar(64) NOT NULL,
  "intent_id" varchar(64) NOT NULL,
  "request_hash" varchar(64) NOT NULL,
  "status" application_proposal_status NOT NULL DEFAULT 'proposed',
  "created_at" timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT "application_proposals_hash_chk" CHECK ("request_hash" ~ '^[0-9a-f]{64}$'),
  CONSTRAINT "application_proposals_intent_fk"
    FOREIGN KEY ("tenant_id", "principal_id", "intent_id")
    REFERENCES "application_transaction_intents" ("tenant_id", "principal_id", "id") ON DELETE cascade,
  CONSTRAINT "application_proposals_credential_fk"
    FOREIGN KEY ("tenant_id", "principal_id", "credential_key_id")
    REFERENCES "application_principal_credentials" ("tenant_id", "principal_id", "key_id") ON DELETE cascade
);
CREATE UNIQUE INDEX "application_proposals_tenant_principal_id_idx"
  ON "application_transaction_proposals" ("tenant_id", "principal_id", "id");
CREATE UNIQUE INDEX "application_proposals_intent_unique_idx"
  ON "application_transaction_proposals" ("tenant_id", "principal_id", "intent_id");
CREATE INDEX "application_proposals_tenant_principal_idx"
  ON "application_transaction_proposals" ("tenant_id", "principal_id");

CREATE FUNCTION steward_reject_application_immutable_update() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'application authority rows are immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER application_resources_immutable
  BEFORE UPDATE ON application_principal_resources
  FOR EACH ROW EXECUTE FUNCTION steward_reject_application_immutable_update();
CREATE TRIGGER application_wallets_immutable
  BEFORE UPDATE ON application_wallets
  FOR EACH ROW EXECUTE FUNCTION steward_reject_application_immutable_update();
CREATE TRIGGER application_idempotency_immutable
  BEFORE UPDATE ON application_idempotency_records
  FOR EACH ROW EXECUTE FUNCTION steward_reject_application_immutable_update();
CREATE TRIGGER application_intents_immutable
  BEFORE UPDATE ON application_transaction_intents
  FOR EACH ROW EXECUTE FUNCTION steward_reject_application_immutable_update();
CREATE TRIGGER application_proposals_immutable
  BEFORE UPDATE ON application_transaction_proposals
  FOR EACH ROW EXECUTE FUNCTION steward_reject_application_immutable_update();

CREATE FUNCTION steward_guard_application_principal_update() RETURNS trigger AS $$
BEGIN
  IF NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.name <> OLD.name
     OR NEW.capabilities <> OLD.capabilities OR NEW.expires_at <> OLD.expires_at
     OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'application principal authority fields are immutable';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER application_principal_authority_immutable
  BEFORE UPDATE ON application_principals
  FOR EACH ROW EXECUTE FUNCTION steward_guard_application_principal_update();

CREATE FUNCTION steward_guard_application_credential_update() RETURNS trigger AS $$
BEGIN
  IF NEW.key_id <> OLD.key_id OR NEW.tenant_id <> OLD.tenant_id
     OR NEW.principal_id <> OLD.principal_id OR NEW.secret_hash <> OLD.secret_hash
     OR NEW.expires_at <> OLD.expires_at OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'application credential authority fields are immutable';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER application_credential_authority_immutable
  BEFORE UPDATE ON application_principal_credentials
  FOR EACH ROW EXECUTE FUNCTION steward_guard_application_credential_update();
