CREATE TABLE IF NOT EXISTS "application_principals" (
  "id" varchar(64) PRIMARY KEY NOT NULL,
  "tenant_id" varchar(64) NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "name" varchar(255) NOT NULL,
  "audit_identity" varchar(255) NOT NULL,
  "capabilities" text[] NOT NULL,
  "owner_references" text[] NOT NULL,
  "expires_at" timestamp with time zone NOT NULL,
  "revoked_at" timestamp with time zone,
  "created_at" timestamp with time zone NOT NULL DEFAULT now(),
  "updated_at" timestamp with time zone NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS "application_principals_tenant_idx" ON "application_principals" ("tenant_id");
CREATE INDEX IF NOT EXISTS "application_principals_active_idx" ON "application_principals" ("tenant_id", "expires_at") WHERE "revoked_at" IS NULL;

CREATE TABLE IF NOT EXISTS "application_principal_credentials" (
  "key_id" varchar(64) PRIMARY KEY NOT NULL,
  "principal_id" varchar(64) NOT NULL REFERENCES "application_principals"("id") ON DELETE cascade,
  "secret_hash" text NOT NULL,
  "expires_at" timestamp with time zone NOT NULL,
  "revoked_at" timestamp with time zone,
  "created_at" timestamp with time zone NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS "application_principal_credentials_principal_idx" ON "application_principal_credentials" ("principal_id");
CREATE INDEX IF NOT EXISTS "application_principal_credentials_active_idx" ON "application_principal_credentials" ("principal_id", "expires_at") WHERE "revoked_at" IS NULL;

CREATE TABLE IF NOT EXISTS "application_wallets" (
  "id" varchar(64) PRIMARY KEY NOT NULL,
  "tenant_id" varchar(64) NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "principal_id" varchar(64) NOT NULL REFERENCES "application_principals"("id") ON DELETE cascade,
  "owner_reference" varchar(255) NOT NULL,
  "chain_family" "chain_family" NOT NULL,
  "steward_agent_id" varchar(64) NOT NULL REFERENCES "agents"("id") ON DELETE restrict,
  "address" varchar(128) NOT NULL,
  "created_at" timestamp with time zone NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS "application_wallets_principal_owner_chain_idx" ON "application_wallets" ("principal_id", "owner_reference", "chain_family");
CREATE INDEX IF NOT EXISTS "application_wallets_tenant_principal_idx" ON "application_wallets" ("tenant_id", "principal_id");

CREATE TABLE IF NOT EXISTS "application_transaction_intents" (
  "id" varchar(64) PRIMARY KEY NOT NULL,
  "tenant_id" varchar(64) NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "principal_id" varchar(64) NOT NULL REFERENCES "application_principals"("id") ON DELETE cascade,
  "wallet_id" varchar(64) NOT NULL REFERENCES "application_wallets"("id") ON DELETE restrict,
  "idempotency_key" varchar(255) NOT NULL,
  "request_hash" varchar(64) NOT NULL,
  "intent" jsonb NOT NULL,
  "created_at" timestamp with time zone NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS "application_transaction_intents_idempotency_idx" ON "application_transaction_intents" ("principal_id", "idempotency_key");
CREATE INDEX IF NOT EXISTS "application_transaction_intents_tenant_principal_idx" ON "application_transaction_intents" ("tenant_id", "principal_id");

CREATE TABLE IF NOT EXISTS "application_transaction_proposals" (
  "id" varchar(64) PRIMARY KEY NOT NULL,
  "tenant_id" varchar(64) NOT NULL REFERENCES "tenants"("id") ON DELETE cascade,
  "principal_id" varchar(64) NOT NULL REFERENCES "application_principals"("id") ON DELETE cascade,
  "intent_id" varchar(64) NOT NULL REFERENCES "application_transaction_intents"("id") ON DELETE restrict,
  "idempotency_key" varchar(255) NOT NULL,
  "request_hash" varchar(64) NOT NULL,
  "status" varchar(32) NOT NULL DEFAULT 'proposed',
  "created_at" timestamp with time zone NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS "application_transaction_proposals_idempotency_idx" ON "application_transaction_proposals" ("principal_id", "idempotency_key");
CREATE INDEX IF NOT EXISTS "application_transaction_proposals_intent_idx" ON "application_transaction_proposals" ("intent_id");
