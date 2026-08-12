ALTER TYPE "application_capability" ADD VALUE IF NOT EXISTS 'transaction:proposal:read';
--> statement-breakpoint
ALTER TABLE "application_principals"
  DROP CONSTRAINT "application_principals_capabilities_nonempty_chk";
--> statement-breakpoint
ALTER TABLE "application_principals"
  ADD CONSTRAINT "application_principals_capabilities_nonempty_chk"
  CHECK (cardinality("capabilities") BETWEEN 1 AND 5);
