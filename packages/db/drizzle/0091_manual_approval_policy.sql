-- STRATA-1097: first-class action-aware manual approval policy.
-- Additive enum member only; no existing policy rows or behavior change.
ALTER TYPE "public"."policy_type" ADD VALUE IF NOT EXISTS 'manual-approval';
