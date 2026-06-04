# Upstream Sync Plan — Steward-Fi/develop → Strata-Reserve/develop

**Date:** 2026-06-04
**Author:** Midas (infra agent)
**Integration branch:** `chore/sync-upstream-develop`
**Base:** `origin/develop` @ `540d9cd`
**Target:** `upstream/develop` @ `2c3ba2c`

---

## TL;DR / Verdict

- **99 commits behind** `upstream/develop`; **0 commits ahead** on `develop`.
- `origin/develop` is a **strict ancestor** of `upstream/develop` (merge-base == `origin/develop` tip == `540d9cd`).
  → The sync of `develop` itself is a **conflict-free integration (effectively a fast-forward)**. There is **no Strata divergence on the `develop` branch**.
- Strata fork divergence lives on **other branches**, not `develop`:
  - `strata-staging` (1 commit ahead): `9a14825` Strata magic-link email template + writable magic-link overrides — touches `packages/auth/src/email-templates/*` and `packages/api/src/routes/platform.ts`.
  - `fix/stable-session-subject-and-verified-email` (in-flight PR, 1 commit): `debcd4e` — touches `packages/api/src/routes/auth.ts` + 2 test files.
- **This PR is a CLEAN MERGE of `develop` only, ready to review.** It deliberately does **NOT** include the two Strata branches above, because both touch files upstream also rewrote (notably `auth.ts`). Those need separate rebase + human review (see Conflict Assessment).
- **Validation:** build (typecheck) 20/20 packages ✓, web `tsc --noEmit` ✓, biome lint (692 files) ✓. Unit tests: see Validation — the only failures (11 Apple-OIDC tests in `@stwd/auth`) are a **pre-existing upstream test-isolation artifact**, reproduced on pristine `upstream/develop`, **not introduced by this merge**.
- **Deploy gate:** brings **~24 new DB migrations (0025–0048)**. Migrations MUST run before/at deploy. Do not deploy from this PR without a migration plan. (Out of scope for this task — flagged for human.)

---

## 1. Categorized Inventory (99 commits, `origin/develop..upstream/develop`)

Areas determined by files touched. SEC = security-relevant, CUST = custody/fund-safety-relevant.

### auth / session / identity
| sha | subject | Strata relevance |
|---|---|---|
| `f69c996` | **[SEC]** fix(auth): enforce SIWS expiry/not-before; trust verified-email-less OAuth providers (#116) | **Directly overlaps** in-flight `fix/stable-session-subject-and-verified-email` (#debcd4e) and Strata auth work. Same code path (`auth.ts`, verified-email claim). **Highest conflict priority.** |
| `781f8fc` | feat(auth): port OIDC/SAML/Farcaster/Telegram provider primitives + identity slice (#79 wave A) | New auth providers + identity slice. Adds `schema-auth.ts`, migrations 0027–0032. Touches code paths Strata uses (session/login). |
| `0467314` | **[SEC]** feat(security): multi-language SDKs, new API surface, hardened auth/audit controls | Large hardening across auth/audit. Rewrites large parts of `auth.ts` + audit. |
| `7eb8d51` | **[SEC]** fix: P0 security findings from the 2026-05-30 audit (#81) | P0 audit remediation. Auth/session. |
| `271a5b6` | **[SEC]** fix(security): drop tenant FKs that broke audit writes; finalize audit-integrity remediation | Audit-integrity; touches tenants + auth. |
| `3faf518` | **[SEC]** security: audit hardening across auth, webhooks, infra, and SDK | Broad hardening base commit. |
| `d6da67f` | fix(agents): require recent admin MFA for signer type/address/chainFamily updates | MFA gate on signer mutation — custody-adjacent. |

### vault / signing (CUSTODY)
| sha | subject | Strata relevance |
|---|---|---|
| `2c3ba2c` | **[CUST]** fix(vault): sign v0 (versioned) Solana transactions (#119) | Solana signing correctness. If Strata signs Solana txs, required. |
| `334dcd5` | **[CUST]** fix(vault): Solana parser fund-safety — count CreateAccount, fail-closed multi-recipient/mint (#112) | **Fund-safety.** Fail-closed on ambiguous Solana txs. High value. |
| `ac54203` | **[CUST/SEC]** fix(api): build /sign request from declared fields only (allowlist integrity) (#97) | **Signing allowlist integrity** — prevents field injection into /sign. High value. |
| `7d4e47a` | feat(vault): provisionVenueWallet with policies-from-birth + approved-addresses withdraw check (#87) | Venue wallet provisioning + withdraw allowlist. Custody path. |
| `6a5e3ff` | **[CUST]** fix(vault): bind keystore context when provisioning venue wallets (#96) | Keystore context binding — custody correctness. |
| `2f9be8d` | fix(vault): support venue-scoped sign keys (#78) | Venue-scoped signing keys. |
| `d5fa1ab` | feat(vault): port agent signers + key quorums (#79 wave B) | Agent signers + key quorums (migrations 0033/0034). Custody control plane. |
| `39089d9` | feat(vault): pluggable KMS/BYOK keystore backend (#84) | KMS/BYOK keystore backend. Relevant if Strata uses third-party KMS. |
| `bfb3af6` | feat(venue-hyperliquid): add withdraw3 signing + closeAllPositions (#86) | HL withdraw3 signing. Custody if trading HL. |

### api / policy / spend-caps (CUSTODY-adjacent)
| sha | subject | Strata relevance |
|---|---|---|
| `1e589ce` | **[CUST]** fix(api): validate operator /withdraw amount + run spend-cap on real notional (#114) | **Spend-cap on real notional** + withdraw amount validation. High value. |
| `efab432` | **[CUST]** fix(api): chain-scope native spend stats so multi-chain spend caps enforce correctly (#118) | Multi-chain spend-cap correctness. |
| `5f6bbee` | **[SEC]** fix(security): policy/cap changes are patron-only, not agent (#94) | **Privilege fix** — agents can't change their own caps/policy. High value. |
| `558ff1c` | fix(api): pass venue at top-level of withdraw policy eval context (#90) | Withdraw policy eval context. |
| `c08aeb0` | feat(trade): add operator deposit endpoint (vault-signed USDC→HL bridge) (#92) | New deposit endpoint (vault-signed). |
| `c8de1d1` | feat(api): operator close-all + withdraw recovery endpoints (#88) | Recovery endpoints. |
| `88b2aed` | feat(api): agent trade token expiry monitoring + token-status endpoint (#89) | Token expiry monitoring. |
| `d313991` | fix(api): defer MFA-gated signing + webhook session gates to the MFA wave | Defers MFA gates — note for sequencing. |
| `f315744` | feat: add per-agent trade policies (#75) | Per-agent trade policies. Policy path. |
| `543ff32` | feat(trade): add more Hyperliquid assets (#77) | More HL assets. |

### policy-engine
| sha | subject | relevance |
|---|---|---|
| `9855f54` | feat(api): port intents + condition-sets (#79 wave C) | Intents + condition-sets (migrations 0036/0037). Policy expressiveness. |
| `4c6d1bf` | style(policy-engine): drop stray blank line | trivial |
| `dd385f4` | test(policy-engine): update 6 tests to assert fail-closed behavior | fail-closed test hardening |
| `38038...` (`0467314` carries `0038_contract_allowlist_policy.sql`) | contract allowlist policy | contract allowlist |

### webhooks
| sha | subject | relevance |
|---|---|---|
| `2f0848f` | fix(api,webhooks): don't cache 5xx idempotency replays; per-attempt webhook sent-at (#115) | Idempotency correctness. |
| `6e000cf` | feat(api): port gas sponsorship + webhook hardening (#79 wave D) | Gas sponsorship + webhook hardening (migrations 0040–0044). |
| `ccde127` | fix(api): complete @stwd/webhooks test mock + restore legacy tenant webhook fan-out | restores legacy tenant fan-out |
| `c3bc178` | fix(webhooks): serialize timestamps to ISO in persistent queue claim query | serialization fix |

### redis
| sha | subject | relevance |
|---|---|---|
| `205e709` | fix(redis): add getdel to Upstash ioredis adapter (single-use tokens on Workers) (#113) | Single-use token correctness on Workers/Upstash. Auth-token relevant. |

### db / schema (migrations 0025–0048 — **DEPLOY GATE**)
Carried across multiple commits above. New migrations:
`0025_approval_queue_principals`, `0026_agent_policies`, `0027_user_identity_metadata`, `0028_tenant_oidc_providers`, `0029_tenant_sso_domains`, `0030_tenant_saml_sso_configs`, `0031_saml_request_replay_storage`, `0032_user_wallet_identity_unique`, `0033_agent_signers`, `0034_agent_key_quorums`, `0036_condition_sets`, `0037_intents`, `0038_contract_allowlist_policy`, `0040_tenant_gas_sponsorship_config`, `0041_sponsored_gas_events`, `0042_webhook_config_tenant_url_unique`, `0043_webhook_delivery_config_snapshot`, `0044_webhook_delivery_processing_status`, `0045_wallet_action_metadata`, `0046_pr79_union_hardening`, `0047_pr79_security_invariants`, `0048_harden_tenant_join_default`.
Plus `schema.ts` / `schema-auth.ts` rewrites. `53f811a` ports `0045` migration.

### openapi
| sha | subject | relevance |
|---|---|---|
| `e4f688d` | feat: schema-driven OpenAPI (infra + pilot + generators) and adaptive Solana priority fees (#104) | OpenAPI infra + adaptive Solana priority fees (custody-adjacent fee logic). Adds `docs/api-reference/openapi.json`. |

### erc8004 / erc8183 (new feature surface)
| sha | subject | relevance |
|---|---|---|
| `135f084` | feat(erc8183): add agentic commerce client (#93) | New package. Not on current Strata path unless adopted. |
| `8c622b2` | feat(erc8004): implement real registry client (#91) | New package. |

### ci (largest group — mostly test/infra plumbing for #79)
`e3d15eb`, `70e73f4`, `d086146`, `8c9e90d`, `7e1a2ce`, `61724fd`, `b62a8da`, `9aa4681`, `eba240c`, `55363a5`, `01069d4`, `916cb1a`, `8407890`, `9025ef9`, `1d97993`, `a5cbef7`, `dd38f98`, `760bde5`, `735c8e1`, `df10e27`, `2d28e4c`, plus worker-bucket test repairs `42c7732`/`b1ae784`/`b67219c`/`ee4b108`, and test migrations `32a240a`/`fa3ca47`/`0aa3044`/`f74a2fa`/`eaea021`/`03bc7cf`/`6cffb9e`/`020d9a0`/`81ee323`/`cfab0f0`/`1a1d050`.
**Relevance:** these are the commits that make the hardened suite green via **per-file/sharded** runs (key: `70e73f4`, `d086146` — directly explain the Apple-OIDC isolation issue, see Validation).

### deploy / docker
| sha | subject | relevance |
|---|---|---|
| `db7bb3a` | fix(deploy): supply proxy REDIS_URL + signing secret; pipe provision secrets over stdin (#117) | **Deploy-relevant** — proxy needs REDIS_URL + signing secret. Affects Railway env. Review against Strata's Railway config. |
| `587aefc` | feat(web): deploy to Cloudflare Workers via OpenNext (#80) | CF Workers web deploy (adds `wrangler.toml`, `deploy-web-cloudflare.yml`). Optional for Strata. |
| `351c9cc` | fix(docker): publish develop branch image (#74) | Docker publish on develop. |
| `b62a8da` | fix(ci): Docker workspace COPY for @stwd/adapters + erc8004 @types/node | Dockerfile workspace copy. |

### docs / chore / other
`6cdf2dd` brand voice docs, `7213aa7`/`bb4d245`/`a7292d0` prune web/dashboard, `0c3837e` release bump sdk/react/eliza, `2113592` lockfile regen, `8afe910`/`2dffa10`/`4115f5f`/`1dff233`/`85e21a9` wave merges, `810e2e5` CSP nonce middleware (web hardening), `53f811a` agent-trader log type.

---

## 2. Security-Relevant & Custody-Relevant Highlights (the high-value set)

**Custody / fund-safety (land + review carefully — these change signing/withdraw behavior):**
- `334dcd5` Solana parser fund-safety (fail-closed multi-recipient/mint).
- `ac54203` /sign allowlist integrity (declared-fields-only).
- `1e589ce` withdraw amount validation + spend-cap on real notional.
- `efab432` multi-chain spend-cap correctness.
- `2c3ba2c` Solana v0 versioned-tx signing.
- `6a5e3ff` keystore context binding on venue wallet provisioning.
- `d5fa1ab` agent signers + key quorums.

**Security / authz:**
- `f69c996` SIWS expiry/not-before enforcement + verified-email-less OAuth trust. **(Overlaps in-flight Strata auth PR — see §3.)**
- `5f6bbee` policy/cap changes patron-only (privilege separation).
- `d6da67f` MFA required for signer mutation.
- `0467314` + `3faf518` + `7eb8d51` + `271a5b6` the #79/audit hardening base (auth, audit-integrity, FK fixes, CSP).
- `205e709` single-use token getdel correctness (token replay surface on Workers).

These constitute the bulk of the "relevant changes" value. All are included in this merge (they're part of `develop`).

---

## 3. Conflict Assessment

### develop itself: NO CONFLICTS
`origin/develop` is a strict ancestor of `upstream/develop`. A `git merge --no-commit --no-ff upstream/develop` reported *"Automatic merge went well"* with **0 conflicts** (613 files changed, staged as a single forward diff). The integration branch is therefore a clean, reviewable merge of the full 99-commit range. **No Strata change on `develop` is clobbered because there is none.**

### Strata divergence is on OTHER branches — and DOES conflict with upstream:
| Strata branch | commit | files | Conflicts with upstream? |
|---|---|---|---|
| `fix/stable-session-subject-and-verified-email` (in-flight PR) | `debcd4e` | `packages/api/src/routes/auth.ts`, `__tests__/auth-wallets.test.ts`, `__tests__/session-subject-claims.test.ts` | **YES — high.** Upstream rewrote `auth.ts` in `f69c996`, `0467314`, `7eb8d51`, `3faf518`, `271a5b6`. `f69c996` specifically also implements the *verified-email claim trust* logic, which is the **same intent** as the in-flight Strata PR. **Likely functional overlap / duplicate intent.** |
| `strata-staging` | `9a14825` | `packages/auth/src/email-templates/strata-reserve.ts`, `email-templates/index.ts`, `packages/api/src/routes/platform.ts` | **Partial.** `email-templates/*` is **NOT touched upstream → clean to rebase.** `platform.ts` **IS touched upstream** (`0467314`, `271a5b6`, `d086146`) → **conflict likely** on the writable magic-link override. |

**These three Strata branches are intentionally excluded from this PR.** Rebasing them onto the synced `develop` is the human-review follow-up. The most important flag: **`f69c996` overlaps the in-flight `fix/stable-session-subject-and-verified-email` PR** — reconcile these before landing either; upstream may already provide (or subtly differ from) the verified-email behavior Strata is building.

---

## 4. Merge vs Cherry-Pick Recommendation

**Recommendation: MERGE (this PR), not cherry-pick.**

Rationale: because `origin/develop` is a strict ancestor, there is no conflicting Strata code on `develop`, so the entire 99-commit history merges cleanly and preserves upstream's commit graph (including the #79 wave structure, which aids future audits). Cherry-picking would needlessly rewrite SHAs, break the audit trail, and risk skipping inter-dependent migration/schema commits. A sequenced cherry-pick plan would only be warranted if the merge had conflicts — it does not.

The real sequencing work is **not** within this merge; it's the **two excluded Strata branches**, handled post-merge (§5).

---

## 5. Sequenced Landing Plan

**Step 0 (this PR):** Merge `chore/sync-upstream-develop` → `develop`. Clean. Carries all 99 commits incl. all security/custody hardening + 24 migrations.
- **Pre-merge human gate:** confirm migration/deploy plan (24 migrations, schema rewrites). Do NOT deploy from the PR; deploy is a separate, gated step (Railway env now also needs proxy `REDIS_URL` + signing secret per `db7bb3a`).

**Step 1 (post-merge, separate PR):** Rebase `strata-staging` magic-link template onto new `develop`.
- `email-templates/*` rebases clean.
- Resolve `platform.ts` writable-magic-link override against upstream's hardened `platform.ts` (review the auth/audit changes there).

**Step 2 (post-merge, separate PR — DO THIS WITH CARE):** Reconcile in-flight `fix/stable-session-subject-and-verified-email` (`debcd4e`) with upstream `f69c996`.
- Determine whether upstream's "trust verified-email-less OAuth providers" + SIWS expiry already satisfies Strata's stable-session-subject + verified-email-claim requirement.
- If yes → drop/trim the Strata PR. If partial → rebase the *delta only* onto `auth.ts` as it now exists. **Re-run `session-subject-claims.test.ts` / `auth-wallets.test.ts` against the new auth.ts.**

**Risk ordering:** Step 0 lowest risk (mechanically clean, fully validated statically). Step 2 highest risk (auth/session semantics, custody-adjacent). Land 0 first, then 1, then 2.

---

## 6. Validation Results (on `chore/sync-upstream-develop`)

| Check | Command | Result |
|---|---|---|
| Install (lockfile changed) | `bun install` | ✓ 3148 packages, exit 0 |
| Typecheck / build (all packages) | `bunx turbo run build --filter='./packages/*'` | ✓ **20/20 successful** |
| Web typecheck | `bunx tsc --noEmit --project web/tsconfig.json` | ✓ exit 0 |
| Lint | `bun run lint` (biome) | ✓ 692 files, no errors |
| Unit tests | `bunx turbo run test` | ⚠ 1 package fails: `@stwd/auth` (11/160 Apple-OIDC tests) — **see note** |

**Note on the 11 `@stwd/auth` failures (Apple-OIDC):**
- They fail only when the whole `@stwd/auth` suite runs in one process; **pass when the Apple test files run file-isolated** (0 fail).
- **Reproduced identically on a pristine `upstream/develop` checkout** (149 pass / 11 fail) → **pre-existing upstream test-isolation artifact, NOT introduced by this merge.** This merge adds nothing to `packages/auth`.
- Upstream's CI is green because it runs the suite **per-file / sharded** (commits `70e73f4` "run api integration suite per-file to stop OOM", `d086146` "shard api integration tests"). Our flat `turbo test` does not shard, exposing the cross-file global-state pollution (mocked JWKS/global fetch).
- **Action for human:** adopt upstream's sharded test invocation in Strata CI, or fix the auth test isolation upstream. Not a blocker for this sync.

**Not run (require live infra; out of scope, no deploy):** `test:e2e:*` (need Postgres/Redis/running server) and the full `@stwd/api` integration suite (PGLite-migration heavy, OOM-prone — the exact suite upstream shards). No DB writes / no deploy were performed, per task constraints.

---

## 7. Rollback

This PR only advances `develop` via a merge commit (`8c3103b` on the branch). Rollback = do not merge the PR, or `git revert -m 1 <merge-sha>` if already merged. **No DB migrations were applied** (validation used ephemeral PGLite only). No Railway/deploy changes were made. The two Strata branches remain untouched and intact.
