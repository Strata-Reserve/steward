# Tenant Email Config

Steward supports per-tenant magic link email settings in addition to the global fallback env vars:

- `RESEND_API_KEY`
- `EMAIL_FROM`

If a tenant has no `tenant_configs.email_config`, auth continues using the global env-based Resend configuration exactly as before.

## Stored Shape

`tenant_configs.email_config` stores:

```json
{
  "provider": "resend",
  "apiKeyEncrypted": "...",
  "from": "Tenant <login@example.com>",
  "replyTo": "support@example.com",
  "templateId": "elizacloud",
  "subjectOverride": "Sign in"
}
```

The plaintext Resend API key is encrypted server-side with Steward's existing `KeyStore` / `STEWARD_MASTER_PASSWORD` flow before it is persisted.

## Platform API

Routes require `X-Steward-Platform-Key`.

### Set or update config

```bash
curl -X PATCH "$API_BASE/platform/tenants/elizacloud/email-config" \
  -H "Content-Type: application/json" \
  -H "X-Steward-Platform-Key: $STEWARD_PLATFORM_KEY" \
  -d '{
    "apiKey": "re_xxxxxxxxx",
    "from": "Eliza Cloud <login@elizacloud.ai>",
    "replyTo": "support@elizacloud.ai",
    "templateId": "elizacloud",
    "subjectOverride": "Sign in to Eliza Cloud"
  }'
```

#### Merge semantics (STRATA-1218)

PATCH **merges**: fields you supply are overwritten, fields you omit are
preserved. This means the non-secret magic-link routing fields can be set
without holding — or destroying — the tenant's Resend secret.

```bash
# Set only the magic-link target. apiKeyEncrypted / provider / from /
# templateId / subjectOverride are all left exactly as they were.
curl -X PATCH "$API_BASE/platform/tenants/strata/email-config" \
  -H "Content-Type: application/json" \
  -H "X-Steward-Platform-Key: $STEWARD_PLATFORM_KEY" \
  -d '{
    "magicLinkBaseUrl": "https://app.stratareserve.co",
    "magicLinkCallbackPath": "/auth/callback"
  }'
```

Notes:

- `apiKey` and `from` are **not** required unless the request is establishing a
  provider config. A magic-link-only tenant (no per-tenant Resend key) is
  legal and falls back to the global `RESEND_API_KEY`.
- `from` is required whenever an API key is present (stored or supplied).
- An empty body `{}` is rejected (400): it would rewrite the row and evict the
  auth cache while changing nothing.
- All supplied fields must be non-empty strings; empty strings are not a way to
  clear a field. Use DELETE to clear the whole config.
- The per-tenant `EmailAuth` cache is evicted on every successful write, so the
  next magic link uses the new values immediately.

#### Magic-link field validation

The magic link carries a login token in its query string, so these fields are
validated strictly:

- `magicLinkBaseUrl` must be an **https origin** with no path, query, fragment,
  or embedded credentials (e.g. `https://app.stratareserve.co`). A trailing
  slash is stripped.
- `magicLinkCallbackPath` must be an **absolute same-app path** beginning with
  `/` (e.g. `/auth/callback`). Values that would retarget another origin —
  `https://evil.com/x`, protocol-relative `//evil.com/x`, or backslash variants
  — are rejected, because the link is built as `new URL(callbackPath, baseUrl)`.

With the two values above, magic links resolve to
`https://app.stratareserve.co/auth/callback?token=...&email=...`.

### Read config

```bash
curl "$API_BASE/platform/tenants/elizacloud/email-config" \
  -H "X-Steward-Platform-Key: $STEWARD_PLATFORM_KEY"
```

Response omits `apiKeyEncrypted` and returns `hasApiKey` instead.

### Clear config

```bash
curl -X DELETE "$API_BASE/platform/tenants/elizacloud/email-config" \
  -H "X-Steward-Platform-Key: $STEWARD_PLATFORM_KEY"
```

## Template IDs

- `default`: built-in Steward template
- `elizacloud`: stub currently falls back to `default`

Unknown template IDs also fall back to the default template.

## Runtime behavior

- `POST /auth/email/send` resolves the tenant from `X-Steward-Tenant`, then `body.tenantId`, then the existing default fallback behavior.
- `POST /auth/email/verify` and `GET /auth/callback/email` use the matching tenant-scoped token store configuration when verifying tokens.
- Updating or deleting tenant email config invalidates the in-process auth cache for that tenant.
