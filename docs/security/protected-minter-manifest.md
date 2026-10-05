# Protected production-minter manifest (STRATA-1499 SF-1)

The protected Steward signer is pinned by one deployment-controlled manifest,
read from the environment once at startup (`packages/api/src/services/prod-minter-boundary.ts`).
No API route can read-modify-write any of it; changing it is a reviewed
Steward release/config change. The canonical digest of the whole manifest
(`manifestDigest`) is frozen into every pending review, so any change
invalidates pending approvals (they must be re-proposed).

| Variable | Required | Format | Meaning |
|---|---|---|---|
| `STEWARD_PROTECTED_MINTER_TENANT` | yes | tenant id | Tenant that owns the signer (`strata`). |
| `STEWARD_PROTECTED_MINTER_AGENT` | yes | agent id | Immutable agent id of the protected signer. |
| `STEWARD_PROTECTED_MINTER_ADDRESS` | yes | `0x` + 40 hex | Expected EVM address; the derived key must match before signing. |
| `STEWARD_PROTECTED_MINTER_FACTORIES` | yes | comma-separated addresses | Approved `DealTokenFactory` targets for `createDealToken`. |
| `STEWARD_PROTECTED_MINTER_TOKENS` | yes | comma-separated `address@provenance` | Independently verified deal tokens for `mint`; `provenance` is the verified deploy tx / receipt ref. |
| `STEWARD_PROTECTED_MINTER_APPROVERS` | yes (may be empty) | comma-separated `users.id` UUIDs | **Pinned approver allowlist.** The only humans who may approve for this signer, by stable user ID. Email is not an identity. |

Safe admin (`0x3Ea77cDf3eC33603bF4135bb1a36712B5e21d721`) and chain (`8453`) are fixed in code.

## Approver allowlist semantics

Approval for the protected signer requires **all** of:

1. an authenticated human session (`session-jwt` carrying `userId`), and
2. live tenant membership owner/admin, and
3. `userId` present in `STEWARD_PROTECTED_MINTER_APPROVERS`, and
4. everything required before (echoed `reviewDigest`, matching `manifestDigest`,
   recomputed digest from the stored payload, current scope recheck, CAS claim,
   one-use issuance claim, requester ≠ approver).

Fail-closed rules:

- **Empty or unset** `STEWARD_PROTECTED_MINTER_APPROVERS` is a valid manifest with
  **no approver**: proposals still queue (202) but every approval is 403 and the
  signer has zero approve capability.
- **Malformed** entries (anything that is not a UUID, including an email address,
  or a duplicate) are a malformed manifest and refuse startup, like any other bad field.
- Tenant membership administration (platform key, `POST/PATCH /platform/tenants/:id/members…`)
  keeps working for ordinary agents and can still promote users to owner/admin,
  but a promoted user is **not** an approver unless their user ID is in this list.
  No tenant/root key, platform key or agent JWT can change the list.
- Removing an approver changes the manifest digest: their next approval is 403
  (not allowlisted), and pending reviews taken under the old digest are refused
  for everyone until re-proposed.

Example:

```sh
STEWARD_PROTECTED_MINTER_TENANT=strata
STEWARD_PROTECTED_MINTER_AGENT=prod-minter
STEWARD_PROTECTED_MINTER_ADDRESS=0x1111111111111111111111111111111111111111
STEWARD_PROTECTED_MINTER_FACTORIES=0x00000000000000000000000000000000000f0001
STEWARD_PROTECTED_MINTER_TOKENS=0x0000000000000000000000000000000000700001@0xdeploytxhash
STEWARD_PROTECTED_MINTER_APPROVERS=6f1c2a1e-0b4d-4f1a-9c3e-2d7b8e9f0a11,0c9d8e7f-6a5b-4c3d-8e2f-1a0b9c8d7e6f
```

Look up the stable user ID with `GET /platform/tenants/:id/members` (platform key) — pin the `userId`, never the email.

## Migrations 0028 / 0029 / 0030 rollback

Rolling back these migrations drops `agents.protected` (the persisted protected
marker), the review evidence (`review_digest`, `manifest_digest`,
`review_projection`, `requested_by`, `approved_by_user_id`) and the durable
one-use issuance claim (`issuance_claimed_at`). That state cannot be recovered by
re-applying the additive migrations, so rollback is **not authorization-safe
after any protected use**. Roll back only (a) before any protected agent has been
created or any protected proposal queued, or (b) together with revoking
`MINTER_ROLE` from the signer via the Safe, so the key has no on-chain authority
while the marker and claim are absent.
