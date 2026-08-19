# Strata v1.6 staging wallet-action policy — proposed, NOT applied

Implementation: STRATA-1097. This document describes the exact object accepted by the new generic `manual-approval` policy primitive.

## Exact supported policy-template object

```json
{
  "name": "v1.6 nominal outbound rehearsal — Base Sepolia USDC",
  "description": "Staging only. One agent, one chain, one token selector, one recipient, <=1 USDC; every matching transfer requires explicit tenant-human approval.",
  "isDefault": false,
  "rules": [
    {
      "id": "v16-base-sepolia-only",
      "type": "allowed-chains",
      "enabled": true,
      "config": {
        "chains": ["eip155:84532"]
      }
    },
    {
      "id": "v16-usdc-contract-sign-target-only",
      "type": "approved-addresses",
      "enabled": true,
      "config": {
        "mode": "whitelist",
        "addresses": ["0x036CbD53842c5426634e7929541eC2318f3dCF7e"]
      }
    },
    {
      "id": "v16-usdc-transfer-selector-recipient-and-amount",
      "type": "contract-allowlist",
      "enabled": true,
      "config": {
        "contracts": [
          {
            "address": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "selectors": ["0xa9059cbb"],
            "constraints": {
              "0xa9059cbb": {
                "recipientAllowlist": ["0x261386fc1A1c6045fE24Ff71354f584Baa94730A"],
                "maxNativeValueWei": "0",
                "maxAmount": "1000000"
              }
            }
          }
        ]
      }
    },
    {
      "id": "v16-one-transfer-per-hour-and-day",
      "type": "rate-limit",
      "enabled": true,
      "config": {
        "maxTxPerHour": 1,
        "maxTxPerDay": 1
      }
    },
    {
      "id": "v16-every-transfer-needs-human",
      "type": "manual-approval",
      "enabled": true,
      "config": {
        "actions": ["wallet_action_transfer"]
      }
    }
  ]
}
```

Assignment (separate sensitive mutation after review):

```json
{
  "agentIds": ["midas"]
}
```

There are no wildcard chain, action, token, selector, recipient, or amount permissions.

## Evaluation semantics

1. Hard rules evaluate and dominate the verdict.
2. Any chain/token/selector/recipient/amount/rate failure is terminal `rejected`; the manual rule cannot rescue it and no approval row is created.
3. Only after every hard rule passes, matching `manual-approval.config.actions` sets `requiresManualApproval=true`.
4. The action is persisted as `pending_approval`; sign/broadcast is not called.
5. It remains pending indefinitely until explicit tenant-human approve or deny. No timer promotes it.
6. Approval re-evaluates current policy before signing.
7. Denial is terminal.

## Who can technically approve today

The existing hardened Steward approval route requires all of:

- `authType === session-jwt` (agent JWT and API-key auth fail);
- current tenant role `owner` or `admin`;
- current active owner/admin membership re-checked from the database at review time;
- MFA verification no older than five minutes;
- a principal different from the action requester (four-eyes/separation of duties).

Approval evidence retains `resolvedByType=user`, the approving user id, resolution timestamp, original requester type/id, and policy results. The proposed named operator is **Sasank Chunduri** (`sasank.chunduri@gmail.com`) after confirming that his staging Steward login has active `strata` owner/admin membership. The application credential cannot self-approve.

## Required staging configuration (not applied)

Steward:

```text
STEWARD_REQUIRED_MANUAL_APPROVAL_ACTIONS=wallet_action_transfer
```

This deployment posture guard makes wallet transfer creation return 503 before creating an action if the assigned policy set lacks an enabled exact manual-approval rule. When unset, Steward's existing zero-policy/default behavior is unchanged. On the current `strata-staging` code line, zero policies is fail-closed (`approved=false`, no manual queue); the implementation pins that exact behavior in a regression test.

Strata API adapter variables remain those documented in STRATA-1095 and must stay unset until this policy is assigned/re-read and JJ approves the bounded rehearsal.

The deployed transfer route also requires a signing authority in addition to API authentication: either an owner/admin browser session with recent MFA, or delegated signer headers (`X-Steward-Signer-Id` + `X-Steward-Signer-Secret`) whose signer has exact permission `wallet_action_transfer`. The automated Strata adapter currently sends only its bearer credential; before activation it must receive a staging-only delegated signer identity/secret (new secret envs, names to be added in the Strata adapter follow-up) or it will correctly receive 403 and submit nothing. The agent/API bearer credential alone is not a signing credential and cannot approve.

## Policy application preflight

Before applying:

1. authenticate as a different `strata` owner/admin human with recent MFA;
2. confirm Sasank's active membership;
3. create template; re-read exact object;
4. simulate correct and four hostile requests;
5. assign only to `midas`; re-read `/agents/midas/policies` and prove all five rules;
6. set `STEWARD_REQUIRED_MANUAL_APPROVAL_ACTIONS`; prove correct request queues and missing-rule agent refuses 503;
7. leave Strata adapter disabled until separate approval.

No policy or transaction has been applied by this PR.
