# Application principal operations

## Release gate

Do not issue or install any application credential until:

1. the complete dynamic negative-authorization matrix passes;
2. real PostgreSQL concurrency, crash rollback, composite-FK, immutability, strict-schema, exact proposal-ID, zero-Vault-call, and migration-over-populated-data tests pass;
3. independent post-PR security review approves the final commit.

Merge and deployment are separate human-controlled steps.

## Provision

1. Choose the smallest exact capability set and explicit `{ kind: "wallet_owner", id }` resources.
2. Set a short credential expiry and separately reviewed principal expiry.
3. Create via `POST /application-principals` using tenant administrator authentication.
4. Capture the returned selector and secret once in the backend deployment secret manager. Never paste either into tickets, logs, shell history, or source control.
5. Send no tenant header, tenant key, or bearer token with the application credential.
6. Smoke-test `Ensure Wallet` with a unique `Idempotency-Key`.
7. Verify one immutable binding, two encrypted chain-key rows, two public addresses, one scoped idempotency row, and an `application.wallet.ensure` audit event whose actor ID equals the principal ID and metadata identifies the credential selector.
8. Run the live allow/deny matrix before enabling product traffic.

## Rotate

1. Call `POST /application-principals/:id/rotate` with a new credential expiry.
2. Update selector and secret atomically in the deployment secret manager.
3. Confirm the new credential works.
4. Confirm the old credential returns the same generic `401` as an unknown credential on the next request.

Rotation revokes old keys immediately. Coordinate deployment to avoid product interruption.

## Revoke / incident response

1. Call `POST /application-principals/:id/revoke` with tenant administrator authentication.
2. Verify application calls return generic `401` immediately from each API replica.
3. Inspect tamper-evident audit events for the authenticated principal ID and server-derived credential selector.
4. Review immutable intent/proposal hashes and assigned resources. A proposal is never proof of signing or execution.
5. Provision a replacement principal instead of reactivating a revoked one.

## Alerts

Alert on authentication rate-limit events, repeated failures, unassigned-resource attempts, deterministic identity collisions, unexpected wallet creation, idempotency conflicts, principal expiry within 14 days, and any application credential observed outside `/application/*`.

## Rollback

Revoke principals and remove application route mounts. Preserve application bindings, idempotency records, intents, proposals, and audit events. Do not drop tables or rewrite historical rows during incident rollback; schema removal requires separately approved destructive work.
