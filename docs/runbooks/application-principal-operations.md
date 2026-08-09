# Application principal operations

## Provision

1. Choose the smallest capability set and explicit owner references.
2. Set a short credential expiry and a separately reviewed principal expiry.
3. Create via `POST /application-principals` using tenant administrator authentication.
4. Capture the returned secret once into the application deployment secret manager. Never paste it into tickets, logs, shell history, or source control.
5. Smoke-test `Ensure Wallet`, then verify an `application.wallet.ensure` audit event whose actor ID equals the principal ID.

## Rotate

1. Call `POST /application-principals/:id/rotate` with a new credential expiry.
2. Update both key-ID and secret values atomically in the application deployment.
3. Confirm the new credential works.
4. Confirm the old credential returns generic `401`.

Rotation revokes old keys immediately; schedule a coordinated deployment window.

## Revoke / incident response

1. Call `POST /application-principals/:id/revoke` with tenant administrator authentication.
2. Verify application calls return `401`.
3. Inspect tamper-evident audit events for the principal ID: wallet ensures, address reads, prepares, proposals, and denied owner attempts.
4. Review proposed intent hashes and assigned owner references. No proposal is proof of execution; inspect execution authorities separately.
5. Provision a replacement principal instead of reactivating a revoked one.

## Alerts

Alert on repeated authentication failures, unassigned owner attempts, unexpected wallet creation volume, idempotency conflicts, principal expiry within 14 days, and any application credential observed outside `/application/*`.

## Rollback

The code rollback is to remove application route mounts after revoking all application principals. Do not drop tables during incident rollback: persisted proposals and audit evidence are records. Schema removal requires a separately approved destructive migration.
