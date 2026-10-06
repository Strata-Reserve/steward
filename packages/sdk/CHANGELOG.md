# @stwd/sdk Changelog

## Unreleased

- Expands Hyperliquid trade asset types to include BNB, SOL, AVAX, ARB, and OP.
- Adds `venue-allowlist`, `leverage-cap` and `calldata-amount-window` to the `PolicyType` union so typed clients can read and write these server-supported policies (STRATA-1499).

## 0.10.0

BREAKING-CHANGES:
- Adds the Sprint 4 trade API surface under `StewardClient.tradeSessions` and `StewardClient.trade.hyperliquid`.
- Consumers that pin exact SDK versions should upgrade to `0.10.0` before using trade session or Hyperliquid order helpers.
