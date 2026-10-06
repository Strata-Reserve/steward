// STRATA-1499: fail-closed network guard for tests. Installed via
// `bun test --preload ./scripts/test-no-network-preload.ts` BEFORE any static
// SDK import, so a test that forgets to mock fetch throws locally instead of
// reaching a live RPC. Tests that need an RPC install their own interceptor.
globalThis.fetch = (async () => {
  throw new Error("Network access is forbidden in tests (STRATA-1499 preload)");
}) as typeof fetch;
