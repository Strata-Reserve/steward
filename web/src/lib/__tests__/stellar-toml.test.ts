/**
 * STRATA-1494 regression: the root `overrides` pins `toml` to ^4 while
 * @stellar/stellar-sdk declares ^3. The sdk reaches web only through the Trezor
 * Solana adapter chain and calls exactly one toml API, `toml.parse(text)`, on the
 * fetched `/.well-known/stellar.toml` (lib/stellartoml/index.js:55). This test
 * resolves `toml` the way the sdk does and parses a representative stellar.toml,
 * so a breaking change in the pinned major shows up here instead of at runtime.
 */
import { describe, expect, test } from "bun:test";
import { createRequire } from "node:module";

const CHAIN = [
  "@solana/wallet-adapter-wallets",
  "@solana/wallet-adapter-trezor",
  "@trezor/connect-web",
  "@trezor/connect",
  "@trezor/blockchain-link",
  "@stellar/stellar-sdk",
];

function sdkRequire() {
  let req = createRequire(import.meta.url);
  for (const pkg of CHAIN) req = createRequire(req.resolve(`${pkg}/package.json`));
  return req;
}

const STELLAR_TOML = `
VERSION = "2.0.0"
NETWORK_PASSPHRASE = "Public Global Stellar Network ; September 2015"
FEDERATION_SERVER = "https://example.org/federation"
SIGNING_KEY = "GBCGRUHDAWSTEX4UBNXKJ5SF2R2VDXIM7KZZSEVFKC3VSUZSEQ35UBOA"
ACCOUNTS = [
  "GBCGRUHDAWSTEX4UBNXKJ5SF2R2VDXIM7KZZSEVFKC3VSUZSEQ35UBOA",
]

[DOCUMENTATION]
ORG_NAME = "Example Org"
ORG_URL = "https://example.org"

[[CURRENCIES]]
code = "USD"
issuer = "GBCGRUHDAWSTEX4UBNXKJ5SF2R2VDXIM7KZZSEVFKC3VSUZSEQ35UBOA"
display_decimals = 2
is_asset_anchored = true
`;

describe("stellar.toml parsing via the toml the stellar-sdk resolves", () => {
  const req = sdkRequire();

  test("the sdk resolves the overridden toml 4.x, not its declared 3.x", () => {
    const { version } = req("toml/package.json") as { version: string };
    expect(version.split(".")[0]).toBe("4");
  });

  test("toml.parse yields the fields the sdk's StellarToml.Resolver returns", () => {
    const toml = req("toml") as { parse: (s: string) => Record<string, unknown> };
    const parsed = toml.parse(STELLAR_TOML);
    expect(parsed.VERSION).toBe("2.0.0");
    expect(parsed.NETWORK_PASSPHRASE).toBe("Public Global Stellar Network ; September 2015");
    expect(parsed.FEDERATION_SERVER).toBe("https://example.org/federation");
    expect(parsed.SIGNING_KEY).toBe("GBCGRUHDAWSTEX4UBNXKJ5SF2R2VDXIM7KZZSEVFKC3VSUZSEQ35UBOA");
    expect(parsed.ACCOUNTS).toEqual(["GBCGRUHDAWSTEX4UBNXKJ5SF2R2VDXIM7KZZSEVFKC3VSUZSEQ35UBOA"]);
    expect((parsed.DOCUMENTATION as Record<string, unknown>).ORG_NAME).toBe("Example Org");
    const [usd] = parsed.CURRENCIES as Array<Record<string, unknown>>;
    expect(usd).toEqual({
      code: "USD",
      issuer: "GBCGRUHDAWSTEX4UBNXKJ5SF2R2VDXIM7KZZSEVFKC3VSUZSEQ35UBOA",
      display_decimals: 2,
      is_asset_anchored: true,
    });
  });

  test("invalid toml throws with line/column, which the sdk formats into its error", () => {
    const toml = req("toml") as { parse: (s: string) => unknown };
    let err: unknown;
    try {
      toml.parse("VERSION = \n");
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(Error);
    expect(typeof (err as { line?: unknown }).line).toBe("number");
    expect(typeof (err as { column?: unknown }).column).toBe("number");
  });
});
