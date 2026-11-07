# patches

- query-string@7.1.3.patch: GHSA-qr28-fpjm-wq7f / STRATA-1624. decode-uri-component is overridden to 0.5.1 (ESM, default export); this patch makes query-string 7 accept both module shapes (`.default || module`). Remove the patch and the override once @walletconnect drops query-string 7.
