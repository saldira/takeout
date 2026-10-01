# saldira's takeout signing keys

A takeout's `bag-info.txt` names the key that signed it (`Signed-By`), with
its fingerprint in parentheses. `saldira-verify --key <fingerprint>` holds
the bundle to the key you name. The fingerprint is the first 16 hex digits
of the SHA-256 of the key's PEM text:

```sh
sha256sum keys/prod.pem | cut -c1-16
```

| Environment | Key | Fingerprint | In use since |
|---|---|---|---|
| **saldira** (app.saldira.ch) | [`prod.pem`](prod.pem) | `2436163cc4fef7be` | 2026-10-01 |
| staging (a test system) | [`staging.pem`](staging.pem) | `fb33acf9900111a1` | 2026-10-01 |

The private keys never leave AWS KMS (ECC NIST P-256, signing only). They
are not rotated, so that a takeout stays verifiable for the ten years its
owner keeps it. A key that is ever retired stays listed here, with the
date it stopped signing.

saldira.ch publishes the same fingerprints. Compare both before trusting
either.
