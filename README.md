# saldira takeout: the format, the keys, and `saldira-verify`

saldira customers can take all their data with them, at any time, as one
signed archive (a *takeout*). This repository lets anyone check such an
archive without saldira:

- **[FORMAT.md](FORMAT.md)**: the takeout format, `saldira-takeout/1`:
  what is where, how the hash chain of the log is computed, and how the
  archive is signed.
- **[DATA_DICTIONARY.md](DATA_DICTIONARY.md)**: every table in an archive,
  column by column.
- **[keys/](keys/)**: saldira's public signing keys and their fingerprints.
- **`saldira-verify`**: a small command-line tool that checks an archive.
  It covers the signature, every file, the hash chain of the log, every
  stored document, and that every journal entry balances. It needs no
  network and no saldira account.

## Install

Download the binary for your system from the
[latest release](../../releases/latest), and check it against `SHA256SUMS`.
Each binary carries a GitHub build attestation, which you can check with:

```sh
gh attestation verify saldira-verify-*.tar.gz --repo saldira/takeout
```

Or build it from source with Rust (stable):

```sh
cargo install --locked --path crates/ledger-verify
```

## Use

```sh
saldira-verify saldira-takeout_acme_7.zip --key 2436163cc4fef7be
```

```text
ok   signature     signed by key 2436163cc4fef7be
ok   signing key   the key is the one you named
ok   tag manifest  4 tag files unchanged
ok   payload       162 files, every one as signed
ok   payload size  13323494.162 (bag says 13323494.162)
ok   log           816 entries in 3 books, one chain each; 814 recomputed, 2 attested
ok   documents     47 documents, each the file its digest names
ok   journal       197 entries in 3 books, every one balanced in its functional currency
VERIFIED
```

- `--key` holds the archive to saldira's key. Without it, the tool checks
  that the archive is intact, but not who signed it.
- `--secrets <file>`: if you also downloaded the secrets file, pass it, and
  every line of the log is recomputed, the masked ones included.
- `--json` prints the result as JSON.

The exit status is 0 when everything holds, 1 when a check fails, and 2
when a file could not be read.

## Where this comes from

The code here is published from saldira's main repository on every release.
It is the same code saldira uses to write and to restore takeouts, so the
two cannot drift apart. Pull requests cannot be merged here. Please open an
issue instead, or report a security problem privately through *Security →
Report a vulnerability*.

## Licence

MIT. See [LICENSE](LICENSE).
