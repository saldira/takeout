# Changelog

## 1.0.0 — 2026-10-01

The first public release: the `saldira-takeout/1` format, saldira's
signing keys, and `saldira-verify`. It checks a takeout's signature (and,
with `--key`, the key), every file of the bag, the hash chain of its log
(every line, with `--secrets`), every stored document, and that every
journal entry balances.
