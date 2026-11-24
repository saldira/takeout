# Changelog

## 1.1.0 — 2026-11-23

`saldira-verify` recomputes every book's trial balance from its journal: per
account and currency, the balance in `trial_balance.csv` must be the exact
sum of that account's journal lines booked up to the archive's
`Bagging-Date`. A difference fails the new `trial balance` check and names
the book, the account and both figures. The format is unchanged
(`saldira-takeout/1`), so every archive taken so far can be checked again.

## 1.0.0 — 2026-10-01

The first public release: the `saldira-takeout/1` format, saldira's
signing keys, and `saldira-verify`. It checks a takeout's signature (and,
with `--key`, the key), every file of the bag, the hash chain of its log
(every line, with `--secrets`), every stored document, and that every
journal entry balances.
