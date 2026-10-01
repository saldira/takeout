# The saldira takeout format, version 1

`saldira-takeout/1` is the format of the archive in which a saldira
customer takes their organisation's data with them. This document is
enough to read a takeout and to check it without saldira's software. The
`saldira-verify` tool in this repository does every check below, and its
source is the reference implementation (`crates/ledger-takeout`,
`crates/ledger-verify`).

Words in **MUST** carry their RFC 2119 meaning.

## 1. The archive

A takeout is one ZIP file, `saldira-takeout_<organisation>_<number>.zip`. It
holds a single top-level folder of the same name, which is a
[BagIt](https://www.rfc-editor.org/rfc/rfc8493) bag, version 1.0:

```text
saldira-takeout_<organisation>_<number>/
  bagit.txt                     BagIt declaration
  bag-info.txt                  what this is (§2)
  manifest-sha256.txt           SHA-256 of every file under data/
  tagmanifest-sha256.txt        SHA-256 of the four files above and signing-key.pem
  tagmanifest-sha256.txt.sig    the signature over tagmanifest-sha256.txt (§3)
  signing-key.pem               the public key that signature verifies with
  data/
    README.md                   a human description of this archive
    log/manifest.json           the log's manifest (§4.2)
    log/log.jsonl               the record: every change, one JSON object per line (§4)
    tables/<book>/<table>.csv   each book's tables (§5)
    tables/tenant/<table>.csv   what the books share: customers and suppliers,
                                items, tax codes, members, …
    tables/missing.csv          anything that could not be produced, and why
    documents/index.csv         one row per stored document (§6)
    documents/originals/<book>/<sha256>.<ext>   every stored document, byte for byte
    documents/issued/<book>/<number>.pdf        issued invoices and credit notes
    readable/<book>/<year>/jahresrechnung.pdf   the financial statements of each closed year
    readable/<book>/vat/        each filed VAT return: the ESTV form (PDF) and
                                its eCH-0217 declaration (XML)
    procedure/data-dictionary.md   every table and column (DATA_DICTIONARY.md here)
    procedure/company-identity.csv the company's name and address over time
```

The PDFs are PDF/A-3b. Every text file is UTF-8.

**The secrets file.** If the customer asked for it, a second file
accompanies the archive, `saldira-takeout_<organisation>_<number>.secrets.jsonl`
(§4.3). It is **never** inside the bag. The bag names it by digest, so the
signature covers it as well.

## 2. `bag-info.txt`

Besides BagIt's `Payload-Oxum` (`<bytes>.<files>` of `data/`), it carries:

| Field | Meaning |
|---|---|
| `Source-Organization` | `saldira` |
| `External-Identifier` | `<organisation>#<number>` |
| `Bagging-Date`, `Bagging-Time` | when it was taken (date; RFC 3339 time) |
| `Takeout-Format` | `saldira-takeout/1` |
| `Log-Entries` | the number of lines in `data/log/log.jsonl` |
| `Books` | the organisation's books, space-separated |
| `Signed-By` | the key that signed it, with its fingerprint in parentheses |
| `Secrets-Sidecar-SHA256` | only when a secrets file was taken: its SHA-256, hex |

## 3. The signature

`tagmanifest-sha256.txt.sig` is an ECDSA signature over the exact bytes of
`tagmanifest-sha256.txt`, on curve P-256 with SHA-256, DER-encoded. The
public key is in `signing-key.pem` (SubjectPublicKeyInfo, PEM, `\n` line
endings). Any OpenSSL checks it:

```sh
openssl dgst -sha256 -verify signing-key.pem \
  -signature tagmanifest-sha256.txt.sig tagmanifest-sha256.txt
```

The tag manifest lists `bagit.txt`, `bag-info.txt`, `manifest-sha256.txt`
and `signing-key.pem`, and `manifest-sha256.txt` lists every file under
`data/`. So one valid signature covers every byte of the bag.

**A valid signature only proves something if the key is saldira's.** The
key's **fingerprint** is the first 16 hex digits of the SHA-256 of the
`signing-key.pem` text. Compare it with the fingerprints saldira publishes
([`keys/`](keys/) here, and on saldira.ch). A bundle signed with anything
else is not a saldira takeout. A local development installation signs with
a published, fixed key, and its `Signed-By` says *development key, NOT a
proof*.

## 4. The log

### 4.1 `log.jsonl`

Every change ever made to the books, one JSON object per line, in the order
saldira applied them. Each line has these fields:

| Field | Type | Meaning |
|---|---|---|
| `id` | integer | position in the organisation's history; strictly increasing |
| `book_id` | string | the book the change was made in |
| `request_id` | string, optional | the client's idempotency key |
| `method` | string | the operation, e.g. `post_entry`, `issue_sales_invoice` |
| `payload` | string | the operation's parameters: a JSON document, as a string |
| `principal` | string | who made the change (their identity provider's subject id) |
| `roles` | string | the roles they made it under, comma-separated |
| `recorded_at` | string | when (RFC 3339) |
| `source_ip` | string, optional | where from, when known |
| `auth_method` | string, optional | how they were authenticated |
| `trace_id` | string, optional | the request's trace id |
| `prev_hash` | string | the previous entry's `entry_hash` in the same book, or `GENESIS` |
| `entry_hash` | string | this entry's hash (§4.4), lowercase hex |
| `attested` | boolean, optional | `true` when the payload is masked (§4.3) |

An optional field that is absent has no value.

### 4.2 `manifest.json`

```json
{
  "format": "saldira-takeout/1",
  "tenant_id": "<organisation>",
  "books": [
    { "book_id": "…", "functional_currency": "CHF", "status": "open",
      "entries": 1234, "chain_head": "<entry_hash of the book's last line>" }
  ],
  "entries": 1234,
  "attested": [ 412 ]
}
```

`books` is in `book_id` order and lists every book, including books without
entries, whose `chain_head` is `GENESIS`. `attested` lists the ids of the
masked lines and is omitted when there are none.

### 4.3 Masked lines and the secrets file

Three operations carry a secret in their payload: `register_webhook` and
`update_webhook` (field `secret`), and `set_ingestion_address` (field
`token`). The log shows such a payload masked, with `…` followed by the
secret's last four characters, and marks the line `"attested": true`.

A masked line's `entry_hash` cannot be recomputed from the line. It is
carried as stored, and the next line's `prev_hash` still links to it.

The secrets file holds each masked line's original payload, one JSON object
per line: `{"id": <line id>, "payload": "<the payload as stored>"}`. With it,
every line's hash can be recomputed.

### 4.4 The hash chain

Each book's lines form a chain. For a line *L* whose book's previous line has
hash *P* (or `GENESIS` for the book's first line):

```text
canonical = book_id ␟ method ␟ payload ␟ principal ␟ roles ␟ recorded_at
            ␟ request_id ␟ source_ip ␟ auth_method ␟ trace_id
entry_hash = lowercase_hex( SHA-256( P ␟ canonical ) )
```

`␟` is the single byte `0x1F` (Unit Separator). The fields are the UTF-8
strings as they appear in the line, and an absent optional field is the
empty string. `P` is the previous hash as text.

A log is intact when, for every line in file order:

1. its `id` is greater than the previous line's;
2. its `prev_hash` is the `entry_hash` of the previous line of the **same
   book**, or `GENESIS` if there is none;
3. unless it is attested, its `entry_hash` is the hash above;
4. and, at the end, every book's last `entry_hash` is the manifest's
   `chain_head` for that book, and the counts and the attested ids match.

Changing, removing, inserting or reordering any line breaks one of these.

### 4.5 A log that was restored

A log may begin a book's chain with a line whose `method` is
`restored_from`. Its payload names the organisation and the `chain_head` of
the takeout the books were restored from, and the chain continues from it.
It records where the history came from and changes nothing in the books.

## 5. Tables

Each `tables/…/*.csv` file is one of the reports described in
[DATA_DICTIONARY.md](DATA_DICTIONARY.md) (also inside every archive, as
`procedure/data-dictionary.md`):

- RFC 4180 quoting, **semicolon**-separated, `\r\n` line endings, UTF-8
  with a byte-order mark (so that Excel in a Swiss locale opens it as it
  is), and a header row of column ids.
- Amounts are decimal strings with a dot and no thousands separator; a
  negative amount has a leading `-`.
- Dates are `YYYY-MM-DD`. An empty cell is no value.

The archive's own index files, `tables/missing.csv`, `documents/index.csv`
and `procedure/company-identity.csv`, are plain RFC 4180: comma-separated,
`\n` line endings, no byte-order mark.

The bank register is one file per bank account,
`tables/<book>/bank_transactions_<account id>.csv`.

`tables/<book>/journal.csv` is the journal: one row per posting line.
`entry_id` groups the lines of one entry. `debit` and `credit` are in
`currency`, and `functional_amount` (positive is debit) is the same line in
the book's `functional_currency`. **Every entry balances**: its
`functional_amount`s sum to zero.

`tables/missing.csv` (`book,report,reason`) lists anything the archive
should have held and could not produce. A table that is not there is listed
there, never silently absent.

## 6. Documents

`documents/index.csv` has one row per stored document: `book`, `sha256`
(hex), `file` (its path under `data/`), `content_type`, `size_bytes`,
`uploaded_by`, `uploaded_at`. Each original is named by the SHA-256 of its
bytes, so a document can be checked by hashing it.

## 7. Checking a takeout

`saldira-verify` (this repository) runs these checks and prints one line per
check:

```text
saldira-verify <archive.zip> [--secrets <secrets.jsonl>] [--key <fingerprint>] [--json]
```

| Check | What it proves |
|---|---|
| `signature` | the tag manifest is signed by `signing-key.pem` |
| `signing key` | with `--key`: that key has the fingerprint you named |
| `tag manifest` | the bag's own files are the ones that were signed |
| `payload` | every file under `data/` is the one the manifest lists, and none is missing or added |
| `payload size` | `Payload-Oxum` matches |
| `log` | the chain is intact (§4.4), and it matches its manifest |
| `secrets` | with `--secrets`: the file is the one the bag names, and with it every line recomputes |
| `documents` | every original is the file its name's digest says |
| `journal` | every journal entry balances in its functional currency |

The exit status is 0 when every check passes, 1 when one fails, and 2 when
the command line or a file could not be read.

## 8. Versions

The format is named in `bag-info.txt` (`Takeout-Format`) and in
`log/manifest.json` (`format`). A reader **MUST** refuse a format it does
not know rather than guess. Additions that a version-1 reader can ignore,
such as new tables, new columns or new folders, keep the version. Anything
else is version 2.
