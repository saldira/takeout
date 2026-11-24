//! **OFF2-D10** — `saldira-verify`: everything a client needs to trust a
//! takeout without trusting saldira.
//!
//! A green run means the bundle is **unchanged since it was signed** (the
//! signature over the tag manifest, the tag manifest over the payload manifest
//! and `bag-info.txt`, the payload manifest over every file), **complete as
//! signed** (nothing listed is missing, nothing present is unlisted), its
//! **log is one unbroken chain** per book that matches its own manifest, every
//! stored document **is the file its name says**, every journal entry
//! **balances to zero** in every currency, and every book's **trial balance
//! recomputes** from its journal's postings.
//!
//! What it cannot say alone is *who* signed. The answer names the key's
//! fingerprint; compare it with the one saldira publishes, or pass it with
//! `--key` and let the verifier compare.

use std::collections::BTreeMap;
use std::io::Read as _;

use ledger_takeout::bag;

/// One finding, in the order the checks ran.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    /// What was checked.
    pub name: &'static str,
    /// Whether it held.
    pub ok: bool,
    /// What was found, in words.
    pub detail: String,
}

/// Everything [`verify`] found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Each check, in order.
    pub checks: Vec<Check>,
    /// The signing key's fingerprint, when the key could be read.
    pub key_fingerprint: Option<String>,
}

impl Report {
    /// Every check held.
    pub fn ok(&self) -> bool {
        !self.checks.is_empty() && self.checks.iter().all(|c| c.ok)
    }

    fn push(&mut self, name: &'static str, ok: bool, detail: impl Into<String>) {
        self.checks.push(Check { name, ok, detail: detail.into() });
    }
}

/// The bag's files by path inside it, its top folder stripped.
pub fn unzip(archive: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(archive))
        .map_err(|e| format!("not a zip archive: {e}"))?;
    let mut out = BTreeMap::new();
    for i in 0..zip.len() {
        let mut f = zip.by_index(i).map_err(|e| e.to_string())?;
        if f.is_dir() {
            continue;
        }
        let name = f.name().map_err(|e| e.to_string())?.into_owned();
        let path = name.split_once('/').map_or(name.as_str(), |(_, rest)| rest).to_string();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(|e| e.to_string())?;
        out.insert(path, buf);
    }
    Ok(out)
}

fn text(files: &BTreeMap<String, Vec<u8>>, path: &str) -> Option<String> {
    files.get(path).map(|b| String::from_utf8_lossy(b).into_owned())
}

/// Check a takeout: `archive` is the zip, `sidecar` the secrets file when the
/// tenant took one, `trusted_key` a fingerprint to hold the signing key to.
pub fn verify(archive: &[u8], sidecar: Option<&[u8]>, trusted_key: Option<&str>) -> Report {
    let mut r = Report::default();
    let files = match unzip(archive) {
        Ok(f) => f,
        Err(e) => {
            r.push("archive", false, e);
            return r;
        }
    };
    verify_files(&files, sidecar, trusted_key, &mut r);
    r
}

/// [`verify`] on an archive already unzipped by [`unzip`]. A restore reads the
/// files it checks, so it unzips once.
pub fn verify_unzipped(
    files: &BTreeMap<String, Vec<u8>>,
    sidecar: Option<&[u8]>,
    trusted_key: Option<&str>,
) -> Report {
    let mut r = Report::default();
    verify_files(files, sidecar, trusted_key, &mut r);
    r
}

fn verify_files(
    files: &BTreeMap<String, Vec<u8>>,
    sidecar: Option<&[u8]>,
    trusted_key: Option<&str>,
    r: &mut Report,
) {
    // ── The signature.
    let (Some(tagmanifest), Some(pem), Some(sig)) =
        (text(files, bag::TAGMANIFEST), text(files, bag::SIGNING_KEY), files.get(bag::SIGNATURE))
    else {
        r.push("signature", false, "the bag has no tag manifest, signing key or signature");
        return;
    };
    let fingerprint = bag::key_fingerprint(&pem);
    r.key_fingerprint = Some(fingerprint.clone());
    match bag::verify_signature(&pem, tagmanifest.as_bytes(), sig) {
        Ok(true) => r.push("signature", true, format!("signed by key {fingerprint}")),
        Ok(false) => r.push("signature", false, "the signature does not match the tag manifest"),
        Err(e) => r.push("signature", false, e),
    }
    match trusted_key {
        Some(k) if k.eq_ignore_ascii_case(&fingerprint) => {
            r.push("signing key", true, "the key is the one you named")
        }
        Some(k) => r.push("signing key", false, format!("signed by {fingerprint}, not by {k}")),
        None => {}
    }

    // ── The tag files.
    match bag::parse_manifest(&tagmanifest) {
        Ok(tags) => {
            let bad: Vec<&String> = tags
                .iter()
                .filter(|(p, d)| files.get(*p).map(|b| bag::sha256_hex(b)) != Some((*d).clone()))
                .map(|(p, _)| p)
                .collect();
            let needed = ["bagit.txt", "bag-info.txt", bag::MANIFEST, bag::SIGNING_KEY];
            let unlisted: Vec<&&str> = needed.iter().filter(|n| !tags.contains_key(**n)).collect();
            r.push(
                "tag manifest",
                bad.is_empty() && unlisted.is_empty(),
                if bad.is_empty() && unlisted.is_empty() {
                    format!("{} tag files unchanged", tags.len())
                } else {
                    format!("changed: {bad:?}; not covered: {unlisted:?}")
                },
            );
        }
        Err(e) => r.push("tag manifest", false, e),
    }

    // ── Every payload file.
    let manifest = match text(files, bag::MANIFEST).map(|t| bag::parse_manifest(&t)) {
        Some(Ok(m)) => m,
        Some(Err(e)) => return r.push("payload", false, e),
        None => return r.push("payload", false, "no payload manifest"),
    };
    let present: BTreeMap<String, String> =
        files.iter().map(|(p, b)| (p.clone(), bag::sha256_hex(b))).collect();
    let payload = bag::check_manifest(&manifest, &present, "data/");
    r.push(
        "payload",
        payload.ok(),
        if payload.ok() {
            format!("{} files, every one as signed", payload.verified)
        } else {
            format!(
                "altered: {:?}; missing: {:?}; unlisted: {:?}",
                payload.altered, payload.missing, payload.unlisted
            )
        },
    );
    let info = text(files, "bag-info.txt").map(|t| bag::parse_bag_info(&t)).unwrap_or_default();
    let bytes: usize =
        files.iter().filter(|(p, _)| p.starts_with("data/")).map(|(_, b)| b.len()).sum();
    let oxum = format!("{bytes}.{}", files.keys().filter(|p| p.starts_with("data/")).count());
    match info.get("Payload-Oxum") {
        Some(o) => r.push("payload size", *o == oxum, format!("{oxum} (bag says {o})")),
        None => r.push("payload size", false, "bag-info.txt names no Payload-Oxum"),
    }

    // ── The log.
    let manifest_json = text(files, "data/log/manifest.json").unwrap_or_default();
    let log_text = text(files, "data/log/log.jsonl").unwrap_or_default();
    let log = serde_manifest(&manifest_json).and_then(|m| {
        ledger_takeout::from_jsonl::<ledger_takeout::LogLine>(&log_text)
            .map(|lines| (m, lines))
            .map_err(|e| e.to_string())
    });
    match log {
        Ok((m, lines)) => match ledger_takeout::check(&m, &lines) {
            Ok(chain) => {
                r.push(
                    "log",
                    true,
                    format!(
                        "{} entries in {} books, one chain each; {} recomputed, {} attested",
                        chain.entries,
                        chain.chain_heads.len(),
                        chain.recomputed,
                        chain.attested.len()
                    ),
                );
                verify_sidecar(sidecar, &info, lines, r);
            }
            Err(e) => r.push("log", false, e.to_string()),
        },
        Err(e) => r.push("log", false, e),
    }

    // ── Every document is what its name says.
    let originals: Vec<(&String, &Vec<u8>)> =
        files.iter().filter(|(p, _)| p.starts_with("data/documents/originals/")).collect();
    let misnamed: Vec<&String> = originals
        .iter()
        .filter(|(p, b)| {
            let name = p.rsplit('/').next().unwrap_or("");
            let stem = name.split('.').next().unwrap_or("");
            stem != bag::sha256_hex(b)
        })
        .map(|(p, _)| *p)
        .collect();
    r.push(
        "documents",
        misnamed.is_empty(),
        if misnamed.is_empty() {
            format!("{} documents, each the file its digest names", originals.len())
        } else {
            format!("not what their names say: {misnamed:?}")
        },
    );

    // ── Every journal entry balances.
    let journals: Vec<(&String, &Vec<u8>)> = files
        .iter()
        .filter(|(p, _)| p.starts_with("data/tables/") && p.ends_with("/journal.csv"))
        .collect();
    let mut unbalanced = Vec::new();
    let mut entries = 0usize;
    for (path, bytes) in &journals {
        match balance(&String::from_utf8_lossy(bytes)) {
            Ok((n, bad)) => {
                entries += n;
                unbalanced.extend(bad.into_iter().map(|e| format!("{path}: entry {e}")));
            }
            Err(e) => unbalanced.push(format!("{path}: {e}")),
        }
    }
    r.push(
        "journal",
        unbalanced.is_empty(),
        if unbalanced.is_empty() {
            format!(
                "{entries} entries in {} books, every one balanced in its functional currency",
                journals.len()
            )
        } else {
            format!("does not balance: {unbalanced:?}")
        },
    );

    verify_trial_balances(files, &info, r);
}

/// **OFF2-D10 (4)**, its second half: every book's `trial_balance.csv`
/// recomputes from its `journal.csv`. The take reads the trial balance as of
/// the day it was bagged, so the journal's lines up to `Bagging-Date` are what
/// it must sum to — per account and currency, in exact decimal arithmetic.
///
/// A book whose journal or trial balance the take could not render is not a
/// difference: `missing.csv` says so, and this check names it. Absent and
/// **not** listed there is a silent gap, and fails.
fn verify_trial_balances(
    files: &BTreeMap<String, Vec<u8>>,
    info: &BTreeMap<String, String>,
    r: &mut Report,
) {
    const NAME: &str = "trial balance";
    let book_of = |path: &str, table: &str| -> Option<String> {
        path.strip_prefix("data/tables/")?
            .strip_suffix(&format!("/{table}.csv"))
            .filter(|b| !b.contains('/'))
            .map(str::to_string)
    };
    let mut books: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for p in files.keys() {
        books.extend(book_of(p, "journal").or_else(|| book_of(p, "trial_balance")));
    }
    if books.is_empty() {
        return;
    }
    let Some(as_of) = info.get("Bagging-Date") else {
        return r.push(NAME, false, "bag-info.txt names no Bagging-Date to read it as of");
    };
    let missing = text(files, "data/tables/missing.csv").unwrap_or_default();
    let listed = |book: &str, report: &str| {
        missing.lines().skip(1).any(|l| {
            let f = record(l, ',');
            f.first().map(String::as_str) == Some(book)
                && f.get(1).map(String::as_str) == Some(report)
        })
    };
    let (mut accounts, mut checked) = (0usize, 0usize);
    let (mut differences, mut skipped) = (Vec::new(), Vec::new());
    for book in &books {
        let journal = text(files, &format!("data/tables/{book}/journal.csv"));
        let stated = text(files, &format!("data/tables/{book}/trial_balance.csv"));
        let (Some(journal), Some(stated)) = (journal.as_deref(), stated.as_deref()) else {
            let absent = if journal.is_none() { "journal" } else { "trial_balance" };
            if listed(book, absent) {
                skipped.push(format!("{book} (no {absent}, as missing.csv says)"));
            } else {
                differences
                    .push(format!("{book}: no {absent}.csv, and missing.csv does not say why"));
            }
            continue;
        };
        match trial_balance(journal, stated, as_of) {
            Ok((n, bad)) => {
                accounts += n;
                checked += 1;
                differences.extend(bad.into_iter().map(|d| format!("{book}: {d}")));
            }
            Err(e) => differences.push(format!("{book}: {e}")),
        }
    }
    let detail = if !differences.is_empty() {
        format!("does not recompute: {differences:?}")
    } else {
        let mut d = format!(
            "{accounts} accounts in {checked} books, every balance as of {as_of} the sum of its postings"
        );
        if !skipped.is_empty() {
            d.push_str(&format!("; not recomputed: {skipped:?}"));
        }
        d
    };
    r.push(NAME, differences.is_empty(), detail);
}

fn serde_manifest(text: &str) -> Result<ledger_takeout::Manifest, String> {
    ledger_takeout::Manifest::from_json(text).map_err(|e| format!("log manifest: {e}"))
}

fn verify_sidecar(
    sidecar: Option<&[u8]>,
    info: &BTreeMap<String, String>,
    lines: Vec<ledger_takeout::LogLine>,
    r: &mut Report,
) {
    let named = info.get("Secrets-Sidecar-SHA256");
    let Some(sidecar) = sidecar else {
        if named.is_some() {
            r.push(
                "secrets",
                true,
                "a sidecar was taken; pass it with --secrets to recompute every row",
            );
        }
        return;
    };
    let Some(named) = named else {
        return r.push("secrets", false, "the bag names no secrets sidecar");
    };
    if bag::sha256_hex(sidecar) != *named {
        return r.push("secrets", false, "the sidecar is not the one the signed bag names");
    }
    let secrets = match ledger_takeout::from_jsonl::<ledger_takeout::SecretLine>(
        &String::from_utf8_lossy(sidecar),
    ) {
        Ok(s) => s,
        Err(e) => return r.push("secrets", false, e.to_string()),
    };
    match ledger_takeout::unmask(lines, &secrets).and_then(|l| ledger_takeout::verify(&l)) {
        Ok(chain) if chain.attested.is_empty() => r.push(
            "secrets",
            true,
            format!("all {} entries recomputed with the secrets", chain.recomputed),
        ),
        Ok(chain) => {
            r.push("secrets", false, format!("{} entries still attested", chain.attested.len()))
        }
        Err(e) => r.push("secrets", false, e.to_string()),
    }
}

/// A decimal in a CSV cell as an integer of millionths — exact, no floats.
/// Formula-escaped cells (`'…`) are unwrapped first.
fn millionths(cell: &str) -> Result<i128, String> {
    let c = cell.trim().trim_start_matches('\'');
    if c.is_empty() {
        return Ok(0);
    }
    let (neg, c) = c.strip_prefix('-').map_or((false, c), |r| (true, r));
    let (int, frac) = c.split_once('.').unwrap_or((c, ""));
    if frac.len() > 6
        || !int.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit())
        || int.is_empty()
    {
        return Err(format!("not an amount: {cell:?}"));
    }
    let v: i128 =
        format!("{int}{frac:0<6}").parse().map_err(|_| format!("not an amount: {cell:?}"))?;
    Ok(if neg { -v } else { v })
}

/// Split one CSV record (RFC 4180, any of `,` `;` as the delimiter).
fn record(line: &str, delim: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            c if c == delim && !quoted => out.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// A CSV file as its header and its records. Records do not span lines unless
/// a quoted cell (a narrative) does; those are joined back by quote parity
/// before splitting. A byte-order mark is dropped, and the delimiter is `;`
/// when the header has one and no `,`.
fn table(csv: &str, what: &str) -> Result<(Vec<String>, Vec<Vec<String>>), String> {
    let body = csv.trim_start_matches('\u{feff}');
    let mut rows: Vec<String> = Vec::new();
    let mut pending = String::new();
    for line in body.split('\n') {
        let line = line.trim_end_matches('\r');
        if !pending.is_empty() {
            pending.push('\n');
        }
        pending.push_str(line);
        if pending.matches('"').count().is_multiple_of(2) {
            rows.push(std::mem::take(&mut pending));
        }
    }
    let mut rows = rows.into_iter().filter(|l| !l.is_empty());
    let header = rows.next().ok_or(format!("an empty {what}"))?;
    let delim = if header.contains(';') && !header.contains(',') { ';' } else { ',' };
    let cols = record(&header, delim);
    Ok((cols, rows.map(|r| record(&r, delim)).collect()))
}

fn column(cols: &[String], name: &str) -> Result<usize, String> {
    cols.iter().position(|c| c == name).ok_or(format!("no `{name}` column"))
}

fn cell(row: &[String], i: usize) -> &str {
    row.get(i).map(String::as_str).unwrap_or("")
}

/// Check a journal CSV: every entry nets to zero **in the functional
/// currency**, the ledger's own invariant (ARCHITECTURE §Core invariants: an
/// FX entry's legs are in several transaction currencies and balance only once
/// converted). Read from `functional_amount`; a journal without that column is
/// held to the stricter per-currency `debit`/`credit` instead. Answers how many
/// entries it saw and the ones that do not balance.
pub fn balance(csv: &str) -> Result<(usize, Vec<String>), String> {
    let (cols, rows) = table(csv, "journal")?;
    let at = |name: &str| column(&cols, name);
    let id = at("entry_id")?;
    let functional = at("functional_amount").and_then(|a| Ok((a, at("functional_currency")?)));
    let mut sums: BTreeMap<(String, String), i128> = BTreeMap::new();
    for f in &rows {
        let (net, ccy) = match &functional {
            Ok((amount, ccy)) => (millionths(cell(f, *amount))?, cell(f, *ccy)),
            Err(_) => {
                let (debit, credit, ccy) = (at("debit")?, at("credit")?, at("currency")?);
                (millionths(cell(f, debit))? - millionths(cell(f, credit))?, cell(f, ccy))
            }
        };
        *sums.entry((cell(f, id).to_string(), ccy.to_string())).or_default() += net;
    }
    let entries = sums.keys().map(|(e, _)| e).collect::<std::collections::BTreeSet<_>>().len();
    let bad =
        sums.into_iter().filter(|(_, v)| *v != 0).map(|((e, c), _)| format!("{e} ({c})")).collect();
    Ok((entries, bad))
}

/// Recompute a book's trial balance from its journal and hold the stated one
/// to it. `journal` is `journal.csv`, `stated` the book's `trial_balance.csv`,
/// `as_of` the date (`YYYY-MM-DD`) the trial balance was read as of: a journal
/// line booked after it is not in it.
///
/// Per account number and currency, the stated `balance` must equal the sum of
/// that account's `functional_amount`s in that `functional_currency`, exactly.
/// An account the trial balance lists with no postings must stand at zero, and
/// an account with postings must be listed. Answers how many accounts it
/// compared and, for each that differs, the account, the currency and both
/// figures.
pub fn trial_balance(
    journal: &str,
    stated: &str,
    as_of: &str,
) -> Result<(usize, Vec<String>), String> {
    let (jc, jrows) = table(journal, "journal")?;
    let (account, date) = (column(&jc, "account_number")?, column(&jc, "booking_date")?);
    let (amount, ccy) = (column(&jc, "functional_amount")?, column(&jc, "functional_currency")?);
    let mut made: BTreeMap<(String, String), i128> = BTreeMap::new();
    for f in jrows.iter().filter(|f| cell(f, date) <= as_of) {
        let key = (cell(f, account).to_string(), cell(f, ccy).to_string());
        *made.entry(key).or_default() += millionths(cell(f, amount))?;
    }
    let (tc, trows) = table(stated, "trial balance")?;
    let (number, balance, currency) =
        (column(&tc, "number")?, column(&tc, "balance")?, column(&tc, "currency")?);
    let mut says: BTreeMap<(String, String), i128> = BTreeMap::new();
    for f in &trows {
        let key = (cell(f, number).to_string(), cell(f, currency).to_string());
        *says.entry(key).or_default() += millionths(cell(f, balance))?;
    }
    let mut bad = Vec::new();
    for (key, stated) in &says {
        let sum = made.get(key).copied().unwrap_or(0);
        if *stated != sum {
            bad.push(format!(
                "account {} ({}): the trial balance says {}, its postings make {}",
                key.0,
                key.1,
                decimal(*stated),
                decimal(sum)
            ));
        }
    }
    for (key, sum) in &made {
        if *sum != 0 && !says.contains_key(key) {
            bad.push(format!(
                "account {} ({}): not in the trial balance, its postings make {}",
                key.0,
                key.1,
                decimal(*sum)
            ));
        }
    }
    Ok((says.len(), bad))
}

/// Millionths back to a decimal string, with at least two places.
fn decimal(m: i128) -> String {
    let sign = if m < 0 { "-" } else { "" };
    let (int, frac) = (m.unsigned_abs() / 1_000_000, m.unsigned_abs() % 1_000_000);
    let frac = format!("{frac:06}");
    let frac = frac.trim_end_matches('0');
    format!("{sign}{int}.{frac:0<2}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amounts_are_exact() {
        assert_eq!(millionths("12.5").unwrap(), 12_500_000);
        assert_eq!(millionths("-0.05").unwrap(), -50_000);
        assert_eq!(millionths("'7").unwrap(), 7_000_000);
        assert_eq!(millionths("").unwrap(), 0);
        assert!(millionths("1e3").is_err());
    }

    #[test]
    fn a_journal_that_balances_and_one_that_does_not() {
        let ok = "\u{feff}entry_id,narrative,debit,credit,currency\r\n\
                  1,\"Rechnung, März\",100.00,,CHF\r\n1,x,,100.00,CHF\r\n\
                  2,y,5.10,,EUR\r\n2,y,,5.1,EUR\r\n";
        assert_eq!(balance(ok).unwrap(), (2, vec![]));
        let bad = "entry_id;debit;credit;currency\n3;10;;CHF\n3;;9.99;CHF\n";
        assert_eq!(balance(bad).unwrap(), (1, vec!["3 (CHF)".to_string()]));
        // An FX entry: its EUR and CHF legs balance only in the functional
        // currency, which is the ledger's invariant and the one checked.
        let fx = "entry_id;debit;credit;currency;functional_amount;functional_currency\n\
                  7;100.00;;EUR;95.50;CHF\n7;;95.50;CHF;-95.50;CHF\n\
                  8;10;;CHF;10;CHF\n8;;9;CHF;-9;CHF\n";
        assert_eq!(balance(fx).unwrap(), (2, vec!["8 (CHF)".to_string()]));
    }

    /// A book in CHF with one EUR invoice, one entry after the take's day, and
    /// an account nothing was posted to — the shapes the take writes.
    const JOURNAL: &str = "\u{feff}entry_id,booking_date,value_date,narrative,account_number,\
        account_name,debit,credit,currency,functional_amount,functional_currency\r\n\
        1,2026-01-05,,\"Rechnung 1, Jan\",1100,Debitoren,100.00,,EUR,95.50,CHF\r\n\
        1,2026-01-05,,\"Rechnung 1, Jan\",3200,Ertrag,,95.50,CHF,-95.50,CHF\r\n\
        2,2026-02-01,,\"Zahlung\nmit Zeilenumbruch\",1020,Bank,40.25,,CHF,40.25,CHF\r\n\
        2,2026-02-01,,\"Zahlung\nmit Zeilenumbruch\",1100,Debitoren,,40.25,CHF,-40.25,CHF\r\n\
        3,2026-12-31,,Später,1020,Bank,1.00,,CHF,1.00,CHF\r\n\
        3,2026-12-31,,Später,3200,Ertrag,,1.00,CHF,-1.00,CHF\r\n";
    const STATED: &str = "\u{feff}number,name,balance,currency\r\n\
        1020,Bank,40.25,CHF\r\n1100,Debitoren,55.25,CHF\r\n\
        3200,Ertrag,-95.5,CHF\r\n4000,Material,0.00,CHF\r\n";

    #[test]
    fn a_trial_balance_recomputes_from_the_postings_as_of_its_day() {
        assert_eq!(trial_balance(JOURNAL, STATED, "2026-06-30").unwrap(), (4, vec![]));
        // Read a day later than it was taken, the December entry belongs in it.
        let (_, bad) = trial_balance(JOURNAL, STATED, "2026-12-31").unwrap();
        assert_eq!(
            bad,
            vec![
                "account 1020 (CHF): the trial balance says 40.25, its postings make 41.25",
                "account 3200 (CHF): the trial balance says -95.50, its postings make -96.50",
            ]
        );
    }

    #[test]
    fn a_tampered_figure_names_its_account_and_both_figures() {
        let tampered = STATED.replace("1100,Debitoren,55.25", "1100,Debitoren,55.20");
        let (n, bad) = trial_balance(JOURNAL, &tampered, "2026-06-30").unwrap();
        assert_eq!(n, 4);
        assert_eq!(
            bad,
            vec!["account 1100 (CHF): the trial balance says 55.20, its postings make 55.25"]
        );
        // An account dropped from the trial balance is named too, and a
        // zero balance on an account with no postings is not a difference.
        let dropped = STATED.replace("1020,Bank,40.25,CHF\r\n", "");
        let (_, bad) = trial_balance(JOURNAL, &dropped, "2026-06-30").unwrap();
        assert_eq!(
            bad,
            vec!["account 1020 (CHF): not in the trial balance, its postings make 40.25"]
        );
        // A figure in another currency than the one the book posts in differs.
        let ccy = STATED.replace("1020,Bank,40.25,CHF", "1020,Bank,40.25,EUR");
        let (_, bad) = trial_balance(JOURNAL, &ccy, "2026-06-30").unwrap();
        assert_eq!(bad.len(), 2, "{bad:?}");
        assert!(trial_balance(JOURNAL, "number,balance\n", "2026-06-30").is_err());
    }

    #[test]
    fn every_book_is_recomputed_and_a_gap_must_be_explained() {
        let files = |entries: &[(&str, &str)]| -> BTreeMap<String, Vec<u8>> {
            entries.iter().map(|(p, b)| (p.to_string(), b.as_bytes().to_vec())).collect()
        };
        let info: BTreeMap<String, String> =
            [("Bagging-Date".to_string(), "2026-06-30".to_string())].into();
        let run = |f: &BTreeMap<String, Vec<u8>>, info: &BTreeMap<String, String>| {
            let mut r = Report::default();
            verify_trial_balances(f, info, &mut r);
            r.checks.pop().unwrap()
        };
        let mut bundle = files(&[
            ("data/tables/main/journal.csv", JOURNAL),
            ("data/tables/main/trial_balance.csv", STATED),
            ("data/tables/missing.csv", "book,report,reason\n"),
        ]);
        let c = run(&bundle, &info);
        assert!(c.ok, "{c:?}");
        assert_eq!(
            c.detail,
            "4 accounts in 1 books, every balance as of 2026-06-30 the sum of its postings"
        );

        // A second book whose journal could not render: said, not failed.
        bundle.insert("data/tables/b2/trial_balance.csv".into(), STATED.as_bytes().to_vec());
        let c = run(&bundle, &info);
        assert!(!c.ok && c.detail.contains("b2: no journal.csv"), "{c:?}");
        bundle.insert(
            "data/tables/missing.csv".into(),
            b"book,report,reason\nb2,journal,over the row cap\n".to_vec(),
        );
        let c = run(&bundle, &info);
        assert!(c.ok && c.detail.contains("b2 (no journal, as missing.csv says)"), "{c:?}");

        // A tampered figure fails the check and says where.
        bundle.insert(
            "data/tables/main/trial_balance.csv".into(),
            STATED.replace("3200,Ertrag,-95.5", "3200,Ertrag,-95.6").into_bytes(),
        );
        let c = run(&bundle, &info);
        assert!(!c.ok, "{c:?}");
        assert!(
            c.detail.contains(
                "main: account 3200 (CHF): the trial balance says -95.60, its postings make -95.50"
            ),
            "{c:?}"
        );

        // Without the day it was taken, it cannot be read as of anything.
        let c = run(&bundle, &BTreeMap::new());
        assert!(!c.ok && c.detail.contains("Bagging-Date"), "{c:?}");
    }

    #[test]
    fn decimals_print_exactly() {
        assert_eq!(decimal(0), "0.00");
        assert_eq!(decimal(-95_500_000), "-95.50");
        assert_eq!(decimal(1_234_567), "1.234567");
        assert_eq!(decimal(-50_000), "-0.05");
    }

    #[test]
    fn something_that_is_not_a_bag_fails_loudly() {
        let r = verify(b"not a zip", None, None);
        assert!(!r.ok());
        assert_eq!(r.checks[0].name, "archive");
    }
}
