//! **OFF2-D10** — `saldira-verify`: everything a client needs to trust a
//! takeout without trusting saldira.
//!
//! A green run means the bundle is **unchanged since it was signed** (the
//! signature over the tag manifest, the tag manifest over the payload manifest
//! and `bag-info.txt`, the payload manifest over every file), **complete as
//! signed** (nothing listed is missing, nothing present is unlisted), its
//! **log is one unbroken chain** per book that matches its own manifest, every
//! stored document **is the file its name says**, and every journal entry
//! **balances to zero** in every currency.
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
        let name = f.name().to_string();
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

/// Check a journal CSV: every entry nets to zero **in the functional
/// currency**, the ledger's own invariant (ARCHITECTURE §Core invariants: an
/// FX entry's legs are in several transaction currencies and balance only once
/// converted). Read from `functional_amount`; a journal without that column is
/// held to the stricter per-currency `debit`/`credit` instead. Answers how many
/// entries it saw and the ones that do not balance.
pub fn balance(csv: &str) -> Result<(usize, Vec<String>), String> {
    let body = csv.trim_start_matches('\u{feff}');
    // Records do not span lines in a journal unless a narrative does; join
    // those back by quote parity before splitting.
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
    let header = rows.next().ok_or("an empty journal")?;
    let delim = if header.contains(';') && !header.contains(',') { ';' } else { ',' };
    let cols = record(&header, delim);
    let at = |name: &str| cols.iter().position(|c| c == name).ok_or(format!("no `{name}` column"));
    let id = at("entry_id")?;
    let functional = at("functional_amount").and_then(|a| Ok((a, at("functional_currency")?)));
    let mut sums: BTreeMap<(String, String), i128> = BTreeMap::new();
    for row in rows {
        let f = record(&row, delim);
        let get = |i: usize| f.get(i).map(String::as_str).unwrap_or("");
        let (net, ccy) = match &functional {
            Ok((amount, ccy)) => (millionths(get(*amount))?, get(*ccy)),
            Err(_) => {
                let (debit, credit, ccy) = (at("debit")?, at("credit")?, at("currency")?);
                (millionths(get(debit))? - millionths(get(credit))?, get(ccy))
            }
        };
        *sums.entry((get(id).to_string(), ccy.to_string())).or_default() += net;
    }
    let entries = sums.keys().map(|(e, _)| e).collect::<std::collections::BTreeSet<_>>().len();
    let bad =
        sums.into_iter().filter(|(_, v)| *v != 0).map(|((e, c), _)| format!("{e} ({c})")).collect();
    Ok((entries, bad))
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

    #[test]
    fn something_that_is_not_a_bag_fails_loudly() {
        let r = verify(b"not a zip", None, None);
        assert!(!r.ok());
        assert_eq!(r.checks[0].name, "archive");
    }
}
