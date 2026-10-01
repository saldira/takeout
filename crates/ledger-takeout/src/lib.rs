//! **OFF2** — the takeout's log: what a client takes with them, and how anyone
//! can check it without us.
//!
//! A takeout carries the tenant's whole `wire_log` (OFF2-D2): every stored
//! column of every row, one JSON object per line, in the tenant-wide id order
//! replay uses. Each row's `entry_hash` is `sha256(prev_hash ‖ US ‖ canonical)`
//! over ten of its fields, chained per book from `GENESIS` — the audit
//! contract `ledger-store-postgres` writes and `verify_wire_log` checks. This
//! crate recomputes it independently, so a bundle can be verified by something
//! that is not the system that wrote it.
//!
//! **Secrets** (OFF2-D5): three methods keep one verbatim in their payload, and
//! a takeout is made to be copied. So those rows ship *masked* and marked
//! `attested` — their stored hash is carried, not recomputed, and the next
//! row's `prev_hash` still links to it. Their raw payloads go to a separate
//! sidecar the tenant asks for, never into the log file itself. With the
//! sidecar, [`unmask`] restores the rows byte for byte and every hash
//! recomputes; that is what a verbatim restore (OFF2-D11) needs.

use std::collections::BTreeMap;
use std::fmt;

pub mod bag;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The format this crate reads and writes. A bundle naming another is refused
/// rather than guessed at.
pub const FORMAT: &str = "saldira-takeout/1";

/// The hash-chain anchor for a book's first entry (the store's own constant).
pub const GENESIS: &str = "GENESIS";

/// The byte that joins the canonical fields (Unit Separator, 0x1f).
const SEP: char = '\u{1f}';

/// One `wire_log` row, as a takeout carries it: every stored column.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogLine {
    /// The source estate's tenant-wide id: the order replay applies rows in.
    pub id: i64,
    /// The book the command was sent to.
    pub book_id: String,
    /// The idempotency key the mutation carried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// The wire method.
    pub method: String,
    /// The stamped request payload, as stored — or masked, when `attested`.
    pub payload: String,
    /// Who sent it (the IdP subject).
    pub principal: String,
    /// The roles it was sent under, comma-separated.
    pub roles: String,
    /// When the edge recorded it (RFC 3339).
    pub recorded_at: String,
    /// The client address, when the transport knew it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    /// How identity was established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    /// The request's trace id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// The previous entry's hash in this book's chain, or [`GENESIS`].
    pub prev_hash: String,
    /// This entry's hash, as stored.
    pub entry_hash: String,
    /// `true` when the payload is masked (OFF2-D5): the hash is carried, not
    /// recomputable from this line alone.
    #[serde(default, skip_serializing_if = "is_false")]
    pub attested: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// One masked row's raw payload — a line of the secrets sidecar (OFF2-D5).
/// The whole payload rather than the one field, because putting a field back
/// into JSON would have to reproduce the original bytes exactly, and only the
/// original bytes do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretLine {
    /// The [`LogLine::id`] it belongs to.
    pub id: i64,
    /// The payload as stored, secret included.
    pub payload: String,
}

/// One book a takeout carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookManifest {
    /// The book id. It is part of every entry's hash, so a restore that keeps
    /// the chain keeps the id (OFF2 §6a).
    pub book_id: String,
    /// The book's functional currency (ISO 4217).
    pub functional_currency: String,
    /// `open`, `closed` or `archived`.
    pub status: String,
    /// How many log entries the book has in this takeout.
    pub entries: u64,
    /// The hash of its last entry, or [`GENESIS`] for an empty book.
    pub chain_head: String,
}

/// What a takeout's log holds — written beside it, checked against it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Always [`FORMAT`].
    pub format: String,
    /// The tenant it was taken from.
    pub tenant_id: String,
    /// Every book of the tenant, in id order.
    pub books: Vec<BookManifest>,
    /// The total number of log lines.
    pub entries: u64,
    /// The ids of the masked lines (OFF2-D5), in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attested: Vec<i64>,
}

impl Manifest {
    /// A manifest from its JSON (`data/log/manifest.json`).
    pub fn from_json(text: &str) -> Result<Self, TakeoutError> {
        serde_json::from_str(text).map_err(|e| TakeoutError::Malformed(format!("manifest: {e}")))
    }
}

/// Why a takeout was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TakeoutError {
    /// The manifest names a format this crate does not read.
    UnknownFormat(String),
    /// A line or the manifest is not what the format says.
    Malformed(String),
    /// The log and its manifest disagree.
    ManifestMismatch(String),
    /// The chain does not hold: a line was changed, removed, added or moved.
    ChainBroken {
        /// The first line where it breaks.
        id: i64,
        /// Its book.
        book_id: String,
        /// `"link"` (its `prev_hash` is not the previous entry's hash) or
        /// `"hash"` (its fields do not hash to its `entry_hash`).
        reason: &'static str,
    },
    /// A verbatim restore needs the secrets sidecar, and these masked lines
    /// have no secret in it.
    SecretsRequired(Vec<i64>),
}

impl fmt::Display for TakeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFormat(v) => {
                write!(f, "unknown takeout format: {v} (this reads {FORMAT})")
            }
            Self::Malformed(m) => write!(f, "malformed takeout: {m}"),
            Self::ManifestMismatch(m) => write!(f, "the log does not match its manifest: {m}"),
            Self::ChainBroken { id, book_id, reason } => {
                write!(f, "hash chain broken at entry {id} of book {book_id} ({reason})")
            }
            Self::SecretsRequired(ids) => write!(
                f,
                "{} masked entries need the secrets sidecar to be restored byte for byte",
                ids.len()
            ),
        }
    }
}

impl std::error::Error for TakeoutError {}

/// The hash a line's fields chain to after `prev` — the store's audit
/// contract, recomputed here. An absent optional field hashes as the empty
/// string, exactly as the store reads a `NULL` column.
pub fn entry_hash(prev: &str, line: &LogLine) -> String {
    let opt = |o: &Option<String>| o.clone().unwrap_or_default();
    let canonical = [
        line.book_id.clone(),
        line.method.clone(),
        line.payload.clone(),
        line.principal.clone(),
        line.roles.clone(),
        line.recorded_at.clone(),
        opt(&line.request_id),
        opt(&line.source_ip),
        opt(&line.auth_method),
        opt(&line.trace_id),
    ]
    .join(&SEP.to_string());
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(SEP.to_string().as_bytes());
    h.update(canonical.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Mask the secret-bearing lines (OFF2-D5). `mask` answers a payload as a
/// reader may see it — the store's `redact_payload` — and any line it changes
/// is masked and attested here, its raw payload moved to the returned sidecar.
pub fn mask(
    lines: Vec<LogLine>,
    mask: impl Fn(&str, &str) -> String,
) -> (Vec<LogLine>, Vec<SecretLine>) {
    let mut secrets = Vec::new();
    let masked = lines
        .into_iter()
        .map(|mut line| {
            let shown = mask(&line.method, &line.payload);
            if shown != line.payload {
                secrets.push(SecretLine {
                    id: line.id,
                    payload: std::mem::replace(&mut line.payload, shown),
                });
                line.attested = true;
            }
            line
        })
        .collect();
    (masked, secrets)
}

/// Put the raw payloads back (OFF2-D5): every attested line takes its payload
/// from the sidecar and stops being attested. Refused, naming them, when any
/// attested line has no secret — a verbatim restore cannot invent one.
pub fn unmask(lines: Vec<LogLine>, secrets: &[SecretLine]) -> Result<Vec<LogLine>, TakeoutError> {
    let by_id: BTreeMap<i64, &str> = secrets.iter().map(|s| (s.id, s.payload.as_str())).collect();
    let missing: Vec<i64> =
        lines.iter().filter(|l| l.attested && !by_id.contains_key(&l.id)).map(|l| l.id).collect();
    if !missing.is_empty() {
        return Err(TakeoutError::SecretsRequired(missing));
    }
    Ok(lines
        .into_iter()
        .map(|mut line| {
            if line.attested {
                line.payload = by_id[&line.id].to_string();
                line.attested = false;
            }
            line
        })
        .collect())
}

/// What [`verify`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainReport {
    /// Lines checked.
    pub entries: u64,
    /// Lines whose hash was recomputed and matched.
    pub recomputed: u64,
    /// Attested lines, linked but not recomputed (OFF2-D5).
    pub attested: Vec<i64>,
    /// Each book's last hash, in book order.
    pub chain_heads: BTreeMap<String, String>,
}

/// Check every line: ids strictly increase, each line links to its book's
/// previous entry, and each line that is not attested hashes to its
/// `entry_hash`. The first failure is the answer.
pub fn verify(lines: &[LogLine]) -> Result<ChainReport, TakeoutError> {
    let mut heads: BTreeMap<String, String> = BTreeMap::new();
    let mut recomputed = 0u64;
    let mut attested = Vec::new();
    let mut last_id = i64::MIN;
    for line in lines {
        if line.id <= last_id {
            return Err(TakeoutError::Malformed(format!(
                "entry {} follows entry {last_id}: ids must increase",
                line.id
            )));
        }
        last_id = line.id;
        let expected = heads.get(&line.book_id).map_or(GENESIS, String::as_str);
        let broken = |reason| TakeoutError::ChainBroken {
            id: line.id,
            book_id: line.book_id.clone(),
            reason,
        };
        if line.prev_hash != expected {
            return Err(broken("link"));
        }
        if line.attested {
            attested.push(line.id);
        } else if entry_hash(expected, line) == line.entry_hash {
            recomputed += 1;
        } else {
            return Err(broken("hash"));
        }
        heads.insert(line.book_id.clone(), line.entry_hash.clone());
    }
    Ok(ChainReport { entries: lines.len() as u64, recomputed, attested, chain_heads: heads })
}

/// The manifest for `lines`, given each book's currency and status (books
/// with no entries are carried too, with a [`GENESIS`] head).
pub fn manifest(
    tenant_id: &str,
    books: &[(String, String, String)],
    lines: &[LogLine],
) -> Manifest {
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    let mut heads: BTreeMap<&str, &str> = BTreeMap::new();
    for l in lines {
        *counts.entry(l.book_id.as_str()).or_default() += 1;
        heads.insert(l.book_id.as_str(), l.entry_hash.as_str());
    }
    let mut books: Vec<BookManifest> = books
        .iter()
        .map(|(id, ccy, status)| BookManifest {
            book_id: id.clone(),
            functional_currency: ccy.clone(),
            status: status.clone(),
            entries: counts.get(id.as_str()).copied().unwrap_or(0),
            chain_head: heads.get(id.as_str()).map_or(GENESIS, |h| *h).to_string(),
        })
        .collect();
    books.sort_by(|a, b| a.book_id.cmp(&b.book_id));
    Manifest {
        format: FORMAT.to_string(),
        tenant_id: tenant_id.to_string(),
        books,
        entries: lines.len() as u64,
        attested: lines.iter().filter(|l| l.attested).map(|l| l.id).collect(),
    }
}

/// Check `lines` against their manifest and their own chain: the format, every
/// line's book is in the manifest, the counts, the attested set and every
/// book's chain head agree. Answers the chain report on success.
pub fn check(manifest: &Manifest, lines: &[LogLine]) -> Result<ChainReport, TakeoutError> {
    if manifest.format != FORMAT {
        return Err(TakeoutError::UnknownFormat(manifest.format.clone()));
    }
    let report = verify(lines)?;
    let mismatch = |m: String| Err(TakeoutError::ManifestMismatch(m));
    if manifest.entries != report.entries {
        return mismatch(format!("{} entries named, {} present", manifest.entries, report.entries));
    }
    if manifest.attested != report.attested {
        return mismatch("the masked entries differ".into());
    }
    for book in report.chain_heads.keys() {
        if !manifest.books.iter().any(|b| &b.book_id == book) {
            return mismatch(format!("book {book} is in the log and not in the manifest"));
        }
    }
    for b in &manifest.books {
        let head = report.chain_heads.get(&b.book_id).map_or(GENESIS, String::as_str);
        if head != b.chain_head {
            return mismatch(format!("book {}'s chain head differs", b.book_id));
        }
    }
    Ok(report)
}

/// Lines as JSON Lines: one object per line, `\n`-terminated.
pub fn to_jsonl<T: Serialize>(items: &[T]) -> String {
    let mut out = String::new();
    for item in items {
        out.push_str(&serde_json::to_string(item).expect("a takeout line serializes"));
        out.push('\n');
    }
    out
}

/// JSON Lines back into lines. Blank lines are skipped; anything else that is
/// not one of `T` is refused with its line number.
pub fn from_jsonl<T: for<'de> Deserialize<'de>>(text: &str) -> Result<Vec<T>, TakeoutError> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(n, l)| {
            serde_json::from_str(l)
                .map_err(|e| TakeoutError::Malformed(format!("line {}: {e}", n + 1)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A chain of `n` lines over two books, hashed the way the store hashes.
    fn chain(specs: &[(&str, &str, &str)]) -> Vec<LogLine> {
        let mut heads: BTreeMap<String, String> = BTreeMap::new();
        specs
            .iter()
            .enumerate()
            .map(|(i, (book, method, payload))| {
                let prev = heads.get(*book).cloned().unwrap_or_else(|| GENESIS.to_string());
                let mut line = LogLine {
                    id: i as i64 + 1,
                    book_id: book.to_string(),
                    request_id: Some(format!("r{i}")),
                    method: method.to_string(),
                    payload: payload.to_string(),
                    principal: "alice".into(),
                    roles: "reader,poster".into(),
                    recorded_at: "2026-10-01T08:00:00Z".into(),
                    source_ip: None,
                    auth_method: Some("jwt".into()),
                    trace_id: None,
                    prev_hash: prev.clone(),
                    entry_hash: String::new(),
                    attested: false,
                };
                line.entry_hash = entry_hash(&prev, &line);
                heads.insert(book.to_string(), line.entry_hash.clone());
                line
            })
            .collect()
    }

    fn sample() -> Vec<LogLine> {
        chain(&[
            ("haupt", "create_party", r#"{"name":"A"}"#),
            ("zweit", "open_account", r#"{"number":"1000"}"#),
            ("haupt", "register_webhook", r#"{"url":"https://x","secret":"s3cr3t-value"}"#),
            ("haupt", "post_entry", r#"{"n":1}"#),
        ])
    }

    fn hide(method: &str, payload: &str) -> String {
        if method == "register_webhook" {
            payload.replace("s3cr3t-value", "…alue")
        } else {
            payload.to_string()
        }
    }

    #[test]
    fn an_intact_chain_verifies_and_names_its_heads() {
        let lines = sample();
        let r = verify(&lines).unwrap();
        assert_eq!((r.entries, r.recomputed), (4, 4));
        assert_eq!(r.chain_heads["haupt"], lines[3].entry_hash);
        assert_eq!(r.chain_heads["zweit"], lines[1].entry_hash);
    }

    #[test]
    fn a_changed_payload_breaks_the_hash_and_a_dropped_line_breaks_the_link() {
        let mut lines = sample();
        lines[3].payload = r#"{"n":2}"#.into();
        assert!(matches!(
            verify(&lines),
            Err(TakeoutError::ChainBroken { id: 4, reason: "hash", .. })
        ));
        let mut lines = sample();
        lines.remove(2);
        assert!(matches!(
            verify(&lines),
            Err(TakeoutError::ChainBroken { id: 4, reason: "link", .. })
        ));
    }

    #[test]
    fn a_masked_line_is_attested_still_links_and_unmasks_to_the_original() {
        let original = sample();
        let (masked, secrets) = mask(original.clone(), hide);
        assert!(masked[2].attested && !masked[2].payload.contains("s3cr3t"));
        assert_eq!(secrets, vec![SecretLine { id: 3, payload: original[2].payload.clone() }]);
        let r = verify(&masked).unwrap();
        assert_eq!((r.recomputed, r.attested.clone()), (3, vec![3]));
        // Without the sidecar a verbatim restore is refused, naming the line…
        assert_eq!(unmask(masked.clone(), &[]), Err(TakeoutError::SecretsRequired(vec![3])));
        // …with it, every line is the original again and every hash recomputes.
        let back = unmask(masked, &secrets).unwrap();
        assert_eq!(back, original);
        assert_eq!(verify(&back).unwrap().recomputed, 4);
    }

    #[test]
    fn the_manifest_is_checked_against_the_log() {
        let (lines, _) = mask(sample(), hide);
        let books = vec![
            ("haupt".to_string(), "CHF".to_string(), "open".to_string()),
            ("zweit".to_string(), "EUR".to_string(), "open".to_string()),
            ("leer".to_string(), "CHF".to_string(), "closed".to_string()),
        ];
        let m = manifest("acme", &books, &lines);
        assert_eq!(m.attested, vec![3]);
        assert_eq!(m.books.iter().find(|b| b.book_id == "leer").unwrap().chain_head, GENESIS);
        check(&m, &lines).unwrap();
        // A truncated log is a different log, whatever its chain says.
        assert!(matches!(check(&m, &lines[..3]), Err(TakeoutError::ManifestMismatch(_))));
        let mut other = m.clone();
        other.format = "saldira-takeout/9".into();
        assert!(matches!(check(&other, &lines), Err(TakeoutError::UnknownFormat(_))));
    }

    #[test]
    fn lines_round_trip_through_json_lines() {
        let (lines, secrets) = mask(sample(), hide);
        assert_eq!(from_jsonl::<LogLine>(&to_jsonl(&lines)).unwrap(), lines);
        assert_eq!(from_jsonl::<SecretLine>(&to_jsonl(&secrets)).unwrap(), secrets);
        assert!(matches!(from_jsonl::<LogLine>("{}\n"), Err(TakeoutError::Malformed(_))));
    }
}
