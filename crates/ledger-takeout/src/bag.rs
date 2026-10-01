//! **OFF2-D4** — the bag: BagIt's manifests (RFC 8493) and the signature over
//! them.
//!
//! A takeout is a BagIt bag. `manifest-sha256.txt` names every payload file
//! under `data/` with its SHA-256; `tagmanifest-sha256.txt` names the tag files
//! — `bagit.txt`, `bag-info.txt`, the payload manifest and the signing key —
//! with theirs; and `tagmanifest-sha256.txt.sig` is an ECDSA P-256 / SHA-256
//! signature over the tag manifest's bytes. So one signature covers every
//! byte: the signature fixes the tag manifest, the tag manifest fixes the
//! payload manifest and `bag-info.txt` (which names the secrets sidecar by
//! digest, OFF2-D5), and the payload manifest fixes every file.
//!
//! The signature is DER, as AWS KMS returns it and as `openssl dgst -sha256
//! -verify signing-key.pem -signature tagmanifest-sha256.txt.sig
//! tagmanifest-sha256.txt` checks it.

use std::collections::BTreeMap;

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePublicKey as _, EncodePublicKey as _, LineEnding};
use sha2::{Digest as _, Sha256};

/// The bag declaration.
pub const BAGIT_TXT: &str = "BagIt-Version: 1.0\nTag-File-Character-Encoding: UTF-8\n";

/// The payload manifest's name.
pub const MANIFEST: &str = "manifest-sha256.txt";
/// The tag manifest's name.
pub const TAGMANIFEST: &str = "tagmanifest-sha256.txt";
/// The signature over the tag manifest.
pub const SIGNATURE: &str = "tagmanifest-sha256.txt.sig";
/// The public key the signature verifies under.
pub const SIGNING_KEY: &str = "signing-key.pem";

/// Lower-case hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// A manifest: one `<sha256>  <path>` line per file, sorted by path.
pub fn manifest_text(entries: &BTreeMap<String, String>) -> String {
    entries.iter().map(|(path, digest)| format!("{digest}  {path}\n")).collect()
}

/// A manifest's lines back into `path → digest`.
pub fn parse_manifest(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for (n, line) in text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        let (digest, path) = line
            .split_once(' ')
            .map(|(d, p)| (d, p.trim_start()))
            .ok_or_else(|| format!("manifest line {} is not `<digest> <path>`", n + 1))?;
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("manifest line {} has no SHA-256", n + 1));
        }
        out.insert(path.to_string(), digest.to_ascii_lowercase());
    }
    Ok(out)
}

/// `bag-info.txt` from labelled values, in the order given.
pub fn bag_info(fields: &[(&str, String)]) -> String {
    fields.iter().map(|(k, v)| format!("{k}: {v}\n")).collect()
}

/// `bag-info.txt`'s values back, by label.
pub fn parse_bag_info(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// What checking a bag's payload found.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PayloadReport {
    /// Files listed and matching.
    pub verified: usize,
    /// Files listed whose bytes hash to something else.
    pub altered: Vec<String>,
    /// Files listed and not present.
    pub missing: Vec<String>,
    /// Payload files present and not listed.
    pub unlisted: Vec<String>,
}

impl PayloadReport {
    /// Every file listed, present and unchanged, and nothing extra.
    pub fn ok(&self) -> bool {
        self.altered.is_empty() && self.missing.is_empty() && self.unlisted.is_empty()
    }
}

/// Check `manifest` against the files: `files` is every path in the bag under
/// `prefix` (`"data/"` for the payload) with its bytes' digest.
pub fn check_manifest(
    manifest: &BTreeMap<String, String>,
    files: &BTreeMap<String, String>,
    prefix: &str,
) -> PayloadReport {
    let mut r = PayloadReport::default();
    for (path, digest) in manifest {
        match files.get(path) {
            Some(d) if d == digest => r.verified += 1,
            Some(_) => r.altered.push(path.clone()),
            None => r.missing.push(path.clone()),
        }
    }
    r.unlisted = files
        .keys()
        .filter(|p| p.starts_with(prefix) && !manifest.contains_key(*p))
        .cloned()
        .collect();
    r
}

/// A P-256 key held in process — the signer for a stack with no KMS, and for
/// tests. Production signs with KMS, never with this.
pub struct LocalSigner(SigningKey);

impl LocalSigner {
    /// A key from 32 secret bytes. `None` when they are not a valid scalar.
    pub fn from_secret(bytes: &[u8; 32]) -> Option<Self> {
        SigningKey::from_slice(bytes).ok().map(LocalSigner)
    }

    /// DER-encoded ECDSA P-256 / SHA-256 over `message`.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig: Signature = self.0.sign(message);
        sig.to_der().as_bytes().to_vec()
    }

    /// The public key as an SPKI PEM — what `signing-key.pem` holds.
    pub fn public_key_pem(&self) -> String {
        self.0
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("a P-256 public key encodes")
    }
}

/// Does `signature` (DER) verify `message` under the SPKI PEM `public_key`?
/// `Err` says why it could not even be checked.
pub fn verify_signature(
    public_key_pem: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    let key = VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|e| format!("signing key: {e}"))?;
    let sig = DerSignature::try_from(signature).map_err(|e| format!("signature: {e}"))?;
    let sig: Signature = sig.try_into().map_err(|e| format!("signature: {e}"))?;
    Ok(key.verify(message, &sig).is_ok())
}

/// The SPKI PEM for a DER-encoded SubjectPublicKeyInfo — KMS's
/// `GetPublicKey` answer, base64-decoded.
pub fn pem_from_spki_der(der: &[u8]) -> Result<String, String> {
    let key = VerifyingKey::from_public_key_der(der).map_err(|e| format!("public key: {e}"))?;
    key.to_public_key_pem(LineEnding::LF).map_err(|e| format!("public key: {e}"))
}

/// A short, stable name for a public key: the first 16 hex digits of the
/// SHA-256 of its PEM. What `bag-info.txt` and the published key list carry.
pub fn key_fingerprint(public_key_pem: &str) -> String {
    sha256_hex(public_key_pem.as_bytes())[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> LocalSigner {
        LocalSigner::from_secret(&[7u8; 32]).unwrap()
    }

    #[test]
    fn a_signature_verifies_and_a_changed_byte_does_not() {
        let s = signer();
        let pem = s.public_key_pem();
        let sig = s.sign(b"tag manifest");
        assert_eq!(verify_signature(&pem, b"tag manifest", &sig), Ok(true));
        assert_eq!(verify_signature(&pem, b"tag manifesT", &sig), Ok(false));
        let other = LocalSigner::from_secret(&[9u8; 32]).unwrap().public_key_pem();
        assert_eq!(verify_signature(&other, b"tag manifest", &sig), Ok(false));
        assert!(verify_signature("not a key", b"x", &sig).is_err());
        assert_eq!(key_fingerprint(&pem).len(), 16);
    }

    #[test]
    fn manifests_round_trip_and_name_what_is_wrong() {
        let mut files = BTreeMap::new();
        files.insert("data/a.csv".to_string(), sha256_hex(b"a"));
        files.insert("data/b.csv".to_string(), sha256_hex(b"b"));
        let text = manifest_text(&files);
        let parsed = parse_manifest(&text).unwrap();
        assert_eq!(parsed, files);
        assert!(check_manifest(&parsed, &files, "data/").ok());

        let mut present = files.clone();
        present.insert("data/b.csv".into(), sha256_hex(b"B"));
        present.remove("data/a.csv");
        present.insert("data/extra.csv".into(), sha256_hex(b"x"));
        let r = check_manifest(&parsed, &present, "data/");
        assert_eq!(r.altered, vec!["data/b.csv"]);
        assert_eq!(r.missing, vec!["data/a.csv"]);
        assert_eq!(r.unlisted, vec!["data/extra.csv"]);
        assert!(parse_manifest("nonsense\n").is_err());
    }

    #[test]
    fn bag_info_round_trips() {
        let text =
            bag_info(&[("Source-Organization", "saldira".into()), ("Payload-Oxum", "10.2".into())]);
        assert_eq!(parse_bag_info(&text)["Payload-Oxum"], "10.2");
    }
}
