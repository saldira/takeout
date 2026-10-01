//! `saldira-verify <bundle.zip> [--secrets <sidecar.jsonl>] [--key <fingerprint>] [--json]`,
//! or `saldira-verify --version`.
//!
//! Exit status 0 when every check holds, 1 when one does not, 2 when the
//! command line or a file could not be read.

use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!(
        "usage: saldira-verify <bundle.zip> [--secrets <sidecar.jsonl>] [--key <fingerprint>] [--json]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (mut bundle, mut secrets, mut key, mut json) = (None, None, None, false);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--secrets" => secrets = args.next(),
            "--key" => key = args.next(),
            "--json" => json = true,
            "-h" | "--help" => return usage(),
            "-V" | "--version" => {
                println!("saldira-verify {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            _ if bundle.is_none() => bundle = Some(a),
            _ => return usage(),
        }
    }
    let Some(bundle) = bundle else { return usage() };
    let read = |path: &str| {
        std::fs::read(path).map_err(|e| {
            eprintln!("saldira-verify: {path}: {e}");
            ExitCode::from(2)
        })
    };
    let archive = match read(&bundle) {
        Ok(b) => b,
        Err(code) => return code,
    };
    let sidecar = match secrets.as_deref().map(read).transpose() {
        Ok(s) => s,
        Err(code) => return code,
    };
    let report = ledger_verify::verify(&archive, sidecar.as_deref(), key.as_deref());
    if json {
        let checks: Vec<serde_json::Value> = report
            .checks
            .iter()
            .map(|c| serde_json::json!({ "check": c.name, "ok": c.ok, "detail": c.detail }))
            .collect();
        let out = serde_json::json!({
            "ok": report.ok(),
            "key_fingerprint": report.key_fingerprint.as_deref().unwrap_or(""),
            "checks": checks,
        });
        println!("{out}");
    } else {
        for c in &report.checks {
            println!("{} {:<13} {}", if c.ok { "ok  " } else { "FAIL" }, c.name, c.detail);
        }
        if key.is_none() {
            if let Some(fp) = &report.key_fingerprint {
                println!(
                    "note          compare the key {fp} with the fingerprint saldira publishes, \
                     or pass it with --key"
                );
            }
        }
        println!("{}", if report.ok() { "VERIFIED" } else { "NOT VERIFIED" });
    }
    if report.ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
