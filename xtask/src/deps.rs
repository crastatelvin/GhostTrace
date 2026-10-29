//! `xtask deps` — dependency license and advisory review (plan P10.1).
//!
//! Offline part: read `cargo metadata`, require every package to declare a
//! license, and require that license string to be on the reviewed allowlist.
//! Any new string fails the command until a human reviews it, so a copyleft or
//! unknown license cannot arrive silently with a routine dependency bump.
//!
//! Advisory part: run `cargo audit` when it is installed (it needs the RustSec
//! database and therefore network). When it is absent the command reports
//! `not_installed` instead of pretending the check passed.

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

use serde_json::{Value, json};

/// License expressions present in the reviewed tree, each permissive (or an OR
/// expression with at least one permissive alternative, which is the license
/// this project actually relies on). A new string must be reviewed and added.
const ALLOWED: &[&str] = &[
    "MIT OR Apache-2.0",
    "MIT",
    "Apache-2.0 OR MIT",
    "MIT/Apache-2.0",
    "Apache-2.0",
    "Unicode-3.0",
    "Zlib OR Apache-2.0 OR MIT",
    "Unlicense OR MIT",
    "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
    "MIT OR Apache-2.0 OR Zlib",
    "Zlib",
    "BSD-3-Clause",
    "BSL-1.0",
    "MIT OR Zlib OR Apache-2.0",
    "BSD-3-Clause OR Apache-2.0",
    "BSD-3-Clause OR MIT OR Apache-2.0",
    "MIT OR Apache-2.0 OR LGPL-2.1-or-later",
    "Apache-2.0/MIT",
    "Unlicense/MIT",
    "BSD-2-Clause OR Apache-2.0 OR MIT",
    "0BSD OR MIT OR Apache-2.0",
    "MIT / Apache-2.0",
    "Apache-2.0 AND MIT",
    "(Apache-2.0 OR MIT) AND BSD-3-Clause",
    "(MIT OR Apache-2.0) AND OFL-1.1 AND Ubuntu-font-1.0",
    "MIT OR Apache-2.0 OR BSD-1-Clause",
    "Apache-2.0 / MIT",
    "ISC",
    "Apache-2.0 OR BSL-1.0",
    "Apache-2.0 OR GPL-2.0-only",
    "(MIT OR Apache-2.0) AND Unicode-3.0",
];

pub fn run() -> Result<(), String> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--locked"])
        .output()
        .map_err(|error| format!("failed to run cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let metadata: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("cargo metadata output: {error}"))?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or_else(|| "cargo metadata has no packages".to_string())?;

    let mut violations = Vec::new();
    let mut histogram: BTreeMap<String, u64> = BTreeMap::new();
    let mut versions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for package in packages {
        let name = package["name"].as_str().unwrap_or("<unknown>");
        let version = package["version"].as_str().unwrap_or("0");
        versions
            .entry(name.to_string())
            .or_default()
            .insert(version.to_string());
        match package["license"].as_str() {
            None => violations.push(format!("{name} {version} declares no license")),
            Some(license) => {
                *histogram.entry(license.to_string()).or_default() += 1;
                if !ALLOWED.contains(&license) {
                    violations.push(format!(
                        "{name} {version} uses unreviewed license {license:?}"
                    ));
                }
            }
        }
    }

    let duplicates: Vec<Value> = versions
        .iter()
        .filter(|(_, versions)| versions.len() > 1)
        .map(|(name, versions)| {
            json!({
                "name": name,
                "versions": versions.iter().collect::<Vec<_>>(),
            })
        })
        .collect();

    let advisory = match Command::new("cargo").args(["audit", "--version"]).output() {
        Ok(version) if version.status.success() => {
            let audit = Command::new("cargo")
                .args(["audit", "--json", "--quiet"])
                .output()
                .map_err(|error| format!("failed to run cargo audit: {error}"))?;
            let parsed: Value = serde_json::from_slice(&audit.stdout).unwrap_or(Value::Null);
            let count = parsed["vulnerabilities"]["count"].as_u64().unwrap_or(0);
            if !audit.status.success() || count > 0 {
                return Err(format!(
                    "cargo audit found {count} vulnerability record(s); see its report"
                ));
            }
            json!({ "status": "ran", "vulnerabilities": count })
        }
        _ => json!({
            "status": "not_installed",
            "note": "install cargo-audit and rerun before a release; it needs the RustSec database",
        }),
    };

    let summary = json!({
        "packages": packages.len(),
        "licenses": histogram,
        "duplicates": duplicates,
        "advisory": advisory,
        "violations": violations,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&summary).map_err(|error| error.to_string())?
    );
    if !violations.is_empty() {
        return Err(format!(
            "{} license violation(s); review and update xtask/src/deps.rs",
            violations.len()
        ));
    }
    Ok(())
}
