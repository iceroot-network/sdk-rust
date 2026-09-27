//! Helpers shared by the vector tests: the vector files of `vectors/`, their manifests, and the
//! devnet chain the vectors were generated under.
//!
//! A vector file is JSONL in the `heartwood-vectors/1` format: a meta record first, then one
//! record per case, `{"op", "network", "height", "name"?, "input", "output"}`, or the same with
//! `"error": {"class", "message"}` in place of `"output"`.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use heartwood_crypto::utils::hex;
use iceroot_sdk_core::profile::DevnetOptions;
use iceroot_sdk_core::{Chain, Profile};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The repository's `vectors/` directory.
pub fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

/// Check `dir/MANIFEST.sha256`: every file under `dir` is listed with its SHA-256, and every
/// listed file exists.
pub fn check_manifest(dir: &Path) {
    let manifest = std::fs::read_to_string(dir.join("MANIFEST.sha256"))
        .unwrap_or_else(|e| panic!("{}: no manifest: {e}", dir.display()));
    let mut listed = BTreeMap::new();
    for line in manifest.lines() {
        let (hash, file) = line
            .split_once("  ")
            .unwrap_or_else(|| panic!("malformed manifest line {line:?}"));
        listed.insert(file.to_owned(), hash.to_owned());
    }
    let mut found = Vec::new();
    collect_files(dir, dir, &mut found);
    found.retain(|file| file != "MANIFEST.sha256");
    found.sort();
    assert_eq!(
        found,
        listed.keys().cloned().collect::<Vec<_>>(),
        "{}: the manifest does not list exactly the files present",
        dir.display()
    );
    for (file, hash) in listed {
        let bytes = std::fs::read(dir.join(&file)).expect("a listed file");
        assert_eq!(
            hex::encode(&Sha256::digest(&bytes)),
            hash,
            "{file}: changed since the manifest was written"
        );
    }
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("a directory") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            collect_files(root, &path, out);
        } else {
            let relative = path.strip_prefix(root).expect("below the root");
            out.push(relative.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// One case of a vector file.
#[derive(Debug, Clone)]
pub struct Record {
    /// 1-based line number in the file.
    pub line: usize,
    /// The operation, for example `tx.build`.
    pub op: String,
    /// The rule height.
    pub height: u32,
    /// The case label, if any.
    pub name: Option<String>,
    /// The operation's input.
    pub input: Value,
    /// The oracle's output, or its error `{class, message}`.
    pub expected: Result<Value, Value>,
}

impl Record {
    /// `class:line op "name"`, for messages.
    pub fn label(&self, class: &str) -> String {
        match &self.name {
            Some(name) => format!("{class}:{} {} {name:?}", self.line, self.op),
            None => format!("{class}:{} {}", self.line, self.op),
        }
    }

    /// The error class the oracle recorded, if the record is a refusal.
    pub fn error_class(&self) -> Option<&str> {
        self.expected
            .as_ref()
            .err()
            .and_then(|error| error["class"].as_str())
    }
}

/// A parsed vector file.
#[derive(Debug, Clone)]
pub struct VectorFile {
    /// The vector class, for example `V01-keys-addresses`.
    pub class: String,
    /// The meta record.
    pub meta: Value,
    /// The cases, in file order.
    pub records: Vec<Record>,
}

impl VectorFile {
    /// Read `vectors/<set>/<class>.jsonl`. Panics, naming the line, on a malformed file.
    pub fn load(set: &str, class: &str) -> VectorFile {
        let path = vectors_dir().join(set).join(format!("{class}.jsonl"));
        let text =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let mut lines = text.lines().enumerate();
        let (_, first) = lines.next().expect("a meta record");
        let meta: Value = serde_json::from_str(first).expect("the meta record is JSON");
        assert_eq!(meta["op"], "meta", "{class}: no meta record");
        assert_eq!(
            meta["class"], class,
            "{class}: meta record of another class"
        );
        assert_eq!(meta["format"], "heartwood-vectors/1");
        let records: Vec<Record> = lines
            .map(|(index, line)| parse_record(class, index + 1, line))
            .collect();
        assert_eq!(
            meta["records"].as_u64(),
            Some(records.len() as u64),
            "{class}: the meta record counts another number of records"
        );
        VectorFile {
            class: class.to_owned(),
            meta,
            records,
        }
    }
}

fn parse_record(class: &str, line: usize, text: &str) -> Record {
    let value: Value =
        serde_json::from_str(text).unwrap_or_else(|e| panic!("{class}:{line}: not JSON: {e}"));
    let op = value["op"].as_str().expect("an op").to_owned();
    let height = u32::try_from(value["height"].as_u64().expect("a height")).expect("u32");
    let name = value.get("name").and_then(Value::as_str).map(str::to_owned);
    let expected = match (value.get("output"), value.get("error")) {
        (Some(output), None) => Ok(output.clone()),
        (None, Some(error)) => Err(error.clone()),
        _ => panic!("{class}:{line}: a record has exactly one of output and error"),
    };
    Record {
        line,
        op,
        height,
        name,
        input: value["input"].clone(),
        expected,
    }
}

/// The devnet of the vector files: the network description and milestones of the first chain
/// definition in Heartwood's V10 class, whose milestone file the oracle ran under (the meta
/// record of every class names its SHA-256).
pub struct Devnet {
    /// The chain, loaded through the SDK.
    pub chain: Chain,
    /// SHA-256 of the milestone file, in hex.
    pub milestones_sha256: String,
}

pub static DEVNET: LazyLock<Devnet> = LazyLock::new(|| {
    let file = VectorFile::load("heartwood", "V10-genesis");
    let record = file.records.first().expect("a chain definition");
    let files = &record.expected.as_ref().expect("an output")["files"];
    let network = files["crypto/network.json"].as_str().expect("network.json");
    let milestones = files["crypto/milestones.json"]
        .as_str()
        .expect("milestones.json");
    let chain = Chain::from_parts(&devnet_profile(), network, milestones)
        .expect("the devnet configuration loads");
    Devnet {
        chain,
        milestones_sha256: hex::encode(&Sha256::digest(milestones.as_bytes())),
    }
});

/// The built-in devnet profile, nothing pinned.
pub fn devnet_profile() -> Profile {
    Profile::devnet(DevnetOptions::default())
}

/// Check that `file` was generated under the devnet milestones of [`DEVNET`].
pub fn check_devnet(file: &VectorFile) {
    assert_eq!(
        file.meta["network"]["milestonesSha256"].as_str(),
        Some(DEVNET.milestones_sha256.as_str()),
        "{}: generated under other devnet milestones",
        file.class
    );
    assert_eq!(file.meta["network"]["pubKeyHash"], 90);
}

/// The JSON text of `value`, keys in their order.
pub fn json_text(value: &Value) -> String {
    serde_json::to_string(value).expect("JSON text")
}

/// What happened to the records of a class. Every class ends by asserting its tally, so a new
/// record is never skipped without a change here.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Tally {
    /// Records whose outcome equals the oracle's.
    pub matched: usize,
    /// Records with a documented difference whose outcome was checked.
    pub divergent: usize,
    /// Records the SDK has no operation for, skipped by an explicit rule.
    pub skipped: usize,
}

/// The outcome of one record.
#[derive(Debug)]
pub enum Outcome {
    /// The SDK's outcome equals the oracle's.
    Matched,
    /// A documented difference, checked.
    Divergent(&'static str),
    /// No SDK operation, by an explicit rule.
    Skipped(&'static str),
    /// A mismatch.
    Failed(String),
}

/// Run every record of `file` through `run`, collect the tally and panic with every failure.
pub fn run_class(file: &VectorFile, mut run: impl FnMut(&Record) -> Outcome) -> Tally {
    let mut tally = Tally::default();
    let mut failures = Vec::new();
    for record in &file.records {
        match run(record) {
            Outcome::Matched => tally.matched += 1,
            Outcome::Divergent(reason) => {
                eprintln!("{}: difference: {reason}", record.label(&file.class));
                tally.divergent += 1;
            }
            Outcome::Skipped(reason) => {
                eprintln!("{}: skipped: {reason}", record.label(&file.class));
                tally.skipped += 1;
            }
            Outcome::Failed(message) => {
                failures.push(format!("{}: {message}", record.label(&file.class)));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} records failed:\n{}",
        failures.len(),
        file.records.len(),
        failures.join("\n")
    );
    tally
}

/// [`Outcome::Matched`] when `actual` is `expected` as JSON text, else a failure showing both.
pub fn compare(expected: &Value, actual: &Value) -> Outcome {
    if json_text(expected) == json_text(actual) {
        Outcome::Matched
    } else {
        Outcome::Failed(format!(
            "\n    expected {}\n    actual   {}",
            json_text(expected),
            json_text(actual)
        ))
    }
}
