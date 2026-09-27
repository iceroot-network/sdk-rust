//! Errors: one type for the keystore, with a stable code and structured details, in the style of
//! the SDK's own error type.
//!
//! Every check that needs the password ends in the one variant
//! [`Error::WrongPasswordOrCorrupt`]: a wrong password, a changed salt, nonce, parameter,
//! ciphertext or tag all give the same answer, so a caller learns nothing from which check
//! failed. The other variants come from checks anyone can make without the password (the layout,
//! the version, the parameters), which [`crate::inspect`] makes as well.
//!
//! Error values never contain secrets: no password, payload or key appears in any of them.

use std::fmt;

use serde_json::{Value, json};

use crate::payload::PayloadKind;

/// A keystore error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The password is wrong, or the keystore was changed or damaged after it was written. The
    /// two cannot be told apart, by design.
    #[error("wrong password, or the keystore was changed or damaged")]
    WrongPasswordOrCorrupt,
    /// The bytes or text are not a keystore of a known layout.
    #[error("not a valid keystore: {problem}")]
    Malformed {
        /// What is wrong with it.
        problem: Malformed,
    },
    /// The keystore's format version is not one this release reads.
    #[error("keystore format version {version} is not supported; this release reads version 1")]
    UnsupportedVersion {
        /// The version byte of the keystore.
        version: u8,
    },
    /// The keystore names a key derivation function this release does not know.
    #[error("key derivation function {kdf} is not supported")]
    UnsupportedKdf {
        /// The KDF byte of the keystore.
        kdf: u8,
    },
    /// The payload kind is unknown, or reserved for a later release.
    #[error("payload kind {kind} is not supported by this release")]
    UnsupportedPayload {
        /// The payload kind byte.
        kind: u8,
    },
    /// A key derivation parameter is outside the bounds: below the floor (a weak keystore) or
    /// above the ceiling (a keystore that would demand too much memory or time).
    #[error("{param} {value} is outside the allowed range {minimum} to {maximum}")]
    ParamsOutOfRange {
        /// The parameter.
        param: Param,
        /// Its value.
        value: u64,
        /// The smallest value allowed.
        minimum: u64,
        /// The largest value allowed.
        maximum: u64,
    },
    /// Secret material of the wrong length for its payload kind.
    #[error("{} is {}; got {length} bytes", kind.as_str(), describe_lengths(*kind))]
    InvalidPayload {
        /// The payload kind.
        kind: PayloadKind,
        /// The length given, in bytes.
        length: usize,
    },
    /// The password cannot be used.
    #[error("the password cannot be used: {problem}")]
    InvalidPassword {
        /// What is wrong with it.
        problem: PasswordProblem,
    },
    /// The memory the key derivation needs could not be allocated.
    #[error("the key derivation needs {memory_kib} KiB of memory, which could not be allocated")]
    OutOfMemory {
        /// The memory asked for, in KiB.
        memory_kib: u32,
    },
    /// No randomness is available for the salt and nonce.
    #[error("no randomness is available")]
    RandomnessUnavailable,
}

fn describe_lengths(kind: PayloadKind) -> &'static str {
    match kind {
        PayloadKind::Bip39Entropy => "24, 28 or 32 bytes (18, 21 or 24 words)",
        PayloadKind::MlDsa65Seed => "32 bytes",
    }
}

impl Error {
    /// The stable code of the error: the variant's name, as the TypeScript SDK reports it.
    pub const fn code(&self) -> &'static str {
        match self {
            Error::WrongPasswordOrCorrupt => "WrongPasswordOrCorrupt",
            Error::Malformed { .. } => "Malformed",
            Error::UnsupportedVersion { .. } => "UnsupportedVersion",
            Error::UnsupportedKdf { .. } => "UnsupportedKdf",
            Error::UnsupportedPayload { .. } => "UnsupportedPayload",
            Error::ParamsOutOfRange { .. } => "ParamsOutOfRange",
            Error::InvalidPayload { .. } => "InvalidPayload",
            Error::InvalidPassword { .. } => "InvalidPassword",
            Error::OutOfMemory { .. } => "OutOfMemory",
            Error::RandomnessUnavailable => "RandomnessUnavailable",
        }
    }

    /// The structured details of the error, as a JSON object. The keys of each code are part of
    /// the API.
    pub fn details(&self) -> Value {
        match self {
            Error::WrongPasswordOrCorrupt | Error::RandomnessUnavailable => json!({}),
            Error::Malformed { problem } => json!({ "reason": problem.as_str() }),
            Error::UnsupportedVersion { version } => json!({ "version": version }),
            Error::UnsupportedKdf { kdf } => json!({ "kdf": kdf }),
            Error::UnsupportedPayload { kind } => json!({ "kind": kind }),
            Error::ParamsOutOfRange {
                param,
                value,
                minimum,
                maximum,
            } => json!({
                "param": param.as_str(),
                "value": value,
                "minimum": minimum,
                "maximum": maximum,
            }),
            Error::InvalidPayload { kind, length } => {
                json!({ "kind": kind.as_str(), "length": length })
            }
            Error::InvalidPassword { problem } => match problem {
                PasswordProblem::Empty => json!({ "reason": problem.as_str() }),
                PasswordProblem::TooLong { bytes, maximum } => {
                    json!({ "reason": problem.as_str(), "bytes": bytes, "maximum": maximum })
                }
            },
            Error::OutOfMemory { memory_kib } => json!({ "memoryKib": memory_kib }),
        }
    }
}

/// What is wrong with a keystore's layout or text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Malformed {
    /// The bytes do not start with the keystore magic.
    Magic,
    /// The bytes end before the header and tag do.
    Truncated,
    /// The payload length does not fit the payload kind.
    PayloadLength,
    /// The total length does not match the header's payload length.
    Length,
    /// The text does not start with the armor prefix.
    ArmorPrefix,
    /// The text after the prefix is not canonical unpadded base64url.
    ArmorEncoding,
    /// The text is longer than any keystore.
    ArmorLength,
}

impl Malformed {
    /// A stable string for the problem: `magic`, `truncated`, `payload-length`, `length`,
    /// `armor-prefix`, `armor-encoding` or `armor-length`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Malformed::Magic => "magic",
            Malformed::Truncated => "truncated",
            Malformed::PayloadLength => "payload-length",
            Malformed::Length => "length",
            Malformed::ArmorPrefix => "armor-prefix",
            Malformed::ArmorEncoding => "armor-encoding",
            Malformed::ArmorLength => "armor-length",
        }
    }
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Malformed::Magic => "it does not start with the keystore magic",
            Malformed::Truncated => "it ends early",
            Malformed::PayloadLength => "the payload length does not fit the payload kind",
            Malformed::Length => "its length does not match its header",
            Malformed::ArmorPrefix => "the text does not start with the keystore prefix",
            Malformed::ArmorEncoding => "the text is not canonical unpadded base64url",
            Malformed::ArmorLength => "the text is longer than any keystore",
        })
    }
}

/// A key derivation parameter, as [`Error::ParamsOutOfRange`] names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Param {
    /// Argon2 memory, in KiB.
    Memory,
    /// Argon2 passes over the memory.
    Iterations,
    /// Argon2 lanes.
    Parallelism,
    /// Memory times iterations: the KiB filled over all passes, which bounds the time.
    Work,
}

impl Param {
    /// A stable string for the parameter: `memory`, `iterations`, `parallelism` or `work`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Param::Memory => "memory",
            Param::Iterations => "iterations",
            Param::Parallelism => "parallelism",
            Param::Work => "work",
        }
    }
}

impl fmt::Display for Param {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Param::Memory => "memory (KiB)",
            Param::Iterations => "iterations",
            Param::Parallelism => "parallelism",
            Param::Work => "work (memory in KiB times iterations)",
        })
    }
}

/// What is wrong with a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PasswordProblem {
    /// The password is empty.
    Empty,
    /// The password is longer than allowed.
    TooLong {
        /// Its length in UTF-8 bytes.
        bytes: usize,
        /// The most bytes allowed.
        maximum: usize,
    },
}

impl PasswordProblem {
    /// A stable string for the problem: `empty` or `too-long`.
    pub const fn as_str(self) -> &'static str {
        match self {
            PasswordProblem::Empty => "empty",
            PasswordProblem::TooLong { .. } => "too-long",
        }
    }
}

impl fmt::Display for PasswordProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PasswordProblem::Empty => f.write_str("it is empty"),
            PasswordProblem::TooLong { bytes, maximum } => {
                write!(
                    f,
                    "it is {bytes} bytes of UTF-8; at most {maximum} are allowed"
                )
            }
        }
    }
}
