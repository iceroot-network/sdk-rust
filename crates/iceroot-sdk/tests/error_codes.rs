//! The error codes of the SDK's crates form one set, which the TypeScript and Go SDKs report: a
//! code that two crates give has the same meaning, and the same details, in both.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use iceroot_sdk::error::VoteProblem;
use iceroot_sdk::vote::{self, SelectError, SnapshotError, SplitError};
use iceroot_sdk::{Error, ErrorCode};

/// The codes of the core, as `ErrorCode::as_str` gives them.
const CORE: [ErrorCode; 33] = [
    ErrorCode::InvalidPhrase,
    ErrorCode::PhraseTooShort,
    ErrorCode::InvalidPath,
    ErrorCode::InvalidAddress,
    ErrorCode::InvalidAmount,
    ErrorCode::InvalidKey,
    ErrorCode::MemoTooLong,
    ErrorCode::NoRecipients,
    ErrorCode::TooManyRecipients,
    ErrorCode::InvalidVote,
    ErrorCode::InvalidName,
    ErrorCode::InvalidFee,
    ErrorCode::FeeUnavailable,
    ErrorCode::InvalidDraft,
    ErrorCode::InvalidTransaction,
    ErrorCode::InvalidSignIn,
    ErrorCode::InvalidRequest,
    ErrorCode::InvalidProfile,
    ErrorCode::NodeUnavailable,
    ErrorCode::RateLimited,
    ErrorCode::Timeout,
    ErrorCode::BadResponse,
    ErrorCode::NotFound,
    ErrorCode::Refused,
    ErrorCode::NetworkMismatch,
    ErrorCode::TxRejected,
    ErrorCode::StaleDraft,
    ErrorCode::UnsupportedOnNetwork,
    ErrorCode::SdkNotInitialized,
    ErrorCode::RandomnessUnavailable,
    ErrorCode::SigningFailed,
    ErrorCode::WrongKey,
    ErrorCode::KeyReleased,
];

fn is_core(code: &str) -> bool {
    CORE.iter().any(|core| core.as_str() == code)
}

/// One error of each code of the vote library.
fn vote_errors() -> Vec<(&'static str, serde_json::Value)> {
    let select = [
        SelectError::Count {
            count: 19,
            minimum: 20,
            maximum: 53,
        },
        SelectError::ValidatorAccount,
        SelectError::Snapshot(SnapshotError::NoSeats),
        SelectError::NotEnoughValidators {
            requested: 20,
            available: 3,
        },
        SelectError::DoesNotFit {
            fits: 17,
            minimum: 20,
            max_entries: 53,
            max_bytes: 400,
        },
        SelectError::BreaksRules {
            problems: vec![vote::Problem::ValidatorAccount],
        },
    ];
    let mut errors: Vec<(&'static str, serde_json::Value)> = select
        .iter()
        .map(|error| (error.code(), error.details()))
        .collect();
    let snapshot = SnapshotError::Window { days: 90 };
    errors.push((snapshot.code(), snapshot.details()));
    let split = SplitError { count: 10_001 };
    errors.push((split.code(), split.details()));
    errors
}

#[test]
fn the_vote_library_shares_only_the_core_s_invalid_vote() {
    let errors = vote_errors();
    let codes: Vec<&str> = errors.iter().map(|(code, _)| *code).collect();
    assert_eq!(
        codes,
        [
            "InvalidPickCount",
            "ValidatorCannotVote",
            "InvalidSnapshot",
            "NotEnoughValidators",
            "DoesNotFit",
            "BreaksRules",
            "InvalidSnapshot",
            "InvalidVote",
        ]
    );
    for (code, details) in &errors {
        assert!(details.is_object(), "{code}");
        if is_core(code) {
            assert_eq!(*code, "InvalidVote");
        }
    }
    // A split that cannot be made has the details of the core's vote with too many entries.
    let core = Error::InvalidVote {
        problem: VoteProblem::TooManyEntries {
            count: 10_001,
            maximum: 10_000,
        },
    };
    assert_eq!(core.code().as_str(), "InvalidVote");
    assert_eq!(errors.last().unwrap().1, core.details());
}

#[cfg(feature = "keystore")]
#[test]
fn the_keystore_shares_only_the_core_s_randomness_unavailable() {
    use iceroot_sdk::keystore::{self, Malformed, Param, PasswordProblem, PayloadKind};

    let errors = [
        keystore::Error::WrongPasswordOrCorrupt,
        keystore::Error::Malformed {
            problem: Malformed::Magic,
        },
        keystore::Error::UnsupportedVersion { version: 2 },
        keystore::Error::UnsupportedKdf { kdf: 2 },
        keystore::Error::UnsupportedPayload { kind: 2 },
        keystore::Error::ParamsOutOfRange {
            param: Param::Memory,
            value: 1,
            minimum: 19_456,
            maximum: 524_288,
        },
        keystore::Error::InvalidPayload {
            kind: PayloadKind::Bip39Entropy,
            length: 16,
        },
        keystore::Error::InvalidPassword {
            problem: PasswordProblem::Empty,
        },
        keystore::Error::OutOfMemory { memory_kib: 1 },
        keystore::Error::RandomnessUnavailable,
    ];
    for error in &errors {
        assert!(error.details().is_object(), "{}", error.code());
        if is_core(error.code()) {
            assert_eq!(error.code(), "RandomnessUnavailable");
            assert_eq!(error.details(), Error::RandomnessUnavailable.details());
        }
    }
    // No code of the keystore is a code of the vote library.
    for (code, _) in vote_errors() {
        assert!(errors.iter().all(|error| error.code() != code), "{code}");
    }
}
