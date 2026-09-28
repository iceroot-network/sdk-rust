//! Vote entries and the network's vote rules.

use core::cmp::Ordering;
use core::fmt;

use serde_json::{Value, json};

use crate::snapshot::Voter;

/// The total of a non-empty vote, in basis points: 10,000 is 100 %.
pub const TOTAL_BASIS_POINTS: u16 = 10_000;

/// One entry of a vote: a validator's name and its share of the account's vote weight.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VoteEntry {
    /// The validator's name.
    pub validator: String,
    /// The share, in basis points.
    pub basis_points: u16,
}

/// Which names a network accepts for validators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameRule {
    /// The Solar-compatible rule: 1 to 20 of `a-z`, `0-9` and `!@$&_.`, not starting with `_`
    /// and not only digits.
    SolarCompatible,
    /// The IceRoot rule: 1 to 20 lowercase letters `a-z`.
    LowercaseLetters,
}

impl NameRule {
    /// Whether `name` is a validator name under this rule.
    pub fn accepts(self, name: &str) -> bool {
        match self {
            NameRule::SolarCompatible => is_solar_compatible_name(name),
            NameRule::LowercaseLetters => {
                (1..=20).contains(&name.len()) && name.bytes().all(|byte| byte.is_ascii_lowercase())
            }
        }
    }
}

/// Whether `name` passes the Solar-compatible name rule, which every IceRoot name also passes.
pub(crate) fn is_solar_compatible_name(name: &str) -> bool {
    (1..=20).contains(&name.len())
        && !name.starts_with('_')
        && name.bytes().all(|byte| {
            matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'!' | b'@' | b'$' | b'&' | b'_' | b'.')
        })
        && name.bytes().any(|byte| !byte.is_ascii_digit())
}

/// A network's vote rules, as the node enforces them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VoteRules {
    /// The fewest entries of a non-empty vote.
    pub min_entries: u8,
    /// The most entries of a vote.
    pub max_entries: u8,
    /// The largest share of one entry, in basis points.
    pub max_entry_basis_points: u16,
    /// The largest vote contents in bytes: one count byte, then per entry a length byte, the
    /// name and two bytes of basis points.
    pub max_bytes: u16,
    /// Which names are validator names.
    pub names: NameRule,
    /// Whether a validator's account may vote.
    pub validators_may_vote: bool,
}

impl VoteRules {
    /// The Solar-compatible stage: 1 to 53 entries, any share from 1 to 10,000 basis points,
    /// 1,024 bytes, Solar's names, and validators may vote.
    pub const SOLAR_COMPATIBLE: VoteRules = VoteRules {
        min_entries: 1,
        max_entries: 53,
        max_entry_basis_points: TOTAL_BASIS_POINTS,
        max_bytes: 1_024,
        names: NameRule::SolarCompatible,
        validators_may_vote: true,
    };

    /// IceRoot from its genesis: 20 to 53 entries of at most 500 basis points each, 1,280 bytes,
    /// lowercase names, and no vote from a validator's account.
    pub const ICEROOT: VoteRules = VoteRules {
        min_entries: 20,
        max_entries: 53,
        max_entry_basis_points: 500,
        max_bytes: 1_280,
        names: NameRule::LowercaseLetters,
        validators_may_vote: false,
    };
}

/// What is wrong with a vote.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Problem {
    /// The account belongs to a validator, and the rules forbid validators to vote.
    ValidatorAccount,
    /// Fewer entries than the rules require.
    TooFewEntries {
        /// Entries in the vote.
        count: usize,
        /// The fewest allowed.
        minimum: u8,
    },
    /// More entries than the rules allow.
    TooManyEntries {
        /// Entries in the vote.
        count: usize,
        /// The most allowed.
        maximum: u8,
    },
    /// A name that is not a validator name under the rules.
    InvalidName {
        /// The name.
        validator: String,
    },
    /// A validator named twice.
    DuplicateValidator {
        /// The name.
        validator: String,
    },
    /// An entry of zero basis points.
    ZeroShare {
        /// The name.
        validator: String,
    },
    /// An entry above the largest share.
    ShareTooLarge {
        /// The name.
        validator: String,
        /// The entry's share.
        basis_points: u16,
        /// The largest allowed.
        maximum: u16,
    },
    /// Shares that do not add up to 10,000 basis points.
    WrongTotal {
        /// The sum of the shares.
        total: u32,
    },
    /// Vote contents above the size limit.
    TooLarge {
        /// The size of the contents.
        bytes: usize,
        /// The limit.
        maximum: u16,
    },
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Problem::ValidatorAccount => f.write_str("a validator's account cannot vote"),
            Problem::TooFewEntries { count, minimum } => write!(
                f,
                "the vote names {count} validators; a vote names at least {minimum}"
            ),
            Problem::TooManyEntries { count, maximum } => write!(
                f,
                "the vote names {count} validators; a vote names at most {maximum}"
            ),
            Problem::InvalidName { validator } => {
                write!(f, "{validator:?} is not a validator name")
            }
            Problem::DuplicateValidator { validator } => {
                write!(f, "{validator} is named more than once")
            }
            Problem::ZeroShare { validator } => write!(f, "{validator} has a share of zero"),
            Problem::ShareTooLarge {
                validator,
                basis_points,
                maximum,
            } => write!(
                f,
                "{validator} has {}; one validator can have at most {}",
                crate::reason::Percent(u128::from(*basis_points)),
                crate::reason::Percent(u128::from(*maximum)),
            ),
            Problem::WrongTotal { total } => write!(
                f,
                "the shares add up to {}, not 100 %",
                crate::reason::Percent(u128::from(*total))
            ),
            Problem::TooLarge { bytes, maximum } => write!(
                f,
                "the vote takes {bytes} bytes; the limit is {maximum} bytes"
            ),
        }
    }
}

impl Problem {
    /// A stable string for the problem: `validator-account`, `too-few-entries`,
    /// `too-many-entries`, `name`, `duplicate`, `zero-share`, `share-too-large`, `sum` or
    /// `too-large`. Where the core's vote problems have the same meaning, the string is the same.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Problem::ValidatorAccount => "validator-account",
            Problem::TooFewEntries { .. } => "too-few-entries",
            Problem::TooManyEntries { .. } => "too-many-entries",
            Problem::InvalidName { .. } => "name",
            Problem::DuplicateValidator { .. } => "duplicate",
            Problem::ZeroShare { .. } => "zero-share",
            Problem::ShareTooLarge { .. } => "share-too-large",
            Problem::WrongTotal { .. } => "sum",
            Problem::TooLarge { .. } => "too-large",
        }
    }

    /// The problem as a JSON object: `reason` ([`Problem::as_str`]) and its values, `count`,
    /// `minimum`, `maximum`, `validator`, `basisPoints` (a share, or the sum of the shares) or
    /// `bytes`. The keys of each reason are part of the API.
    pub fn details(&self) -> Value {
        let reason = self.as_str();
        match self {
            Problem::ValidatorAccount => json!({ "reason": reason }),
            Problem::TooFewEntries { count, minimum } => {
                json!({ "reason": reason, "count": count, "minimum": minimum })
            }
            Problem::TooManyEntries { count, maximum } => {
                json!({ "reason": reason, "count": count, "maximum": maximum })
            }
            Problem::InvalidName { validator }
            | Problem::DuplicateValidator { validator }
            | Problem::ZeroShare { validator } => {
                json!({ "reason": reason, "validator": validator })
            }
            Problem::ShareTooLarge {
                validator,
                basis_points,
                maximum,
            } => json!({
                "reason": reason,
                "validator": validator,
                "basisPoints": basis_points,
                "maximum": maximum,
            }),
            Problem::WrongTotal { total } => json!({ "reason": reason, "basisPoints": total }),
            Problem::TooLarge { bytes, maximum } => {
                json!({ "reason": reason, "bytes": bytes, "maximum": maximum })
            }
        }
    }
}

/// Check a vote against a network's rules. An empty vote, which removes every vote, is valid
/// unless the account is a validator's and the rules forbid validators to vote.
///
/// The problems come in a fixed order: the voter, the entry count, each entry in turn, the total
/// and the size. The order of the entries does not matter to the node, which keeps a vote in its
/// canonical order (see [`sort_entries`]).
pub fn validate_vote(entries: &[VoteEntry], rules: &VoteRules, voter: Voter) -> Vec<Problem> {
    let mut problems = Vec::new();
    if voter == Voter::Validator && !rules.validators_may_vote {
        problems.push(Problem::ValidatorAccount);
    }
    if entries.is_empty() {
        return problems;
    }
    if entries.len() < usize::from(rules.min_entries) {
        problems.push(Problem::TooFewEntries {
            count: entries.len(),
            minimum: rules.min_entries,
        });
    }
    if entries.len() > usize::from(rules.max_entries) {
        problems.push(Problem::TooManyEntries {
            count: entries.len(),
            maximum: rules.max_entries,
        });
    }
    // Summed in 64 bits and checked for repeats with a set, so that any list, however long, is
    // judged in n log n steps without overflow.
    let mut total: u64 = 0;
    let mut named = std::collections::BTreeSet::new();
    for entry in entries {
        if !rules.names.accepts(&entry.validator) {
            problems.push(Problem::InvalidName {
                validator: entry.validator.clone(),
            });
        }
        if !named.insert(entry.validator.as_str()) {
            problems.push(Problem::DuplicateValidator {
                validator: entry.validator.clone(),
            });
        }
        if entry.basis_points == 0 {
            problems.push(Problem::ZeroShare {
                validator: entry.validator.clone(),
            });
        } else if entry.basis_points > rules.max_entry_basis_points {
            problems.push(Problem::ShareTooLarge {
                validator: entry.validator.clone(),
                basis_points: entry.basis_points,
                maximum: rules.max_entry_basis_points,
            });
        }
        total = total.saturating_add(u64::from(entry.basis_points));
    }
    if total != u64::from(TOTAL_BASIS_POINTS) {
        problems.push(Problem::WrongTotal {
            total: u32::try_from(total).unwrap_or(u32::MAX),
        });
    }
    let bytes = vote_bytes(entries);
    if bytes > usize::from(rules.max_bytes) {
        problems.push(Problem::TooLarge {
            bytes,
            maximum: rules.max_bytes,
        });
    }
    problems
}

/// The size of a vote's contents: `1 + Σ (3 + name bytes)`.
pub fn vote_bytes(entries: &[VoteEntry]) -> usize {
    entries.iter().fold(EMPTY_VOTE_BYTES, |size, entry| {
        size.saturating_add(entry_bytes(&entry.validator))
    })
}

/// The size of an empty vote's contents: the count byte.
pub(crate) const EMPTY_VOTE_BYTES: usize = 1;

/// The size of one entry: a length byte, the name and two bytes of basis points.
pub(crate) fn entry_bytes(validator: &str) -> usize {
    validator.len().saturating_add(3)
}

/// The protocol's canonical order of two entries: larger share first, then names in ascending
/// order of their UTF-16 code units (byte order for every validator name).
pub fn canonical_order(a: &VoteEntry, b: &VoteEntry) -> Ordering {
    canonical_cmp(
        (a.basis_points, &a.validator),
        (b.basis_points, &b.validator),
    )
}

/// [`canonical_order`] over (share, name) pairs.
pub(crate) fn canonical_cmp(a: (u16, &str), b: (u16, &str)) -> Ordering {
    b.0.cmp(&a.0)
        .then_with(|| a.1.encode_utf16().cmp(b.1.encode_utf16()))
}

/// Put entries in the protocol's canonical order (see [`canonical_order`]).
pub fn sort_entries(entries: &mut [VoteEntry]) {
    entries.sort_by(canonical_order);
}

/// Why [`split`] cannot share 10,000 basis points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SplitError {
    /// The number of validators given.
    pub count: usize,
}

impl fmt::Display for SplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "10,000 basis points cannot be shared among {} validators",
            self.count
        )
    }
}

impl std::error::Error for SplitError {}

impl SplitError {
    /// The stable code of the error, as the TypeScript and Go SDKs report it: `InvalidVote`, the
    /// core's code for a vote that cannot be made.
    pub const fn code(&self) -> &'static str {
        "InvalidVote"
    }

    /// The structured details of the error, as a JSON object:
    /// `{ "reason": "too-many-entries", "count": <validators given>, "maximum": 10000 }`, the
    /// details of the core's vote problem of the same name.
    pub fn details(&self) -> Value {
        json!({
            "reason": "too-many-entries",
            "count": self.count,
            "maximum": TOTAL_BASIS_POINTS,
        })
    }
}

/// Share 10,000 basis points among validators in whole basis points, as evenly as possible: the
/// remainder goes one basis point each to the first validators of the list. The entries come in
/// the canonical order. No validators give an empty vote; more than 10,000 are refused.
///
/// Twenty validators get 500 basis points each; 53 get 189 (the first 36) or 188.
pub fn split<S: AsRef<str>>(validators: &[S]) -> Result<Vec<VoteEntry>, SplitError> {
    let count = validators.len();
    let Ok(n) = u16::try_from(count) else {
        return Err(SplitError { count });
    };
    if n > TOTAL_BASIS_POINTS {
        return Err(SplitError { count });
    }
    if n == 0 {
        return Ok(Vec::new());
    }
    let share = TOTAL_BASIS_POINTS / n;
    let extra = usize::from(TOTAL_BASIS_POINTS % n);
    let mut entries: Vec<VoteEntry> = validators
        .iter()
        .enumerate()
        .map(|(index, validator)| VoteEntry {
            validator: validator.as_ref().to_owned(),
            basis_points: if index < extra { share + 1 } else { share },
        })
        .collect();
    sort_entries(&mut entries);
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(count: usize) -> Vec<String> {
        (0..count)
            .map(|i| format!("v{}", char::from(b'a' + u8::try_from(i % 26).unwrap())))
            .enumerate()
            .map(|(i, name)| format!("{name}{i}"))
            .collect()
    }

    #[test]
    fn split_shares() {
        let twenty = split(&names(20)).unwrap();
        assert!(twenty.iter().all(|entry| entry.basis_points == 500));
        let all = split(&names(53)).unwrap();
        assert_eq!(all.iter().filter(|e| e.basis_points == 189).count(), 36);
        assert_eq!(all.iter().filter(|e| e.basis_points == 188).count(), 17);
        let three = split(&["c", "b", "a"]).unwrap();
        assert_eq!(
            three,
            vec![
                VoteEntry {
                    validator: "c".into(),
                    basis_points: 3_334
                },
                VoteEntry {
                    validator: "a".into(),
                    basis_points: 3_333
                },
                VoteEntry {
                    validator: "b".into(),
                    basis_points: 3_333
                },
            ]
        );
        for count in [1, 7, 20, 21, 52, 53, 9_999, 10_000] {
            let entries = split(&names(count)).unwrap();
            let total: u32 = entries.iter().map(|e| u32::from(e.basis_points)).sum();
            assert_eq!(total, 10_000);
        }
        assert!(split::<&str>(&[]).unwrap().is_empty());
        assert_eq!(split(&names(10_001)), Err(SplitError { count: 10_001 }));
    }

    #[test]
    fn rules() {
        let vote = split(&names(20)).unwrap();
        assert!(validate_vote(&vote, &VoteRules::SOLAR_COMPATIBLE, Voter::Ordinary).is_empty());
        // Names with digits are Solar-compatible, not IceRoot names.
        let problems = validate_vote(&vote, &VoteRules::ICEROOT, Voter::Ordinary);
        assert_eq!(problems.len(), 20);
        assert!(
            problems
                .iter()
                .all(|p| matches!(p, Problem::InvalidName { .. }))
        );

        let letters: Vec<String> = (0..20)
            .map(|i| {
                let a = char::from(b'a' + u8::try_from(i).unwrap());
                format!("val{a}")
            })
            .collect();
        let vote = split(&letters).unwrap();
        assert!(validate_vote(&vote, &VoteRules::ICEROOT, Voter::Ordinary).is_empty());
        assert_eq!(
            validate_vote(&vote, &VoteRules::ICEROOT, Voter::Validator),
            vec![Problem::ValidatorAccount]
        );
        assert!(validate_vote(&vote, &VoteRules::SOLAR_COMPATIBLE, Voter::Validator).is_empty());
        assert_eq!(
            validate_vote(&[], &VoteRules::ICEROOT, Voter::Validator),
            vec![Problem::ValidatorAccount]
        );
        assert!(validate_vote(&[], &VoteRules::ICEROOT, Voter::Ordinary).is_empty());

        let short = split(&letters[..19]).unwrap();
        let problems = validate_vote(&short, &VoteRules::ICEROOT, Voter::Ordinary);
        assert_eq!(
            problems[0],
            Problem::TooFewEntries {
                count: 19,
                minimum: 20
            }
        );
        assert!(
            problems
                .iter()
                .skip(1)
                .all(|p| matches!(p, Problem::ShareTooLarge { maximum: 500, .. }))
        );

        let mut odd = vote.clone();
        odd[0].basis_points = 0;
        odd[1].validator = odd[2].validator.clone();
        let problems = validate_vote(&odd, &VoteRules::ICEROOT, Voter::Ordinary);
        assert_eq!(
            problems,
            vec![
                Problem::ZeroShare {
                    validator: odd[0].validator.clone()
                },
                Problem::DuplicateValidator {
                    validator: odd[2].validator.clone()
                },
                Problem::WrongTotal { total: 9_500 },
            ]
        );
    }

    #[test]
    fn size_limit() {
        let long: Vec<String> = (0..53)
            .map(|i| {
                let a = char::from(b'a' + u8::try_from(i % 26).unwrap());
                let b = char::from(b'a' + u8::try_from(i / 26).unwrap());
                format!("{a}{b}{}", "x".repeat(18))
            })
            .collect();
        let vote = split(&long).unwrap();
        assert_eq!(vote_bytes(&vote), 1 + 53 * 23);
        assert!(validate_vote(&vote, &VoteRules::ICEROOT, Voter::Ordinary).is_empty());
        assert_eq!(
            validate_vote(&vote, &VoteRules::SOLAR_COMPATIBLE, Voter::Ordinary),
            vec![Problem::TooLarge {
                bytes: 1_220,
                maximum: 1_024
            }]
        );
    }

    #[test]
    fn names_rules() {
        for name in ["a", "genesis_1", "a.b", "x!@$&", "12a"] {
            assert!(NameRule::SolarCompatible.accepts(name), "{name}");
        }
        for name in ["", "_a", "123", "A", "a-b", "abcdefghijklmnopqrstu"] {
            assert!(!NameRule::SolarCompatible.accepts(name), "{name}");
        }
        assert!(NameRule::LowercaseLetters.accepts("abcdefghijklmnopqrst"));
        for name in ["", "genesis_1", "a1", "abcdefghijklmnopqrstu", "é"] {
            assert!(!NameRule::LowercaseLetters.accepts(name), "{name}");
        }
    }

    #[test]
    fn order() {
        let mut entries = vec![
            VoteEntry {
                validator: "b2".into(),
                basis_points: 2_500,
            },
            VoteEntry {
                validator: "a9".into(),
                basis_points: 2_500,
            },
            VoteEntry {
                validator: "b10".into(),
                basis_points: 2_500,
            },
            VoteEntry {
                validator: "a10".into(),
                basis_points: 2_500,
            },
        ];
        sort_entries(&mut entries);
        let order: Vec<&str> = entries.iter().map(|e| e.validator.as_str()).collect();
        assert_eq!(order, ["a10", "a9", "b10", "b2"]);
    }
}
