//! Vote selection for IceRoot wallets.
//!
//! A vote names at least 20 validators with at most 500 basis points each, so wallets offer to
//! fill a vote in one of four modes, or leave it to the holder:
//!
//! - [`Mode::Diversity`], the recommended default, spreads the vote across rank bands first and
//!   declared operators, hosting providers and regions second, among the seated validators and
//!   the next 10 by rank that are in good health; declarations can at most double a validator's
//!   weight, so invented values buy little;
//! - [`Mode::Reliability`] favours validators with a strong record over a rolling 30-day window,
//!   from chain data alone, after at least 7 days of seated history;
//! - [`Mode::MaximumRewards`] favours the highest measured payouts per unit of vote weight, never
//!   declared rates, with at most two picks per declared operator;
//! - [`Mode::SupportNewcomers`] favours healthy validators within the last 10 seats or the 20
//!   ranks below the cutoff, registered for at least 7 days, with complete declarations and no
//!   penalties, with at most two picks per declared operator;
//! - Manual voting has no mode: the holder names the validators, and [`validate_vote`] checks the
//!   vote against the network's rules.
//!
//! Each mode draws its picks from its eligible pool, weighted by score and seeded per account
//! ([`seed`]), so holders who choose the same mode do not all vote for the same validators, and
//! anyone with the same data reproduces a selection exactly. The pools are bounded by rank, which
//! follows vote weight, so validators registered in bulk without votes cannot crowd a draw. A mode
//! whose pool is too small for the requested number of picks tops up from Diversity and says so,
//! and a selection keeps within the network's [`VoteRules`] (at most 1,280 bytes from IceRoot's
//! genesis, 1,024 on the Solar-compatible stage), with fewer picks when long names need it. Every
//! pick carries its [`Reason`]s for the review screen. The library never recasts a vote: [`check`]
//! only reports the picks that no longer meet their criteria, and any new selection is the holder's
//! to review and sign.
//!
//! Everything is a pure function of a [`VoteSnapshot`]: no I/O, no clock, no floating point.
//! [`VoteSnapshot::from_relay`] builds a snapshot from a node's relay data, which has only
//! lifetime counters, and marks it [`SnapshotSource::RelayApproximate`]; an indexer supplies
//! windowed production, penalties, declarations and measured payouts.
//!
//! ```
//! use iceroot_vote::{Mode, SelectRequest, VoteRules, Voter, select, validate_vote};
//! # use iceroot_vote::{SnapshotSource, ValidatorRecord, ValidatorStatus, VoteSnapshot};
//! # let records = (0..30u32)
//! #     .map(|i| ValidatorRecord {
//! #         name: format!("val{}", char::from(b'a' + u8::try_from(i % 26).unwrap()))
//! #             + &"z".repeat(usize::try_from(i / 26).unwrap()),
//! #         address: format!("addr-{i}"),
//! #         rank: Some(i + 1),
//! #         seated: true,
//! #         status: ValidatorStatus::Active,
//! #         registered_height: Some(1),
//! #         seated_days_in_window: Some(30),
//! #         vote_weight: 1_000,
//! #         voters: 3,
//! #         production: None,
//! #         penalties: None,
//! #         declarations: None,
//! #         payouts: None,
//! #         self_funded_weight_bp: None,
//! #     })
//! #     .collect();
//! # let snapshot = VoteSnapshot {
//! #     height: 1_000_000,
//! #     window_days: 30,
//! #     seats: 53,
//! #     block_time_seconds: 8,
//! #     source: SnapshotSource::Indexer,
//! #     records,
//! # };
//! let selection = select(&snapshot, &SelectRequest::new(Mode::Diversity, "holder-address"))?;
//! assert_eq!(selection.entries.len(), 20);
//! for pick in &selection.entries {
//!     assert_eq!(pick.basis_points, 500);
//!     for reason in &pick.reasons {
//!         let _line = reason.to_string(); // shown on the review screen
//!     }
//! }
//! assert!(validate_vote(&selection.vote(), &VoteRules::ICEROOT, Voter::Ordinary).is_empty());
//! # Ok::<(), iceroot_vote::SelectError>(())
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::float_arithmetic, clippy::float_cmp, clippy::float_cmp_const)]

mod check;
mod mode;
mod reason;
mod region;
mod rules;
mod sample;
mod score;
mod select;
mod snapshot;

pub use check::{Finding, check};
pub use mode::Mode;
pub use reason::{Dimension, Reason, Shortfall};
pub use region::Region;
pub use rules::{
    NameRule, Problem, SplitError, TOTAL_BASIS_POINTS, VoteEntry, VoteRules, canonical_order,
    sort_entries, split, validate_vote, vote_bytes,
};
pub use sample::{SEED_TAG, seed};
pub use score::{
    Candidate, DIVERSITY_RANKS_BELOW_CUTOFF, MAX_PICKS_PER_OPERATOR, MIN_PRODUCTION_BP,
    MIN_REGISTERED_DAYS, MIN_SEATED_DAYS, NEAR_CUTOFF_SEATS, NEWCOMER_RANKS_BELOW_CUTOFF,
    RANK_BAND_SIZE, evaluate,
};
pub use select::{
    DEFAULT_PICKS, LIBRARY_VERSION, MAX_PICKS, MIN_PICKS, Pick, PickSource, SelectError,
    SelectRequest, Selection, select,
};
pub use snapshot::{
    Declarations, ELECTION_INTERVAL_ROUNDS, Payouts, Penalties, Production, RelaySnapshot,
    RelayValidator, Resignation, SnapshotError, SnapshotSource, ValidatorRecord, ValidatorStatus,
    VoteSnapshot, Voter, WINDOW_DAYS,
};
