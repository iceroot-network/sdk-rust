//! Checking an earlier selection against newer data.

use crate::mode::Mode;
use crate::reason::{Reason, Shortfall};
use crate::score::{MAX_PICKS_PER_OPERATOR, candidates, declared_key};
use crate::select::{Pick, PickSource, Selection};
use crate::snapshot::{SnapshotError, VoteSnapshot};

/// Whether one pick of a selection still meets its criteria.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Finding {
    /// The validator's name.
    pub validator: String,
    /// Whether the pick still meets its criteria.
    pub still_meets: bool,
    /// The criteria it meets.
    pub reasons: Vec<Reason>,
    /// The criteria it no longer meets; empty when `still_meets`.
    pub shortfalls: Vec<Shortfall>,
}

impl Finding {
    /// One plain English line: what it no longer meets, or that it still meets its criteria.
    pub fn why(&self) -> String {
        if self.still_meets {
            "Still meets its criteria".to_owned()
        } else {
            self.shortfalls
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        }
    }
}

/// Check each pick of a selection against a newer snapshot, in the selection's order. Nothing
/// is changed and nothing is drawn: the wallet tells the holder which picks no longer meet their
/// criteria and may offer a new selection, which the holder reviews and signs. The library
/// never recasts a vote.
///
/// A pick drawn from the mode's pool is judged by the selection's mode, a top-up pick by
/// Diversity, and a pick the holder chose only by whether the validator is still registered and
/// has not resigned. For Maximum Rewards and Support Newcomers, picks beyond two per operator (by
/// current declarations, in draw order) no longer meet the cap: among the mode's picks,
/// validators that declare no operator count as one operator; top-up picks count only towards a
/// declared operator's two.
pub fn check(
    selection: &Selection,
    snapshot: &VoteSnapshot,
) -> Result<Vec<Finding>, SnapshotError> {
    snapshot.validate()?;
    let mode_candidates = candidates(snapshot, selection.mode);
    let diversity_candidates = candidates(snapshot, Mode::Diversity);
    let mut findings: Vec<Finding> = Vec::with_capacity(selection.entries.len());
    for pick in &selection.entries {
        let Some(record) = snapshot.record(&pick.validator) else {
            findings.push(Finding {
                validator: pick.validator.clone(),
                still_meets: false,
                reasons: Vec::new(),
                shortfalls: vec![Shortfall::NotInSnapshot],
            });
            continue;
        };
        let pool = match pick.source {
            PickSource::Mode => &mode_candidates,
            PickSource::TopUp => &diversity_candidates,
            PickSource::Holder => {
                // Only the registration: still there (above) and not resigned.
                let shortfalls = if record.status.is_resigned() {
                    vec![Shortfall::Resigned {
                        status: record.status,
                    }]
                } else {
                    Vec::new()
                };
                findings.push(Finding {
                    validator: pick.validator.clone(),
                    still_meets: shortfalls.is_empty(),
                    reasons: vec![
                        Reason::ChosenByHolder,
                        Reason::Status {
                            status: record.status,
                            rank: record.rank,
                            seated: record.seated,
                        },
                    ],
                    shortfalls,
                });
                continue;
            }
        };
        let judged = pool
            .iter()
            .find(|candidate| candidate.validator == pick.validator);
        let (reasons, shortfalls) = judged.map_or_else(
            || (Vec::new(), vec![Shortfall::NotInSnapshot]),
            |c| (c.reasons.clone(), c.shortfalls.clone()),
        );
        findings.push(Finding {
            validator: pick.validator.clone(),
            still_meets: shortfalls.is_empty(),
            reasons,
            shortfalls,
        });
    }
    if selection.mode.caps_operators() {
        apply_operator_cap(selection, snapshot, &mut findings);
    }
    Ok(findings)
}

/// Mark picks beyond the cap of their operator, in draw order, as `select` applies it: mode picks
/// count towards their operator group, the group of validators that declare no operator
/// included; top-up picks count only towards a declared operator.
fn apply_operator_cap(selection: &Selection, snapshot: &VoteSnapshot, findings: &mut [Finding]) {
    let mut drawn: Vec<(&Pick, &mut Finding)> = selection
        .entries
        .iter()
        .zip(findings.iter_mut())
        .filter(|(pick, _)| pick.source != PickSource::Holder)
        .collect();
    drawn.sort_by_key(|(pick, _)| pick.step);
    let mut counts: Vec<(Option<String>, u32)> = Vec::new();
    for (pick, finding) in drawn {
        let Some(record) = snapshot.record(&pick.validator) else {
            continue;
        };
        let declared = record
            .declarations
            .as_ref()
            .and_then(|d| d.operator.as_ref());
        let (key, label) = declared_key(declared);
        if pick.source == PickSource::TopUp && key.is_none() {
            continue;
        }
        let count = match counts.iter_mut().find(|(k, _)| *k == key) {
            Some((_, n)) => {
                *n += 1;
                *n
            }
            None => {
                counts.push((key, 1));
                1
            }
        };
        if count > MAX_PICKS_PER_OPERATOR {
            finding.still_meets = false;
            finding.shortfalls.push(Shortfall::OperatorCap {
                operator: label,
                maximum: MAX_PICKS_PER_OPERATOR,
            });
        }
    }
}
