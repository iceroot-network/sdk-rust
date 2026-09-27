//! The four vote modes.

use core::fmt;

/// A vote mode: the preference an automatic selection follows.
///
/// Manual voting has no mode: the holder names the validators, and the wallet checks the vote with
/// [`validate_vote`](crate::validate_vote) only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Mode {
    /// The recommended default: spread the vote across declared operators, hosting providers,
    /// regions and rank bands, among validators in good health.
    Diversity,
    /// Favour validators with a strong record over the 30-day window: slots forged against slots
    /// assigned, with no jailing or equivocation, after at least 7 days of seated history.
    Reliability,
    /// Favour validators with the highest measured payouts per unit of vote weight, at most two
    /// picks per declared operator.
    MaximumRewards,
    /// Favour healthy validators near or below the seat cutoff: registered for at least 7 days,
    /// with complete declarations and no penalties.
    SupportNewcomers,
}

impl Mode {
    /// Every mode, Diversity first.
    pub const ALL: [Mode; 4] = [
        Mode::Diversity,
        Mode::Reliability,
        Mode::MaximumRewards,
        Mode::SupportNewcomers,
    ];

    /// The mode's stable identifier, as used in the selection seed and in the TypeScript API:
    /// `diversity`, `reliability`, `maximum-rewards` or `support-newcomers`.
    pub const fn id(self) -> &'static str {
        match self {
            Mode::Diversity => "diversity",
            Mode::Reliability => "reliability",
            Mode::MaximumRewards => "maximum-rewards",
            Mode::SupportNewcomers => "support-newcomers",
        }
    }

    /// The mode for a stable identifier (see [`Mode::id`]).
    pub fn from_id(id: &str) -> Option<Mode> {
        Mode::ALL.into_iter().find(|mode| mode.id() == id)
    }

    /// The mode's name as wallets show it, for example `Maximum Rewards`.
    pub const fn name(self) -> &'static str {
        match self {
            Mode::Diversity => "Diversity",
            Mode::Reliability => "Reliability",
            Mode::MaximumRewards => "Maximum Rewards",
            Mode::SupportNewcomers => "Support Newcomers",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_round_trip() {
        for mode in Mode::ALL {
            assert_eq!(Mode::from_id(mode.id()), Some(mode));
        }
        assert_eq!(Mode::from_id("manual"), None);
        assert_eq!(Mode::from_id("Diversity"), None);
        assert_eq!(Mode::MaximumRewards.to_string(), "Maximum Rewards");
    }
}
