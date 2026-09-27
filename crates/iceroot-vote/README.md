# iceroot-vote

Vote selection for IceRoot wallets. A vote names at least 20 validators with at most 5 % of the account's vote weight each, so wallets offer to fill a vote automatically in one of four modes, or leave it to the holder:

| Mode | Eligible validators | Weight in the draw |
|---|---|---|
| Diversity (recommended) | Not resigned, no jailing or equivocation in the last 30 days, at least 95 % of assigned slots forged when there is a production record | Equal, divided before each draw by `(1 + a)(1 + b)(1 + c)(1 + d)`, where `a` to `d` count the earlier picks with the same declared operator, hosting provider, region (from the declared country) and rank band (1 to 10, 11 to 20, ...) |
| Reliability | At least 7 days seated in the 30-day window, at least 95 % of assigned slots forged, no jailing or equivocation in the window | `1,000,000 × assigned / (assigned + 100 × missed)`: missing 1 % of the slots halves it |
| Maximum Rewards | Seated, payouts measured by the indexer (never declared rates), no jailing or equivocation in the window; at most two picks per declared operator | The square of the payout per unit of vote weight as a share of the best payer's, in basis points |
| Support Newcomers | Ranked within the last 10 seats or below the cutoff, registered for at least 7 days, complete declarations, no penalty ever, at least 95 % of assigned slots forged when there is an earlier record | `100,000 / (10 + distance from the cutoff)` |
| Manual | No selection: the holder names the validators and `validate_vote` checks the vote | |

Validators that declare no operator (or hosting provider, or country) form one group of their own. Past payouts are not a promise.

## How a selection is drawn

- **Seeded per account.** `seed = SHA-256("iceroot/vote-select/v1" ‖ u32 length ‖ account address ‖ u32 length ‖ mode id ‖ u64 snapshot height ‖ u32 draw)`, integers big-endian. Block `i` of the stream is `SHA-256(seed ‖ u64 i)`, read as two 128-bit numbers.
- **Weighted, without replacement.** Candidates are in name order. Each draw takes a number below the total weight from the stream (by rejection, so it is uniform) and picks the candidate whose running sum first exceeds it.
- **Top-up.** When a mode runs out of eligible validators, the rest is drawn from Diversity's pool, and each such pick and the selection say so.
- **Shares.** 10,000 basis points split evenly in whole basis points, one extra to each of the first picks drawn while the remainder lasts; entries in the protocol's canonical order (larger share first, then name). 20 picks get 500 each; 53 get 189 or 188.
- **Reproducible.** The same snapshot, account, mode, number of picks, draw number and library version (`iceroot-vote/1`) give the same selection. "Draw again" increments the draw number.
- **Explained.** Every pick carries its reasons (criteria met, values, groups, and its chance at the step it was drawn), each with a plain English sentence for the review screen.
- **Never recast.** `check` only reports picks that no longer meet their criteria. Any new selection is the holder's to review and sign.

Validator accounts cannot vote: `select` refuses an account that belongs to a validator, unless it resigned for good.

## Data

Everything is a pure function of a `VoteSnapshot`: no I/O, no clock, no floating point, and one dependency (`sha2`). An indexer supplies windowed production, penalties, declarations and measured payouts. `VoteSnapshot::from_relay` builds a snapshot from a node's relay data, which has only lifetime counters and no declarations, payouts or penalties; it is marked `relay-approximate`, and every selection made from it records that. On such a snapshot Diversity works on rank bands only, Reliability needs a chain with 7 days of seated history, and Maximum Rewards and Support Newcomers top up from Diversity.

## Example

```rust
use iceroot_vote::{Mode, SelectRequest, VoteRules, Voter, check, select, validate_vote};

let selection = select(&snapshot, &SelectRequest::new(Mode::Diversity, &address))?;
for pick in &selection.entries {
    println!("{} {}", pick.validator, pick.basis_points);
    for reason in &pick.reasons {
        println!("  {reason}");
    }
}
if let Some(notice) = selection.top_up_notice() {
    println!("{notice}");
}
assert!(validate_vote(&selection.vote(), &VoteRules::ICEROOT, Voter::Ordinary).is_empty());

// Later, with newer data: report, never recast.
for finding in check(&selection, &newer_snapshot)? {
    if !finding.still_meets {
        println!("{}: {}", finding.validator, finding.why());
    }
}
```

## Tests

`cargo test -p iceroot-vote` runs:

- a property test: 10,000 random snapshots, each with a selection attempted in all four modes; every selection is a valid vote, reproducible, drawn from the right pools, and meets its criteria under `check`;
- reproducibility vectors (`tests/data/select-v1.jsonl`): fixture, account, mode, count and draw to the exact selection;
- each mode's criteria and weights on a synthetic snapshot of 80 validators (`tests/data/synthetic-80.json`), against pools and weights computed independently from the criteria above (`synthetic-80.expected.json`);
- a devnet-shaped snapshot from relay data (`tests/data/devnet-relay.json`), including a fresh chain where Reliability tops up;
- top-up and `check` cases.

The fixtures use the JSON shape of the TypeScript API (camelCase, 64- and 128-bit integers as decimal strings), so other bindings can run the same vectors.
