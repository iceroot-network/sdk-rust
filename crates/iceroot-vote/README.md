# iceroot-vote

Vote selection for IceRoot wallets. A vote names at least 20 validators with at most 5 % of the account's vote weight each, so wallets offer to fill a vote automatically in one of four modes, or leave it to the holder:

| Mode | Eligible validators | Weight in the draw |
|---|---|---|
| Diversity (recommended) | Ranked within the seats or the next 10 ranks (1 to 63 with 53 seats), not resigned, no jailing or equivocation in the last 30 days, at least 95 % of assigned slots forged when there is a production record | Equal, then before each draw divided by one plus the earlier picks in the same rank band, and raised for each declared operator, hosting provider and region that fewer earlier picks share than the common one, to at most twice the weight of a validator whose declarations are all common (see below) |
| Reliability | At least 7 days seated in the 30-day window, at least 95 % of assigned slots forged, no jailing or equivocation in the window | `1,000,000 × assigned / (assigned + 100 × missed)`: missing 1 % of the slots halves it |
| Maximum Rewards | Seated, payouts measured by the indexer (never declared rates), no jailing or equivocation in the window; at most two picks per declared operator | The square of the payout per unit of vote weight as a share of the best payer's, counted in 10^15 parts, so that one very large payer does not flatten everyone else's weight: behind a payer a billion times above them, the others still have a million parts or more. The review screen shows the share in parts per million |
| Support Newcomers | Ranked within the last 10 seats or the 20 ranks below the cutoff (44 to 73 with 53 seats), registered for at least 7 days, complete declarations, no penalty ever, at least 95 % of assigned slots forged when there is an earlier record; at most two picks per declared operator | `100,000 / (10 + distance from the cutoff)`, from 3,448 twenty ranks below to 10,000 at the cutoff |
| Manual | No selection: the holder names the validators and `validate_vote` checks the vote | |

For the operator caps of Maximum Rewards and Support Newcomers, validators that declare no operator form one group of their own. Ranks are taken as the snapshot gives them, and a validator without a rank is outside the Diversity and Support Newcomers pools. Past payouts are not a promise.

## Bounded pools

Anyone can register validators for the registration fee, so a party could register many and crowd a draw. Rank follows vote weight, so validators registered in bulk without votes rank below every validator that has votes, and the two modes that take validators without a seat draw from a fixed number of ranks:

- **Diversity** draws only from the seated validators and the next 10 by rank. Beside 53 seated validators, 100 standby validators without votes took 12 of 20 picks from an open pool, or 13.6 when each invented unique declarations. Now 20, 53 or 100 of them give exactly the same selections and take 2.7 of 20 picks, or 3.7 when each invents unique declarations.
- **Support Newcomers** draws only from the last 10 seats and the 20 ranks below the cutoff, with at most two picks per declared operator, top-ups included. Beside 53 seated validators, a party of 30 validators ranked 54 to 83 took 13.8 of 20 picks from an open pool; under one operator name it now gets 2. Under a different name for each validator it still takes 12.7: declarations are statements, so the operator cap can be dodged with different names, and the bound only keeps that share from growing with the party's size. The bound also leaves out honest newcomers ranked further down, who used to dilute such a party's share.

## Diversity: rank bands first, declarations second

Declarations are the validators' own statements, not verified facts, so Diversity spreads a vote over what the chain shows first, and over what validators declare second, with a bounded effect:

- **Rank bands.** Diversity's pool, in rank order (then by name), is split into `⌈n / 10⌉` bands whose sizes differ by at most one: the validator at position `i`, from 0, is in band `⌊i × bands / n⌋`. With 63 validators, the most there can be with 53 seats, that is seven bands of 9, never six of 10 and a last band of 3 whose few members would be picked more often than the rest. These products are computed in 64-bit integers, never in the platform's `usize`, so 32-bit WebAssembly builds and native builds give the same bands for any pool. Before each draw a candidate's weight is `⌊2^64 / (1 + r)⌋`, where `r` counts the earlier picks in its band.
- **Declarations.** In each of three dimensions (declared operator, declared hosting provider, and region from the declared country), the *common* value is the declared value that the most earlier picks share, `m` of them. A candidate whose value `s` earlier picks share has a bonus of `(m - s) / m` in that dimension: 0 for a common value, 1 for a value no earlier pick shares. An undeclared value counts as common, and until an earlier pick declares a value every value is common. The weight is then multiplied by `1 + (operator bonus + hosting bonus + region bonus) / 3`, as an exact fraction, and rounded down once:

  ```text
  weight = ⌊ ⌊2^64 / (1 + r)⌋ × (1 + (o + h + g) / 3) ⌋
  ```

So a candidate weighs at most twice as much as a candidate in the same rank band whose declared operator, hosting provider and region are all common or undeclared. Inventing unique values gains at most that factor of two, and declaring nothing costs at most the same, so neither pays off much: among 60 validators on common infrastructure, 5 that declare invented unique values are picked by 39 % of holders against 30 % for the rest (with an unbounded bonus it was 99 % against 25 %), and among 70 validators that declare nothing and 10 that declare unique values, the silent ones are picked by 24 % of holders against 25 % for a uniform draw (it was 14 %). The worst case for silence is a pool where every other validator invents unique values: 6 silent validators among 60 such are picked by 19 % of holders, against 31 % for the others and 30 % for a uniform draw. Declaring one's real values is never worse than declaring nothing, since a common value and an undeclared one count the same.

## How a selection is drawn

- **Seeded per account.** `seed = SHA-256("iceroot/vote-select/v1" ‖ u32 length ‖ account address ‖ u32 length ‖ mode id ‖ u64 election height ‖ u32 draw)`, integers big-endian. The election height is the snapshot's height rounded down to a multiple of the election interval, 24 rounds of the snapshot's seats (24 × 53 = 1,272 blocks on IceRoot, about 2.8 hours), so every snapshot within one interval gives an account the same draw and whoever supplies the snapshot cannot steer the picks by choosing among recent heights. Block `i` of the stream is `SHA-256(seed ‖ u64 i)`, read as two 128-bit numbers.
- **Weighted, without replacement.** Candidates are in name order. Each draw takes a number below the total weight from the stream (by rejection, so it is uniform) and picks the candidate whose running sum first exceeds it.
- **Top-up.** When a mode runs out of eligible validators, the rest is drawn from Diversity's pool, and each such pick and the selection say so. A top-up of Maximum Rewards or Support Newcomers still gives no declared operator more than two picks in all. Diversity's pool is bounded too, so a capped mode asked for many picks can run out: with 53 seated validators run three to an operator and 30 more ranked below them, each with an operator of its own, Maximum Rewards gives at most 46 picks (36 of its own and 10 top-ups from ranks 54 to 63), and `select` refuses a request for more with `NotEnoughValidators`.
- **Within the vote rules.** A request carries the network's vote rules: `VoteRules::ICEROOT` by default (at most 53 entries and 1,280 bytes), `VoteRules::SOLAR_COMPATIBLE` on the Solar-compatible stage (1,024 bytes). The selection keeps the longest start of the draw that fits both limits, so it has fewer picks than requested when the names are long: 53 names of 20 letters take 1,220 bytes, and 44 of them fit in 1,024. It is then the same selection as one that asks for that many, and `size_notice` gives the sentence to show. The draw does not depend on the rules, so a long name has the same chance as a short one. When fewer than 20 picks fit, `select` refuses with `DoesNotFit`.
- **Checked.** Before it returns a selection, `select` checks its vote with `validate_vote` against the same rules, so every name passes the rules' name rule and every share is within their largest share. A selection that fails is refused with `BreaksRules`, which lists the problems: it means the rules do not fit the snapshot (IceRoot's lowercase names against the Solar-compatible devnet, for example) or allow smaller shares than the picks give.
- **Shares.** 10,000 basis points split evenly in whole basis points, one extra to each of the first picks drawn while the remainder lasts; entries in the protocol's canonical order (larger share first, then name). 20 picks get 500 each; 53 get 189 or 188.
- **Reproducible.** The same snapshot, account, mode, number of picks, vote rules, draw number and library version (`iceroot-vote/1`) give the same selection. "Draw again" increments the draw number.
- **Explained.** Every pick carries its reasons (criteria met, values, groups, and its chance at the step it was drawn), each with a plain English sentence for the review screen. Declared operator and hosting names appear in quotes, as the validator's own statements, with control and invisible characters escaped.
- **Never recast.** `check` only reports picks that no longer meet their criteria. Any new selection is the holder's to review and sign.

Validator accounts cannot vote: `select` refuses an account that belongs to a validator, unless it resigned for good.

## Data

Everything is a pure function of a `VoteSnapshot`: no I/O, no clock, no floating point, and one dependency (`sha2`). An indexer supplies windowed production, penalties, declarations and measured payouts. `VoteSnapshot::from_relay` builds a snapshot from a node's relay data, which has only lifetime counters and no declarations, payouts or penalties; it is marked `relay-approximate`, and every selection made from it records that. On such a snapshot Diversity works on rank bands only, Reliability needs a chain with 7 days of seated history, and Maximum Rewards and Support Newcomers top up from Diversity.

## Example

```rust
use iceroot_vote::{Mode, SelectRequest, VoteRules, Voter, check, select, validate_vote};

// IceRoot's vote rules by default; set `rules` to VoteRules::SOLAR_COMPATIBLE on that stage.
let selection = select(&snapshot, &SelectRequest::new(Mode::Diversity, &address))?;
for pick in &selection.entries {
    println!("{} {}", pick.validator, pick.basis_points);
    for reason in &pick.reasons {
        println!("  {reason}");
    }
}
for notice in [selection.top_up_notice(), selection.size_notice()].into_iter().flatten() {
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

- a property test: 10,000 random snapshots and vote rules, each with a selection attempted in all four modes; every selection is a valid vote under its rules, the longest start of its draw that fits them, the same as under rules that accept any name and share, reproducible, drawn from the right pools, within the rank bounds of the pools and the operator caps, within the Diversity weight bound at every pick, and meets its criteria under `check`, and every refusal for names or shares lists exactly what `validate_vote` finds;
- reproducibility vectors (`tests/data/select-v1.jsonl`): fixture, account, mode, count, draw and vote rules to the exact selection, some with a tighter size limit;
- each mode's criteria and weights on a synthetic snapshot of 80 validators (`tests/data/synthetic-80.json`), against pools, weights and rank bands computed independently from the rules above (`synthetic-80.expected.json`);
- attempts to game the draw, each with bounds on pick frequencies over 2,000 selections: validators that invent unique declarations, a crowd that declares nothing, a few that declare nothing among validators that all invent unique values, a small last rank band, one very large payer (up to a billion times the next best), floods of 20, 53 and 100 standby validators without votes that declare nothing or invent unique values, and a party of 30 validators ranked just below the cutoff under one operator name and under different names;
- the size limits of both stages, with long names, and rules whose name rule or largest share a selection breaks;
- a devnet-shaped snapshot from relay data (`tests/data/devnet-relay.json`), including a fresh chain where Reliability tops up;
- top-up and `check` cases.

The fixtures use the JSON shape of the TypeScript API (camelCase, 64- and 128-bit integers as decimal strings), so other bindings can run the same vectors.
