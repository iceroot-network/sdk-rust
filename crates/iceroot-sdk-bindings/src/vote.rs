//! The vote selection library: the four vote modes, the network's vote rules, and the check of an
//! earlier selection against newer data.
//!
//! Every function is a pure function of its arguments, as in the library itself. Values cross the
//! boundary as JSON in the shape of the TypeScript API: camelCase fields, and the 64- and 128-bit
//! integers a JavaScript number cannot hold (heights, vote weights, payouts, draw weights) as
//! decimal strings. The library's refusals keep their stable codes and details
//! (`InvalidPickCount`, `ValidatorCannotVote`, `InvalidSnapshot`, `NotEnoughValidators`,
//! `DoesNotFit`, `BreaksRules`, and the core's `InvalidVote` for a split that cannot be made); a
//! value of the wrong shape is `InvalidArgument`.

use iceroot_sdk::Chain;
use iceroot_sdk::api::{
    Earnings, Production as ApiProduction, ValidatorInfo, ValidatorStatus as ApiStatus,
};
use iceroot_sdk::vote::{
    self, Candidate, Declarations, Dimension, Finding, LIBRARY_VERSION, Mode, NameRule, Payouts,
    Penalties, Pick, PickSource, Problem, Production, Reason, RelayValidator, SelectError,
    SelectRequest, Selection, Shortfall, SnapshotError, SnapshotSource, SplitError,
    ValidatorRecord, ValidatorStatus, VoteEntry, VoteRules, VoteSnapshot, Voter,
};
use iceroot_sdk::voting;
use serde_json::{Map, Value};

use crate::error::{BindingError, Result};
use crate::write::Json;

impl From<SelectError> for BindingError {
    fn from(error: SelectError) -> BindingError {
        BindingError::with_details(error.code(), error.to_string(), error.details())
    }
}

impl From<SnapshotError> for BindingError {
    fn from(error: SnapshotError) -> BindingError {
        BindingError::with_details(error.code(), error.to_string(), error.details())
    }
}

impl From<SplitError> for BindingError {
    fn from(error: SplitError) -> BindingError {
        BindingError::with_details(error.code(), error.to_string(), error.details())
    }
}

/// The vote library's JSON functions, as one export: `operation` names the function, which takes
/// `first`, `second` and `third` as documented for it (unused arguments are empty):
///
/// | Operation | Function |
/// |---|---|
/// | `select` | [`vote_select`] (snapshot, request) |
/// | `evaluate` | [`vote_evaluate`] (snapshot, mode) |
/// | `check` | [`vote_check`] (selection, snapshot) |
/// | `validate` | [`vote_validate`] (entries, rules, voter) |
/// | `split` | [`vote_split`] (validators) |
/// | `voter` | [`vote_voter`] (snapshot, address) |
/// | `validateSnapshot` | [`vote_validate_snapshot`] (snapshot); an empty string when valid |
///
/// One export instead of seven keeps the WebAssembly module smaller, since each export carries
/// its own conversion of arguments, results and errors.
pub fn vote_call(operation: &str, first: &str, second: &str, third: &str) -> Result<String> {
    match operation {
        "select" => vote_select(first, second),
        "evaluate" => vote_evaluate(first, second),
        "check" => vote_check(first, second),
        "validate" => vote_validate(first, second, third),
        "split" => vote_split(first),
        "voter" => vote_voter(first, second),
        "validateSnapshot" => vote_validate_snapshot(first).map(|()| String::new()),
        _ => Err(Bad("operation").into()),
    }
}

/// A selection of `snapshot` (a vote snapshot in JSON) as `request` asks: JSON
/// `{ mode, account, count, draw, rules }`, where `rules` is a vote rules object. Returns the
/// selection in JSON: `{ libraryVersion, mode, account, snapshotHeight, snapshotSource, draw,
/// requested, rules, seed, pool, toppedUp, entries, sizeNotice, topUpNotice }`, each entry
/// `{ validator, basisPoints, source, step, reasons }`, the entries in the protocol's canonical
/// order, so that their names and shares are the vote to sign.
pub fn vote_select(snapshot: &str, request: &str) -> Result<String> {
    let snapshot = snapshot_from_json(snapshot)?;
    let request = object_of(request, "the request")?;
    let rules = rules_from_object(as_object(field(&request, "rules")?, "rules")?)?;
    let selection = vote::select(
        &snapshot,
        &SelectRequest {
            mode: mode_of(&request)?,
            account: text(&request, "account")?,
            count: int(&request, "count")?,
            draw: int(&request, "draw")?,
            rules,
        },
    )?;
    Ok(selection_json(&selection))
}

/// Every validator of `snapshot` judged by `mode`, in name order: JSON
/// `[{ validator, eligible, weight, reasons, shortfalls }]`.
pub fn vote_evaluate(snapshot: &str, mode: &str) -> Result<String> {
    let snapshot = snapshot_from_json(snapshot)?;
    let mode = Mode::from_id(mode).ok_or(Bad("mode"))?;
    Ok(candidates_json(&vote::evaluate(&snapshot, mode)?))
}

/// Each pick of an earlier selection checked against `snapshot`, in the selection's order: JSON
/// `[{ validator, stillMeets, reasons, shortfalls, why }]`. Of the selection (JSON), only `mode`
/// and each entry's `validator`, `source` and `step` are read, which is all the check uses, so a
/// selection a holder edited (entries marked `holder`) can be checked too.
pub fn vote_check(selection: &str, snapshot: &str) -> Result<String> {
    let selection = selection_from_json(selection)?;
    let snapshot = snapshot_from_json(snapshot)?;
    Ok(findings_json(&vote::check(&selection, &snapshot)?))
}

/// What is wrong with a vote (JSON `[{ validator, basisPoints }]`) under `rules` (a vote rules
/// object in JSON) for a `voter` (`ordinary` or `validator`): JSON `[{ reason, ..., text }]`, in
/// the library's fixed order, empty for a valid vote.
pub fn vote_validate(entries: &str, rules: &str, voter: &str) -> Result<String> {
    let entries = entries_from_json(entries)?;
    let rules = rules_from_object(&object_of(rules, "the vote rules")?)?;
    let voter = match voter {
        "ordinary" => Voter::Ordinary,
        "validator" => Voter::Validator,
        _ => return Err(Bad("voter").into()),
    };
    Ok(problems_json(&vote::validate_vote(&entries, &rules, voter)))
}

/// 10,000 basis points shared among `validators` (a JSON array of names) in whole basis points,
/// the remainder one each to the first ones: JSON `[{ validator, basisPoints }]` in the canonical
/// order.
pub fn vote_split(validators: &str) -> Result<String> {
    let items = list(validators, "the validators")?;
    let mut names = Vec::with_capacity(items.len());
    for item in &items {
        names.push(item.as_str().ok_or(Bad("a validator name"))?);
    }
    Ok(entries_json(&vote::split(&names)?))
}

/// Whether the account `address` may vote as `snapshot` (JSON) shows it: `validator` when it
/// belongs to a validator that has not resigned for good, else `ordinary`.
pub fn vote_voter(snapshot: &str, address: &str) -> Result<String> {
    let snapshot = snapshot_from_json(snapshot)?;
    Ok(voter_id(snapshot.voter(address)).to_owned())
}

/// The vote rules in force at `height` of `chain`, as a vote rules object in JSON: the limits of
/// the milestone, and the name rule and whether validators may vote of the format stage.
pub fn vote_rules_at(chain: &Chain, height: u32) -> String {
    rules_json(&voting::vote_rules(&chain.rules(height)))
}

/// A snapshot of a node's validator list, marked `relay-approximate`: `validators` is every
/// registered validator as the node API client decodes them (a JSON array of validator records in
/// the client's JSON form, of which the fields the snapshot uses are read: `name`, `address`,
/// `rank`, `status`, `voteWeight`, `voters`, `production` and `version`), read at `height` of
/// `chain`, whose milestone gives the seats and the block time. `lookups` (JSON) maps a
/// validator's name to what the caller looked up: `{ registeredHeight?, firstForgedHeight? }`,
/// heights as decimal strings. A validator a vote may not name now (not resigned, and listed
/// without a node version: the node refuses a vote naming it) is left out, as
/// `iceroot_sdk::voting::relay_validator` does.
pub fn vote_snapshot_from_validators(
    chain: &Chain,
    height: u32,
    validators: &str,
    lookups: &str,
) -> Result<String> {
    let items = list(validators, "the validators")?;
    let lookups = object_of(lookups, "the lookups")?;
    let mut validators = Vec::with_capacity(items.len());
    for item in &items {
        let info = validator_info(as_object(item, "a validator")?)?;
        if let Some(mut validator) = voting::relay_validator(&info) {
            apply_lookups(&mut validator, &lookups)?;
            validators.push(validator);
        }
    }
    Ok(snapshot_json(&voting::relay_snapshot(
        chain, height, validators,
    )))
}

/// Checks a snapshot (JSON) as every function of the library does before using it:
/// `InvalidSnapshot` with the problem, or nothing.
pub fn vote_validate_snapshot(snapshot: &str) -> Result<()> {
    snapshot_from_json(snapshot)?.validate()?;
    Ok(())
}

// ---- reading JSON ------------------------------------------------------------------------------

/// A field that is missing or not of its documented type: the one error of reading, turned into
/// `InvalidArgument` once, where a function returns. Being two words, it keeps the readers small.
#[derive(Debug)]
struct Bad(&'static str);

type Read<T> = core::result::Result<T, Bad>;

impl From<Bad> for BindingError {
    fn from(Bad(what): Bad) -> BindingError {
        BindingError::argument(format!("{what} is missing or not of its documented type"))
    }
}

/// The JSON value of `text`.
fn parse(text: &str, what: &'static str) -> Read<Value> {
    serde_json::from_str(text).map_err(|_| Bad(what))
}

fn as_object<'a>(value: &'a Value, what: &'static str) -> Read<&'a Map<String, Value>> {
    value.as_object().ok_or(Bad(what))
}

fn as_list<'a>(value: &'a Value, what: &'static str) -> Read<&'a Vec<Value>> {
    value.as_array().ok_or(Bad(what))
}

fn field<'a>(object: &'a Map<String, Value>, key: &'static str) -> Read<&'a Value> {
    object.get(key).ok_or(Bad(key))
}

/// The member `key`, absent or `null` being `None`.
fn opt_field<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object.get(key).filter(|value| !value.is_null())
}

fn text<'a>(object: &'a Map<String, Value>, key: &'static str) -> Read<&'a str> {
    field(object, key)?.as_str().ok_or(Bad(key))
}

fn opt_text(object: &Map<String, Value>, key: &'static str) -> Read<Option<String>> {
    opt_field(object, key)
        .map(|value| value.as_str().map(str::to_owned).ok_or(Bad(key)))
        .transpose()
}

fn flag(object: &Map<String, Value>, key: &'static str) -> Read<bool> {
    field(object, key)?.as_bool().ok_or(Bad(key))
}

/// The whole number `key`, which must fit `T`.
fn int<T: TryFrom<u64>>(object: &Map<String, Value>, key: &'static str) -> Read<T> {
    whole(field(object, key)?, key)
}

fn opt_int<T: TryFrom<u64>>(object: &Map<String, Value>, key: &'static str) -> Read<Option<T>> {
    opt_field(object, key)
        .map(|value| whole(value, key))
        .transpose()
}

fn whole<T: TryFrom<u64>>(value: &Value, key: &'static str) -> Read<T> {
    value
        .as_u64()
        .and_then(|n| T::try_from(n).ok())
        .ok_or(Bad(key))
}

/// The decimal string `key` (digits only, as the wrapper writes a `bigint`), which must fit `T`.
fn dec<T: TryFrom<u128>>(object: &Map<String, Value>, key: &'static str) -> Read<T> {
    decimal_of(field(object, key)?, key)
}

fn opt_dec<T: TryFrom<u128>>(object: &Map<String, Value>, key: &'static str) -> Read<Option<T>> {
    opt_field(object, key)
        .map(|value| decimal_of(value, key))
        .transpose()
}

fn decimal_of<T: TryFrom<u128>>(value: &Value, key: &'static str) -> Read<T> {
    value
        .as_str()
        .filter(|text| {
            !text.is_empty() && text.len() <= 39 && text.bytes().all(|b| b.is_ascii_digit())
        })
        .and_then(|text| text.parse::<u128>().ok())
        .and_then(|n| T::try_from(n).ok())
        .ok_or(Bad(key))
}

fn opt_object<'a>(
    object: &'a Map<String, Value>,
    key: &'static str,
) -> Read<Option<&'a Map<String, Value>>> {
    opt_field(object, key)
        .map(|value| as_object(value, key))
        .transpose()
}

fn mode_of(object: &Map<String, Value>) -> Read<Mode> {
    Mode::from_id(text(object, "mode")?).ok_or(Bad("mode"))
}

/// The JSON array in `text`.
fn list(text: &str, what: &'static str) -> Read<Vec<Value>> {
    match parse(text, what)? {
        Value::Array(items) => Ok(items),
        _ => Err(Bad(what)),
    }
}

/// The JSON object in `text`.
fn object_of(text: &str, what: &'static str) -> Read<Map<String, Value>> {
    match parse(text, what)? {
        Value::Object(object) => Ok(object),
        _ => Err(Bad(what)),
    }
}

fn snapshot_from_json(text: &str) -> Read<VoteSnapshot> {
    let snapshot = object_of(text, "the snapshot")?;
    let items = as_list(field(&snapshot, "records")?, "records")?;
    let mut records = Vec::with_capacity(items.len());
    for item in items {
        records.push(record_from_json(as_object(item, "a validator record")?)?);
    }
    Ok(VoteSnapshot {
        height: dec(&snapshot, "height")?,
        window_days: int(&snapshot, "windowDays")?,
        seats: int(&snapshot, "seats")?,
        block_time_seconds: int(&snapshot, "blockTimeSeconds")?,
        source: SnapshotSource::from_id(self::text(&snapshot, "source")?).ok_or(Bad("source"))?,
        records,
    })
}

fn record_from_json(record: &Map<String, Value>) -> Read<ValidatorRecord> {
    let production = match opt_object(record, "production")? {
        Some(p) => Some(Production {
            forged: int(p, "forged")?,
            assigned: int(p, "assigned")?,
        }),
        None => None,
    };
    let penalties = match opt_object(record, "penalties")? {
        Some(p) => Some(Penalties {
            jailed_in_window: flag(p, "jailedInWindow")?,
            equivocation_in_window: flag(p, "equivocationInWindow")?,
            ever: flag(p, "ever")?,
        }),
        None => None,
    };
    let declarations = match opt_object(record, "declarations")? {
        Some(d) => Some(Declarations {
            operator: opt_text(d, "operator")?,
            hosting: opt_text(d, "hosting")?,
            country: opt_text(d, "country")?,
            complete: flag(d, "complete")?,
        }),
        None => None,
    };
    let payouts = match opt_object(record, "payouts")? {
        Some(p) => Some(Payouts {
            per_unit_weight: dec(p, "perUnitWeight")?,
            intervals: int(p, "intervals")?,
        }),
        None => None,
    };
    Ok(ValidatorRecord {
        name: text(record, "name")?.to_owned(),
        address: text(record, "address")?.to_owned(),
        rank: opt_int(record, "rank")?,
        seated: flag(record, "seated")?,
        status: ValidatorStatus::from_id(text(record, "status")?).ok_or(Bad("status"))?,
        registered_height: opt_dec(record, "registeredHeight")?,
        seated_days_in_window: opt_int(record, "seatedDaysInWindow")?,
        vote_weight: dec(record, "voteWeight")?,
        voters: int(record, "voters")?,
        production,
        penalties,
        declarations,
        payouts,
        self_funded_weight_bp: opt_int(record, "selfFundedWeightBp")?,
    })
}

/// A validator of the node API client's list, from its JSON form: the fields a relay snapshot
/// reads (its node version included, which says whether a vote may name it), the others left
/// empty.
fn validator_info(validator: &Map<String, Value>) -> Read<ValidatorInfo> {
    let status = match text(validator, "status")? {
        "active" => ApiStatus::Active,
        "standby" => ApiStatus::Standby,
        "resigned-temporary" => ApiStatus::ResignedTemporary,
        "resigned-permanent" => ApiStatus::ResignedPermanent,
        _ => return Err(Bad("status")),
    };
    let production = as_object(field(validator, "production")?, "production")?;
    Ok(ValidatorInfo {
        name: text(validator, "name")?.to_owned(),
        address: text(validator, "address")?.to_owned(),
        public_key: String::new(),
        rank: opt_int(validator, "rank")?,
        status,
        vote_weight: dec(validator, "voteWeight")?,
        vote_share_basis_points: 0,
        voters: dec(validator, "voters")?,
        production: ApiProduction {
            produced: dec(production, "produced")?,
            missed: dec(production, "missed")?,
            productivity_basis_points: None,
            last_block: None,
        },
        earnings: Earnings {
            rewards: 0,
            fees: 0,
            burned_fees: 0,
            donations: 0,
            total: 0,
        },
        version: opt_text(validator, "version")?,
    })
}

/// Sets what the caller looked up for `validator`, from `lookups[validator.name]`.
fn apply_lookups(validator: &mut RelayValidator, lookups: &Map<String, Value>) -> Read<()> {
    if let Some(found) = opt_field(lookups, &validator.name) {
        let found = as_object(found, "a lookup")?;
        validator.registered_height = opt_dec(found, "registeredHeight")?;
        validator.first_forged_height = opt_dec(found, "firstForgedHeight")?;
    }
    Ok(())
}

fn rules_from_object(rules: &Map<String, Value>) -> Read<VoteRules> {
    let names = match text(rules, "names")? {
        "solar-compatible" => NameRule::SolarCompatible,
        "lowercase-letters" => NameRule::LowercaseLetters,
        _ => return Err(Bad("names")),
    };
    Ok(VoteRules {
        min_entries: int(rules, "minEntries")?,
        max_entries: int(rules, "maxEntries")?,
        max_entry_basis_points: int(rules, "maxEntryBasisPoints")?,
        max_bytes: int(rules, "maxBytes")?,
        names,
        validators_may_vote: flag(rules, "validatorsMayVote")?,
    })
}

fn entries_from_json(text: &str) -> Read<Vec<VoteEntry>> {
    let items = list(text, "the entries")?;
    let mut entries = Vec::with_capacity(items.len());
    for item in &items {
        let entry = as_object(item, "an entry")?;
        entries.push(VoteEntry {
            validator: self::text(entry, "validator")?.to_owned(),
            basis_points: int(entry, "basisPoints")?,
        });
    }
    Ok(entries)
}

fn selection_from_json(text: &str) -> Read<Selection> {
    let selection = object_of(text, "the selection")?;
    let mode = mode_of(&selection)?;
    let items = as_list(field(&selection, "entries")?, "entries")?;
    let mut entries = Vec::with_capacity(items.len());
    let mut topped_up = 0u32;
    for item in items {
        let entry = as_object(item, "an entry")?;
        let source = match self::text(entry, "source")? {
            "mode" => PickSource::Mode,
            "top-up" => PickSource::TopUp,
            "holder" => PickSource::Holder,
            _ => return Err(Bad("source")),
        };
        topped_up += u32::from(source == PickSource::TopUp);
        entries.push(Pick {
            validator: self::text(entry, "validator")?.to_owned(),
            basis_points: opt_int(entry, "basisPoints")?.unwrap_or(0),
            source,
            step: int(entry, "step")?,
            reasons: Vec::new(),
        });
    }
    // Only the mode and the picks are read by the check; the rest describes the draw.
    Ok(Selection {
        library_version: LIBRARY_VERSION.to_owned(),
        mode,
        account: String::new(),
        snapshot_height: 0,
        snapshot_source: SnapshotSource::Indexer,
        draw: 0,
        requested: u8::try_from(entries.len()).unwrap_or(u8::MAX),
        rules: VoteRules::ICEROOT,
        seed: [0; 32],
        pool: 0,
        topped_up,
        entries,
    })
}

// ---- writing JSON ------------------------------------------------------------------------------

fn voter_id(voter: Voter) -> &'static str {
    match voter {
        Voter::Ordinary => "ordinary",
        Voter::Validator => "validator",
    }
}

fn write_rules(json: &mut Json, rules: &VoteRules) {
    json.open()
        .field_num("minEntries", rules.min_entries)
        .field_num("maxEntries", rules.max_entries)
        .field_num("maxEntryBasisPoints", rules.max_entry_basis_points)
        .field_num("maxBytes", rules.max_bytes)
        .field_str(
            "names",
            match rules.names {
                NameRule::SolarCompatible => "solar-compatible",
                NameRule::LowercaseLetters => "lowercase-letters",
            },
        )
        .field_bool("validatorsMayVote", rules.validators_may_vote)
        .close();
}

fn rules_json(rules: &VoteRules) -> String {
    let mut json = Json::new();
    write_rules(&mut json, rules);
    json.finish()
}

fn write_entries(json: &mut Json, entries: &[VoteEntry]) {
    json.open_list();
    for entry in entries {
        json.open()
            .field_str("validator", &entry.validator)
            .field_num("basisPoints", entry.basis_points)
            .close();
    }
    json.close_list();
}

fn entries_json(entries: &[VoteEntry]) -> String {
    let mut json = Json::new();
    write_entries(&mut json, entries);
    json.finish()
}

fn snapshot_json(snapshot: &VoteSnapshot) -> String {
    let mut json = Json::new();
    json.open()
        .field_big("height", snapshot.height)
        .field_num("windowDays", snapshot.window_days)
        .field_num("seats", snapshot.seats)
        .field_num("blockTimeSeconds", snapshot.block_time_seconds)
        .field_str("source", snapshot.source.id())
        .key("records")
        .open_list();
    for record in &snapshot.records {
        write_record(&mut json, record);
    }
    json.close_list().close();
    json.finish()
}

fn write_record(json: &mut Json, record: &ValidatorRecord) {
    json.open()
        .field_str("name", &record.name)
        .field_str("address", &record.address)
        .field_opt_num("rank", record.rank)
        .field_bool("seated", record.seated)
        .field_str("status", record.status.id())
        .field_opt_big("registeredHeight", record.registered_height)
        .field_opt_num("seatedDaysInWindow", record.seated_days_in_window)
        .field_big("voteWeight", record.vote_weight)
        .field_num("voters", record.voters)
        .key("production");
    match record.production {
        Some(p) => json
            .open()
            .field_num("forged", p.forged)
            .field_num("assigned", p.assigned)
            .close(),
        None => json.null(),
    };
    json.key("penalties");
    match record.penalties {
        Some(p) => json
            .open()
            .field_bool("jailedInWindow", p.jailed_in_window)
            .field_bool("equivocationInWindow", p.equivocation_in_window)
            .field_bool("ever", p.ever)
            .close(),
        None => json.null(),
    };
    json.key("declarations");
    match &record.declarations {
        Some(d) => json
            .open()
            .field_opt_str("operator", d.operator.as_deref())
            .field_opt_str("hosting", d.hosting.as_deref())
            .field_opt_str("country", d.country.as_deref())
            .field_bool("complete", d.complete)
            .close(),
        None => json.null(),
    };
    json.key("payouts");
    match record.payouts {
        Some(p) => json
            .open()
            .field_big("perUnitWeight", p.per_unit_weight)
            .field_num("intervals", p.intervals)
            .close(),
        None => json.null(),
    };
    json.field_opt_num("selfFundedWeightBp", record.self_funded_weight_bp)
        .close();
}

fn pick_source_id(source: PickSource) -> &'static str {
    match source {
        PickSource::Mode => "mode",
        PickSource::TopUp => "top-up",
        PickSource::Holder => "holder",
    }
}

fn selection_json(selection: &Selection) -> String {
    let mut json = Json::new();
    json.open()
        .field_str("libraryVersion", &selection.library_version)
        .field_str("mode", selection.mode.id())
        .field_str("account", &selection.account)
        .field_big("snapshotHeight", selection.snapshot_height)
        .field_str("snapshotSource", selection.snapshot_source.id())
        .field_num("draw", selection.draw)
        .field_num("requested", selection.requested)
        .key("rules");
    write_rules(&mut json, &selection.rules);
    json.field_str("seed", &selection.seed_hex())
        .field_num("pool", selection.pool)
        .field_num("toppedUp", selection.topped_up)
        .key("entries")
        .open_list();
    for pick in &selection.entries {
        json.open()
            .field_str("validator", &pick.validator)
            .field_num("basisPoints", pick.basis_points)
            .field_str("source", pick_source_id(pick.source))
            .field_num("step", pick.step)
            .key("reasons");
        write_reasons(&mut json, &pick.reasons);
        json.close();
    }
    json.close_list()
        .field_opt_str("sizeNotice", selection.size_notice().as_deref())
        .field_opt_str("topUpNotice", selection.top_up_notice().as_deref())
        .close();
    json.finish()
}

fn candidates_json(candidates: &[Candidate]) -> String {
    let mut json = Json::new();
    json.open_list();
    for candidate in candidates {
        json.open()
            .field_str("validator", &candidate.validator)
            .field_bool("eligible", candidate.eligible)
            .field_big("weight", candidate.weight)
            .key("reasons");
        write_reasons(&mut json, &candidate.reasons);
        json.key("shortfalls");
        write_shortfalls(&mut json, &candidate.shortfalls);
        json.close();
    }
    json.close_list();
    json.finish()
}

fn findings_json(findings: &[Finding]) -> String {
    let mut json = Json::new();
    json.open_list();
    for finding in findings {
        json.open()
            .field_str("validator", &finding.validator)
            .field_bool("stillMeets", finding.still_meets)
            .key("reasons");
        write_reasons(&mut json, &finding.reasons);
        json.key("shortfalls");
        write_shortfalls(&mut json, &finding.shortfalls);
        json.field_str("why", &finding.why()).close();
    }
    json.close_list();
    json.finish()
}

/// The problems of a vote: the library's details (`reason` and its values) and the sentence.
fn problems_json(problems: &[Problem]) -> String {
    let mut json = Json::new();
    json.open_list();
    for problem in problems {
        let mut details = problem.details();
        if let Value::Object(fields) = &mut details {
            fields.insert("text".to_owned(), Value::String(problem.to_string()));
        }
        json.raw(&details.to_string());
    }
    json.close_list();
    json.finish()
}

fn dimension_id(dimension: Dimension) -> &'static str {
    match dimension {
        Dimension::Operator => "operator",
        Dimension::Hosting => "hosting",
        Dimension::Region => "region",
        Dimension::RankBand => "rank-band",
    }
}

/// The reasons: each `kind`, its values and `text`, the sentence of the review screen.
fn write_reasons(json: &mut Json, reasons: &[Reason]) {
    json.open_list();
    for reason in reasons {
        json.open();
        match reason {
            Reason::Drawn {
                pool,
                step,
                candidates,
                weight,
                total_weight,
            } => json
                .field_str("kind", "drawn")
                .field_str("pool", pool.id())
                .field_num("step", *step)
                .field_num("candidates", *candidates)
                .field_big("weight", *weight)
                .field_big("totalWeight", *total_weight),
            Reason::TopUp { mode, mode_picks } => json
                .field_str("kind", "top-up")
                .field_str("mode", mode.id())
                .field_num("modePicks", *mode_picks),
            Reason::Status {
                status,
                rank,
                seated,
            } => json
                .field_str("kind", "status")
                .field_str("status", status.id())
                .field_opt_num("rank", *rank)
                .field_bool("seated", *seated),
            Reason::Production {
                forged,
                assigned,
                approximate,
            } => json
                .field_str("kind", "production")
                .field_num("forged", *forged)
                .field_num("assigned", *assigned)
                .field_bool("approximate", *approximate),
            Reason::NoProductionRecord => json.field_str("kind", "no-production-record"),
            Reason::NoPenaltiesInWindow => json.field_str("kind", "no-penalties-in-window"),
            Reason::NoPenaltiesEver => json.field_str("kind", "no-penalties-ever"),
            Reason::NoPenaltyRecord => json.field_str("kind", "no-penalty-record"),
            Reason::SeatedDays { days } => json
                .field_str("kind", "seated-days")
                .field_num("days", *days),
            Reason::RegisteredDays { days } => json
                .field_str("kind", "registered-days")
                .field_big("days", *days),
            Reason::DeclarationsComplete => json.field_str("kind", "declarations-complete"),
            Reason::Group {
                dimension,
                value,
                earlier_picks,
            } => json
                .field_str("kind", "group")
                .field_str("dimension", dimension_id(*dimension))
                .field_opt_str("value", value.as_deref())
                .field_num("earlierPicks", *earlier_picks),
            Reason::MeasuredPayouts {
                per_unit_weight,
                intervals,
                of_best_ppm,
            } => json
                .field_str("kind", "measured-payouts")
                .field_big("perUnitWeight", *per_unit_weight)
                .field_num("intervals", *intervals)
                .field_num("ofBestPpm", *of_best_ppm),
            Reason::OperatorPicks {
                operator,
                picks,
                maximum,
            } => json
                .field_str("kind", "operator-picks")
                .field_opt_str("operator", operator.as_deref())
                .field_num("picks", *picks)
                .field_num("maximum", *maximum),
            Reason::NearCutoff { rank, seats } => json
                .field_str("kind", "near-cutoff")
                .field_num("rank", *rank)
                .field_num("seats", *seats),
            Reason::SelfFundedWeight { basis_points } => json
                .field_str("kind", "self-funded-weight")
                .field_num("basisPoints", *basis_points),
            Reason::ChosenByHolder => json.field_str("kind", "chosen-by-holder"),
        };
        json.field_str("text", &reason.to_string()).close();
    }
    json.close_list();
}

/// The shortfalls: each `kind`, its values and `text`.
fn write_shortfalls(json: &mut Json, shortfalls: &[Shortfall]) {
    json.open_list();
    for shortfall in shortfalls {
        json.open();
        match shortfall {
            Shortfall::NotInSnapshot => json.field_str("kind", "not-in-snapshot"),
            Shortfall::Resigned { status } => json
                .field_str("kind", "resigned")
                .field_str("status", status.id()),
            Shortfall::PenalizedInWindow {
                jailed,
                equivocation,
            } => json
                .field_str("kind", "penalized-in-window")
                .field_bool("jailed", *jailed)
                .field_bool("equivocation", *equivocation),
            Shortfall::PenalizedEver => json.field_str("kind", "penalized-ever"),
            Shortfall::LowProduction {
                forged,
                assigned,
                minimum_bp,
            } => json
                .field_str("kind", "low-production")
                .field_num("forged", *forged)
                .field_num("assigned", *assigned)
                .field_num("minimumBp", *minimum_bp),
            Shortfall::NoProductionRecord => json.field_str("kind", "no-production-record"),
            Shortfall::TooFewSeatedDays { days, minimum } => json
                .field_str("kind", "too-few-seated-days")
                .field_opt_num("days", *days)
                .field_num("minimum", *minimum),
            Shortfall::RegisteredTooRecently { days, minimum } => json
                .field_str("kind", "registered-too-recently")
                .field_opt_big("days", *days)
                .field_num("minimum", *minimum),
            Shortfall::DeclarationsIncomplete => json.field_str("kind", "declarations-incomplete"),
            Shortfall::NoMeasuredPayouts => json.field_str("kind", "no-measured-payouts"),
            Shortfall::NotSeated => json.field_str("kind", "not-seated"),
            Shortfall::NoRank => json.field_str("kind", "no-rank"),
            Shortfall::NotNearCutoff { rank, seats } => json
                .field_str("kind", "not-near-cutoff")
                .field_num("rank", *rank)
                .field_num("seats", *seats),
            Shortfall::FarBelowCutoff {
                rank,
                seats,
                ranks_below,
            } => json
                .field_str("kind", "far-below-cutoff")
                .field_num("rank", *rank)
                .field_num("seats", *seats)
                .field_num("ranksBelow", *ranks_below),
            Shortfall::OperatorCap { operator, maximum } => json
                .field_str("kind", "operator-cap")
                .field_opt_str("operator", operator.as_deref())
                .field_num("maximum", *maximum),
        };
        json.field_str("text", &shortfall.to_string()).close();
    }
    json.close_list();
}

/// Test seam of the bindings only (feature `fixed-aux`, which the test build of the package turns
/// on and the published build never does): the library's constants, which the wrapper's are tested
/// against, and snapshots of relay data in the library's own relay form, for its devnet-shaped
/// fixture.
#[cfg(feature = "fixed-aux")]
pub mod testing {
    use super::*;
    use iceroot_sdk::vote::{DEFAULT_PICKS, MAX_PICKS, MIN_PICKS, RelaySnapshot, Resignation};

    /// The library's constants, in JSON: `{ modes, modeNames, libraryVersion, minPicks, maxPicks,
    /// defaultPicks, iceroot, solarCompatible }`, the last two the vote rules presets. The wrapper's
    /// constants are tested against them.
    pub fn vote_library() -> String {
        let mut json = Json::new();
        json.open().key("modes").open_list();
        for mode in Mode::ALL {
            json.string(mode.id());
        }
        json.close_list().key("modeNames").open();
        for mode in Mode::ALL {
            json.field_str(mode.id(), mode.name());
        }
        json.close()
            .field_str("libraryVersion", LIBRARY_VERSION)
            .field_num("minPicks", MIN_PICKS)
            .field_num("maxPicks", MAX_PICKS)
            .field_num("defaultPicks", DEFAULT_PICKS)
            .key("iceroot");
        write_rules(&mut json, &VoteRules::ICEROOT);
        json.key("solarCompatible");
        write_rules(&mut json, &VoteRules::SOLAR_COMPATIBLE);
        json.close();
        json.finish()
    }

    /// A snapshot of relay data in the vote library's relay form, for the library's own devnet-shaped fixture. JSON `{ height, seats,
    /// blockTimeSeconds, validators }`, each
    /// validator `{ name, address, rank, resignation, voteWeight, voters, producedBlocks,
    /// missedBlocks, registeredHeight, firstForgedHeight }`), marked `relay-approximate`.
    pub fn vote_snapshot_from_relay(relay: &str) -> Result<String> {
        Ok(snapshot_json(&VoteSnapshot::from_relay(relay_from_json(
            relay,
        )?)))
    }

    fn relay_from_json(json: &str) -> Read<RelaySnapshot> {
        let relay = object_of(json, "the relay data")?;
        let items = as_list(field(&relay, "validators")?, "validators")?;
        let mut validators = Vec::with_capacity(items.len());
        for item in items {
            let validator = as_object(item, "a validator")?;
            let resignation = match opt_field(validator, "resignation").map(Value::as_str) {
                None => None,
                Some(Some("temporary")) => Some(Resignation::Temporary),
                Some(Some("permanent")) => Some(Resignation::Permanent),
                Some(_) => return Err(Bad("resignation")),
            };
            validators.push(RelayValidator {
                name: text(validator, "name")?.to_owned(),
                address: text(validator, "address")?.to_owned(),
                rank: opt_int(validator, "rank")?,
                resignation,
                vote_weight: dec(validator, "voteWeight")?,
                voters: int(validator, "voters")?,
                produced_blocks: int(validator, "producedBlocks")?,
                missed_blocks: opt_int(validator, "missedBlocks")?,
                registered_height: opt_dec(validator, "registeredHeight")?,
                first_forged_height: opt_dec(validator, "firstForgedHeight")?,
            });
        }
        Ok(RelaySnapshot {
            height: dec(&relay, "height")?,
            seats: int(&relay, "seats")?,
            block_time_seconds: int(&relay, "blockTimeSeconds")?,
            validators,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::tests::devnet;
    use serde_json::json;

    fn value(text: &str) -> Value {
        serde_json::from_str(text).unwrap()
    }

    fn record(name: &str, rank: u32) -> Value {
        json!({
            "name": name, "address": format!("addr-{name}"), "rank": rank, "seated": rank <= 53,
            "status": if rank <= 53 { "active" } else { "standby" },
            "registeredHeight": "1", "seatedDaysInWindow": 30, "voteWeight": "1000", "voters": 3,
            "production": { "forged": 100, "assigned": 100 },
            "penalties": { "jailedInWindow": false, "equivocationInWindow": false, "ever": false },
            "declarations": { "operator": format!("op {name}"), "hosting": null, "country": "DE", "complete": true },
            "payouts": { "perUnitWeight": "1000", "intervals": 30 },
            "selfFundedWeightBp": 12,
        })
    }

    fn snapshot(count: u32) -> String {
        let names: Vec<String> = (0..count)
            .map(|i| {
                let a = char::from(b'a' + u8::try_from(i % 26).unwrap());
                let b = char::from(b'a' + u8::try_from(i / 26).unwrap());
                format!("val{a}{b}")
            })
            .collect();
        json!({
            "height": "1000000", "windowDays": 30, "seats": 53, "blockTimeSeconds": 8,
            "source": "indexer",
            "records": names.iter().zip(1..).map(|(n, r)| record(n, r)).collect::<Vec<_>>(),
        })
        .to_string()
    }

    fn iceroot() -> Value {
        value(&rules_json(&VoteRules::ICEROOT))
    }

    #[test]
    fn a_snapshot_reads_back_as_written() {
        let text = snapshot(60);
        let read = snapshot_from_json(&text).unwrap();
        assert_eq!(value(&snapshot_json(&read)), value(&text));
    }

    #[test]
    fn selections_in_every_mode() {
        let snapshot = snapshot(60);
        for mode in Mode::ALL {
            let request = json!({ "mode": mode.id(), "account": "holder", "count": 20, "draw": 0, "rules": iceroot() });
            let selection: Value =
                serde_json::from_str(&vote_select(&snapshot, &request.to_string()).unwrap())
                    .unwrap();
            assert_eq!(selection["libraryVersion"], "iceroot-vote/1");
            assert_eq!(selection["entries"].as_array().unwrap().len(), 20);
            assert_eq!(selection["snapshotHeight"], "1000000");
            let reasons = selection["entries"][0]["reasons"].as_array().unwrap();
            assert!(
                reasons
                    .iter()
                    .all(|r| r["kind"].is_string() && r["text"].is_string())
            );
            // The check reads the selection back.
            let findings: Value =
                serde_json::from_str(&vote_check(&selection.to_string(), &snapshot).unwrap())
                    .unwrap();
            assert!(
                findings
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|f| f["stillMeets"] == true)
            );
        }
    }

    #[test]
    fn refusals_keep_their_codes_and_details() {
        let snapshot = snapshot(10);
        let request = json!({ "mode": "diversity", "account": "holder", "count": 20, "draw": 0, "rules": iceroot() });
        let error = vote_select(&snapshot, &request.to_string()).unwrap_err();
        assert_eq!(error.code(), "NotEnoughValidators");
        assert_eq!(
            error.details(),
            &json!({ "requested": 20, "available": 10 })
        );
        let request = json!({ "mode": "diversity", "account": "holder", "count": 19, "draw": 0, "rules": iceroot() });
        let error = vote_select(&snapshot, &request.to_string()).unwrap_err();
        assert_eq!(error.code(), "InvalidPickCount");
        let error = vote_split(&json!(vec!["a"; 10_001]).to_string()).unwrap_err();
        assert_eq!(error.code(), "InvalidVote");
        assert_eq!(error.details()["reason"], "too-many-entries");
        let error = vote_select("{}", &request.to_string()).unwrap_err();
        assert_eq!(error.code(), "InvalidArgument");
        let bad = snapshot.replace("\"windowDays\":30", "\"windowDays\":7");
        let error = vote_validate_snapshot(&bad).unwrap_err();
        assert_eq!(error.code(), "InvalidSnapshot");
        assert_eq!(error.details(), &json!({ "reason": "window", "days": 7 }));
    }

    #[test]
    fn validate_and_split() {
        let entries = vote_split(r#"["b","a","c"]"#).unwrap();
        assert_eq!(
            entries,
            r#"[{"validator":"b","basisPoints":3334},{"validator":"a","basisPoints":3333},{"validator":"c","basisPoints":3333}]"#
        );
        let problems: Value = serde_json::from_str(
            &vote_validate(&entries, &iceroot().to_string(), "validator").unwrap(),
        )
        .unwrap();
        let reasons: Vec<&str> = problems
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["reason"].as_str().unwrap())
            .collect();
        assert_eq!(
            reasons,
            [
                "validator-account",
                "too-few-entries",
                "share-too-large",
                "share-too-large",
                "share-too-large"
            ]
        );
        assert!(problems[0]["text"].is_string());
        assert!(vote_validate(&entries, &iceroot().to_string(), "nobody").is_err());
    }

    #[test]
    fn the_devnet_s_rules_and_a_validator_list() {
        let chain = devnet();
        assert_eq!(
            value(&vote_rules_at(&chain, 2)),
            value(&rules_json(&VoteRules::SOLAR_COMPATIBLE))
        );
        #[cfg(feature = "fixed-aux")]
        {
            let library = value(&testing::vote_library());
            assert_eq!(library["modeNames"]["maximum-rewards"], "Maximum Rewards");
            assert_eq!(library["iceroot"], iceroot());
        }
        let validators = json!([{
            "name": "genesis_1", "address": "dZ1W1GsDCSyhR148oMhuHy3PkhnnSGCqVn",
            "publicKey": "03287bfebba4c7881a0509717e71b34b63f31e40021c321f89ae04f84be6d6ac37",
            "rank": 1, "status": "active", "voteWeight": "100", "voteShareBasisPoints": 1,
            "voters": "1", "production": { "produced": "5", "missed": "1" },
            "earnings": { "rewards": "0", "fees": "0", "burnedFees": "0", "donations": "0", "total": "0" },
            "version": "4.3.1",
        }, {
            // Its node was never seen: a vote may not name it, so the snapshot leaves it out.
            "name": "unseen", "address": "dUnseenValidatorAddress",
            "publicKey": "02287bfebba4c7881a0509717e71b34b63f31e40021c321f89ae04f84be6d6ac37",
            "rank": 2, "status": "active", "voteWeight": "50", "voteShareBasisPoints": 1,
            "voters": "1", "production": { "produced": "0", "missed": "0" },
            "earnings": { "rewards": "0", "fees": "0", "burnedFees": "0", "donations": "0", "total": "0" },
        }, {
            // Resigned: kept, so a check reports it as resigned.
            "name": "resigned", "address": "dResignedValidatorAddress",
            "publicKey": "02387bfebba4c7881a0509717e71b34b63f31e40021c321f89ae04f84be6d6ac37",
            "status": "resigned-permanent", "voteWeight": "0", "voteShareBasisPoints": 0,
            "voters": "0", "production": { "produced": "0", "missed": "0" },
            "earnings": { "rewards": "0", "fees": "0", "burnedFees": "0", "donations": "0", "total": "0" },
        }]);
        let lookups = json!({ "genesis_1": { "registeredHeight": "1", "firstForgedHeight": "2" } });
        let snapshot: Value = serde_json::from_str(
            &vote_snapshot_from_validators(
                &chain,
                100,
                &validators.to_string(),
                &lookups.to_string(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(snapshot["source"], "relay-approximate");
        assert_eq!(snapshot["seats"], 53);
        let names: Vec<&str> = snapshot["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["genesis_1", "resigned"]);
        let record = &snapshot["records"][0];
        assert_eq!(record["registeredHeight"], "1");
        assert_eq!(record["production"], json!({ "forged": 5, "assigned": 6 }));
        assert_eq!(record["seatedDaysInWindow"], 0);
        assert_eq!(record["status"], "active");
    }
}
