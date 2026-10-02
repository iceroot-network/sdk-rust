//! Account links, version 1: one signed message that joins a GitHub account and an IceRoot
//! account, and the revocation that ends it. `docs/account-links.md` specifies the format.
//!
//! A link is exactly nine lines, and a revocation ten, separated by `\n` with no newline at the
//! end and no carriage return anywhere:
//!
//! ```text
//! IceRoot account link                      IceRoot account link revocation
//! Version: 1                                Version: 1
//! Network: <network name of the profile>    Network: <network name of the profile>
//! GitHub user id: <decimal numeric id>      GitHub user id: <decimal numeric id>
//! Account: <IceRoot address>                Account: <IceRoot address>
//! Public key: <the account's public key>    Public key: <the account's public key>
//! Issued at: <YYYY-MM-DDTHH:MM:SSZ>         Issued at: <YYYY-MM-DDTHH:MM:SSZ>
//! Intent: <the link's intent line>          Ends link issued at: <the ended link's issue time>
//! No transaction or transfer is authorized. Intent: <the revocation's intent line>
//!                                           No transaction or transfer is authorized.
//! ```
//!
//! [`parse`] checks everything, in this order, and refuses with [`Error::InvalidLink`] and the
//! first [`LinkProblem`]: the length and carriage returns, the lines and fixed lines (`format`);
//! the field labels and white space (`field`); the network against the reader's profile
//! (`network`); the GitHub user id, a decimal from 1 to 2^53 - 1 without leading zeros
//! (`github-id`); the public key's canonical form (`key`); that the account is the key's address
//! on that network (`address`); the issue time's form (`issued-at`) and that it is no more than 30
//! seconds ahead of the reader's clock (`future`); a revocation's ended link, earlier than its own
//! issue time (`ends-link`); and what the reader expects (`mismatch`). A link has no expiry.
//!
//! A message is signed only with [`sign`], which runs [`parse`] against the signing account's
//! public key and address and the signer's time first. Plain message signing
//! ([`crate::message::sign`]) refuses any text whose first line is a link's or a revocation's, so
//! a website asking for a plain signature cannot obtain a link signature. The signed record
//! ([`LinkRecord`]) is compact JSON written byte for byte as the TypeScript SDK writes it;
//! [`verify`] checks it. [`check_history`] applies the no-replay rule to a checked message.

use heartwood_crypto::{Aux, PublicKey};
use serde_json::Value;

use crate::address::Address;
use crate::error::{Error, LinkProblem};
use crate::keys::Account;
use crate::message::{self, MessageSignature, compressed_key};
use crate::profile::Profile;
use crate::time::{format_rfc3339_seconds, parse_rfc3339_ms};
use crate::utils::is_lower_hex;

/// The first line of a link.
pub const TITLE: &str = "IceRoot account link";
/// The first line of a revocation.
pub const REVOCATION_TITLE: &str = "IceRoot account link revocation";
/// The second line.
pub const VERSION_LINE: &str = "Version: 1";
/// The intent line of a link.
pub const INTENT_LINE: &str =
    "Intent: Link this GitHub account and this IceRoot account as the same holder.";
/// The intent line of a revocation.
pub const REVOCATION_INTENT_LINE: &str =
    "Intent: End the link between this GitHub account and this IceRoot account.";
/// The last line.
pub const NO_TRANSACTION_LINE: &str = "No transaction or transfer is authorized.";
/// The largest GitHub user id: 2^53 - 1, the largest integer JavaScript reads exactly.
pub const MAX_GITHUB_ID: u64 = 9_007_199_254_740_991;
/// The longest message, in bytes.
pub const MAX_LENGTH: usize = 4096;
/// The longest JSON text [`LinkRecord::from_json`] reads, in bytes.
pub const MAX_JSON_LENGTH: usize = 16_384;
/// How far ahead of the reader's clock a message may be issued, in milliseconds.
pub const MAX_CLOCK_AHEAD_MS: i64 = 30_000;

const NETWORK_LABEL: &str = "Network: ";
const GITHUB_ID_LABEL: &str = "GitHub user id: ";
const ACCOUNT_LABEL: &str = "Account: ";
const PUBLIC_KEY_LABEL: &str = "Public key: ";
const ISSUED_AT_LABEL: &str = "Issued at: ";
const ENDS_LABEL: &str = "Ends link issued at: ";

fn problem(problem: LinkProblem) -> Error {
    Error::InvalidLink { problem }
}

/// A link or a revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkKind {
    /// A link: [`TITLE`].
    Link,
    /// A revocation: [`REVOCATION_TITLE`].
    Revocation,
}

impl LinkKind {
    /// The stable string form: `link` or `revocation`.
    pub const fn as_str(self) -> &'static str {
        match self {
            LinkKind::Link => "link",
            LinkKind::Revocation => "revocation",
        }
    }
}

/// What goes into a new link or revocation message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkRequest<'a> {
    /// The GitHub account's numeric user id.
    pub github_id: u64,
    /// The IceRoot account's public key; the account is its address on the profile's network.
    pub public_key: &'a PublicKey,
    /// When the message is issued, in seconds since 1970-01-01T00:00:00Z.
    pub issued_at: i64,
}

/// What a reader expects of a message. Unset fields are not compared. A signer sets the public
/// key and address of the account it signs with; a verifier sets what it already knows, such as
/// the GitHub user id and the kind of record it reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LinkExpected<'a> {
    /// A link or a revocation.
    pub kind: Option<LinkKind>,
    /// The GitHub user id.
    pub github_id: Option<u64>,
    /// The public key, lowercase hex.
    pub public_key: Option<&'a str>,
    /// The account's address.
    pub address: Option<&'a str>,
}

/// A checked message's fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkMessage {
    /// A link or a revocation.
    pub kind: LinkKind,
    /// The network name.
    pub network: String,
    /// The GitHub user id.
    pub github_id: u64,
    /// The account's address.
    pub account: String,
    /// The public key, lowercase hex.
    pub public_key: String,
    /// The issue time as the message writes it.
    pub issued_at: String,
    /// The issue time, in milliseconds since 1970-01-01T00:00:00Z.
    pub issued_at_ms: i64,
    /// For a revocation, the issue time of the link it ends, as the message writes it.
    pub ends_link_issued_at: Option<String>,
    /// That time in milliseconds since 1970-01-01T00:00:00Z.
    pub ends_link_issued_at_ms: Option<i64>,
}

/// The link message of `request` on the network of `profile`.
pub fn build(profile: &Profile, request: &LinkRequest<'_>) -> Result<String, Error> {
    build_message(profile, request, None)
}

/// The revocation of the link issued at `ends_link_issued_at` (seconds since
/// 1970-01-01T00:00:00Z, earlier than the request's own issue time).
pub fn build_revocation(
    profile: &Profile,
    request: &LinkRequest<'_>,
    ends_link_issued_at: i64,
) -> Result<String, Error> {
    build_message(profile, request, Some(ends_link_issued_at))
}

fn build_message(
    profile: &Profile,
    request: &LinkRequest<'_>,
    ends: Option<i64>,
) -> Result<String, Error> {
    let network = profile.message_network()?;
    if !(1..=MAX_GITHUB_ID).contains(&request.github_id) {
        return Err(problem(LinkProblem::GithubId));
    }
    let issued = format_rfc3339_seconds(request.issued_at).ok_or(problem(LinkProblem::IssuedAt))?;
    let public_key = request.public_key.to_hex();
    let address = Address::from_public_key(request.public_key, profile)?;
    let title = if ends.is_some() {
        REVOCATION_TITLE
    } else {
        TITLE
    };
    let mut lines = vec![
        title.to_owned(),
        VERSION_LINE.to_owned(),
        format!("{NETWORK_LABEL}{network}"),
        format!("{GITHUB_ID_LABEL}{}", request.github_id),
        format!("{ACCOUNT_LABEL}{address}"),
        format!("{PUBLIC_KEY_LABEL}{public_key}"),
        format!("{ISSUED_AT_LABEL}{issued}"),
    ];
    match ends {
        Some(ends) => {
            let ends = format_rfc3339_seconds(ends).ok_or(problem(LinkProblem::EndsLink))?;
            lines.push(format!("{ENDS_LABEL}{ends}"));
            lines.push(REVOCATION_INTENT_LINE.to_owned());
        }
        None => lines.push(INTENT_LINE.to_owned()),
    }
    lines.push(NO_TRANSACTION_LINE.to_owned());
    let message = lines.join("\n");
    // Reading the message back keeps build and parse from drifting, and checks the key's form
    // and the order of the times.
    let now_ms = request.issued_at.saturating_mul(1000);
    parse(profile, &message, &LinkExpected::default(), now_ms)?;
    Ok(message)
}

/// Check the link or revocation `message` for the network of `profile`, against what the reader
/// `expected`, at the reader's time `now_ms` (milliseconds since 1970-01-01T00:00:00Z). The
/// checks and their order are in the module documentation.
pub fn parse(
    profile: &Profile,
    message: &str,
    expected: &LinkExpected<'_>,
    now_ms: i64,
) -> Result<LinkMessage, Error> {
    let network = profile.message_network()?;
    if message.len() > MAX_LENGTH || message.contains('\r') {
        return Err(problem(LinkProblem::Format));
    }
    let lines: Vec<&str> = message.split('\n').collect();
    let (kind, intent, count) = match lines.first() {
        Some(&TITLE) => (LinkKind::Link, INTENT_LINE, 9),
        Some(&REVOCATION_TITLE) => (LinkKind::Revocation, REVOCATION_INTENT_LINE, 10),
        _ => return Err(problem(LinkProblem::Format)),
    };
    let line = |index: usize| lines.get(index).copied().unwrap_or_default();
    if lines.len() != count
        || line(1) != VERSION_LINE
        || line(count - 2) != intent
        || line(count - 1) != NO_TRANSACTION_LINE
    {
        return Err(problem(LinkProblem::Format));
    }
    let field = |line: &'_ str, label: &str| -> Result<String, Error> {
        line.strip_prefix(label)
            .filter(|value| {
                !value.is_empty()
                    && !value.starts_with([' ', '\t'])
                    && !value.ends_with([' ', '\t'])
            })
            .map(str::to_owned)
            .ok_or(problem(LinkProblem::Field))
    };
    let message_network = field(line(2), NETWORK_LABEL)?;
    let github_id = field(line(3), GITHUB_ID_LABEL)?;
    let account = field(line(4), ACCOUNT_LABEL)?;
    let public_key = field(line(5), PUBLIC_KEY_LABEL)?;
    let issued_at = field(line(6), ISSUED_AT_LABEL)?;
    let ends_link_issued_at = (kind == LinkKind::Revocation)
        .then(|| field(line(7), ENDS_LABEL))
        .transpose()?;

    if message_network != network {
        return Err(problem(LinkProblem::Network));
    }
    let github_id = parse_github_id(&github_id).ok_or(problem(LinkProblem::GithubId))?;
    let key = compressed_key(&public_key).ok_or(problem(LinkProblem::Key))?;
    if Address::from_public_key(&key, profile)?.to_string() != account {
        return Err(problem(LinkProblem::Address));
    }
    let issued_at_ms = parse_time(&issued_at).ok_or(problem(LinkProblem::IssuedAt))?;
    if issued_at_ms > now_ms.saturating_add(MAX_CLOCK_AHEAD_MS) {
        return Err(problem(LinkProblem::Future));
    }
    let ends_link_issued_at_ms = match &ends_link_issued_at {
        Some(ends) => Some(
            parse_time(ends)
                .filter(|ends| *ends < issued_at_ms)
                .ok_or(problem(LinkProblem::EndsLink))?,
        ),
        None => None,
    };
    let mismatch =
        |wanted: Option<&str>, actual: &str| wanted.is_some_and(|wanted| wanted != actual);
    if expected.kind.is_some_and(|wanted| wanted != kind)
        || expected.github_id.is_some_and(|wanted| wanted != github_id)
        || mismatch(expected.public_key, &public_key)
        || mismatch(expected.address, &account)
    {
        return Err(problem(LinkProblem::Mismatch));
    }
    Ok(LinkMessage {
        kind,
        network: message_network,
        github_id,
        account,
        public_key,
        issued_at,
        issued_at_ms,
        ends_link_issued_at,
        ends_link_issued_at_ms,
    })
}

/// The GitHub user id in `text`: ASCII digits without a leading zero, from 1 to
/// [`MAX_GITHUB_ID`].
fn parse_github_id(text: &str) -> Option<u64> {
    if text.is_empty() || text.len() > 16 || text.starts_with('0') {
        return None;
    }
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>()
        .ok()
        .filter(|id| (1..=MAX_GITHUB_ID).contains(id))
}

/// Milliseconds since 1970-01-01T00:00:00Z of `text` in the form `YYYY-MM-DDTHH:MM:SSZ`, a real
/// date and time.
fn parse_time(text: &str) -> Option<i64> {
    const FORM: &[u8; 20] = b"0000-00-00T00:00:00Z";
    let form = text.len() == FORM.len()
        && text.bytes().zip(FORM).all(|(byte, &want)| {
            if want == b'0' {
                byte.is_ascii_digit()
            } else {
                byte == want
            }
        });
    form.then(|| parse_rfc3339_ms(text)).flatten()
}

/// Whether `text` has a link's or a revocation's first line. Plain message signing refuses such
/// text ([`crate::message::sign`]).
pub(crate) fn is_link_text(text: &str) -> bool {
    matches!(text.split('\n').next(), Some(TITLE | REVOCATION_TITLE))
}

/// A signed link or revocation: the record a signer hands out and a verifier reads.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkRecord {
    /// The exact message.
    pub message: String,
    /// The signer's public key, lowercase hex.
    pub public_key: String,
    /// The message signature, lowercase hex.
    pub signature: String,
    /// The signature algorithm, for example `secp256k1-bip340-sha256`.
    pub algorithm: String,
    /// The network name, for example `heartwood-devnet-v90`.
    pub network: String,
}

impl LinkRecord {
    /// The record of `message` and its message signature, made by [`sign`] or by a signer
    /// elsewhere. The record is not checked; see [`verify`].
    pub fn from_signature(message: &str, signature: MessageSignature) -> LinkRecord {
        LinkRecord {
            message: message.to_owned(),
            public_key: signature.public_key,
            signature: signature.signature,
            algorithm: signature.algorithm,
            network: signature.network,
        }
    }

    /// The record's message signature.
    pub fn message_signature(&self) -> MessageSignature {
        MessageSignature {
            public_key: self.public_key.clone(),
            signature: self.signature.clone(),
            algorithm: self.algorithm.clone(),
            network: self.network.clone(),
        }
    }

    /// The record as compact JSON text: `{"message","publicKey","signature","algorithm",
    /// "network"}` in this order, no white space and no newline at the end, each text escaped as
    /// JSON requires and no further: byte for byte what JavaScript's `JSON.stringify` writes for
    /// the same object.
    pub fn to_json(&self) -> String {
        let text = |value: &str| Value::String(value.to_owned()).to_string();
        format!(
            "{{\"message\":{},\"publicKey\":{},\"signature\":{},\"algorithm\":{},\"network\":{}}}",
            text(&self.message),
            text(&self.public_key),
            text(&self.signature),
            text(&self.algorithm),
            text(&self.network),
        )
    }

    /// The record in the JSON `text`: an object with exactly the five members, each a text.
    /// The record is not verified; see [`verify`].
    pub fn from_json(text: &str) -> Result<LinkRecord, Error> {
        if text.len() > MAX_JSON_LENGTH {
            return Err(problem(LinkProblem::Json));
        }
        let value: Value = serde_json::from_str(text).map_err(|_| problem(LinkProblem::Json))?;
        LinkRecord::from_json_value(&value)
    }

    /// [`LinkRecord::from_json`] for a parsed JSON value.
    pub fn from_json_value(value: &Value) -> Result<LinkRecord, Error> {
        const MEMBERS: [&str; 5] = ["message", "publicKey", "signature", "algorithm", "network"];
        let object = value.as_object().ok_or(problem(LinkProblem::Json))?;
        if object.len() != MEMBERS.len() {
            return Err(problem(LinkProblem::Json));
        }
        let text = |key: &str| -> Result<String, Error> {
            object
                .get(key)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(problem(LinkProblem::Json))
        };
        Ok(LinkRecord {
            message: text("message")?,
            public_key: text("publicKey")?,
            signature: text("signature")?,
            algorithm: text("algorithm")?,
            network: text("network")?,
        })
    }
}

/// Sign the link or revocation `message` with `account`, at the signer's time `now_ms`
/// (milliseconds since 1970-01-01T00:00:00Z), with fresh randomness. The holder reviews the whole
/// message before this is called.
///
/// The message is first checked with [`parse`] on the network of `profile`, expecting the
/// account's own public key and address, so a message for another account or network, or one
/// issued too far ahead, is never signed.
///
/// # Errors
///
/// [`Error::InvalidLink`] with the reason when a check fails; [`Error::UnsupportedOnNetwork`]
/// without message signing, and [`Error::NetworkMismatch`] for an account of another profile.
pub fn sign(
    profile: &Profile,
    account: &Account,
    message: &str,
    now_ms: i64,
) -> Result<LinkRecord, Error> {
    sign_with(profile, account, message, now_ms, Aux::random())
}

/// [`sign`] with the auxiliary randomness `aux`. Outside tests only [`Aux::random`] exists.
pub fn sign_with(
    profile: &Profile,
    account: &Account,
    message: &str,
    now_ms: i64,
    aux: Aux,
) -> Result<LinkRecord, Error> {
    message::check_signer(profile, account)?;
    let public_key = account.public_key().to_hex();
    let address = account.address().to_string();
    let expected = LinkExpected {
        public_key: Some(&public_key),
        address: Some(&address),
        ..LinkExpected::default()
    };
    parse(profile, message, &expected, now_ms)?;
    let signature = message::signature_of(profile, account, message, aux)?;
    Ok(LinkRecord::from_signature(message, signature))
}

/// Check the signed `record` for the network of `profile`, against what the reader `expected`,
/// at the reader's time `now_ms`: its message passes [`parse`]; its public key and network are
/// the message's and its algorithm is the profile's message signature algorithm (`record`); and
/// the signature, 64 bytes in lowercase hex, verifies for the message under that key
/// (`signature`). Returns the message's fields.
pub fn verify(
    profile: &Profile,
    record: &LinkRecord,
    expected: &LinkExpected<'_>,
    now_ms: i64,
) -> Result<LinkMessage, Error> {
    let fields = parse(profile, &record.message, expected, now_ms)?;
    if record.public_key != fields.public_key
        || record.network != fields.network
        || record.algorithm != message::ALGORITHM
    {
        return Err(problem(LinkProblem::Record));
    }
    let valid = record.signature.len() == 128
        && is_lower_hex(&record.signature)
        && message::verify(&record.message, &record.message_signature());
    if !valid {
        return Err(problem(LinkProblem::Signature));
    }
    Ok(fields)
}

/// What is already recorded for a GitHub user id, an account and a network: the no-replay rule's
/// history.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Recorded {
    /// The network name.
    pub network: String,
    /// The GitHub user id.
    pub github_id: u64,
    /// The account's address.
    pub account: String,
    /// What was recorded, and when.
    pub event: RecordedEvent,
}

/// A recorded event of the no-replay rule. Only events that were verified count: a record that
/// was never verified, or that a reviewer refused, is left out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordedEvent {
    /// A link, by its issue time in milliseconds.
    Link {
        /// The link's `Issued at`.
        issued_at_ms: i64,
    },
    /// A revocation signed by the key holder, by its issue time in milliseconds.
    Revocation {
        /// The revocation's `Issued at`.
        issued_at_ms: i64,
    },
    /// A revocation by the GitHub account, by the time it was posted, in milliseconds.
    GithubUnlink {
        /// The time the GitHub account posted it.
        posted_at_ms: i64,
    },
}

impl RecordedEvent {
    /// The event's time, in milliseconds since 1970-01-01T00:00:00Z.
    pub const fn time_ms(self) -> i64 {
        match self {
            RecordedEvent::Link { issued_at_ms } | RecordedEvent::Revocation { issued_at_ms } => {
                issued_at_ms
            }
            RecordedEvent::GithubUnlink { posted_at_ms } => posted_at_ms,
        }
    }
}

impl Recorded {
    /// The history entry of the checked `message`, once it is verified.
    pub fn of(message: &LinkMessage) -> Recorded {
        let issued_at_ms = message.issued_at_ms;
        Recorded {
            network: message.network.clone(),
            github_id: message.github_id,
            account: message.account.clone(),
            event: match message.kind {
                LinkKind::Link => RecordedEvent::Link { issued_at_ms },
                LinkKind::Revocation => RecordedEvent::Revocation { issued_at_ms },
            },
        }
    }
}

/// The no-replay rule for the checked `message` against the `recorded` history: only the entries
/// of its GitHub user id, account and network count. The message is accepted only when its issue
/// time is later than every one of theirs (`replay`), and a revocation only when it names the
/// issue time of a recorded link (`unknown-link`). Reading the same record again is not a replay:
/// leave a record's own entry out of `recorded` when it is checked again.
pub fn check_history(message: &LinkMessage, recorded: &[Recorded]) -> Result<(), Error> {
    let same = || {
        recorded.iter().filter(|entry| {
            entry.network == message.network
                && entry.github_id == message.github_id
                && entry.account == message.account
        })
    };
    let barrier = same().map(|entry| entry.event.time_ms()).max();
    if barrier.is_some_and(|barrier| message.issued_at_ms <= barrier) {
        return Err(problem(LinkProblem::Replay));
    }
    if let Some(ends) = message.ends_link_issued_at_ms {
        let named = RecordedEvent::Link { issued_at_ms: ends };
        if !same().any(|entry| entry.event == named) {
            return Err(problem(LinkProblem::UnknownLink));
        }
    }
    Ok(())
}
