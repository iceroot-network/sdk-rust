//! The plugin's commands: the SDK's TypeScript interface, natively.
//!
//! Each command reads the same arguments and writes the same answers as the WebAssembly module's
//! export of the same function, through the shared bindings (`iceroot-sdk-bindings`), so the
//! TypeScript guest code (`@iceroot-network/sdk/tauri`) converts them with the same code as the
//! WebAssembly wrapper. Bytes cross as lowercase hex, secrets as UTF-8 bytes, structured values as
//! JSON text; keys, Solar keys, chains and connected networks stay in the plugin and cross as
//! numbers ([`crate::state`]).
//!
//! Commands whose work is slow on purpose (the keystore's Argon2id, key derivation) run on a
//! blocking thread, so the application's async runtime keeps serving other calls.

use std::collections::BTreeMap;
use std::sync::Arc;

use iceroot_sdk::amount::FormatOptions;
use iceroot_sdk::transaction::Operation;
use iceroot_sdk::{Aux, Chain, Draft, Profile, SignedTransaction};
use iceroot_sdk_bindings::keys::Key;
use iceroot_sdk_bindings::ownership::ProofKey;
use iceroot_sdk_bindings::{
    address, amount, chain as chains, draft as drafts, keystore, messages, ownership, phrase,
    profile as profiles, signin, vote,
};
use serde::Serialize;
use tauri::ipc::{CommandScope, GlobalScope};
use tauri::{Runtime, State, Webview, command};
use zeroize::Zeroizing;

use crate::codec::{Secret, SecretBytes, SecretText, from_hex, to_hex};
use crate::error::{Error, Result};
use crate::network::{AtNext, ConnectOptions, RelayScope, Session, SignedSource, relay_allowed};
use crate::state::{Iceroot, Page};

/// Runs `f` on a blocking thread and waits for it.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|error| Error::argument(format!("the call did not complete: {error}")))?
}

fn profile(json: &str) -> Result<Profile> {
    Ok(profiles::from_json(json)?)
}

/// The page `webview` shows now, recorded with the window it is in.
fn page_of<R: Runtime>(state: &Iceroot, webview: &Webview<R>) -> Page {
    state.page(webview.label(), webview.window().label())
}

// ---- the plugin ---------------------------------------------------------------------------------

/// The plugin's version, and whether it was built with the test seams.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Version {
    plugin: &'static str,
    test_seams: bool,
}

/// The plugin's version.
#[command]
pub(crate) async fn version() -> Result<Version> {
    Ok(Version {
        plugin: env!("CARGO_PKG_VERSION"),
        test_seams: cfg!(feature = "test-seams"),
    })
}

// ---- profiles, phrases, addresses, amounts, messages, sign-in -----------------------------------

/// The capabilities of a profile (JSON), by name.
#[command]
pub(crate) async fn profile_capabilities(profile: String) -> Result<Vec<String>> {
    Ok(profiles::capabilities(&self::profile(&profile)?))
}

/// The network name message signatures carry on the network of a profile.
#[command]
pub(crate) async fn profile_message_network(profile: String) -> Result<String> {
    Ok(profiles::message_network(&self::profile(&profile)?)?)
}

/// The algorithm of message signatures on the network of a profile.
#[command]
pub(crate) async fn profile_message_algorithm(profile: String) -> Result<String> {
    Ok(profiles::message_algorithm(&self::profile(&profile)?)?)
}

/// A new 24-word recovery phrase, to show the holder once to write down. The plugin's copy of the
/// answer is overwritten with zeros once it is written into the IPC message.
#[command]
pub(crate) async fn phrase_generate() -> Result<SecretText> {
    let mnemonic = phrase::generate_phrase()?;
    Ok(SecretText(Zeroizing::new(mnemonic.phrase().to_owned())))
}

/// What is wrong with `text` as a recovery phrase, in JSON.
#[command]
pub(crate) async fn phrase_check(text: Secret) -> Result<String> {
    Ok(phrase::check_phrase(text.into_string("the phrase")?))
}

/// The bytes (hex) of an address of the network of a profile.
#[command]
pub(crate) async fn address_parse(text: String, profile: String) -> Result<String> {
    let bytes = address::parse_address(&text, &self::profile(&profile)?)?;
    Ok(to_hex(&bytes))
}

/// The address of a public key (hex) on the network of a profile.
#[command]
pub(crate) async fn address_from_public_key(public_key: String, profile: String) -> Result<String> {
    let key = from_hex(&public_key, "the public key").map_err(|_| {
        Error::from(iceroot_sdk_bindings::BindingError::new(
            "InvalidKey",
            "the public key is not hex",
        ))
    })?;
    Ok(address::address_from_public_key(
        &key,
        &self::profile(&profile)?,
    )?)
}

/// The base units of a decimal amount, as a decimal string.
#[command]
pub(crate) async fn amount_parse(text: String, decimals: u8) -> Result<String> {
    Ok(amount::parse_amount(&text, decimals)?)
}

/// Base units as decimal text.
#[command]
pub(crate) async fn amount_format(
    units: String,
    decimals: u8,
    max_fraction: Option<u8>,
    grouping: bool,
) -> Result<String> {
    Ok(amount::format_amount(
        &units,
        decimals,
        max_fraction,
        grouping,
    )?)
}

/// Whether a message signature verifies; never a refusal for malformed input.
#[command]
pub(crate) async fn message_verify(
    message: String,
    public_key: String,
    signature: String,
    algorithm: String,
) -> Result<bool> {
    let message = from_hex(&message, "the message")?;
    Ok(messages::verify_message(
        &message,
        &public_key,
        &signature,
        &algorithm,
    ))
}

/// The sign-in message of a request (JSON) on the network of a profile.
#[command]
pub(crate) async fn signin_build(profile: String, request: String) -> Result<String> {
    Ok(signin::build_sign_in(&self::profile(&profile)?, &request)?)
}

/// The checked fields of a sign-in message, in JSON.
#[command]
pub(crate) async fn signin_parse(
    profile: String,
    message: String,
    expected: String,
    now_ms: f64,
) -> Result<String> {
    Ok(signin::parse_sign_in(
        &self::profile(&profile)?,
        &message,
        &expected,
        now_ms,
    )?)
}

// ---- keys -----------------------------------------------------------------------------------

/// A key the plugin holds, as the webview sees it: its number and public facts.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyInfo {
    key: u64,
    address: String,
    public_key: String,
    algorithm: String,
    legacy: bool,
    path: Option<String>,
}

fn hold_key(state: &Iceroot, page: &Page, key: Key) -> Result<KeyInfo> {
    let info = KeyInfo {
        key: 0,
        address: key.address()?,
        public_key: to_hex(&key.public_key()?),
        algorithm: key.algorithm()?,
        legacy: key.legacy(),
        path: key.path(),
    };
    Ok(KeyInfo {
        key: state.add_key(page, key)?,
        ..info
    })
}

/// The account at `account` and `index` of a recovery phrase, held by the plugin.
#[command]
pub(crate) async fn key_from_phrase<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    profile: String,
    phrase: Secret,
    account: u32,
    index: u32,
    passphrase: Secret,
) -> Result<KeyInfo> {
    let page = page_of(&state, &webview);
    let profile = self::profile(&profile)?;
    let key = blocking(move || {
        let (mut phrase, passphrase) = (phrase, passphrase);
        let passphrase = passphrase.into_string("the passphrase")?;
        Ok(Key::from_phrase_bytes(
            &profile,
            phrase.bytes_mut(),
            account,
            index,
            passphrase,
        )?)
    })
    .await?;
    hold_key(&state, &page, key)
}

/// The reference implementation's passphrase key, held by the plugin (devnet profiles only).
#[command]
pub(crate) async fn key_from_legacy_passphrase<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    profile: String,
    passphrase: Secret,
) -> Result<KeyInfo> {
    let page = page_of(&state, &webview);
    let profile = self::profile(&profile)?;
    let mut passphrase = passphrase;
    let key = Key::from_legacy_passphrase_bytes(&profile, passphrase.bytes_mut())?;
    hold_key(&state, &page, key)
}

/// The account at `account` and `index` of the recovery phrase a keystore holds, opened with
/// `password` and derived in the plugin: the phrase never enters the webview.
#[command]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn key_from_keystore<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    profile: String,
    keystore: String,
    password: Secret,
    account: u32,
    index: u32,
    passphrase: Secret,
    max_memory_kib: Option<u32>,
) -> Result<KeyInfo> {
    let page = page_of(&state, &webview);
    let profile = self::profile(&profile)?;
    let stored = from_hex(&keystore, "the keystore")?;
    let key = blocking(move || {
        let (mut password, passphrase) = (password, passphrase);
        let passphrase = passphrase.into_string("the passphrase")?;
        Ok(Key::from_keystore(
            &profile,
            &stored,
            password.bytes_mut(),
            account,
            index,
            passphrase,
            max_memory_kib,
        )?)
    })
    .await?;
    hold_key(&state, &page, key)
}

/// A message signature (JSON) with a key the plugin holds; the message is hex.
#[command]
pub(crate) async fn key_sign_message<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    key: u64,
    message: String,
) -> Result<String> {
    let message = from_hex(&message, "the message")?;
    state.with_key(webview.label(), key, |key| Ok(key.sign_message(&message)?))
}

/// A sign-in message's signature (JSON) with a key the plugin holds, for the website of `origin`
/// (as the webview reports it) at `now_ms`: the message is checked against that origin and the
/// key's public key and address first, as `signin_parse` checks it, and signed only if every check
/// passes.
#[command]
pub(crate) async fn key_sign_sign_in<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    key: u64,
    message: String,
    origin: String,
    now_ms: f64,
) -> Result<String> {
    state.with_key(webview.label(), key, |key| {
        Ok(key.sign_sign_in(&message, &origin, now_ms)?)
    })
}

/// Wipes a key the plugin holds. Nothing happens for a key already released.
#[command]
pub(crate) async fn key_release<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    key: u64,
) -> Result<()> {
    state.release_key(webview.label(), key);
    Ok(())
}

// ---- chains ---------------------------------------------------------------------------------

/// A chain the plugin holds, as the webview sees it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChainInfo {
    chain: u64,
    /// The profile, with the network hash pinned, as the wrapper's profile object in JSON.
    profile: String,
    nethash: String,
    network_byte: u8,
    /// The network's own asset, in the JSON of the WebAssembly module's `ChainHandle.token`.
    token: String,
    /// The profile's capabilities, by name.
    capabilities: Vec<String>,
}

pub(crate) fn chain_info(id: u64, chain: &Chain) -> ChainInfo {
    ChainInfo {
        chain: id,
        profile: profiles::to_json(chain.profile()),
        nethash: chain.nethash().to_owned(),
        network_byte: chain.network_byte(),
        token: chains::token(chain),
        capabilities: profiles::capabilities(chain.profile()),
    }
}

/// Loads the crypto configuration a node reports for a profile, and holds the chain.
#[command]
pub(crate) async fn chain_load<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    profile: String,
    configuration: String,
) -> Result<ChainInfo> {
    let page = page_of(&state, &webview);
    let chain = chains::load(&self::profile(&profile)?, &configuration)?;
    let info = chain_info(0, &chain);
    let id = state.add_chain(&page, Arc::new(chain))?;
    Ok(ChainInfo { chain: id, ..info })
}

/// The format stage at a height.
#[command]
pub(crate) async fn chain_stage_at<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    chain: u64,
    height: u32,
) -> Result<String> {
    let chain = state.chain(webview.label(), chain)?;
    Ok(chains::stage_at(&chain, height))
}

/// The rules at a height, in JSON.
#[command]
pub(crate) async fn chain_rules<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    chain: u64,
    height: u32,
) -> Result<String> {
    let chain = state.chain(webview.label(), chain)?;
    Ok(chains::rules(&chain, height))
}

/// The economics at a height, in JSON.
#[command]
pub(crate) async fn chain_economics<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    chain: u64,
    height: u32,
) -> Result<String> {
    let chain = state.chain(webview.label(), chain)?;
    Ok(chains::economics(&chain, height))
}

/// Drops a chain the plugin holds.
#[command]
pub(crate) async fn chain_free<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    chain: u64,
) -> Result<()> {
    state.free_chain(webview.label(), chain);
    Ok(())
}

// ---- drafts and signed transactions -----------------------------------------------------------

/// A draft as the webview holds it: serialized, with what the review screen shows.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DraftInfo {
    /// The draft serialized ([`Draft::serialize`]), as hex: signing sends it back.
    bytes: String,
    /// The summary, in the JSON of the WebAssembly module's `DraftHandle.summary`.
    summary: String,
    /// The unsigned bytes, as hex.
    unsigned_bytes: String,
    /// Each amount of the summary (base units) as the review screen writes it, with the token's
    /// decimals.
    amounts: BTreeMap<String, String>,
    /// The chain of a draft deserialized for a profile, which the plugin now holds; absent for a
    /// draft built on a chain or read on a connection's chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    chain: Option<ChainInfo>,
}

fn draft_info(draft: &Draft, chain: Option<ChainInfo>) -> DraftInfo {
    let summary = draft.summary();
    let decimals = draft.chain().token().decimals;
    let mut amounts = BTreeMap::new();
    let mut add = |value: iceroot_sdk::Amount| {
        amounts.insert(
            value.base_units().to_string(),
            value.format(decimals, FormatOptions::default()),
        );
    };
    match &summary.operation {
        Operation::Transfer { recipients } => recipients.iter().for_each(|r| add(r.amount)),
        Operation::Burn { amount } => add(*amount),
        _ => {}
    }
    add(summary.fee.amount);
    DraftInfo {
        bytes: to_hex(&draft.serialize()),
        summary: drafts::summary(draft),
        unsigned_bytes: to_hex(draft.unsigned_bytes()),
        amounts,
        chain,
    }
}

/// A signed transaction as the webview holds it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignedInfo {
    /// The transaction serialized ([`SignedTransaction::serialize`]), as hex.
    serialized: String,
    /// The transaction's own bytes, as a node takes them, as hex.
    transaction: String,
    id: String,
    /// The node's JSON form.
    json: String,
    /// The summary, in the JSON of the WebAssembly module's `SignedHandle.summary`.
    summary: String,
    verified: bool,
    height: u32,
}

fn signed_info(signed: &SignedTransaction) -> SignedInfo {
    SignedInfo {
        serialized: to_hex(&signed.serialize()),
        transaction: to_hex(signed.bytes()),
        id: signed.id(),
        json: signed.json().to_string(),
        summary: drafts::signed_summary(signed),
        verified: signed.is_verified(),
        height: signed.height(),
    }
}

/// The draft of a request on a chain the plugin holds, with the facts the node reported.
#[command]
pub(crate) async fn draft_build<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    chain: u64,
    request: String,
    facts: String,
) -> Result<DraftInfo> {
    let chain = state.chain(webview.label(), chain)?;
    let draft = drafts::build(&chain, &request, &facts)?;
    Ok(draft_info(&draft, None))
}

/// A serialized draft for a profile, with its chain, which the plugin now holds; or, with
/// `session`, read on the chain of that connected network (see [`read_draft`]).
#[command]
pub(crate) async fn draft_deserialize<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    bytes: String,
    profile: String,
    session: Option<u64>,
) -> Result<DraftInfo> {
    read_draft(
        &state,
        webview.label(),
        webview.window().label(),
        &bytes,
        &profile,
        session,
    )
}

/// The serialized draft `bytes` (hex), for the webview `label` in the window `window`.
///
/// With `session`, a network the webview connected, the draft is read on that connection's
/// chain, which a relay of the profile served, at the connection's next height: a draft built
/// under another network configuration is refused with `NetworkMismatch` (`details.reason`:
/// `configuration`), a fee at the floor of the draft's height reads `floor` when the floor at the
/// connection's next height is the same and `unverified` when a change of the fee table lies
/// between them, and the draft's chain is the connection's, so none is added.
/// Otherwise the draft is read for `profile` under the configuration it carries, whose fee table
/// the pinned network hash does not cover: such a fee reads `unverified`, and the draft's chain
/// is held for the webview and described.
pub(crate) fn read_draft(
    state: &Iceroot,
    label: &str,
    window: &str,
    bytes: &str,
    profile: &str,
    session: Option<u64>,
) -> Result<DraftInfo> {
    if let Some(session) = session {
        let session = state.session(label, session)?;
        let draft = drafts::deserialize_at(
            &from_hex(bytes, "the draft")?,
            &session.chain,
            session.next_height(),
        )?;
        return Ok(draft_info(&draft, None));
    }
    let page = state.page(label, window);
    let draft = drafts::deserialize(&from_hex(bytes, "the draft")?, &self::profile(profile)?)?;
    let chain = Arc::new(draft.chain().clone());
    let id = state.add_chain(&page, Arc::clone(&chain))?;
    Ok(draft_info(&draft, Some(chain_info(id, &chain))))
}

/// The facts of a draft from what the node reported, in JSON.
#[command]
pub(crate) async fn draft_online_facts<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    chain: u64,
    sender: String,
    account: Option<String>,
    status: String,
) -> Result<String> {
    let chain = state.chain(webview.label(), chain)?;
    Ok(drafts::online_facts(
        &chain,
        &sender,
        account.as_deref(),
        &status,
    )?)
}

/// Signs a serialized draft for a profile with keys the plugin holds. The draft is read again
/// here, so the signature covers what the plugin read, not what the webview said it was.
pub(crate) fn sign_draft(
    state: &Iceroot,
    label: &str,
    bytes: &str,
    profile: &str,
    key: u64,
    second_key: Option<u64>,
    aux: Aux,
) -> Result<SignedInfo> {
    let draft = drafts::deserialize(&from_hex(bytes, "the draft")?, &self::profile(profile)?)?;
    state.with_keys(label, key, second_key, |key, second| {
        let signed = drafts::sign(&draft, key, second, aux)?;
        Ok(signed_info(&signed))
    })
}

/// Signs a serialized draft for a profile with keys the plugin holds, with fresh randomness.
#[command]
pub(crate) async fn draft_sign<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    bytes: String,
    profile: String,
    key: u64,
    second_key: Option<u64>,
) -> Result<SignedInfo> {
    sign_draft(
        &state,
        webview.label(),
        &bytes,
        &profile,
        key,
        second_key,
        Aux::random(),
    )
}

/// A serialized signed transaction for a profile; the sender's signature must verify.
#[command]
pub(crate) async fn signed_deserialize(bytes: String, profile: String) -> Result<SignedInfo> {
    let signed = drafts::signed_deserialize(
        &from_hex(&bytes, "the signed transaction")?,
        &self::profile(&profile)?,
    )?;
    Ok(signed_info(&signed))
}

/// A transaction in the node's JSON form, read under a chain the plugin holds at a height.
#[command]
pub(crate) async fn signed_from_json<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    chain: u64,
    json: String,
    height: u32,
) -> Result<SignedInfo> {
    let chain = state.chain(webview.label(), chain)?;
    Ok(signed_info(&drafts::signed_from_json(
        &chain, &json, height,
    )?))
}

/// A transaction's bytes (hex), read under a chain the plugin holds at a height.
#[command]
pub(crate) async fn signed_decode<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    chain: u64,
    bytes: String,
    height: u32,
) -> Result<SignedInfo> {
    let chain = state.chain(webview.label(), chain)?;
    let bytes = from_hex(&bytes, "the transaction")?;
    Ok(signed_info(&drafts::signed_decode(&chain, &bytes, height)?))
}

/// Whether the second signature of a signed transaction verifies for a public key (hex).
#[command]
pub(crate) async fn signed_verify_second_signature<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    source: SignedSource,
    public_key: String,
) -> Result<bool> {
    let signed = source.resolve(&state, webview.label())?;
    Ok(drafts::verify_second_signature(&signed, &public_key))
}

// ---- networks -------------------------------------------------------------------------------

/// A connection, as the webview sees it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Connection {
    session: u64,
    chain: ChainInfo,
    /// The node's configuration, in the client's JSON.
    configuration: String,
    /// The node's status, in the client's JSON.
    status: String,
    at: AtNext,
}

/// Connects to the network of a profile through the relays the application's capabilities
/// allow.
#[command]
pub(crate) async fn net_connect<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    command_scope: CommandScope<RelayScope>,
    global_scope: GlobalScope<RelayScope>,
    profile: String,
    options: Option<ConnectOptions>,
) -> Result<Connection> {
    let profile = self::profile(&profile)?;
    let allows: Vec<_> = command_scope
        .allows()
        .iter()
        .chain(global_scope.allows())
        .cloned()
        .collect();
    let denies: Vec<_> = command_scope
        .denies()
        .iter()
        .chain(global_scope.denies())
        .cloned()
        .collect();
    for relay in crate::network::relays(&profile)? {
        if !relay_allowed(relay.as_str(), &allows, &denies) {
            return Err(Error::relay_not_allowed(relay.as_str()));
        }
    }
    let page = page_of(&state, &webview);
    let connected = Session::connect(&profile, options.unwrap_or_default()).await?;
    let session = connected.session;
    let at = AtNext::of(&session.chain, session.height());
    let session = Arc::new(session);
    let (id, chain_id) = state.add_session(&page, Arc::clone(&session))?;
    let chain = chain_info(chain_id, &session.chain);
    Ok(Connection {
        session: id,
        chain,
        configuration: connected.configuration,
        status: connected.status,
        at,
    })
}

/// A read's answer and the node's height.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReadAnswer {
    /// The answer, in the client's JSON.
    answer: String,
    /// The node's height, as a decimal string: that of its last status, or a higher one a
    /// successful answer reported since. After a status read it may be lower than before, and
    /// the page follows it down.
    height: String,
    /// The rules at the next block, when the height differs from the one the webview knew.
    #[serde(skip_serializing_if = "Option::is_none")]
    at: Option<AtNext>,
}

fn at_if_moved(session: &Session, known: Option<&str>) -> (String, Option<AtNext>) {
    let height = session.height();
    let text = height.to_string();
    let moved = known != Some(text.as_str());
    (text, moved.then(|| AtNext::of(&session.chain, height)))
}

/// Reads an operation of the node API (as the WebAssembly module's `ApiCall` prepares it).
#[command]
pub(crate) async fn net_read<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    session: u64,
    operation: String,
    args: String,
    known_height: Option<String>,
) -> Result<ReadAnswer> {
    let session = state.session(webview.label(), session)?;
    let answer = session.read(&operation, &args).await?;
    let (height, at) = at_if_moved(&session, known_height.as_deref());
    Ok(ReadAnswer { answer, height, at })
}

/// Reads the node's configuration again, refusing a node that now serves another chain.
#[command]
pub(crate) async fn net_node_configuration<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    session: u64,
    known_height: Option<String>,
) -> Result<ReadAnswer> {
    let session = state.session(webview.label(), session)?;
    let answer = session.node_configuration().await?;
    let (height, at) = at_if_moved(&session, known_height.as_deref());
    Ok(ReadAnswer { answer, height, at })
}

/// Submits signed transactions within the pool's limits; the report in JSON.
#[command]
pub(crate) async fn net_submit<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    session: u64,
    transactions: Vec<SignedSource>,
    known_height: Option<String>,
) -> Result<ReadAnswer> {
    let label = webview.label();
    let session = state.session(label, session)?;
    let signed = transactions
        .iter()
        .map(|source| source.resolve(&state, label))
        .collect::<Result<Vec<_>>>()?;
    let answer = session.submit(&signed).await?;
    let (height, at) = at_if_moved(&session, known_height.as_deref());
    Ok(ReadAnswer { answer, height, at })
}

/// Closes a connection: the plugin drops its client. The connection's chain stays until the page
/// frees it (`chain_free`), since drafts and snapshots may still use it.
#[command]
pub(crate) async fn net_close<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    session: u64,
) -> Result<()> {
    state.close_session(webview.label(), session);
    Ok(())
}

// ---- the vote library -----------------------------------------------------------------------

/// One of the vote library's JSON functions, as the WebAssembly module's `voteCall`.
#[command]
pub(crate) async fn vote_call(
    operation: String,
    first: String,
    second: String,
    third: String,
) -> Result<String> {
    blocking(move || Ok(vote::vote_call(&operation, &first, &second, &third)?)).await
}

/// The vote rules at a height of a chain the plugin holds, in JSON.
#[command]
pub(crate) async fn vote_rules_at<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    chain: u64,
    height: u32,
) -> Result<String> {
    let chain = state.chain(webview.label(), chain)?;
    Ok(vote::vote_rules_at(&chain, height))
}

/// A vote snapshot of a node's validator list, in JSON.
#[command]
pub(crate) async fn vote_snapshot_from_validators<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    chain: u64,
    height: u32,
    validators: String,
    lookups: String,
) -> Result<String> {
    let chain = state.chain(webview.label(), chain)?;
    Ok(vote::vote_snapshot_from_validators(
        &chain,
        height,
        &validators,
        &lookups,
    )?)
}

// ---- the keystore ---------------------------------------------------------------------------

/// A new keystore (hex) of a recovery phrase under a password.
#[command]
pub(crate) async fn keystore_encrypt(
    phrase: Secret,
    password: Secret,
    params: String,
) -> Result<String> {
    blocking(move || {
        let (mut phrase, mut password) = (phrase, password);
        let stored = keystore::keystore_encrypt(phrase.bytes_mut(), password.bytes_mut(), &params)?;
        Ok(to_hex(&stored))
    })
    .await
}

/// The recovery phrase a keystore holds, as UTF-8 bytes. Prefer `key_from_keystore`, which opens
/// keys without the phrase entering the webview.
#[command]
pub(crate) async fn keystore_decrypt(
    keystore: String,
    password: Secret,
    max_memory_kib: Option<u32>,
) -> Result<SecretBytes> {
    let stored = from_hex(&keystore, "the keystore")?;
    blocking(move || {
        let mut password = password;
        let mnemonic =
            self::keystore::keystore_decrypt(&stored, password.bytes_mut(), max_memory_kib)?;
        Ok(SecretBytes(Zeroizing::new(
            mnemonic.phrase().as_bytes().to_vec(),
        )))
    })
    .await
}

/// A keystore's header, in JSON.
#[command]
pub(crate) async fn keystore_inspect(keystore: String) -> Result<String> {
    Ok(self::keystore::keystore_inspect(&from_hex(
        &keystore,
        "the keystore",
    )?)?)
}

/// The keystore encrypted again under a new password. `max_memory_kib` lowers the memory the old
/// keystore and the new parameters may ask for, as for `keystore_decrypt`.
#[command]
pub(crate) async fn keystore_change_password(
    keystore: String,
    old_password: Secret,
    new_password: Secret,
    params: String,
    max_memory_kib: Option<u32>,
) -> Result<String> {
    let stored = from_hex(&keystore, "the keystore")?;
    blocking(move || {
        let (mut old, mut new) = (old_password, new_password);
        let changed = self::keystore::keystore_change_password_with_bounds(
            &stored,
            old.bytes_mut(),
            new.bytes_mut(),
            &params,
            max_memory_kib,
        )?;
        Ok(to_hex(&changed))
    })
    .await
}

/// The keystore encrypted again under the same password with new parameters. `max_memory_kib`
/// as for `keystore_change_password`.
#[command]
pub(crate) async fn keystore_reencrypt(
    keystore: String,
    password: Secret,
    params: String,
    max_memory_kib: Option<u32>,
) -> Result<String> {
    let stored = from_hex(&keystore, "the keystore")?;
    blocking(move || {
        let mut password = password;
        let changed = self::keystore::keystore_reencrypt_with_bounds(
            &stored,
            password.bytes_mut(),
            &params,
            max_memory_kib,
        )?;
        Ok(to_hex(&changed))
    })
    .await
}

/// The text form of a keystore.
#[command]
pub(crate) async fn keystore_armor(keystore: String) -> Result<String> {
    Ok(self::keystore::keystore_armor(&from_hex(
        &keystore,
        "the keystore",
    )?))
}

/// The bytes (hex) of a keystore's text form.
#[command]
pub(crate) async fn keystore_dearmor(text: String) -> Result<String> {
    Ok(to_hex(&self::keystore::keystore_dearmor(&text)?))
}

/// Checks keystore parameters (JSON) against the format's bounds.
#[command]
pub(crate) async fn keystore_check_params(
    params: String,
    max_memory_kib: Option<u32>,
) -> Result<()> {
    Ok(self::keystore::keystore_check_params(
        &params,
        max_memory_kib,
    )?)
}

/// Whether keystore parameters are weaker than others.
#[command]
pub(crate) async fn keystore_is_weaker(params: String, than: String) -> Result<bool> {
    Ok(self::keystore::keystore_is_weaker(&params, &than)?)
}

// ---- ownership proofs -----------------------------------------------------------------------

/// One of the ownership proof functions, as the WebAssembly module's `ownershipCall`.
#[command]
pub(crate) async fn ownership_call(
    operation: String,
    first: String,
    second: String,
    now_ms: f64,
) -> Result<String> {
    Ok(ownership::ownership_call(
        &operation, &first, &second, now_ms,
    )?)
}

/// A Solar key the plugin holds, as the webview sees it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProofKeyInfo {
    key: u64,
    address: String,
    public_key: String,
}

/// The Solar key of a passphrase, held by the plugin.
#[command]
pub(crate) async fn proof_key_from_passphrase<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    passphrase: Secret,
) -> Result<ProofKeyInfo> {
    let mut passphrase = passphrase;
    let key = ProofKey::from_passphrase(passphrase.bytes_mut())?;
    let page = page_of(&state, &webview);
    let address = key.address()?;
    let public_key = key.public_key()?;
    Ok(ProofKeyInfo {
        key: state.add_proof_key(&page, key)?,
        address,
        public_key,
    })
}

/// An ownership proof (JSON) signed with a Solar key the plugin holds.
#[command]
pub(crate) async fn proof_key_sign<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    key: u64,
    message: String,
    now_ms: f64,
) -> Result<String> {
    state.with_proof_key(webview.label(), key, |key| {
        Ok(key.sign_proof(&message, now_ms)?)
    })
}

/// Wipes a Solar key the plugin holds.
#[command]
pub(crate) async fn proof_key_release<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    key: u64,
) -> Result<()> {
    state.release_proof_key(webview.label(), key);
    Ok(())
}
