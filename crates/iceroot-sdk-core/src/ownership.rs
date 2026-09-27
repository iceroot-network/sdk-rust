//! Ownership proofs of Solar addresses, version 1.
//!
//! A holder of a Solar address proves control of it by signing a fixed message with the address's
//! key. The message names the address and the IceRoot account its holding should be bound to. It
//! is signed as the reference implementation signs any message: BIP340 Schnorr over the SHA-256
//! of the message's UTF-8 bytes, algorithm `secp256k1-bip340-sha256`. The Solar network no longer
//! runs, so a proof moves nothing and authorizes no transaction; what a proof is accepted for is
//! decided by the process that asks for it. `docs/ownership-proofs.md` specifies the format.
//!
//! The message has exactly nine lines, separated by `\n` with no newline at the end, of printable
//! ASCII only (so a Ledger can display every character), and at most 1,024 characters:
//!
//! ```text
//! IceRoot migration ownership proof
//! Version: 1
//! Source network: solar-mainnet
//! Source address: <Solar mainnet address>
//! IceRoot account: <ice1... or tice1..., in lowercase>
//! Nonce: <64 lowercase hex digits>
//! Issued at: <UTC time as YYYY-MM-DDTHH:MM:SSZ or YYYY-MM-DDTHH:MM:SS.sssZ>
//! Statement: I control the source address above and ask for its holding to be bound to the IceRoot account above.
//! No transaction or transfer is authorized.
//! ```
//!
//! A signed proof is the JSON object `{type, version, network, address, publicKey, algorithm,
//! message, signature}` ([`OwnershipProof`]). It verifies when its message is valid and names
//! `address`, `address` is the Solar mainnet address of `publicKey` (network byte 63), and the
//! signature verifies for the message ([`verify`]).
//!
//! - [`build`] writes a message; [`parse`] checks one, as a signer does before it signs and a
//!   verifier does before it checks the signature.
//! - [`SolarKey`] is a Solar key from its passphrase; [`sign`] signs a message with it.
//! - A key held elsewhere, such as on a Ledger, signs the message there;
//!   [`OwnershipProof::from_signature`] checks the device's signature and makes the proof.
//! - [`verify`] checks a signed proof, and [`OwnershipProof::from_json`] and
//!   [`OwnershipProof::to_json`] read and write its JSON.
//!
//! The IceRoot Legacy Signer signs these proofs, and the SDK's vectors check these functions
//! against its format checks and the reference implementation's keys, addresses and signatures.
//! Where the SDK is stricter, no proof a correct signer makes is refused: the source address must
//! also have a valid checksum and network byte 63, and the issue time must be a real date and
//! time (JavaScript's `Date.parse` rolls 30 February over into March and reads 24:00:00 as the
//! next midnight). [`IceRootAccount::parse`] also refuses a typed account with a character
//! outside ASCII.
//!
//! These functions need no network profile: the source network is always Solar mainnet, and the
//! IceRoot account is written in the IceRoot address format, whatever network the SDK is used
//! with.

use std::fmt;

use heartwood_crypto::Aux;
use heartwood_crypto::crypto::hash::sha256;
use heartwood_crypto::crypto::sig::Signature;
use heartwood_crypto::identities::{KeyPair, PublicKey, SecretKey};
use serde_json::{Value, json};

use crate::address::Address;
use crate::error::{Error, ProofProblem};
use crate::message::{self, compressed_key};
use crate::time::{format_rfc3339_millis, parse_rfc3339_ms};
use crate::utils::is_lower_hex;

/// The `type` of a signed proof.
pub const PROOF_TYPE: &str = "iceroot-migration-ownership-proof";
/// The `version` of a signed proof and of its message.
pub const VERSION: u64 = 1;
/// The source network, in the message and as the `network` of a signed proof.
pub const SOURCE_NETWORK: &str = "solar-mainnet";
/// The network byte of Solar mainnet addresses.
pub const SOLAR_NETWORK_BYTE: u8 = 63;
/// The `algorithm` of a signed proof: the reference implementation's message signatures.
pub const ALGORITHM: &str = message::ALGORITHM;
/// The first line.
pub const TITLE: &str = "IceRoot migration ownership proof";
/// The second line.
pub const VERSION_LINE: &str = "Version: 1";
/// The eighth line.
pub const STATEMENT_LINE: &str = "Statement: I control the source address above and ask for its holding to be bound to the IceRoot account above.";
/// The last line.
pub const NO_TRANSACTION_LINE: &str = "No transaction or transfer is authorized.";
/// The longest message, in characters (all of them ASCII, so also in bytes).
pub const MAX_LENGTH: usize = 1024;
/// How far ahead of the reader's clock a message may be issued, in milliseconds.
pub const MAX_CLOCK_AHEAD_MS: i64 = 300_000;
/// The longest JSON text [`OwnershipProof::from_json`] reads, in bytes.
pub const MAX_JSON_LENGTH: usize = 16_384;

/// The labels of the field lines, from the third line on.
const SOURCE_NETWORK_LABEL: &str = "Source network: ";
const SOURCE_ADDRESS_LABEL: &str = "Source address: ";
const ACCOUNT_LABEL: &str = "IceRoot account: ";
const NONCE_LABEL: &str = "Nonce: ";
const ISSUED_AT_LABEL: &str = "Issued at: ";

fn problem(problem: ProofProblem) -> Error {
    Error::InvalidProof { problem }
}

// ------------------------------------------------------------------------------------------------
// Solar keys and addresses

/// A Solar key from its passphrase: the SHA-256 of the passphrase's UTF-8 text, as the reference
/// implementation derives it (a Solar wallet's 12-word recovery phrase is such a passphrase). The
/// key signs ownership proofs and nothing else, and is wiped when dropped or
/// [released](SolarKey::release).
pub struct SolarKey {
    keys: KeyPair,
    address: Address,
}

impl SolarKey {
    /// The key of `passphrase`, which is hashed exactly as given: any text is accepted. The
    /// IceRoot Legacy Signer trims a typed phrase and joins its words with single spaces first,
    /// which an app that reads a phrase from a text field should do the same way.
    pub fn from_passphrase(passphrase: &str) -> Result<SolarKey, Error> {
        let secret = SecretKey::from_passphrase(passphrase).map_err(|_| Error::SigningFailed {
            reason: "the passphrase gives no valid key".to_owned(),
        })?;
        let keys = KeyPair::from_secret_key(secret);
        let address = source_address(keys.public_key());
        Ok(SolarKey { keys, address })
    }

    /// The key's Solar mainnet address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// The key's public key (33 bytes, compressed).
    pub fn public_key(&self) -> &PublicKey {
        self.keys.public_key()
    }

    /// Wipe the key. Dropping it does the same; this names the moment.
    pub fn release(self) {
        drop(self);
    }
}

impl fmt::Debug for SolarKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SolarKey")
            .field("address", &self.address.to_string())
            .finish_non_exhaustive()
    }
}

/// The Solar mainnet address of `public_key`: network byte 63 and the RIPEMD-160 of the key,
/// in Base58Check. A Ledger's public key gives the address of its proofs this way.
pub fn source_address(public_key: &PublicKey) -> Address {
    Address::from_public_key_for_network_byte(public_key, SOLAR_NETWORK_BYTE)
}

/// Whether `text` has the form the format gives a Solar mainnet address: 34 Base58 characters
/// starting with `S`.
fn is_solar_address_form(text: &str) -> bool {
    text.len() == 34
        && text.starts_with('S')
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() && !matches!(byte, b'0' | b'O' | b'I' | b'l'))
}

/// The Solar mainnet address in `text`: the format's form, a valid checksum and network byte 63.
fn solar_address(text: &str) -> Result<Address, Error> {
    if !is_solar_address_form(text) {
        return Err(problem(ProofProblem::Address));
    }
    Address::parse_for_network_byte(text, SOLAR_NETWORK_BYTE)
        .map_err(|_| problem(ProofProblem::Address))
}

// ------------------------------------------------------------------------------------------------
// IceRoot accounts

/// The IceRoot network an account belongs to, by its prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccountNetwork {
    /// `ice1...`
    Mainnet,
    /// `tice1...`, the public testnet.
    Testnet,
}

impl AccountNetwork {
    /// The stable string form: `mainnet` or `testnet`.
    pub const fn as_str(self) -> &'static str {
        match self {
            AccountNetwork::Mainnet => "mainnet",
            AccountNetwork::Testnet => "testnet",
        }
    }

    /// The account prefix: `ice` or `tice`.
    pub const fn prefix(self) -> &'static str {
        match self {
            AccountNetwork::Mainnet => "ice",
            AccountNetwork::Testnet => "tice",
        }
    }
}

/// The IceRoot account a proof names: a 32-byte hash in Bech32m (BIP 350), `ice1...` on mainnet
/// and `tice1...` on the public testnet, 58 characters after the separator.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IceRootAccount {
    text: String,
    network: AccountNetwork,
    hash: [u8; 32],
}

/// The Bech32 character set.
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
/// The generator of the Bech32 checksum.
const GENERATORS: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];
/// The checksum constant of Bech32m.
const BECH32M: u32 = 0x2bc8_30a3;
/// Characters after the separator: 52 five-bit groups for 32 bytes, and 6 of checksum.
const DATA_CHARACTERS: usize = 58;
const HASH_GROUPS: usize = 52;

fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    let mut check: u32 = 1;
    for value in values {
        let top = check >> 25;
        check = ((check & 0x01ff_ffff) << 5) ^ u32::from(value);
        for (bit, generator) in GENERATORS.iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                check ^= generator;
            }
        }
    }
    check
}

/// Whether `c` is white space to JavaScript's `String.prototype.trim`.
fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\u{9}'..='\u{d}'
            | ' '
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
            | '\u{feff}'
    )
}

impl IceRootAccount {
    /// The account in `text` as a person types it: surrounding white space is removed, and an
    /// account written all in capitals is read in lowercase (as the IceRoot Legacy Signer reads
    /// its account field). The checksum catches a typing error.
    ///
    /// The white space removed is what JavaScript's `trim` removes. Inside the account only
    /// ASCII letters are read: any other character is refused, where JavaScript's `toLowerCase`
    /// would read the Kelvin sign (U+212A) as `k`.
    pub fn parse(text: &str) -> Result<IceRootAccount, Error> {
        let trimmed = text.trim_matches(is_js_space);
        if trimmed.bytes().any(|byte| byte.is_ascii_lowercase()) {
            IceRootAccount::parse_canonical(trimmed)
        } else {
            IceRootAccount::parse_canonical(&trimmed.to_ascii_lowercase())
        }
    }

    /// The account in `text` exactly as a proof message writes it: in lowercase, with nothing
    /// around it.
    pub fn parse_canonical(text: &str) -> Result<IceRootAccount, Error> {
        let (network, data) = if let Some(data) = text.strip_prefix("ice1") {
            (AccountNetwork::Mainnet, data)
        } else if let Some(data) = text.strip_prefix("tice1") {
            (AccountNetwork::Testnet, data)
        } else {
            return Err(problem(ProofProblem::Account));
        };
        let hash = decode_hash(network, data).ok_or(problem(ProofProblem::Account))?;
        Ok(IceRootAccount {
            text: text.to_owned(),
            network,
            hash,
        })
    }

    /// The account's text, in lowercase.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The network of the account's prefix.
    pub fn network(&self) -> AccountNetwork {
        self.network
    }

    /// The 32-byte hash the account encodes.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
}

impl fmt::Display for IceRootAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// The 32-byte hash in the Bech32m `data` after the separator of an account of `network`, if its
/// characters, length, checksum and spare bits are valid.
fn decode_hash(network: AccountNetwork, data: &str) -> Option<[u8; 32]> {
    if data.len() != DATA_CHARACTERS {
        return None;
    }
    let values = data
        .bytes()
        .map(|byte| {
            CHARSET
                .iter()
                .position(|&c| c == byte)
                .and_then(|value| u8::try_from(value).ok())
        })
        .collect::<Option<Vec<u8>>>()?;
    let prefix = network.prefix().as_bytes();
    let expanded = prefix
        .iter()
        .map(|byte| byte >> 5)
        .chain(std::iter::once(0))
        .chain(prefix.iter().map(|byte| byte & 31))
        .chain(values.iter().copied());
    if polymod(expanded) != BECH32M {
        return None;
    }
    // 52 five-bit groups carry the 32 bytes; the last group's 4 spare bits are zero.
    let groups = values.get(..HASH_GROUPS)?;
    if groups.last()? & 15 != 0 {
        return None;
    }
    let mut hash = [0u8; 32];
    let mut accumulator: u32 = 0;
    let mut bits = 0;
    let mut index = 0;
    for &group in groups {
        accumulator = (accumulator << 5) | u32::from(group);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            *hash.get_mut(index)? = u8::try_from((accumulator >> bits) & 0xff).ok()?;
            index += 1;
            accumulator &= (1 << bits) - 1;
        }
    }
    (index == hash.len()).then_some(hash)
}

// ------------------------------------------------------------------------------------------------
// Messages

/// What goes into a new proof message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofRequest<'a> {
    /// The Solar mainnet address whose control is proved.
    pub address: &'a Address,
    /// The IceRoot account its holding should be bound to.
    pub account: &'a IceRootAccount,
    /// The nonce: 64 lowercase hex digits. [`random_nonce`] makes one; a process that issues
    /// its own messages may choose it, for example to tie a proof to one request.
    pub nonce: &'a str,
    /// When the message is issued, in milliseconds since 1970-01-01T00:00:00Z.
    pub issued_at_ms: i64,
}

/// What a reader expects of a proof message. A signer sets the address of the key it signs
/// with; a verifier sets the address its proof names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProofExpected<'a> {
    /// The Solar mainnet address the message must name.
    pub address: Option<&'a str>,
}

/// A checked proof message's fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProofFields {
    /// The Solar mainnet address.
    pub address: String,
    /// The IceRoot account.
    pub account: IceRootAccount,
    /// The nonce.
    pub nonce: String,
    /// The issue time as the message writes it.
    pub issued_at: String,
    /// The issue time, in milliseconds since 1970-01-01T00:00:00Z.
    pub issued_at_ms: i64,
}

/// A new nonce: 64 lowercase hex digits from 32 random bytes.
pub fn random_nonce() -> Result<String, Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::RandomnessUnavailable)?;
    Ok(heartwood_crypto::utils::hex::encode(&bytes))
}

/// The proof message of `request`. The issue time is written with milliseconds, as the IceRoot
/// Legacy Signer writes it (`2026-09-01T12:00:00.000Z`).
pub fn build(request: &ProofRequest<'_>) -> Result<String, Error> {
    if request.address.network_byte() != SOLAR_NETWORK_BYTE {
        return Err(problem(ProofProblem::Address));
    }
    if request.nonce.len() != 64 || !is_lower_hex(request.nonce) {
        return Err(problem(ProofProblem::Nonce));
    }
    let issued_at =
        format_rfc3339_millis(request.issued_at_ms).ok_or(problem(ProofProblem::IssuedAt))?;
    let message = [
        TITLE.to_owned(),
        VERSION_LINE.to_owned(),
        format!("{SOURCE_NETWORK_LABEL}{SOURCE_NETWORK}"),
        format!("{SOURCE_ADDRESS_LABEL}{}", request.address),
        format!("{ACCOUNT_LABEL}{}", request.account),
        format!("{NONCE_LABEL}{}", request.nonce),
        format!("{ISSUED_AT_LABEL}{issued_at}"),
        STATEMENT_LINE.to_owned(),
        NO_TRANSACTION_LINE.to_owned(),
    ]
    .join("\n");
    // Every part is checked above; reading the message back keeps build and parse from drifting.
    parse(&message, &ProofExpected::default(), request.issued_at_ms)?;
    Ok(message)
}

/// Whether `text` has the issue time's form: `YYYY-MM-DDTHH:MM:SSZ` or
/// `YYYY-MM-DDTHH:MM:SS.sssZ`.
fn is_issue_time_form(text: &str) -> bool {
    const SECONDS: &[u8; 20] = b"0000-00-00T00:00:00Z";
    const MILLISECONDS: &[u8; 24] = b"0000-00-00T00:00:00.000Z";
    let pattern: &[u8] = match text.len() {
        20 => SECONDS,
        24 => MILLISECONDS,
        _ => return false,
    };
    text.bytes().zip(pattern).all(|(byte, &want)| {
        if want == b'0' {
            byte.is_ascii_digit()
        } else {
            byte == want
        }
    })
}

/// Check the proof `message` against what the reader `expected`, at the reader's time `now_ms`
/// (milliseconds since 1970-01-01T00:00:00Z): its fixed lines, the source network, the forms of
/// the address, account, nonce and issue time, that it was issued no more than five minutes
/// ahead of `now_ms`, and the expected address. A message issued long ago is not refused: how
/// old a proof may be is the rule of the process that asks for it.
pub fn parse(
    message: &str,
    expected: &ProofExpected<'_>,
    now_ms: i64,
) -> Result<ProofFields, Error> {
    let printable = message
        .bytes()
        .all(|byte| byte == b'\n' || (0x20..=0x7e).contains(&byte));
    if message.is_empty() || message.len() > MAX_LENGTH || !printable {
        return Err(problem(ProofProblem::Format));
    }
    let lines: Vec<&str> = message.split('\n').collect();
    let [
        title,
        version,
        network,
        address,
        account,
        nonce,
        issued_at,
        statement,
        closing,
    ] = lines.as_slice()
    else {
        return Err(problem(ProofProblem::Format));
    };
    if *title != TITLE
        || *version != VERSION_LINE
        || *statement != STATEMENT_LINE
        || *closing != NO_TRANSACTION_LINE
    {
        return Err(problem(ProofProblem::Format));
    }
    let field = |line: &'_ str, label: &str| -> Result<String, Error> {
        line.strip_prefix(label)
            .map(str::to_owned)
            .ok_or(problem(ProofProblem::Field))
    };
    let network = field(network, SOURCE_NETWORK_LABEL)?;
    let address = field(address, SOURCE_ADDRESS_LABEL)?;
    let account = field(account, ACCOUNT_LABEL)?;
    let nonce = field(nonce, NONCE_LABEL)?;
    let issued_at = field(issued_at, ISSUED_AT_LABEL)?;

    if network != SOURCE_NETWORK {
        return Err(problem(ProofProblem::SourceNetwork));
    }
    solar_address(&address)?;
    let account = IceRootAccount::parse_canonical(&account)?;
    if nonce.len() != 64 || !is_lower_hex(&nonce) {
        return Err(problem(ProofProblem::Nonce));
    }
    let issued_at_ms = is_issue_time_form(&issued_at)
        .then(|| parse_rfc3339_ms(&issued_at))
        .flatten()
        .filter(|issued| *issued <= now_ms.saturating_add(MAX_CLOCK_AHEAD_MS))
        .ok_or(problem(ProofProblem::IssuedAt))?;
    if expected.address.is_some_and(|expected| expected != address) {
        return Err(problem(ProofProblem::Mismatch));
    }
    Ok(ProofFields {
        address,
        account,
        nonce,
        issued_at,
        issued_at_ms,
    })
}

// ------------------------------------------------------------------------------------------------
// Signed proofs

/// A signed ownership proof. Its JSON form ([`OwnershipProof::to_json`]) also carries the
/// constant `type`, `version`, `network` and `algorithm`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OwnershipProof {
    /// The Solar mainnet address whose control is proved.
    pub address: String,
    /// The public key of the address, lowercase hex (33 bytes, compressed).
    pub public_key: String,
    /// The signed proof message.
    pub message: String,
    /// The BIP340 signature of the message's SHA-256, lowercase hex (64 bytes).
    pub signature: String,
}

/// Sign the proof `message` with `key`, with fresh randomness, at the signer's time `now_ms`
/// (milliseconds since 1970-01-01T00:00:00Z). The message must pass [`parse`] and name the key's
/// address; the holder reviews the whole message before this is called.
pub fn sign(key: &SolarKey, message: &str, now_ms: i64) -> Result<OwnershipProof, Error> {
    sign_with(key, message, now_ms, Aux::random())
}

/// [`sign`] with the auxiliary randomness `aux`. Outside tests only [`Aux::random`] exists.
pub fn sign_with(
    key: &SolarKey,
    message: &str,
    now_ms: i64,
    aux: Aux,
) -> Result<OwnershipProof, Error> {
    let address = key.address().to_string();
    parse(
        message,
        &ProofExpected {
            address: Some(&address),
        },
        now_ms,
    )?;
    let signature = message::sign_digest_with_keys(&key.keys, &sha256(message.as_bytes()), aux)?;
    let proof = OwnershipProof {
        address,
        public_key: key.public_key().to_hex(),
        message: message.to_owned(),
        signature: signature.to_hex(),
    };
    // As the Legacy Signer does, the signature is checked before the proof is handed out.
    verify(&proof, now_ms).map_err(|_| Error::SigningFailed {
        reason: "the proof's signature does not verify".to_owned(),
    })?;
    Ok(proof)
}

/// Check the signed `proof` at the reader's time `now_ms`: its message passes [`parse`] and names
/// the proof's address, the address is the Solar mainnet address of the public key, and the
/// signature is a BIP340 signature of the message's SHA-256 for that key. Returns the message's
/// fields.
pub fn verify(proof: &OwnershipProof, now_ms: i64) -> Result<ProofFields, Error> {
    let fields = parse(
        &proof.message,
        &ProofExpected {
            address: Some(&proof.address),
        },
        now_ms,
    )?;
    let key = compressed_key(&proof.public_key).ok_or(problem(ProofProblem::Key))?;
    if proof.signature.len() != 128 || !is_lower_hex(&proof.signature) {
        return Err(problem(ProofProblem::Signature));
    }
    if source_address(&key).to_string() != proof.address {
        return Err(problem(ProofProblem::Mismatch));
    }
    let signature =
        Signature::from_hex(&proof.signature).map_err(|_| problem(ProofProblem::Signature))?;
    if !message::verify_digest(
        &sha256(proof.message.as_bytes()),
        &signature,
        key.as_bytes(),
    ) {
        return Err(problem(ProofProblem::Signature));
    }
    Ok(fields)
}

impl OwnershipProof {
    /// The proof of `message` with a signature made elsewhere, such as on a Ledger: `public_key`
    /// and `signature` in lowercase hex. The proof's address is the one the message names, and
    /// the proof must pass [`verify`] at `now_ms`, so a device's wrong or forged signature is
    /// refused before the proof is shown.
    pub fn from_signature(
        message: &str,
        public_key: &str,
        signature: &str,
        now_ms: i64,
    ) -> Result<OwnershipProof, Error> {
        let fields = parse(message, &ProofExpected::default(), now_ms)?;
        let proof = OwnershipProof {
            address: fields.address,
            public_key: public_key.to_owned(),
            message: message.to_owned(),
            signature: signature.to_owned(),
        };
        verify(&proof, now_ms)?;
        Ok(proof)
    }

    /// The proof as a JSON value, with its fields in the order of the format.
    pub fn to_json_value(&self) -> Value {
        json!({
            "type": PROOF_TYPE,
            "version": VERSION,
            "network": SOURCE_NETWORK,
            "address": self.address,
            "publicKey": self.public_key,
            "algorithm": ALGORITHM,
            "message": self.message,
            "signature": self.signature,
        })
    }

    /// The proof as compact JSON text, as the Legacy Signer copies it.
    pub fn to_json(&self) -> String {
        self.to_json_value().to_string()
    }

    /// The signed proof in the JSON `text`: an object with exactly the format's eight fields,
    /// of the supported type, version, network and algorithm. The proof is not verified; see
    /// [`verify`].
    pub fn from_json(text: &str) -> Result<OwnershipProof, Error> {
        if text.len() > MAX_JSON_LENGTH {
            return Err(problem(ProofProblem::Json));
        }
        let value: Value = serde_json::from_str(text).map_err(|_| problem(ProofProblem::Json))?;
        OwnershipProof::from_json_value(&value)
    }

    /// [`OwnershipProof::from_json`] for a parsed JSON value.
    pub fn from_json_value(value: &Value) -> Result<OwnershipProof, Error> {
        const FIELDS: [&str; 8] = [
            "type",
            "version",
            "network",
            "address",
            "publicKey",
            "algorithm",
            "message",
            "signature",
        ];
        let json = || problem(ProofProblem::Json);
        let object = value.as_object().ok_or_else(json)?;
        if object.len() != FIELDS.len() || !FIELDS.iter().all(|key| object.contains_key(*key)) {
            return Err(json());
        }
        let text = |key: &str| object.get(key).and_then(Value::as_str).ok_or_else(json);
        let supported = text("type")? == PROOF_TYPE
            && object.get("version").and_then(Value::as_u64) == Some(VERSION)
            && text("network")? == SOURCE_NETWORK
            && text("algorithm")? == ALGORITHM;
        if !supported {
            return Err(json());
        }
        Ok(OwnershipProof {
            address: text("address")?.to_owned(),
            public_key: text("publicKey")?.to_owned(),
            message: text("message")?.to_owned(),
            signature: text("signature")?.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The IceRoot Legacy Signer's own test key and account.
    const PASSPHRASE: &str = "this is a top secret passphrase";
    const ADDRESS: &str = "SNAgA2XCRZDKfm5Vu9h4KR1bZw5xn9EiC3";
    const PUBLIC_KEY: &str = "034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192";
    const ACCOUNT: &str = "ice1q8y55x5z8dr5uepshat727uvt328lfkklzwvvmt4p42qlcrggxtsk8zw2r";
    /// 2026-09-01T12:00:00.000Z
    const ISSUED: i64 = 1_788_264_000_000;

    fn account() -> IceRootAccount {
        IceRootAccount::parse_canonical(ACCOUNT).unwrap()
    }

    fn message(key: &SolarKey) -> String {
        build(&ProofRequest {
            address: key.address(),
            account: &account(),
            nonce: &"7e".repeat(32),
            issued_at_ms: ISSUED,
        })
        .unwrap()
    }

    fn problem_of<T: fmt::Debug>(result: Result<T, Error>) -> ProofProblem {
        match result {
            Err(Error::InvalidProof { problem }) => problem,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_legacy_signer_s_proof() {
        let key = SolarKey::from_passphrase(PASSPHRASE).unwrap();
        assert_eq!(key.address().to_string(), ADDRESS);
        assert_eq!(key.public_key().to_hex(), PUBLIC_KEY);
        assert!(!format!("{key:?}").contains("keys"));
        let text = message(&key);
        // The fixed proof of the Legacy Signer's tests.
        assert_eq!(
            text,
            [
                TITLE,
                VERSION_LINE,
                "Source network: solar-mainnet",
                &format!("Source address: {ADDRESS}"),
                &format!("IceRoot account: {ACCOUNT}"),
                &format!("Nonce: {}", "7e".repeat(32)),
                "Issued at: 2026-09-01T12:00:00.000Z",
                STATEMENT_LINE,
                NO_TRANSACTION_LINE,
            ]
            .join("\n")
        );
        let proof = sign(&key, &text, ISSUED).unwrap();
        assert_eq!(proof.address, ADDRESS);
        assert_eq!(proof.public_key, PUBLIC_KEY);
        let fields = verify(&proof, ISSUED).unwrap();
        assert_eq!(fields.account, account());
        assert_eq!(fields.account.network(), AccountNetwork::Mainnet);
        assert_eq!(fields.issued_at_ms, ISSUED);
        assert_eq!(fields.issued_at, "2026-09-01T12:00:00.000Z");

        let json = proof.to_json();
        assert!(json.starts_with(
            "{\"type\":\"iceroot-migration-ownership-proof\",\"version\":1,\"network\":\"solar-mainnet\",\"address\":"
        ));
        assert_eq!(OwnershipProof::from_json(&json).unwrap(), proof);
        // A signature made elsewhere, as by a Ledger.
        let again =
            OwnershipProof::from_signature(&text, PUBLIC_KEY, &proof.signature, ISSUED).unwrap();
        assert_eq!(again, proof);
        key.release();
    }

    #[test]
    fn verification_refusals() {
        let key = SolarKey::from_passphrase(PASSPHRASE).unwrap();
        let other = SolarKey::from_passphrase("another passphrase").unwrap();
        let text = message(&key);
        let proof = sign_with(&key, &text, ISSUED, Aux::fixed([0x42; 32])).unwrap();
        let with = |change: &dyn Fn(&mut OwnershipProof)| {
            let mut changed = proof.clone();
            change(&mut changed);
            problem_of(verify(&changed, ISSUED))
        };
        assert_eq!(
            with(&|p| p.message = p.message.replace("7e7e", "7e7f")),
            ProofProblem::Signature
        );
        assert_eq!(
            with(&|p| p.public_key = other.public_key().to_hex()),
            ProofProblem::Mismatch
        );
        assert_eq!(
            with(&|p| p.address = other.address().to_string()),
            ProofProblem::Mismatch
        );
        assert_eq!(
            with(&|p| p.public_key = p.public_key.to_uppercase()),
            ProofProblem::Key
        );
        assert_eq!(
            with(&|p| p.signature = p.signature.to_uppercase()),
            ProofProblem::Signature
        );
        assert_eq!(
            with(&|p| {
                let last = p.signature.pop().unwrap();
                p.signature.push(if last == '0' { '1' } else { '0' });
            }),
            ProofProblem::Signature
        );
        assert_eq!(
            problem_of(verify(&proof, ISSUED - MAX_CLOCK_AHEAD_MS - 1)),
            ProofProblem::IssuedAt
        );
        assert!(verify(&proof, ISSUED - MAX_CLOCK_AHEAD_MS).is_ok());
        // The signer refuses a message that names another key's address.
        assert_eq!(
            problem_of(sign(&other, &text, ISSUED)),
            ProofProblem::Mismatch
        );
        assert_eq!(
            problem_of(OwnershipProof::from_signature(
                &text,
                &other.public_key().to_hex(),
                &proof.signature,
                ISSUED
            )),
            ProofProblem::Mismatch
        );
    }

    #[test]
    fn message_refusals() {
        let key = SolarKey::from_passphrase(PASSPHRASE).unwrap();
        let text = message(&key);
        let check = |text: &str| problem_of(parse(text, &ProofExpected::default(), ISSUED));
        assert_eq!(check(&format!("{text}\n")), ProofProblem::Format);
        assert_eq!(check(&text.replace('\n', "\r\n")), ProofProblem::Format);
        assert_eq!(check(""), ProofProblem::Format);
        assert_eq!(
            check(&text.replace("Version: 1", "Version: 2")),
            ProofProblem::Format
        );
        assert_eq!(
            check(&text.replace("Nonce: ", "Nonce:")),
            ProofProblem::Field
        );
        assert_eq!(
            check(&text.replace("solar-mainnet", "solar-testnet")),
            ProofProblem::SourceNetwork
        );
        assert_eq!(
            check(&text.replace(ADDRESS, "SNAgA2XCRZDKfm5Vu9h4KR1bZw5xn9EiC4")),
            ProofProblem::Address
        );
        assert_eq!(
            check(&text.replace(ACCOUNT, &ACCOUNT.to_uppercase())),
            ProofProblem::Account
        );
        assert_eq!(
            check(&text.replace("ice1q8y5", "ice1q8y6")),
            ProofProblem::Account
        );
        assert_eq!(
            check(&text.replace(&"7e".repeat(32), &"7E".repeat(32))),
            ProofProblem::Nonce
        );
        assert_eq!(
            check(&text.replace("12:00:00.000Z", "12:00:00.00Z")),
            ProofProblem::IssuedAt
        );
        assert_eq!(
            check(&text.replace("2026-09-01T12", "2026-02-30T12")),
            ProofProblem::IssuedAt
        );
        assert_eq!(
            check(&text.replace("12:00:00.000Z", "24:00:00.000Z")),
            ProofProblem::IssuedAt
        );
        assert_eq!(
            check(&text.replace("12:00:00.000Z", "12:05:00.001Z")),
            ProofProblem::IssuedAt
        );
        assert!(
            parse(
                &text.replace("12:00:00.000Z", "12:05:00Z"),
                &ProofExpected::default(),
                ISSUED
            )
            .is_ok()
        );
        assert_eq!(
            check(&text.replace("above.", "above. é")),
            ProofProblem::Format
        );
        assert_eq!(
            problem_of(parse(
                &text,
                &ProofExpected {
                    address: Some("SfjpW5LCYEeX9UnFLWhK97Tc11ZEiQRyQZ")
                },
                ISSUED
            )),
            ProofProblem::Mismatch
        );
    }

    #[test]
    fn build_refusals() {
        let key = SolarKey::from_passphrase(PASSPHRASE).unwrap();
        let devnet = Address::from_public_key_for_network_byte(key.public_key(), 90);
        let account = account();
        let request = |address, nonce, issued_at_ms| ProofRequest {
            address,
            account: &account,
            nonce,
            issued_at_ms,
        };
        let nonce = "7e".repeat(32);
        let refused = |request: ProofRequest<'_>| problem_of(build(&request));
        assert_eq!(
            refused(request(&devnet, &nonce, ISSUED)),
            ProofProblem::Address
        );
        assert_eq!(
            refused(request(key.address(), "7e", ISSUED)),
            ProofProblem::Nonce
        );
        assert_eq!(
            refused(request(key.address(), &nonce, -62_167_219_200_001)),
            ProofProblem::IssuedAt
        );
        let random = random_nonce().unwrap();
        assert_eq!(random.len(), 64);
        assert!(build(&request(key.address(), &random, ISSUED)).is_ok());
    }

    #[test]
    fn accounts() {
        let parsed =
            IceRootAccount::parse(&format!(" \u{feff}{}\n", ACCOUNT.to_uppercase())).unwrap();
        assert_eq!(parsed.as_str(), ACCOUNT);
        assert_eq!(parsed.network().as_str(), "mainnet");
        assert_eq!(parsed.network().prefix(), "ice");
        assert_eq!(
            problem_of(IceRootAccount::parse(&format!("\u{85}{ACCOUNT}"))),
            ProofProblem::Account
        );
        // Mixed case is refused; an account written in capitals is read in lowercase.
        let mixed = format!("ICE1{}", &ACCOUNT[4..]);
        assert_eq!(
            problem_of(IceRootAccount::parse(&mixed)),
            ProofProblem::Account
        );
        assert_eq!(
            problem_of(IceRootAccount::parse_canonical(&ACCOUNT.to_uppercase())),
            ProofProblem::Account
        );
        // The hash, read back five bits at a time, gives the same characters.
        let mut bits: u32 = 0;
        let mut count = 0;
        let mut data = String::new();
        for byte in parsed.hash() {
            bits = (bits << 8) | u32::from(*byte);
            count += 8;
            while count >= 5 {
                count -= 5;
                data.push(char::from(CHARSET[((bits >> count) & 31) as usize]));
            }
        }
        data.push(char::from(CHARSET[((bits << (5 - count)) & 31) as usize]));
        assert_eq!(&ACCOUNT[4..4 + 52], data);
        for bad in [
            "",
            "ice1",
            "bc1q8y55x5z8dr5uepshat727uvt328lfkklzwvvmt4p42qlcrggxtsk8zw2r",
            "tice1q8y55x5z8dr5uepshat727uvt328lfkklzwvvmt4p42qlcrggxtsk8zw2r",
            "ice1q8y55x5z8dr5uepshat727uvt328lfkklzwvvmt4p42qlcrggxtsk8zw2",
            "ice1q8y55x5z8dr5uepshat727uvt328lfkklzwvvmt4p42qlcrggxtsk8zw2rq",
            "ice1b8y55x5z8dr5uepshat727uvt328lfkklzwvvmt4p42qlcrggxtsk8zw2r",
        ] {
            assert!(IceRootAccount::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn json_refusals() {
        let key = SolarKey::from_passphrase(PASSPHRASE).unwrap();
        let proof = sign(&key, &message(&key), ISSUED).unwrap();
        let value = proof.to_json_value();
        let with = |key: &str, replacement: Value| {
            let mut changed = value.clone();
            changed[key] = replacement;
            problem_of(OwnershipProof::from_json(&changed.to_string()))
        };
        assert_eq!(with("type", json!("another")), ProofProblem::Json);
        assert_eq!(with("version", json!(2)), ProofProblem::Json);
        assert_eq!(with("version", json!("1")), ProofProblem::Json);
        assert_eq!(with("network", json!("solar-testnet")), ProofProblem::Json);
        assert_eq!(with("algorithm", json!("ml-dsa-65")), ProofProblem::Json);
        assert_eq!(with("extra", json!(1)), ProofProblem::Json);
        assert_eq!(with("message", json!(1)), ProofProblem::Json);
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove("signature");
        assert_eq!(
            problem_of(OwnershipProof::from_json(&missing.to_string())),
            ProofProblem::Json
        );
        assert_eq!(
            problem_of(OwnershipProof::from_json("[]")),
            ProofProblem::Json
        );
        assert_eq!(
            problem_of(OwnershipProof::from_json(&" ".repeat(MAX_JSON_LENGTH + 1))),
            ProofProblem::Json
        );
        // Pretty-printed JSON, as the Legacy Signer shows it, reads the same.
        let pretty = serde_json::to_string_pretty(&value).unwrap();
        assert_eq!(OwnershipProof::from_json(&pretty).unwrap(), proof);
    }
}
