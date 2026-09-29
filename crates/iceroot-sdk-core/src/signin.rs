//! The sign-in message, version 1: the challenge a website asks a wallet to sign.
//!
//! The message has exactly twelve lines, separated by `\n` with no newline at the end:
//!
//! ```text
//! IceRoot Validator Portal sign-in
//! Version: 1
//! Origin: <origin>
//! URI: <origin>/login
//! Network: heartwood-devnet-v90
//! Public key: <lowercase compressed public key>
//! Address: <the key's address>
//! Nonce: <64 lowercase hex digits>
//! Issued at: <RFC 3339 time>
//! Expires at: <RFC 3339 time>
//! Intent: Sign in to manage your validator proposal and contributions.
//! No transaction or transfer is authorized.
//! ```
//!
//! [`build`] makes one for a server; [`parse`] is what a wallet runs before it asks the holder to
//! sign, and what a server can run again before it checks the signature. Both sides use the same
//! code, so they cannot disagree. [`parse`] checks everything: the fixed lines, a secure origin
//! (HTTPS, or HTTP on the loopback host) with `URI` its `/login`, the network, the forms of the key,
//! address and nonce, that the address is the key's, the expected origin and identity, and the
//! times (expiry in the future, issued no more than 30 seconds ahead, at most 305 seconds apart
//! and at most 305 seconds ago).
//!
//! A wallet signs it with [`sign`], which runs [`parse`] against the origin of the page that asks
//! and the signing account's own public key and address, and signs only a message that passes.
//! The signature is a message signature ([`crate::message`]), so a server checks it with
//! [`crate::message::verify`]. A wallet never signs a sign-in message as a plain message from a
//! generic prompt: a challenge that a page of another origin fetched for the holder's key and
//! relayed would give that page a valid sign-in (see [`crate::message`]).

use crate::address::Address;
use crate::error::{Error, SignInProblem};
use crate::keys::Account;
use crate::message::{self, MessageSignature, compressed_key};
use crate::profile::Profile;
use crate::time::{format_rfc3339_seconds, parse_rfc3339_ms};
use crate::utils::is_lower_hex;
use heartwood_crypto::Aux;
use heartwood_crypto::PublicKey;

/// The first line.
pub const TITLE: &str = "IceRoot Validator Portal sign-in";
/// The second line.
pub const VERSION_LINE: &str = "Version: 1";
/// The eleventh line.
pub const INTENT_LINE: &str =
    "Intent: Sign in to manage your validator proposal and contributions.";
/// The last line.
pub const NO_TRANSACTION_LINE: &str = "No transaction or transfer is authorized.";
/// The longest message, in bytes.
pub const MAX_LENGTH: usize = 4096;
/// The longest a message may be valid, and the oldest it may be, in milliseconds.
pub const MAX_LIFETIME_MS: i64 = 305_000;
/// How far ahead of the reader's clock a message may be issued, in milliseconds.
pub const MAX_CLOCK_AHEAD_MS: i64 = 30_000;

/// What a server puts in a new sign-in message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInRequest<'a> {
    /// The website's origin, for example `https://validators.example`.
    pub origin: &'a str,
    /// The signer's public key.
    pub public_key: &'a PublicKey,
    /// A single-use nonce: 64 lowercase hex digits from 32 random bytes.
    pub nonce: &'a str,
    /// When the message is issued, in seconds since 1970-01-01T00:00:00Z.
    pub issued_at: i64,
    /// When it expires, in seconds since 1970-01-01T00:00:00Z; at most 300 seconds later.
    pub expires_at: i64,
}

/// What a reader expects of a sign-in message. Unset fields are not compared, as in the format's
/// published checks, so a wallet sets every field: the origin of the page that asks (as the
/// browser reports it, never one the page claims) and the selected identity's public key and
/// address. Otherwise a message made for another website or another identity passes. The
/// TypeScript SDK requires all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SignInExpected<'a> {
    /// The origin of the website that asks.
    pub origin: Option<&'a str>,
    /// The public key of the identity selected in the wallet, lowercase hex.
    pub public_key: Option<&'a str>,
    /// The address of that identity.
    pub address: Option<&'a str>,
}

/// A checked sign-in message's fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignInChallenge {
    /// The website's origin.
    pub origin: String,
    /// The origin's `/login`.
    pub uri: String,
    /// The network name.
    pub network: String,
    /// The signer's public key, lowercase hex.
    pub public_key: String,
    /// The signer's address.
    pub address: String,
    /// The nonce.
    pub nonce: String,
    /// When the message was issued, in milliseconds since 1970-01-01T00:00:00Z.
    pub issued_at_ms: i64,
    /// When it expires, in milliseconds since 1970-01-01T00:00:00Z.
    pub expires_at_ms: i64,
}

fn problem(problem: SignInProblem) -> Error {
    Error::InvalidSignIn { problem }
}

/// The sign-in message of `request` on the network of `profile`.
pub fn build(profile: &Profile, request: &SignInRequest<'_>) -> Result<String, Error> {
    let network = profile.message_network()?;
    if !is_allowed_origin(request.origin) {
        return Err(problem(SignInProblem::Origin));
    }
    let public_key = request.public_key.to_hex();
    if compressed_key(&public_key).is_none() {
        return Err(problem(SignInProblem::Identity));
    }
    if request.nonce.len() != 64 || !is_lower_hex(request.nonce) {
        return Err(problem(SignInProblem::Identity));
    }
    let lifetime = request.expires_at.checked_sub(request.issued_at);
    if !lifetime.is_some_and(|lifetime| (1..=300).contains(&lifetime)) {
        return Err(problem(SignInProblem::Expired));
    }
    let issued = format_rfc3339_seconds(request.issued_at);
    let expires = format_rfc3339_seconds(request.expires_at);
    let (Some(issued), Some(expires)) = (issued, expires) else {
        return Err(problem(SignInProblem::Expired));
    };
    let address = Address::from_public_key(request.public_key, profile)?;
    let origin = request.origin;
    Ok([
        TITLE.to_owned(),
        VERSION_LINE.to_owned(),
        format!("Origin: {origin}"),
        format!("URI: {origin}/login"),
        format!("Network: {network}"),
        format!("Public key: {public_key}"),
        format!("Address: {address}"),
        format!("Nonce: {}", request.nonce),
        format!("Issued at: {issued}"),
        format!("Expires at: {expires}"),
        INTENT_LINE.to_owned(),
        NO_TRANSACTION_LINE.to_owned(),
    ]
    .join("\n"))
}

/// Check the sign-in `message` for the network of `profile`, against what the reader `expected`,
/// at the reader's time `now_ms` (milliseconds since 1970-01-01T00:00:00Z).
pub fn parse(
    profile: &Profile,
    message: &str,
    expected: &SignInExpected<'_>,
    now_ms: i64,
) -> Result<SignInChallenge, Error> {
    let network = profile.message_network()?;
    if message.len() > MAX_LENGTH || message.contains('\r') {
        return Err(problem(SignInProblem::Format));
    }
    let lines: Vec<&str> = message.split('\n').collect();
    let [
        title,
        version,
        origin,
        uri,
        message_network,
        public_key,
        address,
        nonce,
        issued_at,
        expires_at,
        intent,
        no_transaction,
    ] = lines.as_slice()
    else {
        return Err(problem(SignInProblem::Format));
    };
    if *title != TITLE
        || *version != VERSION_LINE
        || *intent != INTENT_LINE
        || *no_transaction != NO_TRANSACTION_LINE
    {
        return Err(problem(SignInProblem::Format));
    }
    let field = |line: &'_ str, prefix: &str| -> Result<String, Error> {
        line.strip_prefix(prefix)
            .map(str::to_owned)
            .ok_or(problem(SignInProblem::Field))
    };
    let challenge = SignInChallenge {
        origin: field(origin, "Origin: ")?,
        uri: field(uri, "URI: ")?,
        network: field(message_network, "Network: ")?,
        public_key: field(public_key, "Public key: ")?,
        address: field(address, "Address: ")?,
        nonce: field(nonce, "Nonce: ")?,
        issued_at_ms: 0,
        expires_at_ms: 0,
    };
    let issued_at = field(issued_at, "Issued at: ")?;
    let expires_at = field(expires_at, "Expires at: ")?;

    if !is_allowed_origin(&challenge.origin)
        || challenge.uri != format!("{}/login", challenge.origin)
    {
        return Err(problem(SignInProblem::Origin));
    }
    if challenge.network != network {
        return Err(problem(SignInProblem::Network));
    }
    let key = compressed_key(&challenge.public_key).ok_or(problem(SignInProblem::Identity))?;
    if challenge.nonce.len() != 64 || !is_lower_hex(&challenge.nonce) {
        return Err(problem(SignInProblem::Identity));
    }
    if Address::from_public_key(&key, profile)?.to_string() != challenge.address {
        return Err(problem(SignInProblem::Identity));
    }
    let mismatch =
        |wanted: Option<&str>, actual: &str| wanted.is_some_and(|wanted| wanted != actual);
    if mismatch(expected.origin, &challenge.origin)
        || mismatch(expected.public_key, &challenge.public_key)
        || mismatch(expected.address, &challenge.address)
    {
        return Err(problem(SignInProblem::Mismatch));
    }

    let (Some(issued), Some(expires)) =
        (parse_rfc3339_ms(&issued_at), parse_rfc3339_ms(&expires_at))
    else {
        return Err(problem(SignInProblem::Expired));
    };
    let valid_times = expires > now_ms
        && issued <= now_ms.saturating_add(MAX_CLOCK_AHEAD_MS)
        && expires > issued
        && expires - issued <= MAX_LIFETIME_MS
        && now_ms.saturating_sub(issued) <= MAX_LIFETIME_MS;
    if !valid_times {
        return Err(problem(SignInProblem::Expired));
    }
    Ok(SignInChallenge {
        issued_at_ms: issued,
        expires_at_ms: expires,
        ..challenge
    })
}

/// Sign the sign-in `message` with `account`, for the website of `origin` (the origin of the page
/// that asks, as the browser reports it, never one the page claims), at the signer's time `now_ms`
/// (milliseconds since 1970-01-01T00:00:00Z), with fresh randomness.
///
/// The message is first checked with [`parse`], expecting `origin` and the account's own public
/// key and address, so a challenge made for another website or another identity, or one that has
/// lapsed, is never signed. The origin is the caller's to report truthfully.
///
/// # Errors
///
/// [`Error::InvalidSignIn`] with the reason when a check fails; [`Error::UnsupportedOnNetwork`]
/// without message signing, and [`Error::NetworkMismatch`] for an account of another profile.
pub fn sign(
    profile: &Profile,
    account: &Account,
    message: &str,
    origin: &str,
    now_ms: i64,
) -> Result<MessageSignature, Error> {
    sign_with(profile, account, message, origin, now_ms, Aux::random())
}

/// [`sign`] with the auxiliary randomness `aux`. Outside tests only [`Aux::random`] exists.
pub fn sign_with(
    profile: &Profile,
    account: &Account,
    message: &str,
    origin: &str,
    now_ms: i64,
    aux: Aux,
) -> Result<MessageSignature, Error> {
    message::check_signer(profile, account)?;
    let public_key = account.public_key().to_hex();
    let address = account.address().to_string();
    parse(
        profile,
        message,
        &SignInExpected {
            origin: Some(origin),
            public_key: Some(&public_key),
            address: Some(&address),
        },
        now_ms,
    )?;
    message::sign_with(profile, account, message, aux)
}

/// Whether `origin` is a secure web origin in its serialized form: `https://host[:port]`, or
/// `http://` on `localhost`, `127.0.0.1` or `[::1]`, with a lowercase host, no path, no user
/// name and no default port.
pub fn is_allowed_origin(origin: &str) -> bool {
    let Some((scheme, authority)) = origin.split_once("://") else {
        return false;
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(':') && !port.contains(']') => (host, Some(port)),
        _ => (authority, None),
    };
    let default_port = match scheme {
        "https" => "443",
        "http" => "80",
        _ => return false,
    };
    if let Some(port) = port {
        let valid = !port.is_empty()
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && !port.starts_with('0')
            && port.parse::<u32>().is_ok_and(|port| port <= 65_535)
            && port != default_port;
        if !valid {
            return false;
        }
    }
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    match scheme {
        "http" => loopback,
        _ => loopback || is_ipv4(host) || is_domain(host),
    }
}

/// Whether `host` is an IPv4 address in its serialized form.
fn is_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 3
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
                && part.parse::<u16>().is_ok_and(|value| value <= 255)
        })
}

/// Whether `host` is a lowercase domain name that a URL keeps as it is: labels of `a-z`, `0-9`
/// and inner hyphens, at most 63 characters each and 253 in all, with a last label that is not a
/// number (a URL would read such a host as an IPv4 address).
fn is_domain(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let label_ok = |label: &&str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    };
    let numeric = |label: &str| {
        label.bytes().all(|byte| byte.is_ascii_digit())
            || label
                .strip_prefix("0x")
                .is_some_and(|hex| hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
    };
    labels.iter().all(label_ok) && labels.last().is_some_and(|last| !numeric(last))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Account;
    use crate::profile::DevnetOptions;

    const NONCE: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const ISSUED: i64 = 1_790_426_096;

    fn devnet() -> Profile {
        Profile::devnet(DevnetOptions::default())
    }

    fn message(account: &Account, origin: &str) -> String {
        build(
            &devnet(),
            &SignInRequest {
                origin,
                public_key: account.public_key(),
                nonce: NONCE,
                issued_at: ISSUED,
                expires_at: ISSUED + 300,
            },
        )
        .unwrap()
    }

    fn account() -> Account {
        Account::from_legacy_passphrase(&devnet(), "this is a top secret passphrase").unwrap()
    }

    fn problem_of<T: std::fmt::Debug>(result: Result<T, Error>) -> SignInProblem {
        match result {
            Err(Error::InvalidSignIn { problem }) => problem,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn build_then_parse() {
        let account = account();
        let text = message(&account, "https://validators.example");
        assert_eq!(
            text,
            "IceRoot Validator Portal sign-in\nVersion: 1\nOrigin: https://validators.example\n\
             URI: https://validators.example/login\nNetwork: heartwood-devnet-v90\n\
             Public key: 034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192\n\
             Address: dEHxjxZybRiykTqqZUgfQoMqZZ3RxVj1dt\n\
             Nonce: 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n\
             Issued at: 2026-09-26T12:34:56Z\nExpires at: 2026-09-26T12:39:56Z\n\
             Intent: Sign in to manage your validator proposal and contributions.\n\
             No transaction or transfer is authorized."
        );
        let expected = SignInExpected {
            origin: Some("https://validators.example"),
            public_key: Some("034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192"),
            address: Some("dEHxjxZybRiykTqqZUgfQoMqZZ3RxVj1dt"),
        };
        let now = ISSUED * 1000 + 1000;
        let challenge = parse(&devnet(), &text, &expected, now).unwrap();
        assert_eq!(challenge.nonce, NONCE);
        assert_eq!(challenge.issued_at_ms, ISSUED * 1000);
        assert_eq!(challenge.expires_at_ms, (ISSUED + 300) * 1000);
        assert_eq!(challenge.uri, "https://validators.example/login");
    }

    #[test]
    fn a_sign_in_message_is_signed_only_once_it_passes_every_check() {
        let account = account();
        let origin = "https://validators.example";
        let text = message(&account, origin);
        let now = ISSUED * 1000 + 1000;
        let signed = sign(&devnet(), &account, &text, origin, now).unwrap();
        assert_eq!(signed.public_key, account.public_key().to_hex());
        assert_eq!(signed.network, "heartwood-devnet-v90");
        assert!(crate::message::verify(&text, &signed));

        // A page of another origin that fetched this challenge cannot have it signed.
        assert_eq!(
            problem_of(sign(
                &devnet(),
                &account,
                &text,
                "https://phish.example",
                now
            )),
            SignInProblem::Mismatch
        );
        // Nor can a challenge for another identity be signed with this account.
        let other =
            Account::from_legacy_passphrase(&devnet(), "another top secret passphrase").unwrap();
        assert_eq!(
            problem_of(sign(&devnet(), &other, &text, origin, now)),
            SignInProblem::Mismatch
        );
        assert_eq!(
            problem_of(sign(&devnet(), &account, &text, origin, now + 400_000)),
            SignInProblem::Expired
        );
        assert_eq!(
            problem_of(sign(&devnet(), &account, "hello", origin, now)),
            SignInProblem::Format
        );
        // An account of another profile is refused before the message is read.
        let other_profile = Profile::devnet_pq(DevnetOptions::default());
        assert!(sign(&other_profile, &account, &text, origin, now).is_err());
    }

    #[test]
    fn refusals() {
        let account = account();
        let text = message(&account, "https://validators.example");
        let now = ISSUED * 1000 + 1000;
        let none = SignInExpected::default();
        let check = |text: &str, expected: &SignInExpected<'_>, now: i64| {
            problem_of(parse(&devnet(), text, expected, now))
        };
        assert_eq!(
            check(&format!("{text}\n"), &none, now),
            SignInProblem::Format
        );
        assert_eq!(
            check(&text.replace('\n', "\r\n"), &none, now),
            SignInProblem::Format
        );
        assert_eq!(
            check(&text.replace("Version: 1", "Version: 2"), &none, now),
            SignInProblem::Format
        );
        assert_eq!(
            check(&text.replace("Nonce: ", "Nonce:"), &none, now),
            SignInProblem::Field
        );
        assert_eq!(
            check(&text.replace("/login", "/logout"), &none, now),
            SignInProblem::Origin
        );
        assert_eq!(
            check(&text.replace("devnet-v90", "devnet-v63"), &none, now),
            SignInProblem::Network
        );
        assert_eq!(
            check(&text.replace("Nonce: 00", "Nonce: 0"), &none, now),
            SignInProblem::Identity
        );
        assert_eq!(
            check(
                &text.replace(
                    "dEHxjxZybRiykTqqZUgfQoMqZZ3RxVj1dt",
                    "dDSccdbPRhfrcbUeFLMbGC1rtnfCsjJcNF"
                ),
                &none,
                now
            ),
            SignInProblem::Identity
        );
        let other_origin = SignInExpected {
            origin: Some("https://evil.example"),
            ..none
        };
        assert_eq!(check(&text, &other_origin, now), SignInProblem::Mismatch);
        let other_address = SignInExpected {
            address: Some("dDSccdbPRhfrcbUeFLMbGC1rtnfCsjJcNF"),
            ..none
        };
        assert_eq!(check(&text, &other_address, now), SignInProblem::Mismatch);
        // Expired, issued too far ahead, and too old.
        assert_eq!(
            check(&text, &none, (ISSUED + 300) * 1000),
            SignInProblem::Expired
        );
        assert_eq!(
            check(&text, &none, ISSUED * 1000 - 30_001),
            SignInProblem::Expired
        );
        assert!(parse(&devnet(), &text, &none, ISSUED * 1000 - 30_000).is_ok());
        assert!(parse(&devnet(), &text, &none, (ISSUED + 300) * 1000 - 1).is_ok());
        assert_eq!(
            check(&text.replace("12:39:56Z", "12:40:02Z"), &none, now),
            SignInProblem::Expired,
            "more than 305 seconds apart"
        );
        assert_eq!(
            check(&text.replace("12:34:56Z", "12:34:56"), &none, now),
            SignInProblem::Expired
        );
        let long = format!("{text}{}", " ".repeat(MAX_LENGTH));
        assert_eq!(check(&long, &none, now), SignInProblem::Format);
    }

    #[test]
    fn origins() {
        for good in [
            "https://validators.example",
            "https://a.b.example:8443",
            "https://localhost",
            "https://1.2.3.4",
            "https://intranet",
            "http://localhost:3000",
            "http://127.0.0.1:8080",
            "http://[::1]:5173",
            "http://localhost",
        ] {
            assert!(is_allowed_origin(good), "{good}");
        }
        for bad in [
            "http://validators.example",
            "https://validators.example/",
            "https://validators.example/login",
            "https://Validators.example",
            "https://validators.example:443",
            "http://localhost:80",
            "https://user@validators.example",
            "https://validators.example:0",
            "https://validators.example:65536",
            "https://validators.example:08443",
            "https://validators.example:",
            "https://-bad.example",
            "https://a..example",
            "https://example.123",
            "https://01.2.3.4",
            "ftp://validators.example",
            "https://",
            "validators.example",
            "https://validators.example?x",
            "https://validators.example#x",
            "https://*.example",
        ] {
            assert!(!is_allowed_origin(bad), "{bad}");
        }
    }

    #[test]
    fn build_refusals() {
        let account = account();
        let request = |origin, nonce, expires_at| SignInRequest {
            origin,
            public_key: account.public_key(),
            nonce,
            issued_at: ISSUED,
            expires_at,
        };
        let refused = |request: SignInRequest<'_>| match build(&devnet(), &request) {
            Err(Error::InvalidSignIn { problem }) => problem,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            refused(request("http://validators.example", NONCE, ISSUED + 300)),
            SignInProblem::Origin
        );
        assert_eq!(
            refused(request("https://validators.example", "00", ISSUED + 300)),
            SignInProblem::Identity
        );
        assert_eq!(
            refused(request("https://validators.example", NONCE, ISSUED + 301)),
            SignInProblem::Expired
        );
        assert_eq!(
            refused(request("https://validators.example", NONCE, ISSUED)),
            SignInProblem::Expired
        );
    }
}
