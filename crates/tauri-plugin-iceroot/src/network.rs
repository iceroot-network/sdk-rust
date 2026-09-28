//! Connected networks: the SDK's node API client over reqwest, inside the plugin.
//!
//! Requests are built and answers decoded by the same code as in the WebAssembly module (the
//! bindings' `api` module over `iceroot-sdk-api`); the plugin sends them with the client's reqwest
//! transport, which tries the relays in order, keeps to the node's request allowance and retries
//! HTTP 429 with backoff. The webview never reaches a node: its content security policy needs no
//! node origin.
//!
//! A relay is reached only when the application's capabilities allow it: each connection's
//! relays must match an `allow` entry (`{ "url": "http://127.0.0.1:6003/api" }`, `*` matching any
//! run of characters other than `/`, `**` any run) of the `net-connect` command's scope or of the
//! plugin's global scope, and no `deny` entry.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use iceroot_sdk::api::{
    ApiError, Backoff, HttpClient, HttpOptions, RateLimit, Relay, Response, SolarCompat,
};
use iceroot_sdk::{Chain, Profile, SignedTransaction};
use iceroot_sdk_bindings::api::{PreparedCall, Submission};
use serde::{Deserialize, Serialize};

use crate::codec::from_hex;
use crate::error::{Error, Result};
use crate::state::Iceroot;

/// An entry of the relay scope in an application's capabilities: a relay URL, including the API
/// base path, where `*` matches any run of characters other than `/` and `**` any run at all.
#[derive(Debug, Clone, Deserialize)]
pub struct RelayScope {
    /// The relay URL pattern, for example `http://127.0.0.1:6003/api`,
    /// `https://*.example.org/api` or `http://127.0.0.1:*/api`.
    pub url: String,
}

impl RelayScope {
    /// Whether `relay`, in the form a URL parser writes it (a lowercase host, `\` read as `/`,
    /// percent-encoding normalized, no trailing `/`), matches the entry.
    pub fn matches(&self, relay: &str) -> bool {
        let pattern = self.url.trim_end_matches('/');
        wildcard(pattern.as_bytes(), relay.as_bytes())
    }
}

/// Whether `text` matches `pattern`, where `*` matches any run of bytes other than `/` (none
/// included) and `**` any run of bytes. Linear in the text for each byte of the pattern.
fn wildcard(pattern: &[u8], text: &[u8]) -> bool {
    // reach[j]: whether the pattern read so far matches the first j bytes of the text.
    let mut reach: Vec<bool> = std::iter::once(true)
        .chain(text.iter().map(|_| false))
        .collect();
    let mut rest = pattern;
    while let Some((&first, tail)) = rest.split_first() {
        reach = if first == b'*' {
            let (crosses, tail) = match tail.split_first() {
                Some((b'*', tail)) => (true, tail),
                _ => (false, tail),
            };
            rest = tail;
            // A run ending at j extends one ending at j - 1 unless byte j - 1 is a `/` that the
            // wildcard may not cross.
            let mut on = false;
            reach
                .iter()
                .enumerate()
                .map(|(j, &here)| {
                    let extends = on
                        && (crosses || j.checked_sub(1).and_then(|k| text.get(k)) != Some(&b'/'));
                    on = here || extends;
                    on
                })
                .collect()
        } else {
            rest = tail;
            std::iter::once(false)
                .chain(
                    reach
                        .iter()
                        .zip(text)
                        .map(|(&here, &byte)| here && byte == first),
                )
                .collect()
        };
    }
    reach.last() == Some(&true)
}

/// Whether the scopes allow `relay`: an allow entry matches and no deny entry does. The entries
/// match the relay as a URL parser writes it, the form the HTTP client reaches (a lowercase host,
/// `\` read as `/`, percent-encoding normalized), so that no spelling of a URL reaches a host
/// its entries do not name. A relay that does not parse is not allowed.
pub(crate) fn relay_allowed(
    relay: &str,
    allows: &[Arc<RelayScope>],
    denies: &[Arc<RelayScope>],
) -> bool {
    let Ok(url) = tauri::Url::parse(relay) else {
        return false;
    };
    let relay = url.as_str().trim_end_matches('/');
    allows.iter().any(|entry| entry.matches(relay))
        && !denies.iter().any(|entry| entry.matches(relay))
}

/// Options of a connection, as `connect` takes them in TypeScript.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectOptions {
    /// Extra headers for every request, for a relay behind a proxy that needs a token.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// The request allowance to keep to; `None` for the reference implementation's default.
    #[serde(default)]
    pub rate_limit: Option<Allowance>,
    /// Time allowed for one request, in milliseconds; 15,000 by default.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

/// A request allowance, or none.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Allowance {
    /// At most `requests` per `window_ms` milliseconds.
    Limit {
        /// Requests per window.
        requests: u32,
        /// The window, in milliseconds.
        #[serde(rename = "windowMs")]
        window_ms: u64,
    },
    /// `false`: no budget; HTTP 429 is still retried with backoff.
    Unlimited(bool),
}

/// A network the plugin connected to: the chain it serves, pinned, and the client that reaches it.
pub struct Session {
    pub(crate) chain: Arc<Chain>,
    client: HttpClient,
    seats: u32,
    max_per_request: u32,
    max_bytes: u32,
    /// The highest block height the node reported, by an answer's `X-Block-Height` or its status.
    height: AtomicU64,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("nethash", &self.chain.nethash())
            .field("relays", &self.client.relays())
            .field("height", &self.height())
            .finish_non_exhaustive()
    }
}

/// What a connection reads first.
pub(crate) struct Connected {
    pub(crate) session: Session,
    pub(crate) configuration: String,
    pub(crate) status: String,
}

impl Session {
    /// Connects to the network of `profile`: reads the chain its first answering relay serves and
    /// checks it against the profile (a devnet profile without a pinned network hash is pinned
    /// now), then the node's configuration, refusing a node of another chain, and its status.
    pub(crate) async fn connect(profile: &Profile, options: ConnectOptions) -> Result<Connected> {
        profile.require(iceroot_sdk::profile::Capability::Connect)?;
        let relays = relays(profile)?;
        let client = HttpClient::with_options(relays, http_options(options))?;
        let height = AtomicU64::new(0);
        let note = |response: &Response| {
            if let Some(seen) = response.block_height() {
                height.fetch_max(seen, Ordering::Relaxed);
            }
        };

        let call = SolarCompat::new(0).crypto_configuration();
        let crypto = client
            .exchange(call.request(), |response| {
                note(response);
                call.decode(response)
            })
            .await?;
        let chain = Arc::new(Chain::from_node(profile, &crypto)?);

        let call = SolarCompat::new(0).node_configuration();
        let node = client
            .exchange(call.request(), |response| {
                note(response);
                call.decode(response)
            })
            .await?;
        chain.check_node(&node)?;
        let configuration = serde_json::to_string(&node)
            .map_err(|error| Error::argument(format!("the node configuration: {error}")))?;

        let session = Session {
            chain,
            client,
            seats: node.seats,
            max_per_request: node.pool.max_transactions_per_request,
            max_bytes: node.pool.max_transaction_bytes,
            height,
        };
        let status = session.read("nodeStatus", "{}").await?;
        Ok(Connected {
            session,
            configuration,
            status,
        })
    }

    /// The highest block height the node reported so far; 0 before any.
    pub(crate) fn height(&self) -> u64 {
        self.height.load(Ordering::Relaxed)
    }

    fn note(&self, response: &Response) {
        if let Some(seen) = response.block_height() {
            self.height.fetch_max(seen, Ordering::Relaxed);
        }
    }

    /// Reads `operation` of the node API with its JSON `args`, as the WebAssembly module's
    /// `ApiCall` prepares it, and returns the answer in the same JSON.
    pub(crate) async fn read(&self, operation: &str, args: &str) -> Result<String> {
        let call = PreparedCall::prepare(self.seats, operation, args)?;
        let answer = self
            .client
            .exchange(call.raw_request(), |response| {
                self.note(response);
                call.decode_api(response)
            })
            .await?;
        if operation == "nodeStatus"
            && let Some(height) = status_height(&answer)
        {
            self.height.fetch_max(height, Ordering::Relaxed);
        }
        Ok(answer)
    }

    /// Reads the node's configuration again, refusing a node that now serves another chain.
    pub(crate) async fn node_configuration(&self) -> Result<String> {
        let call = SolarCompat::new(0).node_configuration();
        let node = self
            .client
            .exchange(call.request(), |response| {
                self.note(response);
                call.decode(response)
            })
            .await?;
        self.chain.check_node(&node)?;
        serde_json::to_string(&node)
            .map_err(|error| Error::argument(format!("the node configuration: {error}")))
    }

    /// Submits `transactions` in as few requests as the pool's limits allow, as the WebAssembly
    /// module's `SubmitPlanHandle` plans them, and returns the report in the same JSON.
    pub(crate) async fn submit(&self, transactions: &[SignedTransaction]) -> Result<String> {
        let mut submission = Submission::new(self.max_per_request, self.max_bytes);
        for transaction in transactions {
            submission.add(transaction)?;
        }
        let count = submission.plan()?;
        for index in 0..count {
            let request = submission.raw_request(index)?.clone();
            let report = self
                .client
                .exchange(&request, |response| {
                    self.note(response);
                    submission.decode_report(index, response)
                })
                .await?;
            submission.keep(index, report)?;
        }
        Ok(submission.finish()?)
    }
}

/// The height of a node status answer in the client's JSON.
fn status_height(answer: &str) -> Option<u64> {
    let value: serde_json::Value = serde_json::from_str(answer).ok()?;
    value.get("height")?.as_str()?.parse().ok()
}

/// The relays of `profile`, parsed.
pub(crate) fn relays(profile: &Profile) -> Result<Vec<Relay>> {
    let relays = profile
        .endpoints()
        .relays
        .iter()
        .map(|relay| Relay::parse(relay))
        .collect::<std::result::Result<Vec<_>, ApiError>>()?;
    if relays.is_empty() {
        return Err(Error::argument("a network needs at least one relay URL"));
    }
    Ok(relays)
}

fn http_options(options: ConnectOptions) -> HttpOptions {
    let defaults = HttpOptions::default();
    let rate_limit = match options.rate_limit {
        None => defaults.rate_limit,
        Some(Allowance::Limit {
            requests,
            window_ms,
        }) => RateLimit {
            requests: requests.max(1),
            window: Duration::from_millis(window_ms.max(1)),
        },
        // No budget: the allowance is never spent.
        Some(Allowance::Unlimited(_)) => RateLimit {
            requests: u32::MAX,
            window: Duration::from_millis(1),
        },
    };
    HttpOptions {
        timeout: options
            .timeout_ms
            .map_or(defaults.timeout, |ms| Duration::from_millis(ms.max(1))),
        rate_limit,
        backoff: Backoff::default(),
        user_agent: concat!("tauri-plugin-iceroot/", env!("CARGO_PKG_VERSION")).to_owned(),
        headers: options.headers,
    }
}

/// The node's height answered with a read, and, when it differs from the height the guest code
/// already knows, the chain's rules at the next block, so the guest's `net.rules`,
/// `net.economics` and `net.stage` stay synchronous.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AtNext {
    /// The node's height, as a decimal string.
    pub(crate) height: String,
    /// The next block's height, the rules' height.
    pub(crate) next_height: u32,
    /// The format stage at the next block.
    pub(crate) stage: String,
    /// The rules at the next block, in the JSON of `Chain.rules`.
    pub(crate) rules: String,
    /// The economics at the next block, in the JSON of `Chain.economics`.
    pub(crate) economics: String,
}

impl AtNext {
    /// The rules of `chain` after the block at `height`.
    pub(crate) fn of(chain: &Chain, height: u64) -> AtNext {
        let next = u32::try_from(height.saturating_add(1)).unwrap_or(u32::MAX);
        AtNext {
            height: height.to_string(),
            next_height: next,
            stage: iceroot_sdk_bindings::chain::stage_at(chain, next),
            rules: iceroot_sdk_bindings::chain::rules(chain, next),
            economics: iceroot_sdk_bindings::chain::economics(chain, next),
        }
    }
}

/// A signed transaction as the guest code holds it: its serialized form, which must verify, or
/// the transaction's bytes read under a chain the page holds at a height.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SignedSource {
    /// `SignedTransaction.serialize()`'s bytes as hex, for a profile (JSON) with the network hash
    /// pinned.
    Serialized {
        /// The serialized transaction, as hex.
        serialized: String,
        /// The profile, as the wrapper's profile object in JSON.
        profile: String,
    },
    /// The transaction's own bytes as hex, read under the chain `chain` at `height`.
    Decoded {
        /// The chain's number.
        chain: u64,
        /// The transaction's bytes, as hex.
        transaction: String,
        /// The height it was built or read for.
        height: u32,
    },
}

impl SignedSource {
    /// The signed transaction.
    pub(crate) fn resolve(&self, state: &Iceroot, label: &str) -> Result<SignedTransaction> {
        match self {
            SignedSource::Serialized {
                serialized,
                profile,
            } => {
                let profile = iceroot_sdk_bindings::profile::from_json(profile)?;
                Ok(iceroot_sdk_bindings::draft::signed_deserialize(
                    &from_hex(serialized, "the signed transaction")?,
                    &profile,
                )?)
            }
            SignedSource::Decoded {
                chain,
                transaction,
                height,
            } => {
                let chain = state.chain(label, *chain)?;
                Ok(iceroot_sdk_bindings::draft::signed_decode(
                    &chain,
                    &from_hex(transaction, "the transaction")?,
                    *height,
                )?)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(url: &str) -> Arc<RelayScope> {
        Arc::new(RelayScope {
            url: url.to_owned(),
        })
    }

    #[test]
    fn relays_need_an_allow_entry_and_no_deny_entry() {
        let allows = [
            entry("http://127.0.0.1:6003/api"),
            entry("https://*.example.org/api/"),
        ];
        let denies = [entry("https://bad.example.org/*")];
        assert!(relay_allowed("http://127.0.0.1:6003/api", &allows, &[]));
        assert!(!relay_allowed("http://127.0.0.1:6004/api", &allows, &[]));
        assert!(relay_allowed(
            "https://devnet.example.org/api",
            &allows,
            &denies
        ));
        assert!(!relay_allowed(
            "https://bad.example.org/api",
            &allows,
            &denies
        ));
        assert!(!relay_allowed("http://127.0.0.1:6003/api", &[], &[]));
        assert!(!relay_allowed("not a url", &allows, &[]));
    }

    #[test]
    fn a_wildcard_stays_within_a_segment_unless_doubled() {
        assert!(wildcard(b"*", b""));
        assert!(wildcard(b"a*b*c", b"aXXbYYc"));
        assert!(!wildcard(b"a*b*c", b"aXXbYY"));
        assert!(wildcard(b"**", b"any/thing"));
        assert!(!wildcard(b"*", b"any/thing"));
        assert!(wildcard(b"a/*/c", b"a/b/c"));
        assert!(!wildcard(b"a/*/c", b"a/b/b/c"));
        assert!(wildcard(b"a/**/c", b"a/b/b/c"));
        let ports = [entry("http://127.0.0.1:*/api")];
        assert!(relay_allowed("http://127.0.0.1:4973/api", &ports, &[]));
        assert!(!relay_allowed("http://127.0.0.1:6003/n/1/api", &ports, &[]));
        let under = [entry("http://127.0.0.1:6003/**")];
        assert!(relay_allowed("http://127.0.0.1:6003/n/1/api", &under, &[]));
    }

    #[test]
    fn no_spelling_of_a_url_reaches_a_host_the_entries_do_not_name() {
        let allows = [entry("https://*.example.org/api")];
        assert!(relay_allowed(
            "https://Devnet.Example.org/api",
            &allows,
            &[]
        ));
        for relay in [
            "https://evil.test/.example.org/api",
            "https://evil.test/x.example.org/api",
            "https://evil.test\\.example.org/api",
            "https://evil.test%2F.example.org/api",
            "https://evil.test:443/.example.org/api",
        ] {
            assert!(!relay_allowed(relay, &allows, &[]), "{relay}");
        }
    }

    /// A relay on a local port that answers from the devnet answers recorded in the node API
    /// client's fixtures, by method and path, and records each request's method and path.
    async fn recorded_relay() -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../iceroot-sdk-api/tests/fixtures/devnet");
        let index: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(fixtures.join("index.json")).unwrap())
                .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay = format!("http://{}/api", listener.local_addr().unwrap());
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 8192];
                // Up to the end of the headers, then the body its length gives.
                loop {
                    let n = socket.read(&mut buffer).await.unwrap();
                    request.extend_from_slice(&buffer[..n]);
                    let text = String::from_utf8_lossy(&request).to_string();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let length = text
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|value| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if request.len() >= end + 4 + length || n == 0 {
                            break;
                        }
                    }
                    if n == 0 {
                        break;
                    }
                }
                let text = String::from_utf8_lossy(&request).to_string();
                let mut first = text.lines().next().unwrap_or("").split(' ');
                let (method, target) = (first.next().unwrap_or(""), first.next().unwrap_or(""));
                let path = target.strip_prefix("/api").unwrap_or(target).to_owned();
                log.lock().unwrap().push(format!("{method} {path}"));
                let entry = index.as_array().unwrap().iter().find(|entry| {
                    entry["method"] == method && entry["path"].as_str() == Some(path.as_str())
                });
                let (status, body) = match entry {
                    Some(entry) => (
                        entry["status"].as_u64().unwrap(),
                        std::fs::read_to_string(fixtures.join(entry["file"].as_str().unwrap()))
                            .unwrap(),
                    ),
                    None => (
                        404,
                        r#"{"statusCode":404,"error":"Not Found","message":"none"}"#.to_owned(),
                    ),
                };
                let answer = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\nx-block-height: 80\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(answer.as_bytes()).await.unwrap();
            }
        });
        (relay, seen)
    }

    fn devnet(relay: &str) -> Profile {
        iceroot_sdk_bindings::profile::from_json(&format!(
            r#"{{"id":"devnet","backend":"solar-compat","api":{{"relays":["{relay}"]}},"chain":{{"networkByte":90}},"keyScheme":"bip32-secp256k1"}}"#
        ))
        .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_session_connects_reads_and_submits_through_the_client() {
        let (relay, seen) = recorded_relay().await;
        let options: ConnectOptions = serde_json::from_str(r#"{"rateLimit":false}"#).unwrap();
        let connected = Session::connect(&devnet(&relay), options).await.unwrap();
        let session = connected.session;
        // The chain the node serves, pinned from its configuration.
        assert_eq!(session.chain.network_byte(), 90);
        assert_eq!(session.chain.nethash().len(), 64);
        let configuration: serde_json::Value =
            serde_json::from_str(&connected.configuration).unwrap();
        assert!(
            configuration["pool"]["maxTransactionsPerRequest"]
                .as_u64()
                .unwrap()
                > 0
        );
        let status: serde_json::Value = serde_json::from_str(&connected.status).unwrap();
        assert!(status["height"].as_str().unwrap().parse::<u64>().unwrap() > 0);
        assert!(session.height() >= 80);

        let account: serde_json::Value = serde_json::from_str(
            &session
                .read(
                    "account",
                    r#"{"address":"dZ1W1GsDCSyhR148oMhuHy3PkhnnSGCqVn"}"#,
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(account["address"], "dZ1W1GsDCSyhR148oMhuHy3PkhnnSGCqVn");
        let missing = session
            .read("transaction", &format!(r#"{{"id":"{}"}}"#, "00".repeat(32)))
            .await
            .unwrap();
        assert_eq!(missing, "null");
        let refused = session.read("no-such-operation", "{}").await.unwrap_err();
        assert_eq!(refused.code(), "InvalidArgument");
        // The node configuration again, checked against the pinned chain.
        session.node_configuration().await.unwrap();
        // An empty submission is refused before anything is sent.
        let empty = session.submit(&[]).await.unwrap_err();
        assert_eq!(empty.code(), "InvalidRequest");

        let requests = seen.lock().unwrap().clone();
        assert_eq!(
            requests[..3],
            [
                "GET /node/configuration/crypto",
                "GET /node/configuration",
                "GET /node/status"
            ]
        );
        assert!(
            requests.iter().all(|request| !request.contains("POST")),
            "{requests:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_node_of_another_chain_is_refused() {
        let (relay, _) = recorded_relay().await;
        let pinned = iceroot_sdk_bindings::profile::from_json(&format!(
            r#"{{"id":"devnet","backend":"solar-compat","api":{{"relays":["{relay}"]}},"chain":{{"networkByte":90,"nethash":"{}"}},"keyScheme":"bip32-secp256k1"}}"#,
            "00".repeat(32)
        ))
        .unwrap();
        let error = Session::connect(&pinned, ConnectOptions::default())
            .await
            .err()
            .unwrap();
        assert_eq!(error.code(), "NetworkMismatch");
        let unreachable = devnet("http://127.0.0.1:9/api");
        let error = Session::connect(&unreachable, ConnectOptions::default())
            .await
            .err()
            .unwrap();
        assert_eq!(error.code(), "NodeUnavailable");
    }

    #[test]
    fn options_read_as_typescript_writes_them() {
        let options: ConnectOptions = serde_json::from_str(
            r#"{"headers":[["authorization","Bearer t"]],"rateLimit":{"requests":40,"windowMs":60000},"timeoutMs":5000}"#,
        )
        .unwrap();
        let http = http_options(options);
        assert_eq!(http.rate_limit.requests, 40);
        assert_eq!(http.timeout, Duration::from_secs(5));
        assert_eq!(http.headers.len(), 1);
        let unlimited: ConnectOptions = serde_json::from_str(r#"{"rateLimit":false}"#).unwrap();
        assert_eq!(http_options(unlimited).rate_limit.requests, u32::MAX);
        assert!(serde_json::from_str::<ConnectOptions>(r#"{"transport":1}"#).is_err());
        assert_eq!(status_height(r#"{"height":"80"}"#), Some(80));
        assert_eq!(status_height("{}"), None);
    }
}
