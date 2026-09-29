# iceroot-sdk-api

A sans-IO client for IceRoot node APIs. The crate builds every request and decodes every answer; the host performs the HTTP exchange with its own stack (`fetch` in browsers and webviews, reqwest natively, `net/http` in Go). One mapping from the node's resources to the SDK's IceRoot-shaped types therefore serves every language the SDK is built for.

## Backends

| Backend | Serves | Type |
|---|---|---|
| Solar-compatible | The REST API of the reference implementation under its `/api` base path, as today's devnet serves it | `SolarCompat` |

The mappers speak IceRoot's terms: a validator is never a "delegate", a validator's name is never a "username", vote shares are whole basis points and amounts are integers in base units.

## Calls

`SolarCompat` prepares one `Call` per operation. `call.request()` is what to send; `call.decode(&response)` turns the answer into a typed value or a typed `ApiError`.

| Call | Route | Returns |
|---|---|---|
| `node_status` | `GET /node/status` | `NodeStatus` |
| `node_configuration` | `GET /node/configuration` | `NodeConfiguration` (chain identity, milestone at the tip, `PoolLimits` with `max_transactions_per_request` and `max_transaction_bytes`, pool fees) |
| `crypto_configuration` | `GET /node/configuration/crypto` | `CryptoConfiguration` (network, milestones, genesis block as the node's JSON text) |
| `supply` | `GET /blockchain` | `Supply` |
| `fee_statistics` | `GET /node/fees` | `FeeStatistics` |
| `account` | `GET /wallets/{address}` | `AccountInfo` |
| `history`, `account_votes` | `GET /wallets/{address}/transactions[/sent\|/received]`, `/votes` | `Page<TxRecord>` with directions |
| `transaction`, `unconfirmed_transaction` | `GET /transactions/{id}`, `/transactions/unconfirmed/{id}` | `Option<TxRecord>` |
| `transactions`, `unconfirmed_transactions`, `votes`, `vote` | `GET /transactions`, `/transactions/unconfirmed`, `/votes`, `/votes/{id}` | `Page<TxRecord>`, `Option<TxRecord>` |
| `submit` | `POST /transactions` | `SubmitPlan`, then `SubmitReport` with an accepted or rejected outcome per transaction |
| `latest_block`, `genesis_block`, `block`, `blocks`, `block_transactions`, `missed_slots` | `GET /blocks/...` | `BlockInfo`, `Page<BlockInfo>`, `Page<TxRecord>`, `Page<MissedSlot>` |
| `validators`, `validator`, `voters`, `validator_blocks`, `validator_missed_slots` | `GET /delegates/...` | `ValidatorInfo` with rank, status, vote weight, voters and production counters |
| `resolve_name` | `GET /delegates/{name}` | `Option<ResolvedName>` |
| `round_validators` | `GET /rounds/{round}/delegates` | `Vec<RoundValidator>` |

Submissions are split into requests of at most the pool's `maxTransactionsPerRequest`, and a transaction above `maxTransactionBytes` is refused with reason `too-large` before it is sent. Refusals by the node keep its code (`ERR_LOW_FEE`, `ERR_APPLY`, ...) and get a normalized reason: `low-fee`, `nonce`, `balance`, `duplicate`, `invalid`, `pool-full`, `wrong-network`, `too-large` or `other`.

## Rate limit

The reference implementation allows 100 requests per 60 seconds per client address and answers HTTP 429 beyond that. `RequestBudget` spends requests against a `RateLimit` before they are sent, and `Backoff` spaces retries after a 429. A `Retry-After` is honoured up to `Backoff::MAX_RETRY_AFTER` (one minute); a longer one ends the retries instead of blocking the client. Both take the time as an argument, so they work in WebAssembly as well.

## Transports

Every transport keeps the same bounds: it reads at most `MAX_RESPONSE_BYTES` (8 MiB) of an answer and never decompresses it, skipping a relay that declares or sends more like one that cannot be reached, and it spaces retries after HTTP 429 with `Backoff`, moving to the next relay when a relay's retries are spent or it asks for more than a minute. `HttpClient` (feature `http`, below) does, and so do the TypeScript package's `fetch` transport and the Tauri plugin, which uses `HttpClient`. The Go SDK embeds the SDK compiled to WebAssembly, which performs no input or output, so its own transport must keep these bounds; the module's exports `transportLimits` and `backoffDelay` give it the limit and the waits (see [`iceroot-sdk-ffi`](../iceroot-sdk-ffi/README.md)). A decoder's own refusal of a longer body comes only after the host has read it, so it bounds nothing the host holds.

## Feature `http`

`HttpClient` sends calls with reqwest (rustls) to a list of relays: reads go to the first relay that answers, 429 is retried after the backoff (a relay whose retries are spent, or that asks for more than a minute, is skipped), and requests keep to the request budget. An answer is read up to `MAX_RESPONSE_BYTES` (8 MiB) and never decompressed; a relay that declares or sends more is skipped like one that cannot be reached. Every decoder also refuses a longer body with `BadResponse` before parsing it, whatever transport received it. `HttpOptions::headers` adds headers to every request, for a relay behind a proxy that asks for a token; their values never appear in the client's `Debug` output. The relays are not assumed to serve one chain: without `HttpOptions::identity` a request goes to whichever relay answers, so a failover can reach a relay of another chain. With it (`Chain::relay_identity` of a chain loaded from a relay, in the core), each relay is asked for its node configuration before its first use, a relay that names another network hash or byte is never asked anything else by that client, and one that cannot be checked now is skipped and checked again on the next request. It is available on native targets only; a WebAssembly build never contains reqwest, hyper or tokio.

A client of more than one relay must be given the identity. The TypeScript package, the Tauri plugin and the Go SDK check every relay whatever the application does; `HttpClient` checks only with `HttpOptions::identity`, and its default options set none. Load the chain first, checking the node's configuration against it since any relay may have answered, then send everything else through a client with the chain's identity. With the `iceroot-sdk` crate:

```rust,no_run
use iceroot_sdk::api::{HttpClient, HttpOptions, Relay, SolarCompat};
use iceroot_sdk::{Chain, Error, Profile};

async fn connect(profile: &Profile) -> Result<(Chain, SolarCompat, HttpClient), Error> {
    let relays = profile.endpoints().relays.iter().map(|relay| Relay::parse(relay)).collect::<Result<Vec<_>, _>>()?;
    // Loading the chain: any relay may answer, so the node's configuration is checked against it.
    let loader = HttpClient::new(relays.clone())?;
    let configuration = loader.send(&SolarCompat::new(0).node_configuration()).await?;
    let api = SolarCompat::for_configuration(&configuration);
    let chain = Chain::from_node(profile, &loader.send(&api.crypto_configuration()).await?)?;
    chain.check_node(&configuration)?;
    // Everything else: each relay is checked to serve this chain before its first use.
    let options = HttpOptions { identity: Some(chain.relay_identity()), ..HttpOptions::default() };
    Ok((chain, api, HttpClient::with_options(relays, options)?))
}
```

```rust,no_run
use iceroot_sdk_api::{HttpClient, Relay, SolarCompat};

# async fn run() -> Result<(), iceroot_sdk_api::ApiError> {
let client = HttpClient::new(vec![Relay::parse("http://127.0.0.1:4003/api")?])?;
let configuration = client.send(&SolarCompat::new(0).node_configuration()).await?;
let api = SolarCompat::for_configuration(&configuration);
let validators = client.send(&api.validators(Default::default())).await?;
# Ok(())
# }
```

## Feature `serde`

With `serde`, the request values (`Request`, `Response`, `Relay`, `PageRequest`, `TxFilter`, `BlockRef`, `HistoryDirection`, `SubmitTx`) and every answer implement `Serialize` and `Deserialize`. The client stays sans-IO; the feature adds no dependency. The JSON form is the one every binding of the SDK exchanges, so it is the same for every language:

- field names in camel case (`senderPublicKey`), enum values as lower-case words joined by hyphens (`resigned-temporary`, `low-fee`);
- integers of 64 bits and more (amounts, nonces, heights, times, lifetime counters) as decimal strings, which JavaScript numbers could not hold exactly; smaller integers (ranks, basis points, page numbers, sizes, wire types) as numbers;
- absent optional values left out;
- asset ids as `ROOT` or 64 hex digits;
- a transaction kind as a `kind` field, with `typeGroup` and `typeId` beside it for `other`; transaction details tagged by `kind`, and submission outcomes by `status` (`accepted` or `rejected`) next to the transaction's `id`.

A transfer from the recorded devnet fixtures, as `serde_json` writes it:

```json
{
  "id": "b2abe2cabab608935280c144a15ebea3e4e8348c530a983ffbf6013a13ab54a9",
  "status": "confirmed",
  "block": {
    "id": "04bc52da30e3fcc46da881d48f9d50b6754befc6fdfe8faf6746f3591b8741ba",
    "height": "82",
    "confirmations": "1",
    "time": { "chain": "648", "unix": "1790484455" }
  },
  "sender": "daTBxkSJk2tZhujYcYSQtxj5RRFZ8HcxW8",
  "senderPublicKey": "03f5679f03b0f7569d29708aed1ce026a0a2c1aa4145f6aa51a3298253d58d725f",
  "nonce": "1",
  "fee": "2000000",
  "burnedFee": "1800000",
  "memo": "fixture: two recipients",
  "secondSigned": false,
  "version": 3,
  "details": {
    "kind": "transfer",
    "recipients": [
      { "address": "dZ1W1GsDCSyhR148oMhuHy3PkhnnSGCqVn", "amount": "1000000000" },
      { "address": "dMVgdVMdEWR2rVH6RRgXqheywVTzbgLNyG", "amount": "2000000000" }
    ]
  }
}
```

## Tests

```sh
cargo test -p iceroot-sdk-api --all-features
```

The mappers are tested against responses recorded from a local devnet (`tests/fixtures/devnet`), and `tests/serde.rs` writes every decoded answer as JSON and reads it back unchanged. `tests/live.rs` runs every call against a running node when `ICEROOT_SDK_LIVE_RELAY` names its API:

```sh
ICEROOT_SDK_LIVE_RELAY=http://127.0.0.1:4003/api cargo test -p iceroot-sdk-api --features http --test live -- --ignored
```
