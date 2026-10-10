# IceRoot SDK for Rust

The IceRoot SDK for Rust provides keys, addresses, amounts, transaction drafts and signing, a node API client, vote selection, encrypted keystores and signed proofs. It builds on Heartwood Core's byte-exact crypto layer. The [TypeScript SDK](https://github.com/iceroot-network/sdk-typescript) and [Go SDK](https://github.com/iceroot-network/sdk-go) use this Rust core through bindings.

## Status

- Early development. The API may change before 1.0.
- Only classical devnet formats are supported today.
- Nothing is published to crates.io, and there are no release tags yet.

The supported profile is `devnet` (network byte 90). It supports transfers, votes, burns, second keys, validator registration and resignation, and message signing. `devnet-pq` and `id-devnet` are declared with every capability disabled. There is no public testnet or mainnet profile yet.

The public `Stage` values describe chain formats: `S1` means today's secp256k1 keys, BIP340 signatures and Base58Check addresses; `Pq` means post-quantum ML-DSA-65 keys and signatures; `Id` means IceRoot formats with Bech32m addresses and 128-bit amounts. Declared stages do not imply support: the chain currently resolves to `S1`.

## Install

Use the public `prod` branch until the first release tag follows:

```toml
[dependencies]
iceroot-sdk = { git = "https://github.com/iceroot-network/sdk-rust", branch = "prod" }
```

For a fixed revision, replace `branch = "prod"` with `rev = "<exact commit>"`. `Cargo.lock` records the resolved commit. The `v0.1.0` tag does not exist yet. Building fetches `heartwood-crypto` from [heartwood-core](https://github.com/iceroot-network/heartwood-core) over public HTTPS without a key or token. The toolchain is pinned in [rust-toolchain.toml](rust-toolchain.toml).

The default `keystore` feature can be disabled with `default-features = false`. Enable `http` for the native async HTTP transport, or `serde` for JSON serialization of API values.

## Quickstart

This function builds and signs a transfer offline from a saved `/node/configuration/crypto` JSON string. The nonce and height below are example facts, not values to use for a live account. Review the recipient, amount and fee before signing. Then the sans-IO client prepares a node status request. Your HTTP stack sends `call.request()` to the node's `/api` base URL and supplies the response to the decoder.

```rust
use iceroot_sdk::{
    amount::Amount,
    api::{Response, SolarCompat},
    fee::FeeChoice,
    keys::{Account, AccountOptions},
    phrase::Mnemonic,
    profile::DevnetOptions,
    transaction::{Draft, DraftRequest, OnlineFacts, Operation, Recipient},
    Chain, Profile,
};

fn example(
    configuration: &str,
    exchange: impl FnOnce(&iceroot_sdk::api::Request) -> Response,
) -> Result<(), Box<dyn std::error::Error>> {
    let profile = Profile::devnet(DevnetOptions::default());
    let chain = Chain::load(&profile, configuration)?;
    let phrase = Mnemonic::generate()?;
    let sender = Account::from_phrase(chain.profile(), &phrase, &AccountOptions::default())?;
    let recipient = Account::from_phrase(
        chain.profile(),
        &phrase,
        &AccountOptions {
            index: 1,
            ..AccountOptions::default()
        },
    )?;
    let request = DraftRequest {
        operation: Operation::Transfer {
            recipients: vec![Recipient {
                address: *recipient.address(),
                amount: Amount::parse("1.5", chain.token().decimals)?,
            }],
        },
        memo: Some("invoice 42".to_owned()),
        fee: FeeChoice::Exact(Amount::parse("0.01", chain.token().decimals)?),
    };
    let facts = OnlineFacts {
        sender: sender.public_key().clone(),
        nonce: 1,
        height: 2,
        second_key: None,
    };
    let signed = Draft::build(&chain, &request, &facts)?.sign(&sender, None)?;
    println!("{} {}", signed.id(), signed.json());
    let call = SolarCompat::new(53).node_status();
    let status = call.decode(&exchange(call.request()))?;
    println!("{status:?}");
    Ok(())
}
```

The transfer follows the [crate documentation example](crates/iceroot-sdk/src/lib.rs). For live transactions, load and check the node's chain with `Chain::from_node` and `Chain::check_node`, and obtain the account facts with `OnlineFacts::from_node`. Signing does not submit a transaction.

## Crates

| Crate | Purpose |
|---|---|
| `iceroot-sdk` | Application entry point; re-exports the core, API, vote library and optional keystore. |
| `iceroot-sdk-core` | Profiles, keys, addresses, amounts, transaction drafts, signing, sign-in messages, ownership proofs and account links. |
| [`iceroot-sdk-api`](crates/iceroot-sdk-api/README.md) | Sans-IO node requests and decoders, with optional native HTTP transport and JSON serialization. |
| [`iceroot-vote`](crates/iceroot-vote/README.md) | Four vote selection modes, vote validation and checks of existing selections. Pure functions. |
| [`iceroot-sdk-bindings`](crates/iceroot-sdk-bindings/README.md) | Shared JSON boundary and key handles for language bindings. |
| [`tauri-plugin-iceroot`](crates/tauri-plugin-iceroot/README.md) | Tauri 2 plugin with native keys, signing, node requests and keystores. Separate workspace. |
| [`iceroot-sdk-ffi`](crates/iceroot-sdk-ffi/README.md) | WebAssembly exports embedded by the Go SDK using wazero. |
| [`iceroot-link-cli`](crates/iceroot-link-cli/README.md) | Offline signing, revocation and verification of account links. |
| [`iceroot-keystore`](crates/iceroot-keystore/README.md) | Password-encrypted recovery-phrase entropy with Argon2id and XChaCha20-Poly1305. |

## Documentation

- [SDK guide](https://docs.iceroot.com/developers/sdk/)
- [Node REST API](https://docs.iceroot.com/developers/rest-api/)
- [Network status](https://docs.iceroot.com/network/status/)
- Format specifications in [docs/](docs/): [ownership proofs](docs/ownership-proofs.md), [account links](docs/account-links.md) and [keystores](docs/keystore-format.md).
- [Maintaining the SDK](docs/maintaining.md): development checks, releases, vectors and devnet tests.

## Security

Follow the [security policy](https://github.com/iceroot-network/.github/blob/prod/SECURITY.md). Do not open public issues for vulnerabilities.

## Contributing

See the [contribution guide](https://github.com/iceroot-network/.github/blob/prod/CONTRIBUTING.md). Pull requests go against `dev`.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
