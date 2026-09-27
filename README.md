# IceRoot SDK (Rust)

The Rust core of the IceRoot SDK: recovery phrases and keys, addresses, amounts, transaction builders and signing, fees, the node API client and the vote selection library. It builds on Heartwood Core's byte-exact layer, so the SDK and the node share one implementation of every format. The TypeScript SDK and, later, the Go SDK are built from this core.

The SDK is in early development. Releases are tagged here on GitHub; nothing is published to a package registry yet.

[Contributing](https://github.com/iceroot-network/.github/blob/prod/CONTRIBUTING.md). Work on `dev`. Production changes reach `prod` through a reviewed `dev` → `prod` pull request.

## Crates

| Crate | What it holds |
|---|---|
| `iceroot-sdk` | The one crate applications depend on. It re-exports the others. |
| `iceroot-sdk-core` | Network profiles and capabilities, the rules and economics in force, BIP39 recovery phrases and hardened key derivation, accounts, addresses, amounts, transaction drafts and signing, serialized drafts, message signing and the sign-in message, and the error type with its stable codes. No input or output: the node API client builds on it. |

Every byte and verdict of a key, address, signature or transaction comes from `heartwood-crypto`. The SDK adds only client code and never enables a `heartwood-crypto` feature; `tools/check-deps.sh` enforces that, and keeps Heartwood Core's consensus crates out of the dependency tree.

## What works today

- **Networks.** The `devnet` profile (network byte 90) in today's formats: transfers to 1 to 256 recipients with a memo, votes, burns, second keys, validator registration and resignation, and message signing. The profiles of the IceRoot stages to come (`devnet-pq`, `id-devnet`) are declared with every capability off, so an application can list them and hide what they cannot do yet. The public testnet and mainnet get their profiles when their genesis is fixed.
- **Keys.** New phrases have 24 words; imports of 18, 21 or 24 words are accepted and shorter ones refused. Keys are derived with hardened steps only, at `m/44'/1'/account'/0'/index'` on devnets and the public testnet. The reference implementation's passphrase keys (the SHA-256 of the passphrase) can be imported on devnet profiles, for existing devnet wallets; they are never used for new accounts.
- **Drafts.** A draft is built from an operation and the facts a node reports (nonce, height, second key), checked against every rule, and signed as a separate step. A draft can be serialized, signed in another context (a sandboxed page, a native plugin, another device) and sent back.
- **Fees.** A draft always carries an explicit fee and says where it comes from. This release resolves the default fee from the node's fee statistics, or takes an exact fee; the exact fee floor of the milestone in force comes with the next revision of `heartwood-crypto`.

## Using it

```toml
[dependencies]
iceroot-sdk = { git = "https://github.com/iceroot-network/sdk-rust", tag = "v0.1.0" }
```

The example in the documentation of `iceroot-sdk` builds and signs a transfer (`cargo doc --open -p iceroot-sdk`).

Building from source needs read access to the `heartwood-core` repository, which is fetched over SSH through the host alias `github-iceroot` (see `Cargo.toml`). Point the alias at GitHub with a key that can read the repository:

```text
# ~/.ssh/config
Host github-iceroot
    HostName github.com
    User git
    IdentityFile ~/.ssh/<a key with read access to heartwood-core>
```

`.cargo/config.toml` makes Cargo fetch with the `git` command line, so this configuration applies.

## Development

The toolchain is pinned in `rust-toolchain.toml` (Rust 1.98.0, as Heartwood Core).

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
tools/check-deps.sh
# WebAssembly: libsecp256k1 is C, so a clang with the wasm32 target is needed.
CC_wasm32_unknown_unknown=clang AR_wasm32_unknown_unknown=llvm-ar \
  cargo build --workspace --target wasm32-unknown-unknown --release
```

### Vectors

- `vectors/heartwood/`: copies of Heartwood Core's golden vectors of `heartwood-crypto` at the pinned revision, generated from the reference implementation, with `MANIFEST.sha256`. `crates/iceroot-sdk-core/tests/heartwood_vectors.rs` runs every record through the SDK's public API; records the SDK has no operation for (blocks, peer status) are skipped by an explicit rule, and each class asserts how many records matched, differed as documented, or were skipped. Updating the pinned revision updates these files in the same change.
- `vectors/sdk/`: the SDK's own vectors, in the same `heartwood-vectors/1` format: BIP39 phrases and seeds (the published vectors, non-ASCII passphrases, validation, and the genesis passphrases of Heartwood Core's devnet), hardened derivation (the BIP32 test vectors and wallet paths), message signatures, and sign-in messages. `tools/oracle/gen-sdk-vectors.js` generates them with the reference implementation's own libraries as the oracle:

  ```sh
  node tools/oracle/gen-sdk-vectors.js <built reference checkout> <browser wallet checkout>
  ```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
