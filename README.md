# IceRoot SDK (Rust)

The Rust core of the IceRoot SDK: recovery phrases and keys, addresses, amounts, transaction builders and signing, fees, the node API client and the vote selection library. It builds on Heartwood Core's byte-exact layer, so the SDK and the node share one implementation of every format. The TypeScript SDK and, later, the Go SDK are built from this core.

The SDK is in early development. Releases are tagged here on GitHub; nothing is published to a package registry yet.

[Contributing](https://github.com/iceroot-network/.github/blob/prod/CONTRIBUTING.md). Work on `dev`. Production changes reach `prod` through a reviewed `dev` → `prod` pull request.

## Crates

| Crate | What it holds |
|---|---|
| `iceroot-sdk` | The one crate applications depend on. It re-exports the others. |
| `iceroot-sdk-core` | Network profiles and capabilities, the rules and economics in force, BIP39 recovery phrases and hardened key derivation, accounts, addresses, amounts, transaction drafts and signing, serialized drafts, message signing and the sign-in message, and the error type with its stable codes. No input or output: it reads what the node API client decodes (the chain, a draft's nonce, height and second key, fee statistics, submission outcomes) and checks it on the way. |
| `iceroot-sdk-api` | A sans-IO node API client: it builds each request and decodes each answer into IceRoot-shaped values (accounts, validators, transactions, blocks, node facts), and plans submissions within the pool's limits. The host performs the HTTP exchange; the optional `http` feature adds an async reqwest transport on native targets. See [its README](crates/iceroot-sdk-api/README.md). |

Every byte and verdict of a key, address, signature or transaction comes from `heartwood-crypto`. The SDK adds only client code and never enables a `heartwood-crypto` feature; `tools/check-deps.sh` enforces that, and keeps Heartwood Core's consensus crates out of the dependency tree.

## What works today

- **Networks.** The `devnet` profile (network byte 90) in today's formats: transfers to 1 to 256 recipients with a memo, votes, burns, second keys, validator registration and resignation, and message signing. The profiles of the IceRoot stages to come (`devnet-pq`, `id-devnet`) are declared with every capability off, so an application can list them and hide what they cannot do yet. The public testnet and mainnet get their profiles when their genesis is fixed.
- **Keys.** New phrases have 24 words; imports of 18, 21 or 24 words are accepted and shorter ones refused. Keys are derived with hardened steps only, at `m/44'/1'/account'/0'/index'` on devnets and the public testnet. The reference implementation's passphrase keys (the SHA-256 of the passphrase) can be imported on devnet profiles, for existing devnet wallets; they are never used for new accounts.
- **Drafts.** A draft is built from an operation and the facts a node reports (nonce, height, second key), checked against every rule, and signed as a separate step. A draft can be serialized, signed in another context (a sandboxed page, a native plugin, another device) and sent back.
- **Nodes.** Reads of today's devnet API (node status and configuration, accounts and history, transactions and the pool, blocks, validators, rounds, supply and fee statistics), submissions batched by the pool's limits with each refusal's reason, and a request budget for the node's rate limit. The chain a node serves is loaded and pinned from its own configuration, and a node of another chain is refused.
- **Fees.** A draft always carries an explicit fee and says where it comes from. This release resolves the default fee from the node's fee statistics, or takes an exact fee; the exact fee floor of the milestone in force comes with the next revision of `heartwood-crypto`.

## Using it

Releases are tags of this repository, `v0.1.0`, `v0.2.0` and so on, each with a release page on GitHub that states the `heartwood-crypto` revision it contains and what changed. Depend on the crates at a release tag:

```toml
[dependencies]
iceroot-sdk = { git = "https://github.com/iceroot-network/sdk-rust", tag = "v0.1.0" }
# With the async HTTP transport (native targets only):
# iceroot-sdk = { git = "https://github.com/iceroot-network/sdk-rust", tag = "v0.1.0", features = ["http"] }
```

`Cargo.lock` then records the exact commit. Nothing is published to crates.io yet. JavaScript and TypeScript applications use the package of [sdk-typescript](https://github.com/iceroot-network/sdk-typescript) instead: its release of the same version attaches the npm package tarball, built from this release, which installs by URL with `npm install https://github.com/iceroot-network/sdk-typescript/releases/download/v0.1.0/iceroot-network-sdk-0.1.0.tgz`.

The node API client is `iceroot_sdk::api`. The example in the documentation of `iceroot-sdk` builds and signs a transfer (`cargo doc --open -p iceroot-sdk`).

Building from source needs read access to the `heartwood-core` repository, which is fetched over SSH through the host alias `github-iceroot` (see `Cargo.toml`). Point the alias at GitHub with a key that can read the repository:

```text
# ~/.ssh/config
Host github-iceroot
    HostName github.com
    User git
    IdentityFile ~/.ssh/<a key with read access to heartwood-core>
```

`.cargo/config.toml` makes Cargo fetch with the `git` command line, so this configuration applies. An application that depends on the SDK needs the same in its own `.cargo/config.toml`, and its builds (CI, Docker) need the alias too. Where an SSH host alias is not practical, a git URL rewrite does the same for the build's environment:

```sh
git config --global url."git@github.com:iceroot-network/heartwood-core.git".insteadOf \
  "ssh://git@github-iceroot/iceroot-network/heartwood-core.git"
```

## Development

The toolchain is pinned in `rust-toolchain.toml` (Rust 1.98.0, as Heartwood Core).

```sh
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
tools/check-deps.sh
node tools/notice.mjs --check
# WebAssembly: libsecp256k1 is C, so a clang with the wasm32 target is needed.
CC_wasm32_unknown_unknown=clang AR_wasm32_unknown_unknown=llvm-ar \
  cargo build --workspace --target wasm32-unknown-unknown --release
```

`NOTICE` lists the third-party crates a build links, with their licences, copyright lines and licence texts, and carries Heartwood Core's notice. It is generated from `Cargo.lock`: after changing a dependency, run `node tools/notice.mjs` and commit the result.

### Continuous integration

`.github/workflows/ci.yml` runs on pull requests to `dev` and `prod` and on pushes to `prod`: formatting, clippy (native with every feature, and wasm32), the tests with both vector sets, the documentation, the wasm32 build, the dependency guard and the `NOTICE` check. A second job builds and tests against Heartwood Core's `dev` branch, so a change there is seen before the next `heartwood-crypto` tag; it does not block a merge.

The workflows read `heartwood-core` with a read-only deploy key of that repository, stored in this repository as the secret `HEARTWOOD_DEPLOY_KEY`; `tools/ci/heartwood-access.sh` installs it for the host alias. Pull requests from forks get no secrets, so their runs stop at that step.

### Releasing

1. Set the version in `Cargo.toml` (`[workspace.package]`) on `dev` and merge `dev` into `prod` through a pull request.
2. Tag the merge commit on `prod` with `v` and the version, and push the tag: `git tag -a v0.1.0 -m "IceRoot SDK for Rust 0.1.0"`, then `git push origin v0.1.0`.
3. `.github/workflows/release.yml` runs the tests again and publishes the release page with `tools/release.mjs`, which refuses a tag that differs from the version or is not on `prod`. `node tools/release.mjs --tag v0.1.0 --dry-run` shows the notes without publishing.

Release sdk-rust first: the TypeScript package of the same version is built from this tag.

### Vectors

- `vectors/heartwood/`: copies of Heartwood Core's golden vectors of `heartwood-crypto` at the pinned revision, generated from the reference implementation, with `MANIFEST.sha256`. `crates/iceroot-sdk-core/tests/heartwood_vectors.rs` runs every record through the SDK's public API; records the SDK has no operation for (blocks, peer status) are skipped by an explicit rule, and each class asserts how many records matched, differed as documented, or were skipped. Updating the pinned revision updates these files in the same change.
- `vectors/sdk/`: the SDK's own vectors, in the same `heartwood-vectors/1` format: BIP39 phrases and seeds (the published vectors, non-ASCII passphrases, validation, and the genesis passphrases of Heartwood Core's devnet), hardened derivation (the BIP32 test vectors and wallet paths), message signatures, and sign-in messages. `tools/oracle/gen-sdk-vectors.js` generates them with the reference implementation's own libraries as the oracle:

  ```sh
  node tools/oracle/gen-sdk-vectors.js <built reference checkout> <browser wallet checkout>
  ```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
