# IceRoot SDK (Rust)

The Rust core of the IceRoot SDK: recovery phrases and keys, addresses, amounts, transaction builders and signing, fees, the node API client and the vote selection library. It builds on Heartwood Core's byte-exact layer, so the SDK and the node share one implementation of every format. The TypeScript SDK and, later, the Go SDK are built from this core.

The SDK is in early development. Releases are tagged here on GitHub; nothing is published to a package registry yet.

[Contributing](https://github.com/iceroot-network/.github/blob/prod/CONTRIBUTING.md). Work on `dev`. Production changes reach `prod` through a reviewed `dev` → `prod` pull request.

## Crates

| Crate | What it holds |
|---|---|
| `iceroot-sdk` | The one crate applications depend on. It re-exports the others. |
| `iceroot-sdk-core` | Network profiles and capabilities, the rules and economics in force, BIP39 recovery phrases and hardened key derivation, accounts, addresses, amounts, transaction drafts and signing, serialized drafts, message signing and the sign-in message, and the error type with its stable codes. No input or output: it reads what the node API client decodes (the chain, a draft's nonce, height and second key, submission outcomes) and checks it on the way. |
| `iceroot-sdk-api` | A sans-IO node API client: it builds each request and decodes each answer into IceRoot-shaped values (accounts, validators, transactions, blocks, node facts), and plans submissions within the pool's limits. The host performs the HTTP exchange; the optional `http` feature adds an async reqwest transport on native targets, and the optional `serde` feature gives every request value and answer the JSON form the SDK's bindings share. See [its README](crates/iceroot-sdk-api/README.md). |

Every byte and verdict of a key, address, signature or transaction comes from `heartwood-crypto`. The SDK adds only client code and never enables a `heartwood-crypto` feature; `tools/check-deps.sh` enforces that, and keeps Heartwood Core's consensus crates out of the dependency tree.

## What works today

- **Networks.** The `devnet` profile (network byte 90) in today's formats: transfers to 1 to 256 recipients with a memo, votes, burns, second keys, validator registration and resignation, and message signing. The profiles of the IceRoot stages to come (`devnet-pq`, `id-devnet`) are declared with every capability off, so an application can list them and hide what they cannot do yet. The public testnet and mainnet get their profiles when their genesis is fixed.
- **Keys.** New phrases have 24 words; imports of 18, 21 or 24 words are accepted and shorter ones refused. Keys are derived with hardened steps only, at `m/44'/1'/account'/0'/index'` on devnets and the public testnet. The reference implementation's passphrase keys (the SHA-256 of the passphrase) can be imported on devnet profiles, for existing devnet wallets; they are never used for new accounts.
- **Drafts.** A draft is built from an operation and the facts a node reports (nonce, height, second key), checked against every rule, and signed as a separate step. A draft can be serialized, signed in another context (a sandboxed page, a native plugin, another device) and sent back.
- **Nodes.** Reads of today's devnet API (node status and configuration, accounts and history, transactions and the pool, blocks, validators, rounds, supply and fee statistics), submissions batched by the pool's limits with each refusal's reason, and a request budget for the node's rate limit. The chain a node serves is loaded and pinned from its own configuration, and a node of another chain is refused.
- **Fees.** A draft always carries an explicit fee and says where it comes from. The default fee is the exact fee floor of the milestone in force for the transaction's type and size, computed by `heartwood-crypto`'s own function, the one the node checks every fee with; an exact fee or a multiple of the floor can be chosen instead. Where the milestone has no enabled dynamic fee table there is no floor, since the node's pool then applies settings of its own: the default fee is refused with `FeeUnavailable` and a draft needs an exact fee. The SDK never guesses a fee from what other transactions paid. A draft read back from its serialized form computes the floor again and calls its fee the floor only when it is.

## Using it

Releases are tags of this repository, `v0.1.0`, `v0.2.0` and so on, each with a release page on GitHub that states the `heartwood-crypto` revision it contains and what changed. Depend on the crates at a release tag:

```toml
[dependencies]
iceroot-sdk = { git = "https://github.com/iceroot-network/sdk-rust", tag = "v0.1.0" }
# With the async HTTP transport (native targets only):
# iceroot-sdk = { git = "https://github.com/iceroot-network/sdk-rust", tag = "v0.1.0", features = ["http"] }
# With Serialize and Deserialize on the node API client's values (for example to hand them to a
# web page as JSON):
# iceroot-sdk = { git = "https://github.com/iceroot-network/sdk-rust", tag = "v0.1.0", features = ["serde"] }
```

`Cargo.lock` then records the exact commit. Nothing is published to crates.io yet. JavaScript and TypeScript applications use the package of [sdk-typescript](https://github.com/iceroot-network/sdk-typescript) instead: its release of the same version attaches the npm package tarball, built from this release, which installs by URL with `npm install https://github.com/iceroot-network/sdk-typescript/releases/download/v0.1.0/iceroot-network-sdk-0.1.0.tgz`.

The node API client is `iceroot_sdk::api`. The example in the documentation of `iceroot-sdk` builds and signs a transfer (`cargo doc --open -p iceroot-sdk`).

Building from source needs read access to the `heartwood-core` repository while it is private. `Cargo.toml` fetches it over SSH from `ssh://git@github.com/iceroot-network/heartwood-core.git`, so any SSH key GitHub accepts for that repository works: the default key, or the one `~/.ssh/config` names for `github.com`. `.cargo/config.toml` makes Cargo fetch with the `git` command line, so the machine's SSH and git configuration apply; an application that depends on the SDK needs the same in its own `.cargo/config.toml`:

```toml
[net]
git-fetch-with-cli = true
```

Where the key with access sits behind an SSH host alias instead (a separate key per organisation, for example), rewrite the address for the command that fetches, with git configuration from the environment, which Cargo passes on to git:

```sh
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0='url.ssh://git@<alias>/iceroot-network/.insteadOf' \
GIT_CONFIG_VALUE_0='ssh://git@github.com/iceroot-network/' \
  cargo fetch --locked
```

Once Cargo holds the commit `Cargo.lock` pins, builds need no access at all (`cargo build --offline`). On a CI machine or in a container, the same rewrite can go in the global git configuration instead (`git config --global url.<alias URL>.insteadOf <github.com URL>`), as `tools/ci/heartwood-access.sh` does with a deploy key. A rewrite in a repository's own git configuration has no effect, because Cargo fetches in a repository of its own.

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

The workflows read `heartwood-core` with a read-only deploy key of that repository, stored in this repository as the secret `HEARTWOOD_DEPLOY_KEY`; `tools/ci/heartwood-access.sh` installs it under an SSH host alias of its own and rewrites `heartwood-core`'s `github.com` address to that alias, so the key serves that repository only. Pull requests from forks get no secrets, so their runs stop at that step. While `heartwood-core` is private, only pull request runs save the dependency cache: it holds Cargo's copy of `heartwood-core`, and a pull request from a fork can restore the caches of this repository's branches.

### Releasing

1. Set the version in `Cargo.toml` (`[workspace.package]`) on `dev` and merge `dev` into `prod` through a pull request.
2. Tag the merge commit on `prod` with `v` and the version, and push the tag: `git tag -a v0.1.0 -m "IceRoot SDK for Rust 0.1.0"`, then `git push origin v0.1.0`.
3. `.github/workflows/release.yml` runs the tests again and publishes the release page with `tools/release.mjs`, which refuses a tag that differs from the version or is not on `prod`. `node tools/release.mjs --tag v0.1.0 --dry-run` shows the notes without publishing.

Release sdk-rust first: the TypeScript package of the same version is built from this tag.

### Vectors

- `vectors/heartwood/`: copies of Heartwood Core's golden vectors of `heartwood-crypto` at the pinned tag, generated from the reference implementation, with `MANIFEST.sha256`. `crates/iceroot-sdk-core/tests/heartwood_vectors.rs` runs every record through the SDK's public API, except the reference's raw signatures of chosen 32-byte inputs, which go through the test seam of the feature `fixed-aux` because no public function signs a chosen digest; records the SDK has no operation for (blocks, peer status) are skipped by an explicit rule, and each class asserts how many records matched, differed as documented, or were skipped. Updating the pinned tag updates these files in the same change.
- `vectors/sdk/`: the SDK's own vectors, in the same `heartwood-vectors/1` format: BIP39 phrases and seeds (the published vectors, non-ASCII passphrases, validation, and the genesis passphrases of Heartwood Core's devnet), hardened derivation (the BIP32 test vectors and wallet paths), message signatures, sign-in messages, transactions of every operation (transfers to 1, 2 and 256 recipients, memos at the 255-byte limit, votes of 1, 20 and 53 entries, second-signed transactions, keys from legacy passphrases and from recovery phrases) built by the SDK and compared with the reference's bytes, ids and JSON, and the fee floor of every operation at sizes on both sides of its rounding. `tools/oracle/gen-sdk-vectors.js` generates them with the reference implementation as the oracle: its own libraries, transaction builders and transaction handlers (Node 18):

  ```sh
  node tools/oracle/gen-sdk-vectors.js <built reference checkout> <browser wallet checkout>
  ```

### Devnet end-to-end test

`crates/iceroot-sdk/tests/e2e.rs`, behind the `e2e` feature, runs against a local devnet: it connects and pins the chain, imports a genesis wallet with the legacy passphrase import, creates an account from a new recovery phrase, funds it, sends a transfer with a memo and a vote, waits until each is forged and reads it back through the node API client, and checks that a fee one base unit below the floor is refused with the node's own code. `tools/e2e/devnet.sh` starts a fresh one-node devnet of the reference implementation through its devnet tooling (`ICEROOT_DEVNET_TOOLS`), runs the test, and stops and removes the devnet; the chain never runs more than five rounds:

```sh
ICEROOT_DEVNET_TOOLS=<devnet tooling> tools/e2e/devnet.sh run -- \
  cargo test -p iceroot-sdk --features e2e --test e2e -- --ignored
```

The TypeScript SDK's `npm run test:e2e` runs the same harness for its Node and Chromium tests and then this test, which also verifies the messages they signed.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
