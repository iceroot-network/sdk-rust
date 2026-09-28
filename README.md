# IceRoot SDK (Rust)

The Rust core of the IceRoot SDK: recovery phrases and keys, addresses, amounts, transaction builders and signing, fees, the node API client, the vote selection library and ownership proofs of Solar addresses. It builds on Heartwood Core's byte-exact layer, so the SDK and the node share one implementation of every format. The TypeScript and Go SDKs are built from this core.

The SDK is in early development. Releases are tagged here on GitHub; nothing is published to a package registry yet.

[Contributing](https://github.com/iceroot-network/.github/blob/prod/CONTRIBUTING.md). Work on `dev`. Production changes reach `prod` through a reviewed `dev` → `prod` pull request.

## Crates

| Crate | What it holds |
|---|---|
| `iceroot-sdk` | The one crate applications depend on. It re-exports the others, the keystore behind the feature `keystore`, which is on by default, and gives the vote library the rules in force and a node's validator list. |
| `iceroot-sdk-core` | Network profiles and capabilities, the rules and economics in force, BIP39 recovery phrases and hardened key derivation, accounts, addresses, amounts, transaction drafts and signing, serialized drafts, message signing and the sign-in message, ownership proofs of Solar addresses, and the error type with its stable codes. No input or output: it reads what the node API client decodes (the chain, a draft's nonce, height and second key, submission outcomes) and checks it on the way. |
| `iceroot-sdk-api` | A sans-IO node API client: it builds each request and decodes each answer into IceRoot-shaped values (accounts, validators, transactions, blocks, node facts), and plans submissions within the pool's limits. The host performs the HTTP exchange; the optional `http` feature adds an async reqwest transport on native targets, and the optional `serde` feature gives every request value and answer the JSON form the SDK's bindings share. See [its README](crates/iceroot-sdk-api/README.md). |
| `iceroot-vote` | Vote selection for wallets: the four vote modes (Diversity, Reliability, Maximum Rewards, Support Newcomers) that fill a vote from validator data for the holder to review, with the reasons for every pick; the network's vote rules and `validate_vote` for manual votes; and `check`, which reports picks that no longer meet their criteria and never recasts a vote. Pure functions: no I/O, no clock, no floating point. See [its README](crates/iceroot-vote/README.md). |
| `iceroot-sdk-bindings` | The boundary the SDK's bindings share: arguments read and answers written in the JSON forms of the TypeScript API, with errors keeping their stable codes, and the key handles the bindings hold. The WebAssembly module of the TypeScript package and the Tauri plugin both build on it, so the two implementations of the TypeScript interface read and write the same JSON. Applications do not depend on it. See [its README](crates/iceroot-sdk-bindings/README.md). |
| `tauri-plugin-iceroot` | The SDK as a Tauri 2 plugin for desktop and mobile wallets: the native implementation of the TypeScript interface that `@iceroot-network/sdk/tauri` calls, with keys and signing in Rust behind opaque handles, drafts crossing as serialized bytes, node requests over reqwest to the relays the application allows, the keystore with native presets, the vote library and ownership proofs. A workspace of its own, since it builds against Tauri and the platform's webview libraries. See [its README](crates/tauri-plugin-iceroot/README.md). |
| `iceroot-sdk-ffi` | The exports the Go SDK calls: the core compiled for `wasm32-wasip1`, which [sdk-go](https://github.com/iceroot-network/sdk-go) embeds and runs with wazero, in pure Go. A small JSON-in, JSON-out function set over `iceroot-sdk-bindings`, with keys behind opaque handles that are wiped when released; the host performs the HTTP exchanges. See [its README](crates/iceroot-sdk-ffi/README.md). |
| `iceroot-keystore` | The keystore format: a recovery phrase's entropy encrypted under a password with Argon2id and XChaCha20-Poly1305, with per-platform presets and bounds on the parameters. Pure functions that store nothing; no dependency on Heartwood Core. See [its README](crates/iceroot-keystore/README.md) and [the format specification](docs/keystore-format.md). |

Every byte and verdict of a key, address, signature or transaction comes from `heartwood-crypto`. The SDK adds only client code and never enables a `heartwood-crypto` feature; `tools/check-deps.sh` enforces that, and keeps Heartwood Core's consensus crates out of the dependency tree.

## What works today

- **Networks.** The `devnet` profile (network byte 90) in today's formats: transfers to 1 to 256 recipients with a memo, votes, burns, second keys, validator registration and resignation, and message signing (of UTF-8 text only: in today's format a message signature over a transaction's bytes would sign that transaction, so other bytes are refused). The profiles of the IceRoot stages to come (`devnet-pq`, `id-devnet`) are declared with every capability off, so an application can list them and hide what they cannot do yet. The public testnet and mainnet get their profiles when their genesis is fixed.
- **Keys.** New phrases have 24 words; imports of 18, 21 or 24 words are accepted and shorter ones refused. Keys are derived with hardened steps only, at `m/44'/1'/account'/0'/index'` on devnets and the public testnet. The reference implementation's passphrase keys (the SHA-256 of the passphrase) can be imported on devnet profiles, for existing devnet wallets; they are never used for new accounts.
- **Drafts.** A draft is built from an operation and the facts a node reports (nonce, height, second key), checked against every rule, and signed as a separate step. A draft can be serialized, signed in another context (a sandboxed page, a native plugin, another device) and sent back.
- **Nodes.** Reads of today's devnet API (node status and configuration, accounts and history, transactions and the pool, blocks, validators, rounds, supply and fee statistics), submissions batched by the pool's limits with each refusal's reason, and a request budget for the node's rate limit. The chain a node serves is loaded and pinned from its own configuration, and a node of another chain is refused.
- **Fees.** A draft always carries an explicit fee and says where it comes from. The default fee is the exact fee floor of the milestone in force for the transaction's type and size, computed by `heartwood-crypto`'s own function, the one the node checks every fee with; an exact fee or a multiple of the floor can be chosen instead. Where the milestone has no enabled dynamic fee table there is no floor, since the node's pool then applies settings of its own: the default fee is refused with `FeeUnavailable` and a draft needs an exact fee. The SDK never guesses a fee from what other transactions paid. A draft read back from its serialized form computes the floor again, under the network configuration the serialized form carries, and calls its fee the floor only when it is. That configuration is checked against the pinned network hash and byte, its seats and its token's labels, but the hash does not cover its fee table: a signer that does not trust the context that built a draft judges the fee by its amount, not by its source.
- **Votes.** Four vote modes fill a vote of 20 to 53 validators from a snapshot of validator data, for the holder to review and sign: Diversity (recommended), Reliability, Maximum Rewards and Support Newcomers. Each draw is seeded per account, so holders of one mode do not all vote alike, and anyone with the same data reproduces it; every pick carries its reasons for the review screen, and a mode short of validators tops up from Diversity and says so. The pools are bounded by rank, so validators registered in bulk cannot crowd a draw, and a selection keeps within the network's vote rules. `check` reports the picks of an earlier selection that no longer meet their criteria; nothing recasts a vote. `iceroot_sdk::voting` gives the library the vote rules in force and a snapshot of a node's validator list; on today's devnet that list has only lifetime counters, so the snapshot is marked approximate, and it leaves out the validators a node refuses votes for (not resigned, and no node of theirs seen running).
- **Keystore.** A recovery phrase's entropy encrypted under a password (Argon2id and XChaCha20-Poly1305), with presets for desktops, phones and web pages, and bounds that refuse weak or oversized parameters. The app stores the bytes, or their text form; the SDK stores nothing.
- **Tauri apps.** `tauri-plugin-iceroot` runs all of the above natively for Tauri 2 applications, behind the same TypeScript interface as the WebAssembly package: the page holds no key and reaches no node. Checked on Linux (WebKitGTK) with the SDK's TypeScript suites and the devnet scenario, and built for Android (`aarch64-linux-android`), macOS (`aarch64-apple-darwin`) and iOS (`aarch64-apple-ios`).
- **Ownership proofs.** The version 1 ownership proof of a Solar address, as the IceRoot Legacy Signer signs it: a fixed message naming the Solar address and the IceRoot account its holding should be bound to, signed with the Solar key (network byte 63). `iceroot_sdk::ownership` builds and checks the message, signs it with a key from a Solar passphrase, checks a signature made on a Ledger, and verifies a signed proof. See [the format](docs/ownership-proofs.md), which also drafts how claims on an asset distributed from an archived Solar snapshot use these proofs.

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
# Without the keystore (the feature `keystore`, on by default), for a server that never holds a
# user's recovery seed:
# iceroot-sdk = { git = "https://github.com/iceroot-network/sdk-rust", tag = "v0.1.0", default-features = false }
```

`Cargo.lock` then records the exact commit. Nothing is published to crates.io yet. JavaScript and TypeScript applications use the package of [sdk-typescript](https://github.com/iceroot-network/sdk-typescript) instead: its release of the same version attaches the npm package tarball, built from this release, which installs by URL with `npm install https://github.com/iceroot-network/sdk-typescript/releases/download/v0.1.0/iceroot-network-sdk-0.1.0.tgz`.

The node API client is `iceroot_sdk::api`, the vote library `iceroot_sdk::vote` and the keystore `iceroot_sdk::keystore`. The examples in the documentation of `iceroot-sdk` build and sign a transfer, share a vote and refuse a selection, and encrypt a recovery phrase's entropy and restore the phrase (`cargo doc --open -p iceroot-sdk`). Every error has a stable code and structured details, the same in every crate and in the TypeScript SDK; the documentation of `iceroot-sdk` lists the codes.

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

Once Cargo holds the commit `Cargo.lock` pins, builds need no access at all (`cargo build --offline`). On a CI machine or in a container, the same rewrite can go in the global git configuration instead (`git config --global url.<alias URL>.insteadOf <github.com URL>`); this repository's own CI reads `heartwood-core` over HTTPS with a token (see [Continuous integration](#continuous-integration)). A rewrite in a repository's own git configuration has no effect, because Cargo fetches in a repository of its own.

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
# The Go SDK's module, the same way for wasm32-wasip1:
CC_wasm32_wasip1=clang AR_wasm32_wasip1=llvm-ar \
  cargo build -p iceroot-sdk-ffi --target wasm32-wasip1 --release
```

`NOTICE` lists the third-party crates a build links, with their licences, copyright lines and licence texts, and carries Heartwood Core's notice. It is generated from `Cargo.lock`: after changing a dependency, run `node tools/notice.mjs` and commit the result.

The Tauri plugin is a workspace of its own and needs the webview's development files on Linux; its checks are in [its README](crates/tauri-plugin-iceroot/README.md#development). The SDK's TypeScript repository runs its full test suites through the plugin in a Tauri application (`npm run test:tauri-plugin`).

### Continuous integration

`.github/workflows/ci.yml` runs on pull requests to `dev` and `prod` and on pushes to `prod`: formatting, clippy (native with every feature, and wasm32), the tests with both vector sets, the documentation, the wasm32 build, clippy and the build of the Go SDK's exports for `wasm32-wasip1`, the dependency guard (which checks both WebAssembly targets) and the `NOTICE` check. The Go SDK's own workflow builds its embedded module from this repository and runs these vector runners on `wasm32-wasip1` in Go. The job `tauri-plugin` runs the plugin's formatting, clippy, tests and documentation with the webview's development files installed, and builds it for Android with the runner's NDK, linked as a shared library in which every symbol must resolve (`-z defs`). The job `tauri-plugin-apple` builds it for macOS (`aarch64-apple-darwin`) and iOS (`aarch64-apple-ios`) on a macOS runner with Xcode, each linked as a shared library in which every symbol must resolve. A further job builds and tests against Heartwood Core's `dev` branch, so a change there is seen before the next `heartwood-crypto` tag; it does not block a merge.

The workflows read `heartwood-core` over HTTPS with a fine-grained personal access token, stored in this repository as the secret `HEARTWOOD_TOKEN`. The token covers `heartwood-core` alone, with read-only access to its contents (and the read-only metadata GitHub adds to every token) and no other permission. `tools/ci/heartwood-access.sh` masks the token in the job's log, rewrites `heartwood-core`'s SSH addresses to HTTPS, and gives git the token as an authorization header for that repository's address only, as git configuration in the job's environment: no git configuration file holds it, and Cargo's git database, which the dependency cache saves, never sees it. The script also makes Cargo fetch with the `git` command line, which reads that configuration. The job that tests against Heartwood Core's `dev` branch checks that branch out with the same token and does not keep it in the checkout. Pull requests from forks get no secrets, so their runs stop at that step. While `heartwood-core` is private, only pull request runs save the dependency cache: it holds Cargo's copy of `heartwood-core`, and a pull request from a fork can restore the caches of this repository's branches.

### Releasing

1. Set the version in `Cargo.toml` (`[workspace.package]`) on `dev`, write what applications must know about it (changed or removed interfaces) in `release-notes/v<version>.md`, and merge `dev` into `prod` through a pull request. Before that, update `webpki-root-certs` to its newest version in both lock files (`cargo update -p webpki-root-certs` here and in `crates/tauri-plugin-iceroot`, then `node tools/notice.mjs`): on Android the node API client trusts the root certificates of that crate, which change only when it is updated.
2. Tag the merge commit on `prod` with `v` and the version, and push the tag: `git tag -a v0.1.0 -m "IceRoot SDK for Rust 0.1.0"`, then `git push origin v0.1.0`.
3. `.github/workflows/release.yml` runs the tests again and publishes the release page with `tools/release.mjs`, which refuses a tag that differs from the version or is not on `prod`. The page carries the version's notes from `release-notes/` and the commits since the previous tag. `node tools/release.mjs --tag v0.1.0 --dry-run` shows the notes without publishing.

Release sdk-rust first: the TypeScript package of the same version is built from this tag.

### Vectors

- `vectors/heartwood/`: copies of Heartwood Core's golden vectors of `heartwood-crypto` at the pinned tag, generated from the reference implementation, with `MANIFEST.sha256`. `crates/iceroot-sdk-core/tests/heartwood_vectors.rs` runs every record through the SDK's public API, except the reference's raw signatures of chosen 32-byte inputs, which go through the test seam of the feature `fixed-aux` because no public function signs a chosen digest; records the SDK has no operation for (blocks, peer status) are skipped by an explicit rule, and each class asserts how many records matched, differed as documented, or were skipped. Updating the pinned tag updates these files in the same change.
- `vectors/sdk/`: the SDK's own vectors, in the same `heartwood-vectors/1` format: BIP39 phrases and seeds (the published vectors, non-ASCII passphrases, validation, and the genesis passphrases of Heartwood Core's devnet), hardened derivation (the BIP32 test vectors and wallet paths), message signatures, sign-in messages, transactions of every operation (transfers to 1, 2 and 256 recipients, memos at the 255-byte limit, votes of 1, 20 and 53 entries, second-signed transactions, keys from legacy passphrases and from recovery phrases) built by the SDK and compared with the reference's bytes, ids and JSON, the fee floor of every operation at sizes on both sides of its rounding, and ownership proofs (IceRoot accounts as typed, messages built and parsed, proofs signed and verified, with the verdicts of the IceRoot Legacy Signer's own format checks). `tools/oracle/gen-sdk-vectors.js` generates them with the reference implementation as the oracle: its own libraries, transaction builders and transaction handlers (Node 18):

  ```sh
  node tools/oracle/gen-sdk-vectors.js <built reference checkout> <browser wallet checkout>
  ```

  `vectors/sdk/S07-keystore.jsonl` holds the keystore's vectors (encryption with fixed salts and nonces, decryption, wrong passwords, a change to every field, parameters out of range, the text form), generated from the format specification with an implementation independent of the crate by `tools/oracle/gen-keystore-vectors.js`, and run by `crates/iceroot-keystore/tests/vectors.rs`; see [its README](crates/iceroot-keystore/README.md).
- `crates/iceroot-vote/tests/data/`: the vote library's vectors: selections reproduced exactly from fixture, account, mode, count, draw and vote rules (`select-v1.jsonl`), and each mode's pools, weights and rank bands on a synthetic snapshot of 80 validators against an independently computed expected file; see [its README](crates/iceroot-vote/README.md).

### Devnet end-to-end test

`crates/iceroot-sdk/tests/e2e.rs`, behind the `e2e` feature, runs against a local devnet: it connects and pins the chain, imports a genesis wallet with the legacy passphrase import, creates an account from a new recovery phrase, funds it, sends a transfer with a memo and a vote, waits until each is forged and reads it back through the node API client, and checks that a fee one base unit below the floor is refused with the node's own code. `tools/e2e/devnet.sh` starts a fresh one-node devnet of the reference implementation through its devnet tooling (`ICEROOT_DEVNET_TOOLS`), runs the test, and stops and removes the devnet; the chain never runs more than five rounds:

```sh
ICEROOT_DEVNET_TOOLS=<devnet tooling> tools/e2e/devnet.sh run -- \
  cargo test -p iceroot-sdk --features e2e --test e2e -- --ignored
```

The TypeScript SDK's `npm run test:e2e` runs the same harness for its Node and Chromium tests and then this test, which also verifies the messages they signed.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
