# Maintaining the Rust SDK

## Development checks

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

The Tauri plugin is a workspace of its own and needs the webview's development files on Linux; its checks are in [its README](../crates/tauri-plugin-iceroot/README.md#development). The SDK's TypeScript repository runs its full test suites through the plugin in a Tauri application (`npm run test:tauri-plugin`).

### Continuous integration

`.github/workflows/ci.yml` runs on pull requests to `dev` and `prod` and on pushes to `prod`: formatting, clippy (native with every feature, and wasm32), the tests with both vector sets, the documentation, the wasm32 build, clippy and the build of the Go SDK's exports for `wasm32-wasip1`, the dependency guard (which checks both WebAssembly targets) and the `NOTICE` check. The Go SDK's own workflow builds its embedded module from this repository and runs these vector runners on `wasm32-wasip1` in Go. The job `tauri-plugin` runs the plugin's formatting, clippy, tests and documentation with the webview's development files installed, and builds it for Android with the runner's NDK, linked as a shared library in which every symbol must resolve (`-z defs`). The job `tauri-plugin-apple` builds it for macOS (`aarch64-apple-darwin`) and iOS (`aarch64-apple-ios`) on a macOS runner with Xcode, each linked as a shared library in which every symbol must resolve. A further job builds and tests against Heartwood Core's `dev` branch, so a change there is seen before the next `heartwood-crypto` tag; it does not block a merge.

The workflows fetch the public Heartwood Core repository over HTTPS without a dependency secret.

### Releasing

1. Set the version in `Cargo.toml` (`[workspace.package]`) on `dev`, write what applications must know about it (changed or removed interfaces) in `release-notes/v<version>.md`, and merge `dev` into `prod` through a pull request. Before that, update `webpki-root-certs` to its newest version in both lock files (`cargo update -p webpki-root-certs` here and in `crates/tauri-plugin-iceroot`, then `node tools/notice.mjs`): on Android the node API client trusts the root certificates of that crate, which change only when it is updated.
2. Tag the merge commit on `prod` with `v` and the version, and push the tag: `git tag -a v0.1.0 -m "IceRoot SDK for Rust 0.1.0"`, then `git push origin v0.1.0`.
3. `.github/workflows/release.yml` runs the tests again and publishes the release page with `tools/release.mjs`, which refuses a tag that differs from the version or is not on `prod`. The page carries the version's notes from `release-notes/` and the commits since the previous tag. `node tools/release.mjs --tag v0.1.0 --dry-run` shows the notes without publishing.

Release sdk-rust first: the TypeScript package of the same version is built from this tag.

### Vectors

Vector regeneration uses maintainers' tooling. The reference checkout is a built copy of [solar-core-ref](https://github.com/iceroot-network/solar-core-ref). The wallet checkout and devnet tooling checkout are maintainers' tooling and are not required to use the SDK. The committed vector files are the checked artefacts. Keep them available to readers who cannot run those generators.

- `vectors/heartwood/`: copies of Heartwood Core's golden vectors of `heartwood-crypto` at the pinned tag, generated from the reference implementation, with `MANIFEST.sha256`. `crates/iceroot-sdk-core/tests/heartwood_vectors.rs` runs every record through the SDK's public API, except the reference's raw signatures of chosen 32-byte inputs, which go through the test seam of the feature `fixed-aux` because no public function signs a chosen digest; records the SDK has no operation for (blocks, peer status) are skipped by an explicit rule, and each class asserts how many records matched, differed as documented, or were skipped. Updating the pinned tag updates these files in the same change.
- `vectors/sdk/`: the SDK's own vectors, in the same `heartwood-vectors/1` format: BIP39 phrases and seeds (the published vectors, non-ASCII passphrases, validation, and the genesis passphrases of Heartwood Core's devnet), hardened derivation (the BIP32 test vectors and wallet paths), message signatures, sign-in messages, transactions of every operation (transfers to 1, 2 and 256 recipients, memos at the 255-byte limit, votes of 1, 20 and 53 entries, second-signed transactions, keys from legacy passphrases and from recovery phrases) built by the SDK and compared with the reference's bytes, ids and JSON, the fee floor of every operation at sizes on both sides of its rounding, and ownership proofs (IceRoot accounts as typed, messages built and parsed, proofs signed and verified, with the verdicts of the IceRoot Legacy Signer's own format checks). `tools/oracle/gen-sdk-vectors.js` generates them with the reference implementation as the oracle: its own libraries, transaction builders and transaction handlers (Node 18):

  ```sh
  node tools/oracle/gen-sdk-vectors.js <built reference checkout> <browser wallet checkout>
  ```

  `vectors/sdk/S07-keystore.jsonl` holds the keystore's vectors (encryption with fixed salts and nonces, decryption, wrong passwords, a change to every field, parameters out of range, the text form), generated from the format specification with an implementation independent of the crate by `tools/oracle/gen-keystore-vectors.js`, and run by `crates/iceroot-keystore/tests/vectors.rs`; see [its README](../crates/iceroot-keystore/README.md).
- `crates/iceroot-vote/tests/data/`: the vote library's vectors: selections reproduced exactly from fixture, account, mode, count, draw and vote rules (`select-v1.jsonl`), and each mode's pools, weights and rank bands on a synthetic snapshot of 80 validators against an independently computed expected file; see [its README](../crates/iceroot-vote/README.md).

### Devnet end-to-end test

`crates/iceroot-sdk/tests/e2e.rs`, behind the `e2e` feature, runs against a local devnet: it connects and pins the chain, imports a genesis wallet with the legacy passphrase import, creates an account from a new recovery phrase, funds it, sends a transfer with a memo and a vote, waits until each is forged and reads it back through the node API client, and checks that a fee one base unit below the floor is refused with the node's own code. `tools/e2e/devnet.sh` starts a fresh one-node devnet of the reference implementation through its devnet tooling (`ICEROOT_DEVNET_TOOLS`), runs the test, and stops and removes the devnet; the chain never runs more than five rounds:

```sh
ICEROOT_DEVNET_TOOLS=<devnet tooling> tools/e2e/devnet.sh run -- \
  cargo test -p iceroot-sdk --features e2e --test e2e -- --ignored
```

The TypeScript SDK's `npm run test:e2e` runs the same harness for its Node and Chromium tests and then this test, which also verifies the messages they signed.

