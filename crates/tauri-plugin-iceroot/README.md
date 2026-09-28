# tauri-plugin-iceroot

The IceRoot SDK as a Tauri 2 plugin, for desktop and mobile applications (tested on Linux and built for Android so far; see [Platforms](#platforms)). It is the native implementation of the SDK's TypeScript interface: the application's page imports `@iceroot-network/sdk/tauri` from [sdk-typescript](https://github.com/iceroot-network/sdk-typescript) instead of `@iceroot-network/sdk`, and the same calls run here, in Rust, instead of in WebAssembly inside the webview.

- **Keys stay in Rust.** Keys from recovery phrases, legacy passphrases and keystores, and the Solar keys of ownership proofs, are held by the plugin. The page holds opaque numbers and receives public keys, addresses and signatures only. A key is held for the webview that opened it, reachable from that webview only, and wiped when the page releases it, when the webview loads another page and when its window closes (for a webview closed on its own or moved to another window, see [What the plugin does not protect](#what-the-plugin-does-not-protect)).
- **Drafts cross as serialized bytes.** A draft is built by the core and given to the page as its serialized form with its review summary. Signing sends the bytes back: the plugin reads the draft again under the network's pinned profile and signs what it read.
- **Node requests leave from Rust.** The SDK's node API client, with the same request builders and answer decoders as the WebAssembly module, sends each request with reqwest (rustls), to the relays the application's capabilities allow and nowhere else: it follows no redirect. (A proxy named by `HTTP_PROXY`, `HTTPS_PROXY` or `ALL_PROXY` in the application's environment is used, as curl uses it; a plain-HTTP request passes through it in the clear.) The page reaches no node, so its content security policy needs no node origin and no `'wasm-unsafe-eval'`; Android's cleartext rule and iOS App Transport Security, which govern the platform's own HTTP stacks, do not apply to these requests.
- **The keystore runs natively.** Argon2id with the desktop or mobile preset (256 or 128 MiB) runs on a blocking thread, off the webview. `Keys.fromKeystore` opens an account straight from a keystore: the phrase is decrypted and the key derived in the plugin, and never enters the page.
- **One implementation.** Arguments are read and answers written by [`iceroot-sdk-bindings`](../iceroot-sdk-bindings/README.md), the code the WebAssembly module uses, and every key, address, signature, transaction, vote selection, keystore and proof comes from the SDK's core and, through it, from `heartwood-crypto`. The SDK's TypeScript test suites and its native vectors pass through the plugin as they pass through WebAssembly.

The crate forbids unsafe code. It is a workspace of its own, with its own `Cargo.lock`, because it builds against Tauri and the platform's webview libraries (WebKitGTK on Linux), which the SDK's other crates never need.

## Using it

In the application's `src-tauri/Cargo.toml`, at a release tag of this repository:

```toml
[dependencies]
tauri-plugin-iceroot = { git = "https://github.com/iceroot-network/sdk-rust", tag = "v0.1.0" }
```

Register the plugin:

```rust
// src-tauri/src/lib.rs
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_iceroot::init())
        .run(tauri::generate_context!())
        .expect("error while running the application");
}
```

Grant its commands and the relays it may reach in a capability (`src-tauri/capabilities/main.json`, listed in `app.security.capabilities` of `tauri.conf.json`):

```json
{
  "identifier": "main",
  "windows": ["main"],
  "permissions": [
    "iceroot:default",
    {
      "identifier": "iceroot:allow-net-connect",
      "allow": [{ "url": "http://127.0.0.1:6003/api" }, { "url": "https://devnet.example.org/api" }]
    }
  ]
}
```

`iceroot:default` allows every command of the SDK except `net_connect`, which needs `iceroot:allow-net-connect` with the relays it may reach. The page needs no other permission; add Tauri's own (`core:default` and the like) only for what the application's page uses itself. No relay is reachable until an `allow` entry of `iceroot:allow-net-connect` (or of the plugin's global scope) names it: an entry is a relay URL with its API base path, where `*` matches any run of characters other than `/` and `**` any run at all; a `deny` entry wins over an allow. The plugin compares the relay as a URL parser writes it (lowercase host, normalized escapes), so no other spelling of a URL reaches a host the entries do not name, and it follows no redirect: a relay that answers with one counts as unavailable and the next relay is tried. The only other host a request can pass through is a proxy the application's environment names (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`). A relay that is not allowed is refused with `InvalidProfile` (`details.reason: "not-allowed"`) before any request. Without `iceroot:allow-net-connect` in the capability, Tauri refuses `net_connect` itself, which the page sees as `SdkNotInitialized`.

The page then uses the SDK as with the WebAssembly entry, awaiting each call; see the Tauri quickstart and the desktop and mobile wallet guides of sdk-typescript.

## Commands and permissions

Each command reads the arguments and writes the answers of the WebAssembly module's export of the same function, so the TypeScript guest code converts them with the same code: bytes cross as lowercase hex, secrets (phrases, passphrases, passwords) as arrays of UTF-8 bytes that the plugin overwrites with zeros when the command ends, structured values as JSON text, and keys, chains and connections as numbers. A refusal carries the SDK error's stable code, message and details, and becomes the SDK's error class of that code in the page. [`permissions/autogenerated/reference.md`](permissions/autogenerated/reference.md) lists every command's permission.

| Group | Commands |
|---|---|
| Profiles, phrases, addresses, amounts | `profile_capabilities`, `profile_message_network`, `profile_message_algorithm`, `phrase_generate`, `phrase_check`, `address_parse`, `address_from_public_key`, `amount_parse`, `amount_format` |
| Messages and sign-in | `message_verify`, `signin_build`, `signin_parse` |
| Keys | `key_from_phrase`, `key_from_legacy_passphrase`, `key_from_keystore`, `key_sign_message`, `key_release` |
| Chains | `chain_load`, `chain_stage_at`, `chain_rules`, `chain_economics`, `chain_free` |
| Drafts and signed transactions | `draft_build`, `draft_deserialize`, `draft_online_facts`, `draft_sign`, `signed_deserialize`, `signed_from_json`, `signed_decode`, `signed_verify_second_signature` |
| Networks | `net_connect`, `net_read`, `net_node_configuration`, `net_submit`, `net_close` |
| Vote library | `vote_call`, `vote_rules_at`, `vote_snapshot_from_validators` |
| Keystore | `keystore_encrypt`, `keystore_decrypt`, `keystore_inspect`, `keystore_change_password`, `keystore_reencrypt`, `keystore_armor`, `keystore_dearmor`, `keystore_check_params`, `keystore_is_weaker` |
| Ownership proofs | `ownership_call`, `proof_key_from_passphrase`, `proof_key_sign`, `proof_key_release` |
| The plugin | `version` |

An application that never shows a recovery phrase after creating it can deny `keystore_decrypt` (`iceroot:deny-keystore-decrypt`) and open accounts with `key_from_keystore` only.

## What the plugin does not protect

- **The page itself.** Code running in the application's page can ask the plugin to sign with the keys that page opened. The plugin keeps keys out of the page's memory and out of other webviews, not out of reach of a compromised page; the application's content security policy and review screens still matter.
- **The IPC messages.** A phrase or password the page sends travels in Tauri's IPC message, which neither the page nor the plugin can wipe. Keep secrets out of the page where possible: create a phrase, show it once, encrypt it with `keystore_encrypt`, and afterwards open accounts with `key_from_keystore`. An application built with Tauri's `tracing` feature records every IPC request, secrets included, in its traces: never enable it in a build that ships.
- **A key the page never releases** stays in the plugin until the page's object is collected (the guest code asks the plugin to drop it), the page navigates or reloads, or the window closes.
- **A webview closed on its own, or moved.** In a window with several webviews (Tauri's multi-webview windows, behind its `unstable` feature), each webview's keys are wiped with its page and with its window, but Tauri reports no event when one webview closes while its window stays open: its keys stay until the window closes. Release them before closing such a webview. A webview's window is recorded when it opens a key, loads a chain or connects, so a webview moved to another window goes with its old window until it next does: its keys are wiped when the old window closes, not the new one.
- **Remote pages.** Never grant `iceroot` permissions in a capability with a `remote` entry (pages loaded from a URL). The plugin's handles are numbers counted up from 1, and every frame of a webview's page can use that page's handles: that is safe only when every page and frame the webview shows is the application's own code.
- **Memory below the heap.** The plugin wipes the keys it holds and the secrets it receives. Deriving a key or signing can leave copies of intermediate values on the thread's stack, which the plugin does not overwrite (the WebAssembly entry overwrites its stack after such calls).

## Platforms

| Target | State |
|---|---|
| Linux (`x86_64-unknown-linux-gnu`, WebKitGTK) | Built and tested: the SDK's TypeScript suites, its native vectors and the devnet end-to-end scenario run through the plugin in the Tauri example of sdk-typescript under `tauri-driver` (`npm run test:tauri-plugin`, and the job `tauri` of `npm run test:e2e`). HTTPS relays are verified by the platform's verifier with the system's root certificates; it checks no certificate revocation on Linux |
| Android (`aarch64-linux-android`) | Builds with the Android NDK (r29, API level 24), the plugin alone and the example application as the library an Android project loads; not yet run on a device or an emulator. HTTPS relays are verified against the Mozilla root certificates built into the plugin (`webpki-root-certs`), since the platform's verifier needs the application's Java environment, which a plugin cannot set up. So a relay whose certificate comes from a private or user-installed authority is refused; the roots are those of the `webpki-root-certs` version in the application's `Cargo.lock`, and a root Mozilla adds or distrusts later arrives only with a rebuild (run `cargo update -p webpki-root-certs` before each release of the application); and no certificate revocation is checked |
| macOS (`aarch64-apple-darwin`), iOS (`aarch64-apple-ios`) | Builds in CI on a macOS runner with Xcode, the plugin alone, linked as a shared library for each target; not yet run in an application, on a device or in a simulator. HTTPS relays are verified by the platform's verifier |
| Windows | Not built yet. WebView2 reports a page load when the navigation starts, before the old page stops, so the page-bound wiping needs another check there (for example, again when the load finishes) before Windows is supported |

## Development

The toolchain is sdk-rust's (`rust-toolchain.toml`). On Linux the build needs the development files of WebKitGTK 4.1 and GTK 3 (Debian and Ubuntu: `libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libayatana-appindicator3-dev libxdo-dev libssl-dev`); sdk-typescript's Tauri container (`test/contexts/tauri/Dockerfile`) has them. From this directory:

```sh
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features
# Android, with the NDK's clang for the C code (libsecp256k1, aws-lc) and as the linker:
CC_aarch64_linux_android=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang \
AR_aarch64_linux_android=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar \
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang \
  cargo build --locked --release --target aarch64-linux-android
# macOS and iOS, on a Mac with Xcode:
cargo build --locked --release --target aarch64-apple-darwin
cargo build --locked --release --target aarch64-apple-ios
```

`tools/check-deps.sh` checks the plugin's dependency tree with the workspace's, and `NOTICE` covers the crates it links besides Tauri. The build script writes the permissions of the commands (`permissions/autogenerated`, `permissions/schemas`); commit them with a change to the commands.

The feature `test-seams` is the plugin's test build: signatures and ownership proofs with fixed auxiliary randomness, the keystore vectors' salts and nonces under lowered bounds, and the vote library's and the keystore's constants, as commands granted by the permission `iceroot:test-seams`, so the SDK's TypeScript tests compare the plugin with native Rust byte for byte. No application enables it.
