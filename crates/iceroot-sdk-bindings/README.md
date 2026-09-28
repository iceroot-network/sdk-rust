# iceroot-sdk-bindings

The boundary the IceRoot SDK's bindings share. The SDK's TypeScript interface has two implementations: the WebAssembly module of [sdk-typescript](https://github.com/iceroot-network/sdk-typescript), and the native Tauri plugin [`tauri-plugin-iceroot`](../tauri-plugin-iceroot/README.md). The Go exports in [`iceroot-sdk-ffi`](../iceroot-sdk-ffi/README.md) use this boundary too. All three hand the same calls to the SDK's Rust core, so the code that reads their arguments and writes their answers lives in this crate once.

- Arguments and answers are in the JSON forms of the TypeScript API: camel-case fields, amounts, nonces and other integers a JavaScript number cannot hold as decimal strings.
- Every failure is a `BindingError` with the stable code and structured details of the crate that raised it (the core, the node API client, the vote library, the keystore), plus `InvalidArgument` for a value of the wrong shape.
- Keys are held by the binding (`keys::Key`, `ownership::ProofKey`) and wiped where they are held on release or drop; secrets given as bytes are overwritten with zeros.
- No I/O: `api::PreparedCall` builds a node request and decodes its answer; the host sends it.

Applications do not depend on this crate. Rust applications use `iceroot-sdk`; web and Tauri applications use the TypeScript package.

The features `fixed-aux` and `keystore-testing` are the test seams of the bindings' test builds (fixed signing randomness, the keystore vectors' salts and nonces). No build that ships enables them; `tools/check-deps.sh` refuses them on any normal edge of the workspace.
