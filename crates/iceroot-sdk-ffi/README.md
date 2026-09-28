# iceroot-sdk-ffi

The exports the Go SDK calls. [sdk-go](https://github.com/iceroot-network/sdk-go) embeds this crate built for `wasm32-wasip1` and runs it with wazero, in pure Go, with no cgo. Every operation hands its work to [`iceroot-sdk-bindings`](../iceroot-sdk-bindings/README.md), the boundary the TypeScript module and the Tauri plugin share, so the three bindings read and write the same values. The crate performs no network or file input or output: Go makes the HTTP exchanges the node API client prepares, and hands the answers back to be decoded.

## The boundary

- Four exports: `sdk_alloc(length) -> pointer`, `sdk_call() -> u64`, `sdk_clear()` and `sdk_wipe_stack()`. `sdk_alloc` gives the one input buffer (at most 16 MiB); the host writes a JSON request there and calls `sdk_call`, whose result holds the answer's pointer in its upper 32 bits and its length in the lower 32 bits, or zero when the input or the answer is too large. The host reads the answer before the next call, then calls `sdk_clear`, which overwrites both buffers, and `sdk_wipe_stack`, which overwrites 64 KiB of the stack. No pointer the host passes is ever read.
- A request is `{ op, ...arguments }`; an answer is `{ result }` or `{ error: { code, message, details } }`, with the stable codes of the SDK's errors and `InvalidArgument` for a value of the wrong shape. `src/dispatch.rs` lists the operations. Bytes cross as hex, and amounts, nonces and other wide integers as decimal strings.
- Keys stay in the module behind handles, numbers that are never reused within an instance. Releasing a handle overwrites the key where it is held. Passwords, and phrases the host holds as bytes (`phraseHex`), cross as hex and are decoded into buffers that are overwritten after use; every string of a parsed request is overwritten before the call returns.
- The host calls one operation at a time, supplies randomness through WASI, and closes the instance after a trap or a cancelled call, so no handle outlives an interrupted operation.

The checks of a profile against the chain a node serves stay in Rust. `Session::call` runs the same dispatcher natively, and the `json` example reads one request per line and writes one answer per line, for the Go SDK's differential tests against native Rust.

## Building

```sh
rustup target add wasm32-wasip1
CC_wasm32_wasip1=clang AR_wasm32_wasip1=llvm-ar \
  cargo build --locked -p iceroot-sdk-ffi --release --target wasm32-wasip1
cargo test --locked -p iceroot-sdk-ffi
```

The Go SDK's `scripts/build-wasm.sh` builds the module it embeds from this crate with fixed release settings, so that the same sources give the same bytes. The feature `test-seams` adds fixed signing randomness for the differential tests; it is never enabled in the embedded module, which refuses an `aux` argument. While the core has the classical backend, the build compiles libsecp256k1 from C with clang; the Go program that embeds the module needs no C compiler.
