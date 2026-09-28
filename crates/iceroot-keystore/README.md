# iceroot-keystore

The IceRoot keystore format: a recovery seed encrypted under a password, as pure functions. The key comes from the password by Argon2id; the seed is sealed with XChaCha20-Poly1305; the header, which holds the parameters, salt and nonce, is authenticated with it. The crate stores nothing: each app keeps the keystore where its platform keeps secrets best. It has no dependency on Heartwood Core and builds for `wasm32-unknown-unknown` unchanged (RustCrypto's `argon2` and `chacha20poly1305`, pure Rust).

The byte layout, the checks a reader makes and the rules for wallets are in [the format specification](../../docs/keystore-format.md).

## Using it

```rust
use iceroot_keystore::{Payload, Preset, decrypt, encrypt, inspect};

// The entropy of an 18-, 21- or 24-word recovery phrase: 24, 28 or 32 bytes.
let payload = Payload::bip39_entropy(&entropy)?;
let keystore: Vec<u8> = encrypt(&payload, password, Preset::Mobile)?;

// Later: the header without the password, then the payload with it.
let header = inspect(&keystore)?;
let payload = decrypt(&keystore, password)?;
let entropy = payload.secret_bytes(); // wiped when `payload` is dropped
```

| Function | What it does |
|---|---|
| `encrypt(payload, password, params)` | Encrypt under a `Preset` or explicit `Params`, with a fresh salt and nonce from the operating system's generator (`crypto.getRandomValues` in WebAssembly) |
| `decrypt(bytes, password)` | Check the layout, the parameters and the password; return the `Payload` |
| `decrypt_with_bounds(bytes, password, bounds)` | The same under tighter bounds, for example `Bounds::STANDARD.with_memory_ceiling_kib(...)` on a platform short of memory |
| `inspect(bytes)` | The `Header` (version, KDF, parameters, salt, nonce, payload kind and length), without the password |
| `change_password(bytes, old, new, params)` | Decrypt and encrypt again under a new password, salt and nonce |
| `reencrypt(bytes, password, params)` | Move a keystore to new parameters with a new salt and nonce, for example after `header.params().is_weaker_than(&Preset::Mobile.params())` |
| `change_password_with_bounds(...)`, `reencrypt_with_bounds(...)` | The same under tighter bounds: the old keystore is opened, and the new parameters checked, under the given ceiling |
| `armor(bytes)`, `dearmor(text)` | The text form, `irks:` and unpadded base64url, for stores that hold strings only |

The salt and nonce always come from the operating system's generator: no function of a normal build takes them, or a generator, from the caller. Deterministic encryption for vectors (`encrypt_with_salt_and_nonce`) and the weak test bounds exist only with the test-only feature `testing`, which the crate's own tests turn on through a dev-dependency on itself and which `tools/check-deps.sh` refuses on any normal or build dependency; an app must never enable it.

A payload is seed material only: the entropy of a BIP39 phrase of 18, 21 or 24 words (`PayloadKind::Bip39Entropy`; 12- and 15-word phrases are refused, as they are for keys). The phrase itself is never stored: `Mnemonic::entropy` in `iceroot-sdk-core` gives a phrase's entropy, and `Mnemonic::from_entropy` restores the phrase from it. The kind `PayloadKind::MlDsa65Seed` (the 32-byte ML-DSA-65 key generation seed of IceRoot's post-quantum keys) is reserved: this release reads its header but neither writes nor decrypts it, and a later release enables it without changing the format.

Passwords are Unicode text, normalized to NFKD, non-empty and at most 1,024 bytes of UTF-8. Everything secret is wiped after use: the normalized password (normalized one character at a time with ICU4X, the normalizer the SDK's core uses for recovery phrases, over buffers of exact size, so that the normalizer's own buffer never moves to the heap), the derived key, Argon2's memory and the Blake2b state that absorbs the password, XChaCha20's keystream buffer and the Poly1305 state (through the `zeroize` features of `blake2`, `cipher` and `poly1305`, which `src/crypto.rs` checks at build time where it can), and the payload, which lives on the heap so that moving it leaves no copy. No error or `Debug` output contains a secret. What the crate cannot wipe: the caller's own copy of the password, stack temporaries inside Argon2's compression and XChaCha20's key setup, and whatever the caller copies out of `secret_bytes()`.

## Errors

Every check made with the key derived from the password gives the one error `WrongPasswordOrCorrupt`: a wrong password and a changed salt, nonce, parameter, ciphertext or tag cannot be told apart. The other errors come from checks anyone can make without the password.

| Code | When | Details |
|---|---|---|
| `WrongPasswordOrCorrupt` | Wrong password, or a keystore changed or damaged | none |
| `Malformed` | Not a keystore of a known layout, or not canonical text | `reason`: `magic`, `truncated`, `payload-length`, `length`, `armor-prefix`, `armor-encoding`, `armor-length` |
| `UnsupportedVersion` | A format version other than 1 | `version` |
| `UnsupportedKdf` | A KDF other than Argon2id | `kdf` |
| `UnsupportedPayload` | An unknown payload kind, or the reserved one | `kind` |
| `ParamsOutOfRange` | A parameter below the floor or above the ceiling | `param` (`memory`, `iterations`, `parallelism`, `work`), `value`, `minimum`, `maximum` |
| `InvalidPayload` | Secret material of the wrong length for its kind | `kind`, `length` |
| `InvalidPassword` | An empty or over-long password | `reason` (`empty`, `too-long`), and `bytes`, `maximum` |
| `OutOfMemory` | The key derivation's memory could not be allocated | `memoryKib` |
| `RandomnessUnavailable` | The operating system's generator failed | none |

## Presets and bounds

| Preset | For | Memory | Iterations | Lanes |
|---|---|---|---|---|
| `Desktop` | Native code on desktops and laptops (the Tauri plugin on Linux, macOS, Windows) | 256 MiB | 3 | 4 |
| `Mobile` | Native code on phones and tablets (the Tauri plugin on Android, iOS) | 128 MiB | 3 | 4 |
| `Web` | WebAssembly in a page, a browser extension or a webview | 64 MiB | 4 | 4 |

Every keystore's parameters must lie within `Bounds::STANDARD`, when it is written and when it is read:

| Parameter | Floor | Ceiling |
|---|---|---|
| Memory | 19,456 KiB (19 MiB) | 524,288 KiB (512 MiB) |
| Iterations | 2 | 16 |
| Parallelism | 1 | 16 |
| Work (memory in KiB times iterations) | 38,912 | 2,097,152 (2 GiB filled in all) |

The floor is OWASP's minimum for Argon2id (19 MiB, 2 iterations, 1 lane): a keystore weaker than that is refused, even with the right password. The ceilings keep a crafted keystore from demanding more than 512 MiB of memory, or more than about 2.7 times the desktop preset's work, before its password is checked. The floor belongs to format version 1 and never rises within it, so every keystore written by an earlier release still opens; presets may rise in later releases, and an app moves a keystore to its current preset with `reencrypt` after an unlock.

`Params::is_weaker_than` decides that move: a keystore is weaker than a preset when it has less memory, or the same memory and fewer iterations. Memory comes first and a keystore never moves to less of it, so a keystore written with the desktop preset and opened in a browser keeps its 256 MiB rather than dropping to the web preset's 64 MiB.

### Measurements

A decryption (the key derivation, plus the allocation and wiping of its memory) per preset, the median of five runs, repeated over several runs, on a desktop with an AMD Ryzen 9 7950X while the machine was otherwise busy (a load of 19 to 24 on its 32 threads). WebAssembly ran under Node 22.22.0, built with the workspace's release profile (opt-level 3) and with the size profile the TypeScript package ships (`opt-level = "z"`, fat LTO). Reproduce with `tests/measure.rs` (see its header).

| Preset | Native | WebAssembly, opt-level 3 | WebAssembly, opt-level "z" |
|---|---|---|---|
| Desktop, 256 MiB × 3 | 0.50 to 0.53 s | 0.65 to 0.71 s | 0.76 to 0.82 s |
| Mobile, 128 MiB × 3 | 0.22 to 0.26 s | 0.31 to 0.35 s | 0.36 to 0.41 s |
| Web, 64 MiB × 4 | 0.14 to 0.15 s | 0.19 to 0.22 s | 0.23 to 0.25 s |
| Floor, 19 MiB × 2 | 0.013 to 0.016 s | 0.026 to 0.033 s | 0.030 to 0.037 s |

With less load, the same machine ran the Argon2 of the desktop preset in 0.37 s natively. Lanes cost no extra time (they run one after another; 64 MiB × 3 with 1 and 4 lanes measured 80 and 86 ms). For the presets, WebAssembly was 1.3 to 1.7 times slower than native code. Argon2's native code uses AVX2 on x86-64 and portable code elsewhere; the WebAssembly figures approximate the portable code, which is what ARM devices run.

### Why these presets

The target is 0.5 to 1.5 seconds on a mid-range device of each kind, with the most memory the platform can spare, since memory is what makes an attacker's guesses expensive. No mid-range device was measured: the estimates below scale the figures above by single-core speed and memory bandwidth, taking a mid-range laptop as 1.5 to 2 times slower than this machine, a mid-range phone's native code as 2 to 3 times slower, and WebAssembly in a mid-range phone's webview as 3 to 4 times slower than under Node here. They should be confirmed on real devices when the apps adopt the format; the presets can change in a later release without breaking stored keystores.

- **Desktop, 256 MiB × 3.** About 0.6 to 1.0 s on a mid-range laptop (0.37 to 0.50 s here). Desktops can spare 256 MiB for a second; 512 MiB would push older laptops past 1.5 s.
- **Mobile, 128 MiB × 3.** ARM runs the portable code, about the WebAssembly speed here (0.31 to 0.35 s), so about 0.6 to 1.0 s on a mid-range phone. 128 MiB is a modest transient allocation for an app on current Android and iOS devices; 256 MiB would risk the system ending the app on phones with little memory.
- **Web, 64 MiB × 4.** A browser page, an extension's service worker or a mobile webview may not get hundreds of MiB, and a WebAssembly instance's memory never shrinks once grown, so the memory stays at RFC 9106's 64 MiB and the fourth iteration buys the time instead: about 0.35 to 0.5 s in a mid-range laptop's browser and 0.7 to 1.0 s in a mid-range phone's webview (0.23 to 0.25 s here with the package's build).

All three are at or above RFC 9106's second recommended option (64 MiB, 3 iterations, 4 lanes) and well above OWASP's minimum. Four lanes cost nothing now and let a later native release derive the lanes in parallel on multi-core devices without changing the stored keystores.

## What a wallet must do

- **Never store the password,** or anything derived from it, and never the phrase or the entropy outside a keystore. Hold the decrypted payload only while it is needed, and drop it on lock.
- **Keep the keystore where the platform's storage is best:** a file in the app's private data directory, or the platform's secure storage where it fits (Keychain on iOS and macOS, Keystore-backed storage on Android, the system keyring on Linux and Windows); `chrome.storage.local` in an extension; IndexedDB in a page. The keystore is safe to store unprotected, but platform protection adds a second barrier. Use the text form only where a store holds strings.
- **Pick the preset of the platform** the keystore is created on, and re-encrypt with `reencrypt` after an unlock when `inspect(...).params().is_weaker_than(&preset.params())` (never to less memory).
- **Show one message for `WrongPasswordOrCorrupt`,** such as "wrong password", and keep a backup path: the recovery phrase restores the account when a keystore is lost or damaged.
- **Set the password rules:** the format refuses only an empty password; the app decides the minimum length and strength.
- **In WebAssembly,** run the keystore functions in a worker that can be ended, or accept that the module's memory stays at its peak (64 MiB and more) after an unlock. Tighten the memory ceiling with `decrypt_with_bounds`, `change_password_with_bounds` and `reencrypt_with_bounds` where the platform cannot spare 512 MiB.

## Tests

```sh
cargo test -p iceroot-keystore
# The same tests in WebAssembly under Node, with the wasm-bindgen CLI's test runner at the
# version of the lockfile's wasm-bindgen:
CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
  cargo test -p iceroot-keystore --release --target wasm32-unknown-unknown
```

The vectors are `vectors/sdk/S07-keystore.jsonl`, in the `heartwood-vectors/1` record format: encryption with fixed salts and nonces, decryption, wrong passwords, a change to every header field, the ciphertext and the tag, every parameter out of range, the bounds at their edges, the header without the password, and the text form. `tools/oracle/gen-keystore-vectors.js` generates them from the specification alone, with `@noble/hashes` (Argon2id) and `@noble/ciphers` (XChaCha20-Poly1305) as an implementation independent of the crate:

```sh
npm install --prefix <dir> @noble/hashes@2.4.0 @noble/ciphers@2.4.0
node tools/oracle/gen-keystore-vectors.js <dir>
```

The generator also rewrites `vectors/sdk/MANIFEST.sha256`. The vectors include memory that is not a multiple of four blocks per lane (where Argon2 fills fewer blocks than the memory it hashes) and the exact edges of the text form's length.

Most vectors use parameters far below the format's floor, so that they run in milliseconds. Their records name the bounds `test`, which is `Bounds::TEST`: the floor lowered to Argon2's own minimums (8 KiB, 1 iteration, 1 lane), the ceilings unchanged. It exists only with the crate's test-only `testing` feature (see above). Records with the bounds `standard` use the real bounds, including a keystore at the floor that is fully derived and one that the floor refuses.
