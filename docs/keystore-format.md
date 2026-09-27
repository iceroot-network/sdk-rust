# The IceRoot keystore format, version 1

A keystore is a recovery seed encrypted under a password. It is written and read by the functions of the `iceroot-keystore` crate; the apps store it. This document is enough to implement a reader or writer; `tools/oracle/gen-keystore-vectors.js` is one, written from it, and the vectors in `vectors/sdk/S07-keystore.jsonl` check both against each other.

## Primitives

- **Key derivation:** Argon2id, version 0x13 (RFC 9106), with a 32-byte output and no secret key or associated data. Its inputs are the password bytes, the 16-byte salt and the parameters of the header: memory `m` in KiB, iterations `t` and lanes `p`.
- **Encryption:** XChaCha20-Poly1305 (the extended-nonce construction of draft-irtf-cfrg-xchacha over the ChaCha20-Poly1305 of RFC 8439), with the derived key, the 24-byte nonce of the header, the 60 bytes of the header as associated data, and the payload as plaintext.
- **Password bytes:** the UTF-8 encoding of the password's Unicode NFKD normalization, so that the same text typed on different systems gives the same key. A password must be non-empty and at most 1,024 bytes of UTF-8 before normalization.

Every keystore has a fresh salt and nonce from a cryptographically secure generator (the operating system's, or `crypto.getRandomValues` in WebAssembly), so every keystore has its own key; a rewritten keystore (a new password, new parameters) gets a new salt and nonce too.

## Byte layout

All integers are big-endian.

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | Magic | `IRKS` (`49 52 4b 53`) |
| 4 | 1 | Format version | `1` |
| 5 | 1 | Key derivation function | `1`: Argon2id as above |
| 6 | 4 | Memory, KiB | u32 |
| 10 | 4 | Iterations | u32 |
| 14 | 4 | Parallelism (lanes) | u32 |
| 18 | 16 | Salt | random |
| 34 | 24 | Nonce | random |
| 58 | 1 | Payload kind | `1` BIP39 entropy, `2` ML-DSA-65 seed (reserved) |
| 59 | 1 | Payload length, bytes | `n` |
| 60 | n | Ciphertext | the encrypted payload |
| 60 + n | 16 | Tag | Poly1305 |

Bytes 0 to 59 are the header; they are the associated data of the encryption, so a change to any of them makes decryption fail. A keystore of 18, 21 or 24 words is 100, 104 or 108 bytes long. Every field has one encoding and the length is fixed by the header, so a keystore has exactly one byte form.

## Payload kinds

| Kind | Name | Length | This release |
|---|---|---|---|
| 1 | `bip39-entropy` | 24, 28 or 32 bytes: the entropy of a BIP39 phrase of 18, 21 or 24 words | written and read |
| 2 | `ml-dsa-65-seed` | 32 bytes: the ML-DSA-65 key generation seed (ξ) of IceRoot's post-quantum keys | reserved: headers are read, nothing is written or decrypted |

The payload is seed material only: never the text of a phrase, never a derived key, never metadata. The phrase is its entropy plus a checksum, so the entropy restores it. Phrases of 12 and 15 words (16 and 20 bytes) are refused, as they are for keys. Other kinds are unknown and refused.

## Parameter bounds

A writer refuses parameters outside these bounds, and a reader refuses a keystore whose parameters are outside them before deriving anything.

| Parameter | Floor | Ceiling |
|---|---|---|
| Memory | 19,456 KiB (19 MiB) | 524,288 KiB (512 MiB) |
| Iterations | 2 | 16 |
| Parallelism | 1 | 16 |
| Work: memory in KiB × iterations | 38,912 | 2,097,152 |

Argon2's own rule, at least 8 KiB of memory per lane, holds within these bounds. The floor (OWASP's minimum for Argon2id) refuses weak keystores; the ceilings stop a crafted keystore from demanding more than 512 MiB of memory, or 2 GiB of memory filled over all passes, before its password is checked. A reader may use a lower ceiling where its platform cannot spare the memory. The floor belongs to version 1 and never rises within it: a keystore written under version 1's bounds always opens.

The presets, one per kind of platform, are in the crate's README with the measurements behind them: desktop 256 MiB × 3 iterations × 4 lanes, mobile 128 MiB × 3 × 4, web 64 MiB × 4 × 4. They may rise in later releases; a wallet re-encrypts a keystore after the next unlock when its memory is below its platform's current preset, or its memory equals the preset's and its iterations are below it. A keystore never moves to less memory: one written with the desktop preset and opened in a browser keeps its 256 MiB.

## Reading a keystore

A reader makes these checks in this order and reports the first that fails:

1. The first 4 bytes are the magic. Else `Malformed` (`magic`).
2. There is a fifth byte. Else `Malformed` (`truncated`).
3. The version is 1. Else `UnsupportedVersion`.
4. There are at least 76 bytes (header and tag). Else `Malformed` (`truncated`).
5. The KDF is 1. Else `UnsupportedKdf`.
6. The payload kind is known (1 or 2). Else `UnsupportedPayload`.
7. The payload length is one the kind allows. Else `Malformed` (`payload-length`).
8. The total length is 76 plus the payload length. Else `Malformed` (`length`).

These eight checks read the header without the password (`inspect`). To decrypt, a reader then checks:

9. The kind is one it decrypts (kind 2 is not, in this release). Else `UnsupportedPayload`.
10. The parameters are within the bounds, in the order parallelism, memory, iterations, work. Else `ParamsOutOfRange`, naming the first parameter out of range.
11. The password is non-empty and at most 1,024 bytes. Else `InvalidPassword`.
12. The key derivation and the tag. Any failure is `WrongPasswordOrCorrupt`.

The checks before the twelfth depend only on the keystore's bytes, which anyone who holds it can read, and on the password's length, so their specific answers tell an attacker nothing new. The twelfth has one answer for a wrong password and for any change to the salt, nonce, parameters, ciphertext or tag, by design.

## Text form

For stores that hold strings only: the prefix `irks:` followed by the keystore's bytes in base64url without padding (RFC 4648, section 5). Every keystore has exactly one text form. A reader makes these checks in this order and reports the first that fails:

1. The text starts with the exact lowercase prefix `irks:`. Else `Malformed` (`armor-prefix`).
2. Every character after the prefix is one of the 64 characters of the base64url alphabet (`A` to `Z`, `a` to `z`, `0` to `9`, `-`, `_`): no padding, whitespace, line breaks or characters outside ASCII. Else `Malformed` (`armor-encoding`).
3. There are at most 1,366 of them, the unpadded length of 1,024 bytes, far more than a keystore of version 1 needs (108 bytes at most). Else `Malformed` (`armor-length`). The check comes after the alphabet's, so the length is a count of one-byte characters in every implementation.
4. The encoding is canonical: its length is not one more than a multiple of 4, and the unused bits of its last character are zero. Else `Malformed` (`armor-encoding`).

The decoded bytes are then read as above.

## What a wallet must do

- Never store the password or anything derived from it, and never store the phrase or its entropy outside a keystore.
- Keep the keystore where the platform's storage is best: the app's private data directory or the platform's secure storage (Keychain, Keystore-backed storage, the system keyring), `chrome.storage.local` in an extension, IndexedDB in a page.
- Create keystores with the preset of the platform, and re-encrypt after an unlock when the stored parameters are below it, as above (never to less memory).
- Show one message for `WrongPasswordOrCorrupt`, and keep the recovery phrase as the way back when a keystore is lost or damaged.
- Decide the password rules; the format refuses only an empty password.

## Versions

Version 1 is the only version. A later version changes the version byte, and readers that do not know it answer `UnsupportedVersion` without reading further. A new payload kind or KDF within version 1 gets a new code; readers that do not know it answer `UnsupportedPayload` or `UnsupportedKdf`. Enabling the reserved kind 2 changes no byte of the format.
