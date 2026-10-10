# Ownership proofs of Solar addresses

An ownership proof shows that the holder of a Solar address controls its key, and names the IceRoot account that the address's holding should be bound to. The Solar network no longer runs, so a proof moves nothing and authorizes no transaction: it is a signed statement, and the process that asks for it decides what it is accepted for.

This document is the normative description of the version 1 format used by the IceRoot Legacy Signer, which signs proofs with a Solar recovery phrase or a Ledger. The SDK builds, signs and verifies the same proofs (`iceroot_sdk::ownership`), and its vectors check it against the Legacy Signer's own format checks and the reference implementation's keys, addresses and signatures.

## The message, version 1

Nine lines separated by `\n`, with no `\r` and no newline at the end. Only printable ASCII (0x20 to 0x7e) is allowed besides the line breaks, so a Ledger can display every character, and the message is at most 1,024 characters long.

```text
IceRoot migration ownership proof
Version: 1
Source network: solar-mainnet
Source address: <Solar mainnet address>
IceRoot account: <ice1... or tice1..., in lowercase>
Nonce: <64 lowercase hexadecimal characters>
Issued at: <UTC time as YYYY-MM-DDTHH:MM:SSZ or YYYY-MM-DDTHH:MM:SS.sssZ>
Statement: I control the source address above and ask for its holding to be bound to the IceRoot account above.
No transaction or transfer is authorized.
```

| Field | Rule |
|---|---|
| Source address | 34 Base58 characters starting with `S`: Base58Check (double SHA-256 checksum) of network byte 63 followed by the RIPEMD-160 of the public key. |
| IceRoot account | A 32-byte hash in Bech32m (BIP 350) with the prefix `ice` (mainnet) or `tice` (public testnet): 58 characters after the separator `1`, the last 6 of them the checksum; the 4 spare bits of the 52nd character are zero. Written in lowercase. |
| Nonce | 64 lowercase hex digits. A signer uses 32 random bytes; a process that issues its own messages may choose it, for example to tie a proof to one request. |
| Issued at | A real UTC date and time with seconds, and optionally exactly three digits of milliseconds. A reader refuses a message issued more than five minutes ahead of its own clock. How old a proof may be is the rule of the process that asks for it. |

A signer shows the whole message to the holder before signing, checks that it names the address of the key in use, and refuses every other text. A proof's signature is a plain message signature over the text, so any other signer of messages must refuse a proof's text: the SDK's message signing refuses text whose first line is the proof's title, and signs a proof only through `ownership::sign`. Message signing refuses a website's sign-in message the same way, and signs one only through `signin::sign`, which checks it against the origin of the page that asks and the signing account first.

## The signed proof

```json
{
  "type": "iceroot-migration-ownership-proof",
  "version": 1,
  "network": "solar-mainnet",
  "address": "<Solar mainnet address>",
  "publicKey": "<33-byte compressed secp256k1 public key, hex>",
  "algorithm": "secp256k1-bip340-sha256",
  "message": "<the version 1 message>",
  "signature": "<64-byte BIP340 signature, hex>"
}
```

The signature is Solar's own message signature: BIP340 Schnorr over the SHA-256 of the message's UTF-8 bytes, under the public key without its first byte. The Legacy Signer copies the proof as compact JSON with the fields in this order; `OwnershipProof::to_json` writes the same bytes.

## Verification

1. The object has these eight fields, with the type, version, network and algorithm above.
2. `message` follows the version 1 format, was issued no more than five minutes ahead of the verifier's clock, and its source address equals `address`.
3. `publicKey` is a valid compressed key in lowercase hex, and its Solar mainnet address equals `address`.
4. `signature` is 128 lowercase hex digits and a valid BIP340 signature of the SHA-256 of `message` under `publicKey`.

The proof contains only public information.

### Where the SDK is stricter

The Legacy Signer's format check reads the source address by its pattern and the issue time with JavaScript's `Date.parse`. The SDK also requires:

- a valid Base58Check checksum and network byte 63 for the source address (a Base58 text starting with `S` can belong to network byte 62 or 64, or have a wrong checksum);
- a real date and time (`Date.parse` reads 30 February and 29 February of a common year as days of March, and 24:00:00 as the next day's midnight);
- ASCII only in a typed IceRoot account (JavaScript's `toLowerCase` reads the Kelvin sign, U+212A, as `k`, so the Legacy Signer's account field accepts it in place of a capital K).

No proof a correct signer makes for a real key at a real time is refused: a signer checks that the message names its own key's address, and writes the current time. The vectors record these cases as documented differences.

## Functions

In Rust, `iceroot_sdk::ownership` (the module of `iceroot-sdk-core`). These functions need no network profile.

| Function | What it does |
|---|---|
| `SolarKey::from_passphrase(text)` | A Solar key from its passphrase: the SHA-256 of the text, as the reference derives it (a Solar wallet's 12-word recovery phrase is such a passphrase). The text is hashed exactly as given; the Legacy Signer trims a typed phrase and joins its words with single spaces first. The key is wiped when dropped. |
| `source_address(&public_key)` | The Solar mainnet address of a public key, for a key held on a Ledger. |
| `IceRootAccount::parse(text)` | An IceRoot account as a person types it: surrounding white space removed (the characters JavaScript's `trim` removes), an account written all in capitals read in lowercase, the checksum checked. `parse_canonical` reads it exactly as a message writes it. |
| `random_nonce()` | 64 lowercase hex digits from 32 random bytes. |
| `build(&ProofRequest { address, account, nonce, issued_at_ms })` | The message, with the issue time in milliseconds, as the Legacy Signer writes it. |
| `parse(message, &ProofExpected { address }, now_ms)` | The checks of the message format, with the reader's clock and, when given, the address the message must name. |
| `sign(&key, message, now_ms)` | Checks the message against the key's address and signs it. The signature is verified before the proof is returned. |
| `OwnershipProof::from_signature(message, public_key, signature, now_ms)` | The proof of a signature made elsewhere, such as on a Ledger, after checking it. |
| `verify(&proof, now_ms)` | The verification above; returns the message's fields. |
| `OwnershipProof::from_json(text)`, `to_json()` | The signed proof's JSON. |

Every refusal is the error `InvalidProof`, with the `reason` `format`, `field`, `source-network`, `address`, `account`, `nonce`, `issued-at`, `mismatch`, `key`, `signature` or `json`.

## Vectors

`vectors/sdk/S08-ownership-proofs.jsonl`, generated by `tools/oracle/gen-sdk-vectors.js` (see [maintaining](maintaining.md#vectors)): accounts as typed, messages built and parsed, proofs signed with a fixed auxiliary randomness, and proofs verified. The verdicts on messages and proofs come from the Legacy Signer's own scripts (`legacy-signer/proof-protocol.js` and `legacy-signer/sandbox.js`, whose SHA-256 the meta record names), run with the reference implementation's crypto package in place of the Solar bundle the signer loads. Keys, addresses and signatures come from the reference; valid IceRoot accounts are encoded with `@scure/base`'s Bech32m, the library under the reference's own BIP32 library.
