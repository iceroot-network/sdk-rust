# Ownership proofs of Solar addresses

An ownership proof shows that the holder of a Solar address controls its key, and names the IceRoot account that the address's holding should be bound to. The Solar network no longer runs, so a proof moves nothing and authorizes no transaction: it is a signed statement, and the process that asks for it decides what it is accepted for.

Version 1 is the format of the IceRoot Legacy Signer (the browser wallet repository's `docs/legacy-signer.md`), which signs proofs with a Solar recovery phrase or a Ledger. The SDK builds, signs and verifies the same proofs (`iceroot_sdk::ownership`), and its vectors check it against the Legacy Signer's own format checks and the reference implementation's keys, addresses and signatures.

The last section is a draft: how the claim binding of the launchpad distribution kit can use these proofs for claims on an asset distributed from an archived snapshot of the Solar chain.

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
| Nonce | 64 lowercase hex digits. A signer uses 32 random bytes; a process that issues its own messages may choose it, for example to tie a proof to one request (see the claims draft). |
| Issued at | A real UTC date and time with seconds, and optionally exactly three digits of milliseconds. A reader refuses a message issued more than five minutes ahead of its own clock. How old a proof may be is the rule of the process that asks for it. |

A signer shows the whole message to the holder before signing, checks that it names the address of the key in use, and refuses every other text. A proof's signature is a plain message signature over the text, so any other signer of messages must refuse a proof's text: the SDK's message signing refuses text whose first line is the proof's title, and signs a proof only through `ownership::sign`.

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

`vectors/sdk/S08-ownership-proofs.jsonl`, generated by `tools/oracle/gen-sdk-vectors.js` (see the README): accounts as typed, messages built and parsed, proofs signed with a fixed auxiliary randomness, and proofs verified. The verdicts on messages and proofs come from the Legacy Signer's own scripts (`legacy-signer/proof-protocol.js` and `legacy-signer/sandbox.js`, whose SHA-256 the meta record names), run with the reference implementation's crypto package in place of the Solar bundle the signer loads. Keys, addresses and signatures come from the reference; valid IceRoot accounts are encoded with `@scure/base`'s Bech32m, the library under the reference's own BIP32 library.

## Draft: claims on an asset distributed from an archived snapshot

**Status: draft.** Nothing here is implemented yet; the terms file belongs to the launchpad distribution kit, which is built later.

An asset on IceRoot can be distributed to the holders recorded in an archived snapshot of the Solar chain's final state. No validator can observe a chain that no longer runs, so such a distribution is the issuer's, not a certified migration: the issuer creates the asset with a fixed supply, publishes the snapshot file and its SHA-256 so that anyone can recompute every holder's share, and pays claims. A holder claims by signing an ownership proof with the Solar key of the snapshot address, naming the IceRoot account to be paid. The claim binding of the launchpad distribution kit checks the claims and pays them in its transfer batches, with a public record of every payment.

### The claim message

A claim is an ownership proof of version 1 whose nonce is the distribution's **claim nonce**. The Legacy Signer and a Ledger sign it without any change: the claim page composes the message, and the holder pastes it into the Legacy Signer (**Paste a proof message**), reads it and signs it.

```text
claim nonce = hex( SHA-256( "iceroot/snapshot-claim/v1" ‖ terms hash ‖ u32 length ‖ source address ) )
```

- `"iceroot/snapshot-claim/v1"`: those 25 ASCII bytes.
- `terms hash`: the 32-byte SHA-256 of the distribution's terms file, exactly as published.
- `source address`: the Solar mainnet address in its Base58 text, as ASCII bytes, after its length as a big-endian 32-bit integer.
- `hex`: 64 lowercase hex digits.

The claim nonce ties a proof to one distribution and one address. A proof made for anything else (another distribution, a migration, an earlier request) carries another nonce and is refused, and anyone who holds the terms file can recompute every claim's nonce.

### The terms file

A JSON file the issuer publishes before claims open, whose hash every claim commits to. At least:

| Field | Meaning |
|---|---|
| `type`, `version` | `iceroot-snapshot-distribution`, `1` |
| `asset` | The AssetID of the distributed asset. |
| `sourceNetwork` | `solar-mainnet` |
| `snapshotSha256` | The SHA-256 of the published snapshot file. |
| `network` | `mainnet` or `testnet`: the IceRoot network paid, which the claimed account's prefix must match. |
| `share` | How a snapshot balance becomes an amount of the asset, exactly, in base units. |
| `opens`, `closes` | The claim window, in UTC. |
| `unclaimed` | What happens to units not claimed when the window closes. |

### What the claim binding checks

In this order, at the time it receives the claim:

1. The signed proof verifies (the verification above, with the binding's clock).
2. Its nonce is the claim nonce of this terms file and the proof's source address.
3. The account's prefix matches the terms' network.
4. The source address holds a positive balance in the snapshot.
5. The issue time is within the claim window, and the claim arrives before the window closes.

For each source address the binding is the valid claim with the latest issue time, until the transfer that pays it is built; a claim whose issue time is not later than the current binding's does not replace it. A holder can so correct the account named, but only before payment. After payment the binding is final and further claims for the address are refused.

### The published record

For every payment, the kit publishes one line:

```json
{
  "type": "iceroot-snapshot-claim",
  "version": 1,
  "terms": "<terms hash, hex>",
  "amount": "<amount paid, base units, decimal>",
  "proof": { "type": "iceroot-migration-ownership-proof", "...": "the signed proof" },
  "payout": "<id of the transaction that paid it>"
}
```

Anyone can check each line: the proof verifies, its nonce is the claim nonce, the amount follows from the snapshot and the terms' share rule, and the transaction pays that amount to the named account. Together with the snapshot, the lines show what was claimed and what is left unclaimed.

### Limits

- A proof shows control of a Solar key, not who holds it. A key that leaked after the chain stopped lets its finder claim, and nothing in a claim can tell the two apart. The latest-issue-time rule lets a holder override a finder's claim, and a finder the holder's, until payment; the issuer's payout timing decides the window.
- Proofs are public once submitted. Submitting someone else's proof only binds the account that holder named.
- The snapshot's correctness is the issuer's publication; a claim neither proves nor certifies it.
- The first line of a version 1 message reads "IceRoot migration ownership proof", a wording that predates claims. A later message version could name the distribution and its asset in words for the holder to read; it would need a new Legacy Signer release and new vectors.

### Open points

- The SDK adds `claim_nonce(terms_hash, source_address)` and the claim binding's checks once this draft is accepted, with vectors from an independent implementation.
- The terms file's exact format, and whether the claim page, the Legacy Signer or both compose the message.
