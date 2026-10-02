# Account links

An account link joins one GitHub account and one IceRoot account. It is one message signed with the IceRoot account's key, published by the GitHub account, and checked by whoever counts it. A revocation signed by the same key ends it. The SDK builds, parses, signs and verifies both messages (`iceroot_sdk::link`), and checks the no-replay rule over the links and revocations already recorded. Its vectors (`vectors/sdk/S09-account-links.jsonl`) come from an implementation of this document written independently of the SDK (`tools/oracle/gen-link-vectors.js`).

A link establishes only that the holder of the key and the holder of the GitHub account agreed to link them. Links are made per network: the message names its network, and a reset or a new network needs a new link, signed again.

## The link message, version 1

Exactly nine lines, separated by `\n` (LF), with no newline at the end and no carriage return anywhere:

```text
IceRoot account link
Version: 1
Network: <network name of the profile>
GitHub user id: <decimal numeric id>
Account: <IceRoot address>
Public key: <the account's public key>
Issued at: <YYYY-MM-DDTHH:MM:SSZ>
Intent: Link this GitHub account and this IceRoot account as the same holder.
No transaction or transfer is authorized.
```

## The revocation message, version 1

Exactly ten lines, in the same rules:

```text
IceRoot account link revocation
Version: 1
Network: <network name of the profile>
GitHub user id: <decimal numeric id>
Account: <IceRoot address>
Public key: <the account's public key>
Issued at: <YYYY-MM-DDTHH:MM:SSZ>
Ends link issued at: <the issue time of the link it ends>
Intent: End the link between this GitHub account and this IceRoot account.
No transaction or transfer is authorized.
```

| Field | Rule |
|---|---|
| Network | The message network name of the reader's profile (`heartwood-devnet-v90` on the devnet profile). |
| GitHub user id | A decimal integer from 1 to 9007199254740991 (2^53 - 1), ASCII digits only, without leading zeros or a sign. The numeric id, never the login, which can change. |
| Account | The address of `Public key` on that network. |
| Public key | The profile's canonical form: 33 bytes of a compressed secp256k1 key, in lowercase hex, a point on the curve. |
| Issued at | A real UTC date and time with whole seconds, written `YYYY-MM-DDTHH:MM:SSZ`, at most 30 seconds after the reader's clock. A link has no expiry: it lasts until it is replaced or revoked. |
| Ends link issued at | The `Issued at` of the link the revocation ends, in the same form, earlier than the revocation's own `Issued at`. |

Each field line is its label, one space and the value: a value that is empty or has a space or tab before or after it is refused. The fixed lines are compared character for character. Messages are never normalised, trimmed or re-wrapped before they are signed or checked.

## The checks, in order

A reader (`link::parse`, given the profile, the message, what it expects and its clock) refuses with the error `InvalidLink` and the first reason that applies:

| Reason | Check |
|---|---|
| `format` | At most 4,096 bytes; no `\r`; nine lines under the link's first line or ten under the revocation's; the version line, the kind's own intent line and the last line exact. |
| `field` | Each field line starts with its label and its value is not empty and has no space or tab around it. |
| `network` | The network is the reader's. |
| `github-id` | The GitHub user id's form and range. |
| `key` | The public key's form, and that it is a valid key. |
| `address` | The account is the key's address on the network. |
| `issued-at` | The issue time's form, and that it is a real date and time. |
| `future` | The issue time is no more than 30 seconds after the reader's clock. |
| `ends-link` | A revocation's ended link time has the same form and is earlier than its own issue time. |
| `mismatch` | What the reader expects, where it sets it: the kind (link or revocation), the GitHub user id, the public key and the account. |

A signer sets the expected public key and account to the signing account's; a verifier sets what it already knows.

## Signing and the signed record

Both messages are signed with the account's ordinary message signature: BIP340 over the SHA-256 of the exact UTF-8 text, algorithm `secp256k1-bip340-sha256`, as `message::sign` signs any text. A message signature can never pass as a transaction's, and the first line keeps a link from passing as a sign-in message or an ownership proof.

A link is signed only through `link::sign`, which first parses the message against the signing account's public key and address, its network and the signer's clock, so a message for another account or network, or one issued too far ahead, is never signed. Plain message signing (`message::sign` and `message::sign_bytes`) refuses, with `InvalidArgument`, any text whose first line is `IceRoot account link` or `IceRoot account link revocation`, as it refuses ownership-proof and sign-in text, so a website asking for a plain signature cannot obtain a link signature.

The signed record is compact JSON with exactly these members, in this order:

```json
{"message":"<the exact message, newlines written as \n>","publicKey":"<public key>","signature":"<signature>","algorithm":"secp256k1-bip340-sha256","network":"heartwood-devnet-v90"}
```

It is UTF-8 with no white space between tokens and no newline at the end. Each text is escaped as JSON requires and no further: `\"`, `\\`, `\b`, `\f`, `\n`, `\r` and `\t`, other characters below U+0020 as `\u00XX` in lowercase hex, and every other character as itself. This is what JavaScript's `JSON.stringify` writes for the same object, and `LinkRecord::to_json` writes the same bytes. A reader (`LinkRecord::from_json`) accepts the members in any order, but exactly these five, each once and each a text, in at most 16,384 bytes; otherwise it refuses with the reason `json`.

`link::verify` checks a record: its message passes the checks above; its `publicKey` and `network` are the message's and its `algorithm` is the profile's (`record`); and its signature is 64 bytes in lowercase hex that verify for the message under the public key (`signature`).

## The no-replay rule

A signed link is durable, so an old one could be posted again after a revocation. For each GitHub user id, account and network, the barrier is the latest time among the recorded events: the `Issued at` of every verified link and every verified signed revocation, and the posting time of every revocation made by the GitHub account itself. `link::check_history` refuses:

| Reason | Check |
|---|---|
| `replay` | A link or revocation whose `Issued at` is not later than the barrier. |
| `unknown-link` | A revocation whose `Ends link issued at` is not the `Issued at` of a recorded link of the same GitHub user id, account and network. |

Only the entries of the same GitHub user id, account and network count. Records that were never verified, or that a reviewer refused, are left out of the history and do not move the barrier. Reading the same record again is not a replay: its own entry is left out when it is checked again. Re-linking after a revocation therefore always needs a new message, freshly signed by the key holder.

## Key rotation

The message carries the key that signed it, and the check is that the account is that key's address. On a network where a key can rotate while the address stays, a link signed by a former key stays valid, and a reader that has the account's key history checks that the key was the address's at the link's issue time. The devnet profile has no rotation.

## Vectors

`vectors/sdk/S09-account-links.jsonl` holds 113 records in the `heartwood-vectors/1` format, each with its output or its error (`{"class": "InvalidLink", "details": {"reason": ...}}`):

- `link.build`: links and revocations built from a GitHub user id, a public key and the times, and the requests refused;
- `link.parse`: valid messages and every refusal above, with each line altered, another network, a key and an address that do not match, non-ASCII text, extra spaces, CRLF line endings, a 32-byte message, a time too far ahead and revocations whose times are out of order;
- `link.sign`: records signed through the checked path with the fixed auxiliary randomness 0x42 x 32, and messages that path refuses;
- `link.verify`: records checked, tampered with, or in another JSON form;
- `link.history`: the no-replay rule, including a revocation naming a link that does not exist, a link older than the last revocation and a revocation older than a later link;
- `message.sign`: plain message signing refusing link and revocation text, and signing near misses.

`crates/iceroot-sdk-core/tests/link.rs` runs every record through the SDK's public functions. To generate the file again, with a built checkout of the reference implementation (for its keys, addresses and signatures):

```sh
node tools/oracle/gen-link-vectors.js <reference checkout>
```
