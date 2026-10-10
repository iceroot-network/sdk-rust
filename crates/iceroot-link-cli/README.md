# iceroot-link

A command-line signer for IceRoot account links: it signs a link or a revocation message with an account's key, and verifies a signed record. It is for a holder whose key lives on a machine without a wallet. The format, the checks and the record are specified in [docs/account-links.md](../../docs/account-links.md); every check and the signature come from the SDK's `link` module. The program needs no network.

```sh
cargo build --release -p iceroot-link-cli    # target/release/iceroot-link
```

## Signing

A link message built by an application, for example a validator portal, follows [the version 1 account link format](../../docs/account-links.md#the-link-message-version-1). Save it to a file exactly as given, with no final line break, then:

```sh
iceroot-link sign   --network devnet --message-file link.txt   --out link.json   --phrase-file ~/.iceroot/phrase
iceroot-link revoke --network devnet --message-file revoke.txt --out revoke.json --phrase-file ~/.iceroot/phrase
```

`sign` accepts only a link message and `revoke` only a revocation message. The program checks the message on the network of `--network` before it reads the secret, checks that the message names the secret's own account, shows the whole message, and signs only after you type `yes`. `--yes` signs without asking, for scripted use; the message is still shown. The signature is made by the SDK's checked path, `link::sign`, and the record is written to the new `--out` file byte for byte as the SDK writes it (an existing file is never replaced). The comment to post is printed on standard output: `/bounty link` or `/bounty unlink`, then the record. Post it exactly as printed, as a new comment on a bounty-labelled issue of the programs repository, and never edit it.

| Option | Meaning |
| --- | --- |
| `--network <profile>` | The SDK profile: `devnet`, `devnet-pq` or `id-devnet`. Today only `devnet` signs. |
| `--message-file <file>` | The message, exactly as the wizard wrote it. |
| `--out <file>` | A new file for the signed record. |
| `--phrase-file <file>` | The recovery phrase, in a file only you can read and write (`chmod 600`). |
| `--passphrase-file <file>` | A legacy passphrase, in a file only you can read and write; on profiles in today's formats only. One line ending at the end of the file is removed; nothing else is changed. |
| `--phrase-stdin` | The recovery phrase, piped in (`gpg --decrypt phrase.gpg \| iceroot-link sign ... --phrase-stdin`). A terminal is refused, since it would echo the phrase, and a file redirected to standard input must be private, as for `--phrase-file`. |
| `--account <n>`, `--index <n>` | The account number and address index of the recovery phrase (0 and 0 when absent). |
| `--yes` | Sign without asking. |

Exactly one secret source is given. A secret is never read from an argument or the environment: an option such as `--phrase` or a phrase typed as an argument is refused, and no message of the program repeats an argument. A secret file must be a regular file owned by you that its group and others can neither read nor write.

With `--phrase-stdin` the confirmation is read from the terminal (`/dev/tty`), since standard input holds the phrase; without a terminal, read the message the program shows and run it again with `--yes`.

## Verifying

```sh
iceroot-link verify link.json [--network devnet] [--now 2026-10-01T12:00:00Z]
```

`verify` reads a signed record and checks it with the SDK's `link::verify`: the format, the network, the account's key and the signature, at the clock's time or at `--now`. It prints the message's fields when the record is valid. A valid record is not yet a link in effect: the programs repository's review and the portal's own checks (the seven-day wait and the no-replay rule) decide that.

## Secrets

- The secret's bytes are read into a buffer that is wiped when dropped, without the standard library's input buffer; the recovery phrase and the key are wiped by the SDK when dropped, and the key is released as soon as the record is signed.
- Nothing the program prints or writes contains the secret; its tests search standard output, standard error and the record for every word of the phrase and the passphrase.
- The terminal's echo is never turned off by the program, because doing so needs unsafe code or another dependency: a phrase is read from a file or a pipe instead.

Exit status: 0 when done, 1 when a check refuses or a file cannot be read or written, 2 when the command line cannot be used.

## Tests

`cargo test -p iceroot-link-cli` runs the program as a process. The terminal tests use `script` and `setsid` from util-linux, and run on Linux only.
