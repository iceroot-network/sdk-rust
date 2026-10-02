//! `iceroot-link`: sign, revoke and verify IceRoot account links from the command line.
//!
//! An account link joins a GitHub account and an IceRoot account (see the SDK's
//! `docs/account-links.md`). This program signs a link or a revocation message that the
//! validator portal's link wizard built, for a holder whose key lives on a machine without a
//! wallet, and verifies a signed record. It needs no network.
//!
//! - The secret comes from a file that only its user can read (`--phrase-file`, or on profiles in
//!   today's formats `--passphrase-file`) or from a pipe (`--phrase-stdin`, which refuses a
//!   terminal), never from an argument or the environment, and is never printed.
//! - The whole message is shown before signing, and signing waits for a confirmation unless
//!   `--yes` is given.
//! - Signing goes only through the SDK's checked path, `link::sign`, and the record is written
//!   exactly as the SDK writes it.

mod args;
mod clock;
mod secret;

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::Path;
use std::process::ExitCode;

use iceroot_sdk_core::error::LinkProblem;
use iceroot_sdk_core::link::{self, LinkExpected, LinkKind, LinkRecord};
use iceroot_sdk_core::profile::{Capability, DevnetOptions, IdDevnetOptions};
use iceroot_sdk_core::{Account, AccountOptions, Error, Mnemonic, Profile};

use crate::args::{Command, SecretSource, SignKind, SignOptions, VerifyOptions};

const USAGE: &str = "\
iceroot-link: sign, revoke and verify IceRoot account links

Usage:
  iceroot-link sign   --network <profile> --message-file <file> --out <file> <secret> [--yes]
  iceroot-link revoke --network <profile> --message-file <file> --out <file> <secret> [--yes]
  iceroot-link verify <record.json> [--network <profile>] [--now <YYYY-MM-DDTHH:MM:SSZ>]

sign signs an account link message, revoke a revocation message, each exactly as the portal's
link wizard wrote it to the message file. The whole message is shown first, and signing waits
for you to type yes, unless --yes is given for scripted use. The signed record is written to a
new --out file, and the comment to post is printed.

The secret, one of:
  --phrase-file <file>      a recovery phrase, in a file only you can read (chmod 600)
  --passphrase-file <file>  a legacy passphrase, in a file only you can read; profiles in
                            today's formats only (one line ending at the end is removed)
  --phrase-stdin            a recovery phrase piped in; a terminal is refused, since it would
                            echo the phrase, and a file redirected in must be private
A secret is never read from an argument or the environment.

Options:
  --network <profile>  devnet, devnet-pq or id-devnet (verify: devnet when absent)
  --account <n>        the account number of the recovery phrase (0 when absent)
  --index <n>          the address index of the recovery phrase (0 when absent)
  --now <time>         verify at this UTC time instead of the clock

Exit status: 0 done, 1 refused, 2 the command line cannot be used.
";

/// Why the program stops.
enum Failure {
    /// The command line cannot be used (exit status 2).
    Usage(String),
    /// A check refused the input, or input and output failed (exit status 1).
    Refused(String),
}

fn refused(text: impl Into<String>) -> Failure {
    Failure::Refused(text.into())
}

fn main() -> ExitCode {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(text)) => {
            eprintln!("iceroot-link: {text}\nRun `iceroot-link help` for the usage.");
            ExitCode::from(2)
        }
        Err(Failure::Refused(text)) => {
            eprintln!("iceroot-link: refused: {text}");
            ExitCode::from(1)
        }
    }
}

fn run(arguments: Vec<OsString>) -> Result<(), Failure> {
    match args::parse(arguments).map_err(|error| Failure::Usage(error.0))? {
        Command::Help => {
            print!("{USAGE}");
            Ok(())
        }
        Command::Version => {
            println!("iceroot-link {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Sign(options) => sign(&options),
        Command::Verify(options) => verify(&options),
    }
}

/// The SDK profile `name` names. The name is not repeated in the error: it is an argument.
fn profile(name: &str) -> Result<Profile, Failure> {
    match name {
        "devnet" => Ok(Profile::devnet(DevnetOptions::default())),
        "devnet-pq" => Ok(Profile::devnet_pq(DevnetOptions::default())),
        "id-devnet" => Ok(Profile::id_devnet(IdDevnetOptions::default())),
        _ => Err(Failure::Usage(
            "--network names no profile of this SDK: use devnet, devnet-pq or id-devnet".to_owned(),
        )),
    }
}

fn kind_of(kind: SignKind) -> LinkKind {
    match kind {
        SignKind::Link => LinkKind::Link,
        SignKind::Revocation => LinkKind::Revocation,
    }
}

/// The words for a message of `kind`.
fn noun(kind: LinkKind) -> &'static str {
    match kind {
        LinkKind::Link => "account link",
        LinkKind::Revocation => "account link revocation",
    }
}

/// The first line of the comment that publishes a record of `kind`.
fn comment_command(kind: LinkKind) -> &'static str {
    match kind {
        LinkKind::Link => "/bounty link",
        LinkKind::Revocation => "/bounty unlink",
    }
}

/// The text of an SDK error, with the stable reason of a link check.
fn describe(error: &Error) -> String {
    match error {
        Error::InvalidLink { problem } => format!("{error} (reason: {})", problem.as_str()),
        other => other.to_string(),
    }
}

fn sign(options: &SignOptions) -> Result<(), Failure> {
    let profile = profile(&options.network)?;
    let kind = kind_of(options.kind);
    // The legacy passphrase import exists only on profiles in today's formats.
    let legacy = profile.require(Capability::LegacyPassphraseImport).is_ok();
    if matches!(options.secret, SecretSource::PassphraseFile(_)) && !legacy {
        return Err(refused(
            "--passphrase-file is only for profiles in today's formats; this network takes a \
             recovery phrase (--phrase-file or --phrase-stdin)",
        ));
    }
    if options.secret == SecretSource::PhraseStdin {
        secret::check_stdin_is_not_a_terminal(io::stdin().is_terminal())
            .map_err(|error| refused(error.to_string()))?;
    }
    if options.out.symlink_metadata().is_ok() {
        return Err(refused(
            "the --out file already exists: name a new file, so no record is overwritten",
        ));
    }

    // The message is checked before the secret is read: text that is not a message of this
    // command's kind is refused without touching a key.
    let message = read_message(&options.message_file)?;
    let expected_kind = LinkExpected {
        kind: Some(kind),
        ..LinkExpected::default()
    };
    let now = clock::now_ms().map_err(refused)?;
    link::parse(&profile, &message, &expected_kind, now)
        .map_err(|error| not_a_message_of(kind, &message, &error))?;

    let account = load_account(&profile, options)?;
    let public_key = account.public_key().to_hex();
    let address = account.address().to_string();
    let expected_account = LinkExpected {
        kind: Some(kind),
        public_key: Some(&public_key),
        address: Some(&address),
        ..LinkExpected::default()
    };
    if let Err(error) = link::parse(&profile, &message, &expected_account, now) {
        return Err(match error {
            Error::InvalidLink {
                problem: LinkProblem::Mismatch,
            } => refused(format!(
                "the message names another account than this secret's key, whose account is \
                 {address}: nothing was signed"
            )),
            other => refused(describe(&other)),
        });
    }

    show(kind, &message, &address);
    if !options.yes {
        confirm(kind, options.secret == SecretSource::PhraseStdin)?;
    }

    let now = clock::now_ms().map_err(refused)?;
    let record = link::sign(&profile, &account, &message, now);
    account.release();
    let record = record.map_err(|error| refused(describe(&error)))?;
    let json = record.to_json();
    write_new(&options.out, &json)?;

    println!("{}\n{json}", comment_command(kind));
    eprintln!(
        "iceroot-link: signed. The record is in the --out file. Post the two lines printed \
         above, exactly, as a new comment on a bounty-labelled issue of the programs \
         repository, and never edit that comment."
    );
    Ok(())
}

/// The message in `path`: at most the format's length, UTF-8, and never changed.
fn read_message(path: &Path) -> Result<String, Failure> {
    let file = File::open(path)
        .map_err(|error| refused(format!("the --message-file file cannot be opened: {error}")))?;
    let mut bytes = Vec::new();
    let limit = u64::try_from(link::MAX_LENGTH + 1).unwrap_or(u64::MAX);
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| refused(format!("the --message-file file cannot be read: {error}")))?;
    String::from_utf8(bytes).map_err(|_| {
        refused("the --message-file file is not UTF-8 text, so it is not an account link message")
    })
}

/// The refusal of a message that is not a valid message of `kind`.
fn not_a_message_of(kind: LinkKind, message: &str, error: &Error) -> Failure {
    let other = match kind {
        LinkKind::Link => (LinkKind::Revocation, "iceroot-link revoke"),
        LinkKind::Revocation => (LinkKind::Link, "iceroot-link sign"),
    };
    // Only the kind is expected at this point, so a mismatch is a message of the other kind.
    let is_other_kind = matches!(
        error,
        Error::InvalidLink {
            problem: LinkProblem::Mismatch
        }
    );
    if is_other_kind {
        return refused(format!(
            "the message file holds an {}, not an {}: sign it with `{}`",
            noun(other.0),
            noun(kind),
            other.1
        ));
    }
    let mut text = format!(
        "the message file is not a valid {} message: {}",
        noun(kind),
        describe(error)
    );
    if message.ends_with('\n') {
        text.push_str(
            ". The file ends with a line break, and the message has none: save the message \
             without a final line break",
        );
    }
    refused(text)
}

/// The account of the secret, read from its source. The secret's bytes and the recovery phrase
/// are wiped when this function returns; the account wipes its key when released.
fn load_account(profile: &Profile, options: &SignOptions) -> Result<Account, Failure> {
    let from_phrase = |bytes: &[u8], source: &str| {
        let phrase = Mnemonic::parse_utf8(bytes).map_err(|error| {
            refused(format!(
                "the {source} does not hold a valid recovery phrase: {error}"
            ))
        })?;
        let choice = AccountOptions {
            account: options.account,
            index: options.index,
            passphrase: "",
        };
        Account::from_phrase(profile, &phrase, &choice).map_err(|error| refused(describe(&error)))
    };
    match &options.secret {
        SecretSource::PhraseFile(path) => {
            let bytes = secret::read_private_file(path, "--phrase-file")
                .map_err(|error| refused(error.to_string()))?;
            from_phrase(&bytes, "--phrase-file file")
        }
        SecretSource::PhraseStdin => {
            let bytes = secret::read_stdin().map_err(|error| refused(error.to_string()))?;
            from_phrase(&bytes, "standard input")
        }
        SecretSource::PassphraseFile(path) => {
            let bytes = secret::read_private_file(path, "--passphrase-file")
                .map_err(|error| refused(error.to_string()))?;
            let text =
                secret::passphrase_text(&bytes).map_err(|error| refused(error.to_string()))?;
            Account::from_legacy_passphrase(profile, text)
                .map_err(|error| refused(describe(&error)))
        }
    }
}

/// Show the whole message on the standard error, which stays on the terminal when the output is
/// redirected. The message has passed the SDK's checks, so it holds no control character.
fn show(kind: LinkKind, message: &str, address: &str) {
    let rule = "-".repeat(72);
    eprintln!(
        "iceroot-link: the {} to sign, in full:\n\n{rule}\n{message}\n{rule}\n\nIt is signed \
         with the key of {address}. A signature over this message authorizes no transaction or \
         transfer.",
        noun(kind)
    );
}

/// Ask on the terminal, or on the standard input when it does not hold the secret, and go on
/// only on `yes`.
fn confirm(kind: LinkKind, stdin_holds_secret: bool) -> Result<(), Failure> {
    eprint!("Sign this {}? Type yes to sign: ", noun(kind));
    let _ = io::stderr().flush();
    let answer = if stdin_holds_secret {
        read_terminal_line()?
    } else {
        read_answer(io::stdin().lock())?
    };
    let answer = answer.trim();
    if answer.eq_ignore_ascii_case("yes") || answer.eq_ignore_ascii_case("y") {
        Ok(())
    } else {
        Err(refused("not confirmed: nothing was signed"))
    }
}

/// One answer line from the controlling terminal: standard input holds the secret.
fn read_terminal_line() -> Result<String, Failure> {
    let no_terminal = || {
        refused(
            "the phrase came through standard input and there is no terminal to confirm on: \
             read the message above and run again with --yes",
        )
    };
    #[cfg(unix)]
    {
        let terminal = File::open("/dev/tty").map_err(|_| no_terminal())?;
        read_answer(io::BufReader::new(terminal))
    }
    #[cfg(not(unix))]
    {
        Err(no_terminal())
    }
}

fn read_answer(source: impl BufRead) -> Result<String, Failure> {
    let mut answer = String::new();
    source
        .take(256)
        .read_line(&mut answer)
        .map_err(|_| refused("the answer cannot be read: nothing was signed"))?;
    Ok(answer)
}

/// Write `text` to the new file `path`, never replacing a file.
fn write_new(path: &Path, text: &str) -> Result<(), Failure> {
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| refused(format!("the --out file cannot be created: {error}")))?;
    let written = file
        .write_all(text.as_bytes())
        .and_then(|()| file.sync_all());
    if let Err(error) = written {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(refused(format!(
            "the --out file cannot be written: {error}"
        )));
    }
    Ok(())
}

fn verify(options: &VerifyOptions) -> Result<(), Failure> {
    let profile = profile(&options.network)?;
    let now = match &options.now {
        Some(text) => clock::parse_ms(text).ok_or_else(|| {
            Failure::Usage(
                "--now takes a UTC time written as YYYY-MM-DDTHH:MM:SSZ, from 1970".to_owned(),
            )
        })?,
        None => clock::now_ms().map_err(refused)?,
    };
    let file = File::open(&options.record)
        .map_err(|error| refused(format!("the record file cannot be opened: {error}")))?;
    let mut bytes = Vec::new();
    let limit = u64::try_from(link::MAX_JSON_LENGTH + 1).unwrap_or(u64::MAX);
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| refused(format!("the record file cannot be read: {error}")))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| refused("the record file is not UTF-8 text, so it is not a signed record"))?;
    let record = LinkRecord::from_json(&text)
        .map_err(|error| refused(format!("not a valid signed record: {}", describe(&error))))?;
    let fields = link::verify(&profile, &record, &LinkExpected::default(), now)
        .map_err(|error| refused(format!("not a valid signed record: {}", describe(&error))))?;

    let mut report = format!(
        "valid: a signed {} on {}\nGitHub user id: {}\nAccount: {}\nPublic key: {}\nIssued at: {}\n",
        noun(fields.kind),
        fields.network,
        fields.github_id,
        fields.account,
        fields.public_key,
        fields.issued_at,
    );
    if let Some(ends) = &fields.ends_link_issued_at {
        report.push_str(&format!("Ends link issued at: {ends}\n"));
    }
    print!("{report}");
    if record.to_json() != text {
        eprintln!(
            "iceroot-link: note: the file is not byte for byte the record a signer writes (for \
             example, it has white space or a final line break). Post the record exactly as the \
             signer wrote it."
        );
    }
    eprintln!(
        "iceroot-link: the signature, the format and the account's key check out. Whether the \
         link is in effect is decided by its review in the programs repository and by the \
         portal's own checks: the seven-day wait and the no-replay rule."
    );
    Ok(())
}
