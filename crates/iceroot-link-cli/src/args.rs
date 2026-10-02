//! The command line, read without echoing any argument back.
//!
//! An argument may be a secret typed in the wrong place, so no message of this module repeats an
//! argument's text: a problem names the option or the argument's position instead.

use std::ffi::OsString;
use std::path::PathBuf;

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// Sign a link (`sign`) or a revocation (`revoke`).
    Sign(SignOptions),
    /// Verify a signed record.
    Verify(VerifyOptions),
    /// Print the usage.
    Help,
    /// Print the version.
    Version,
}

/// Which message a signing command accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignKind {
    /// `sign`: a link.
    Link,
    /// `revoke`: a revocation.
    Revocation,
}

/// Where the secret comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretSource {
    /// A recovery phrase in a private file.
    PhraseFile(PathBuf),
    /// A legacy passphrase in a private file (profiles in today's formats only).
    PassphraseFile(PathBuf),
    /// A recovery phrase read from a pipe on standard input.
    PhraseStdin,
}

/// The options of `sign` and `revoke`.
#[derive(Debug, PartialEq, Eq)]
pub struct SignOptions {
    /// Link or revocation.
    pub kind: SignKind,
    /// The profile name.
    pub network: String,
    /// The message to sign.
    pub message_file: PathBuf,
    /// Where the signed record goes.
    pub out: PathBuf,
    /// The secret's source.
    pub secret: SecretSource,
    /// The account number of a recovery phrase.
    pub account: u32,
    /// The address index of a recovery phrase.
    pub index: u32,
    /// Sign without asking.
    pub yes: bool,
}

/// The options of `verify`.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifyOptions {
    /// The signed record.
    pub record: PathBuf,
    /// The profile name.
    pub network: String,
    /// The verifier's time, `YYYY-MM-DDTHH:MM:SSZ`; the clock when absent.
    pub now: Option<String>,
}

/// A command line that cannot be used. The text never contains an argument.
#[derive(Debug, PartialEq, Eq)]
pub struct UsageError(pub String);

/// The profile `verify` uses when `--network` is absent.
pub const DEFAULT_NETWORK: &str = "devnet";

/// Option names that would carry a secret. They do not exist: a secret is read only from a
/// private file or a pipe.
const SECRET_OPTIONS: [&str; 10] = [
    "--phrase",
    "--passphrase",
    "--mnemonic",
    "--seed",
    "--secret",
    "--key",
    "--private-key",
    "--secret-key",
    "--password",
    "--words",
];

/// The refusal of a secret given as an argument.
pub const SECRET_ARGUMENT: &str = "a secret is never read from an argument or the environment: \
put the recovery phrase in a file only you can read (--phrase-file) or pipe it in (--phrase-stdin)";

fn usage(text: impl Into<String>) -> UsageError {
    UsageError(text.into())
}

/// Read the arguments after the program name.
pub fn parse(arguments: Vec<OsString>) -> Result<Command, UsageError> {
    let mut arguments = arguments.into_iter();
    let Some(first) = arguments.next() else {
        return Ok(Command::Help);
    };
    let rest: Vec<OsString> = arguments.collect();
    match first.to_str() {
        Some("sign") => parse_sign(SignKind::Link, rest),
        Some("revoke") => parse_sign(SignKind::Revocation, rest),
        Some("verify") => parse_verify(rest),
        Some("help" | "--help" | "-h") if rest.is_empty() => Ok(Command::Help),
        Some("--version" | "-V") if rest.is_empty() => Ok(Command::Version),
        _ => Err(usage(
            "the first argument is not a command: use sign, revoke, verify or help",
        )),
    }
}

/// One option or argument, by position (1-based, counting from the command).
struct Reader {
    items: Vec<OsString>,
    next: usize,
}

impl Reader {
    fn new(items: Vec<OsString>) -> Reader {
        Reader { items, next: 0 }
    }

    /// The next item and its position after the command.
    fn take(&mut self) -> Option<(usize, OsString)> {
        let item = self.items.get(self.next).cloned()?;
        self.next += 1;
        Some((self.next, item))
    }

    /// The value of `option`, which must follow it.
    fn value(&mut self, option: &str) -> Result<OsString, UsageError> {
        match self.take() {
            Some((_, value)) => Ok(value),
            None => Err(usage(format!("{option} needs a value"))),
        }
    }
}

/// The option an argument names: its text when it is one of `known`, else `None`. A secret
/// option name is refused here, also in the `--name=value` form.
fn option_name(
    item: &OsString,
    position: usize,
    known: &[&'static str],
) -> Result<Option<&'static str>, UsageError> {
    let Some(text) = item.to_str() else {
        return Ok(None);
    };
    let name = text.split_once('=').map_or(text, |(name, _)| name);
    if SECRET_OPTIONS.contains(&name) {
        return Err(usage(SECRET_ARGUMENT));
    }
    if name != text {
        return Err(usage(format!(
            "the argument at position {position}: write an option and its value as two arguments"
        )));
    }
    Ok(known.iter().copied().find(|option| *option == text))
}

fn set_once<T>(slot: &mut Option<T>, value: T, option: &str) -> Result<(), UsageError> {
    if slot.is_some() {
        return Err(usage(format!("{option} is given twice")));
    }
    *slot = Some(value);
    Ok(())
}

/// A refusal of an argument that is not an option of the command. Several words in one argument
/// look like a recovery phrase, which is refused as a secret.
fn unexpected(item: &OsString, position: usize) -> UsageError {
    let words = item
        .to_str()
        .map_or(0, |text| text.split_whitespace().count());
    if words >= 12 {
        usage(SECRET_ARGUMENT)
    } else if item.to_str().is_some_and(|text| text.starts_with('-')) {
        usage(format!(
            "the option at position {position} is not an option of this command"
        ))
    } else {
        usage(format!(
            "the argument at position {position} is not expected"
        ))
    }
}

fn number(value: &OsString, option: &str) -> Result<u32, UsageError> {
    value
        .to_str()
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|text| text.parse::<u32>().ok())
        .filter(|number| *number < 1 << 31)
        .ok_or_else(|| usage(format!("{option} takes a whole number below 2^31")))
}

fn text(value: OsString, option: &str) -> Result<String, UsageError> {
    value
        .into_string()
        .map_err(|_| usage(format!("{option} is not UTF-8 text")))
}

const SIGN_OPTIONS: [&str; 10] = [
    "--network",
    "--message-file",
    "--out",
    "--phrase-file",
    "--passphrase-file",
    "--phrase-stdin",
    "--account",
    "--index",
    "--yes",
    "--help",
];

fn parse_sign(kind: SignKind, items: Vec<OsString>) -> Result<Command, UsageError> {
    let mut reader = Reader::new(items);
    let mut network = None;
    let mut message_file = None;
    let mut out = None;
    let mut secrets: Vec<SecretSource> = Vec::new();
    let mut account = None;
    let mut index = None;
    let mut yes = false;
    while let Some((position, item)) = reader.take() {
        match option_name(&item, position, &SIGN_OPTIONS)? {
            Some("--network") => {
                let value = text(reader.value("--network")?, "--network")?;
                set_once(&mut network, value, "--network")?;
            }
            Some("--message-file") => {
                let value = PathBuf::from(reader.value("--message-file")?);
                set_once(&mut message_file, value, "--message-file")?;
            }
            Some("--out") => {
                let value = PathBuf::from(reader.value("--out")?);
                set_once(&mut out, value, "--out")?;
            }
            Some("--phrase-file") => {
                let value = PathBuf::from(reader.value("--phrase-file")?);
                secrets.push(SecretSource::PhraseFile(value));
            }
            Some("--passphrase-file") => {
                let value = PathBuf::from(reader.value("--passphrase-file")?);
                secrets.push(SecretSource::PassphraseFile(value));
            }
            Some("--phrase-stdin") => secrets.push(SecretSource::PhraseStdin),
            Some("--account") => {
                let value = number(&reader.value("--account")?, "--account")?;
                set_once(&mut account, value, "--account")?;
            }
            Some("--index") => {
                let value = number(&reader.value("--index")?, "--index")?;
                set_once(&mut index, value, "--index")?;
            }
            Some("--yes") => {
                if yes {
                    return Err(usage("--yes is given twice"));
                }
                yes = true;
            }
            Some("--help") if position == 1 && reader.items.len() == 1 => {
                return Ok(Command::Help);
            }
            _ => return Err(unexpected(&item, position)),
        }
    }
    let secret = match secrets.len() {
        0 => {
            return Err(usage(
                "no secret source: give --phrase-file, --passphrase-file or --phrase-stdin",
            ));
        }
        1 => secrets.remove(0),
        _ => {
            return Err(usage(
                "give one secret source: --phrase-file, --passphrase-file or --phrase-stdin",
            ));
        }
    };
    if matches!(secret, SecretSource::PassphraseFile(_)) && (account.is_some() || index.is_some()) {
        return Err(usage(
            "--account and --index select a key of a recovery phrase; a passphrase has one key",
        ));
    }
    Ok(Command::Sign(SignOptions {
        kind,
        network: network.ok_or_else(|| usage("--network is required"))?,
        message_file: message_file.ok_or_else(|| usage("--message-file is required"))?,
        out: out.ok_or_else(|| usage("--out is required"))?,
        secret,
        account: account.unwrap_or(0),
        index: index.unwrap_or(0),
        yes,
    }))
}

const VERIFY_OPTIONS: [&str; 3] = ["--network", "--now", "--help"];

fn parse_verify(items: Vec<OsString>) -> Result<Command, UsageError> {
    let mut reader = Reader::new(items);
    let mut record = None;
    let mut network = None;
    let mut now = None;
    while let Some((position, item)) = reader.take() {
        match option_name(&item, position, &VERIFY_OPTIONS)? {
            Some("--network") => {
                let value = text(reader.value("--network")?, "--network")?;
                set_once(&mut network, value, "--network")?;
            }
            Some("--now") => {
                let value = text(reader.value("--now")?, "--now")?;
                set_once(&mut now, value, "--now")?;
            }
            Some("--help") if position == 1 && reader.items.len() == 1 => {
                return Ok(Command::Help);
            }
            Some(_) => return Err(unexpected(&item, position)),
            None => {
                let is_option = item.to_str().is_some_and(|text| text.starts_with('-'));
                if is_option || record.is_some() {
                    return Err(unexpected(&item, position));
                }
                record = Some(PathBuf::from(item));
            }
        }
    }
    Ok(Command::Verify(VerifyOptions {
        record: record.ok_or_else(|| usage("verify needs the record file"))?,
        network: network.unwrap_or_else(|| DEFAULT_NETWORK.to_owned()),
        now,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line<T: AsRef<str>>(items: &[T]) -> Vec<OsString> {
        items
            .iter()
            .map(|item| OsString::from(item.as_ref()))
            .collect()
    }

    const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank \
                          year wave sausage worth useful legal will";

    fn base(secret: &[&str]) -> Vec<String> {
        let mut items: Vec<String> = [
            "sign",
            "--network",
            "devnet",
            "--message-file",
            "m.txt",
            "--out",
            "r.json",
        ]
        .map(String::from)
        .to_vec();
        items.extend(secret.iter().map(|item| item.to_string()));
        items
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn sign_reads_its_options() {
        let command = parse(line(&base(&[
            "--phrase-file",
            "p",
            "--index",
            "3",
            "--yes",
        ])))
        .unwrap();
        assert_eq!(
            command,
            Command::Sign(SignOptions {
                kind: SignKind::Link,
                network: "devnet".into(),
                message_file: "m.txt".into(),
                out: "r.json".into(),
                secret: SecretSource::PhraseFile("p".into()),
                account: 0,
                index: 3,
                yes: true,
            })
        );
    }

    #[test]
    fn a_secret_in_an_argument_is_refused_without_repeating_it() {
        let cases: Vec<Vec<String>> = vec![
            base(&["--phrase", PHRASE]),
            base(&[&format!("--phrase={PHRASE}")]),
            base(&["--passphrase", "a passphrase"]),
            base(&["--mnemonic", PHRASE]),
            base(&["--phrase-stdin", PHRASE]),
            strings(&["sign", PHRASE]),
            strings(&["verify", "r.json", PHRASE]),
        ];
        for items in cases {
            let error = parse(line(&items)).unwrap_err();
            assert_eq!(error.0, SECRET_ARGUMENT, "{items:?}");
            assert!(!error.0.contains("legal") && !error.0.contains("passphrase\""));
        }
    }

    #[test]
    fn no_message_repeats_an_argument() {
        let cases: Vec<Vec<String>> = vec![
            base(&["--phrase-file", "p", "secret-word"]),
            base(&["--phrase-file", "p", "--secret-word"]),
            base(&[
                "--phrase-file",
                "p",
                "--network",
                "devnet",
                "--network",
                "secret-word",
            ]),
            base(&["--phrase-file", "p", "--account", "secret-word"]),
            base(&["--phrase-file", "p", "--network=secret-word"]),
            strings(&["secret-word"]),
            strings(&["verify", "r.json", "secret-word"]),
        ];
        for items in cases {
            let error = parse(line(&items)).unwrap_err();
            assert!(!error.0.contains("secret-word"), "{}", error.0);
        }
    }

    #[test]
    fn exactly_one_secret_source() {
        assert!(parse(line(&base(&[]))).unwrap_err().0.contains("no secret"));
        let both = base(&["--phrase-file", "p", "--phrase-stdin"]);
        assert!(parse(line(&both)).unwrap_err().0.contains("one secret"));
        let passphrase = base(&["--passphrase-file", "p", "--account", "1"]);
        assert!(parse(line(&passphrase)).is_err());
    }

    #[test]
    fn verify_reads_its_options() {
        let command = parse(line(&["verify", "r.json", "--now", "2026-01-02T03:04:05Z"])).unwrap();
        assert_eq!(
            command,
            Command::Verify(VerifyOptions {
                record: "r.json".into(),
                network: "devnet".into(),
                now: Some("2026-01-02T03:04:05Z".into()),
            })
        );
        assert!(parse(line(&["verify"])).is_err());
        assert!(parse(line(&["verify", "a", "b"])).is_err());
        assert!(parse(line(&["verify", "a", "--yes"])).is_err());
    }
}
