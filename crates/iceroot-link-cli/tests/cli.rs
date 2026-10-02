//! The `iceroot-link` program, run as a process: where it reads secrets from, what it refuses,
//! what it writes, and that no secret reaches any of its outputs.
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use iceroot_sdk_core::link::{self, LinkExpected, LinkKind, LinkRecord, LinkRequest};
use iceroot_sdk_core::message::ALGORITHM;
use iceroot_sdk_core::profile::DevnetOptions;
use iceroot_sdk_core::{Account, AccountOptions, Mnemonic, Profile};

const BIN: &str = env!("CARGO_BIN_EXE_iceroot-link");

/// A fictional GitHub user id from the documentation range.
const GITHUB_ID: u64 = 9_999_999_001;

/// The test's recovery phrase: 24 words from fixed entropy, none of which the program's own
/// texts use, so finding any of them in an output means the secret leaked.
fn phrase() -> Mnemonic {
    Mnemonic::from_entropy(&[0x6d; 32]).unwrap()
}

/// The test's legacy passphrase, as written to its file (with a final line break).
const PASSPHRASE: &str = "Quokka zephyr 7731 marmalade lighthouse";

fn devnet() -> Profile {
    Profile::devnet(DevnetOptions::default())
}

fn account(index: u32) -> Account {
    let options = AccountOptions {
        index,
        ..AccountOptions::default()
    };
    Account::from_phrase(&devnet(), &phrase(), &options).unwrap()
}

fn now_s() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn link_message(account: &Account, issued_at: i64) -> String {
    let request = LinkRequest {
        github_id: GITHUB_ID,
        public_key: account.public_key(),
        issued_at,
    };
    link::build(&devnet(), &request).unwrap()
}

fn revocation_message(account: &Account, issued_at: i64, ends: i64) -> String {
    let request = LinkRequest {
        github_id: GITHUB_ID,
        public_key: account.public_key(),
        issued_at,
    };
    link::build_revocation(&devnet(), &request, ends).unwrap()
}

/// A fresh directory of the test's own.
fn workdir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("iceroot-link-cli")
        .join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_mode(path: &Path, content: &[u8], mode: u32) {
    let _ = fs::remove_file(path);
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// Run the program with `arguments` and `stdin` piped in.
fn exec(arguments: &[&str], stdin: &[u8]) -> Output {
    run_command(Command::new(BIN).args(arguments), stdin)
}

fn run_command(command: &mut Command, stdin: &[u8]) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    // The program may stop before reading; a closed pipe is not an error here.
    let _ = input.write_all(stdin);
    drop(input);
    child.wait_with_output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// The files of one signing run.
struct Run {
    dir: PathBuf,
    message: PathBuf,
    out: PathBuf,
    phrase: PathBuf,
    passphrase: PathBuf,
}

impl Run {
    fn new(name: &str, message: &str) -> Run {
        let dir = workdir(name);
        let run = Run {
            message: dir.join("message.txt"),
            out: dir.join("record.json"),
            phrase: dir.join("phrase.txt"),
            passphrase: dir.join("passphrase.txt"),
            dir,
        };
        fs::write(&run.message, message).unwrap();
        write_mode(
            &run.phrase,
            format!("{}\n", phrase().phrase()).as_bytes(),
            0o600,
        );
        write_mode(&run.passphrase, format!("{PASSPHRASE}\n").as_bytes(), 0o600);
        run
    }

    fn path(path: &Path) -> &str {
        path.to_str().unwrap()
    }

    /// `command` (`sign` or `revoke`) on devnet with the message and out files and `extra`.
    fn arguments<'a>(&'a self, command: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
        let mut arguments = vec![
            command,
            "--network",
            "devnet",
            "--message-file",
            Run::path(&self.message),
            "--out",
            Run::path(&self.out),
        ];
        arguments.extend_from_slice(extra);
        arguments
    }

    fn sign(&self, extra: &[&str], stdin: &[u8]) -> Output {
        exec(&self.arguments("sign", extra), stdin)
    }

    fn with_phrase_file(&self) -> Output {
        self.sign(&["--phrase-file", Run::path(&self.phrase), "--yes"], b"")
    }

    fn record(&self) -> String {
        fs::read_to_string(&self.out).unwrap()
    }
}

fn assert_refused(output: &Output, status: i32, needle: &str) {
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(status), "stderr: {stderr}");
    assert!(stderr.contains(needle), "{needle:?} not in: {stderr}");
    assert!(output.stdout.is_empty(), "stdout: {}", text(&output.stdout));
}

/// Every form of the secrets that could leak: each phrase, each pair of neighbouring words and
/// each word on its own (as a whole word), and the passphrase and its words.
fn assert_no_secret(label: &str, haystack: &str) {
    let mut needles: Vec<String> = Vec::new();
    for words in [
        phrase().phrase().to_owned(),
        Mnemonic::from_entropy(&[0x3c; 32])
            .unwrap()
            .phrase()
            .to_owned(),
    ] {
        let words: Vec<&str> = words.split(' ').collect();
        needles.push(words.join(" "));
        needles.extend(words.windows(2).map(|pair| pair.join(" ")));
    }
    needles.push(PASSPHRASE.to_owned());
    for needle in &needles {
        assert!(
            !haystack.contains(needle.as_str()),
            "{label}: found {needle:?}"
        );
    }
    let secret_words: Vec<String> = [
        phrase().phrase().to_owned(),
        Mnemonic::from_entropy(&[0x3c; 32])
            .unwrap()
            .phrase()
            .to_owned(),
        PASSPHRASE.to_owned(),
    ]
    .iter()
    .flat_map(|text| text.split(' ').map(str::to_lowercase).collect::<Vec<_>>())
    .collect();
    for word in haystack
        .split(|character: char| !character.is_ascii_alphanumeric())
        .map(str::to_lowercase)
    {
        assert!(
            word.len() < 4 || !secret_words.contains(&word),
            "{label}: found the secret word {word:?}"
        );
    }
}

fn all_output(output: &Output, out: &Path) -> String {
    format!(
        "{}\n{}\n{}",
        text(&output.stdout),
        text(&output.stderr),
        fs::read_to_string(out).unwrap_or_default()
    )
}

#[test]
fn sign_then_verify() {
    let signer = account(0);
    let message = link_message(&signer, now_s() - 5);
    let run = Run::new("sign_then_verify", &message);
    let output = run.with_phrase_file();
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));

    let record = LinkRecord::from_json(&run.record()).unwrap();
    let fields =
        link::verify(&devnet(), &record, &LinkExpected::default(), now_s() * 1000).unwrap();
    assert_eq!(fields.kind, LinkKind::Link);
    assert_eq!(fields.github_id, GITHUB_ID);
    assert_eq!(fields.account, signer.address().to_string());

    let verified = exec(&["verify", Run::path(&run.out)], b"");
    assert_eq!(
        verified.status.code(),
        Some(0),
        "{}",
        text(&verified.stderr)
    );
    let stdout = text(&verified.stdout);
    assert!(stdout.starts_with("valid: a signed account link on heartwood-devnet-v90\n"));
    assert!(stdout.contains(&format!("GitHub user id: {GITHUB_ID}\n")));
    assert!(stdout.contains(&format!("Account: {}\n", signer.address())));
    // The record is exactly the signer's: no note about its bytes.
    assert!(!text(&verified.stderr).contains("not byte for byte"));
}

#[test]
fn the_record_is_byte_identical_to_the_sdk_s() {
    let signer = account(0);
    let message = link_message(&signer, now_s() - 5);
    let run = Run::new("the_record_is_byte_identical", &message);
    let output = run.with_phrase_file();
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));

    let written = fs::read(&run.out).unwrap();
    let record = LinkRecord::from_json(std::str::from_utf8(&written).unwrap()).unwrap();
    // The SDK's record of the same message, key and signature, as the SDK writes it.
    let expected = LinkRecord {
        message: message.clone(),
        public_key: signer.public_key().to_hex(),
        signature: record.signature.clone(),
        algorithm: ALGORITHM.to_owned(),
        network: devnet().message_network().unwrap(),
    };
    assert_eq!(written, expected.to_json().into_bytes());
    assert!(!written.ends_with(b"\n"));
    assert_eq!(record.message, message, "the message is signed unchanged");
    // The comment to post: the command line, then the record exactly as written.
    let stdout = text(&output.stdout);
    assert_eq!(stdout, format!("/bounty link\n{}\n", expected.to_json()));
}

#[test]
fn revoke_then_verify() {
    let signer = account(0);
    let link_time = now_s() - 3600;
    let message = revocation_message(&signer, now_s() - 5, link_time);
    let run = Run::new("revoke_then_verify", &message);
    let output = exec(
        &run.arguments(
            "revoke",
            &["--phrase-file", Run::path(&run.phrase), "--yes"],
        ),
        b"",
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(text(&output.stdout).starts_with("/bounty unlink\n{\"message\":"));

    let verified = exec(&["verify", Run::path(&run.out)], b"");
    assert_eq!(
        verified.status.code(),
        Some(0),
        "{}",
        text(&verified.stderr)
    );
    let stdout = text(&verified.stdout);
    assert!(stdout.starts_with("valid: a signed account link revocation on "));
    assert!(stdout.contains("Ends link issued at: "));
}

#[test]
fn each_command_signs_only_its_own_kind() {
    let signer = account(0);
    let revocation = revocation_message(&signer, now_s() - 5, now_s() - 3600);
    let run = Run::new("each_command_signs_only_its_own_kind", &revocation);
    let output = run.with_phrase_file();
    assert_refused(&output, 1, "sign it with `iceroot-link revoke`");
    assert!(!run.out.exists());

    fs::write(&run.message, link_message(&signer, now_s() - 5)).unwrap();
    let output = exec(
        &run.arguments(
            "revoke",
            &["--phrase-file", Run::path(&run.phrase), "--yes"],
        ),
        b"",
    );
    assert_refused(&output, 1, "sign it with `iceroot-link sign`");
    assert!(!run.out.exists());
}

#[test]
fn a_secret_file_others_can_read_is_refused() {
    let signer = account(0);
    let run = Run::new(
        "a_secret_file_others_can_read",
        &link_message(&signer, now_s() - 5),
    );
    for mode in [0o644, 0o640, 0o604, 0o620, 0o602, 0o660, 0o666] {
        for (option, path) in [
            ("--phrase-file", &run.phrase),
            ("--passphrase-file", &run.passphrase),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
            let output = run.sign(&[option, Run::path(path), "--yes"], b"");
            assert_refused(&output, 1, "make it private with chmod 600");
            assert!(!run.out.exists(), "mode {mode:o}");
            assert_no_secret("refusal", &all_output(&output, &run.out));
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    // Readable by its own user alone: 0400 and 0600 are accepted.
    fs::set_permissions(&run.phrase, fs::Permissions::from_mode(0o400)).unwrap();
    let output = run.with_phrase_file();
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
}

#[test]
fn a_directory_or_a_missing_file_is_refused_without_its_path() {
    let signer = account(0);
    let run = Run::new(
        "a_directory_or_a_missing_file",
        &link_message(&signer, now_s() - 5),
    );
    let missing = run.dir.join("missing-secret-file");
    let output = run.sign(&["--phrase-file", Run::path(&missing), "--yes"], b"");
    assert_refused(&output, 1, "the --phrase-file file cannot be opened");
    assert!(!text(&output.stderr).contains("missing-secret-file"));
    let output = run.sign(&["--phrase-file", Run::path(&run.dir), "--yes"], b"");
    assert_eq!(output.status.code(), Some(1));
    assert!(!run.out.exists());
}

#[test]
fn a_phrase_given_as_an_argument_is_refused() {
    let signer = account(0);
    let run = Run::new(
        "a_phrase_given_as_an_argument",
        &link_message(&signer, now_s() - 5),
    );
    let words = phrase().phrase().to_owned();
    let inline = format!("--phrase={words}");
    let cases: Vec<Vec<&str>> = vec![
        vec!["--phrase", &words, "--yes"],
        vec![&inline, "--yes"],
        vec![&words, "--yes"],
        vec!["--mnemonic", &words, "--yes"],
        vec!["--passphrase", PASSPHRASE, "--yes"],
        vec!["--phrase-file", Run::path(&run.phrase), &words, "--yes"],
    ];
    for extra in cases {
        let output = run.sign(&extra, b"");
        assert_refused(&output, 2, "a secret is never read from an argument");
        assert!(!run.out.exists());
        assert_no_secret("argument", &all_output(&output, &run.out));
    }
    // Nor from the environment: with the phrase in the environment and no source, nothing is
    // signed.
    let output = run_command(
        Command::new(BIN)
            .args(run.arguments("sign", &["--yes"]))
            .env("ICEROOT_PHRASE", &words)
            .env("ICEROOT_PASSPHRASE", PASSPHRASE)
            .env("PHRASE", &words),
        b"",
    );
    assert_refused(&output, 2, "no secret source");
    assert!(!run.out.exists());
}

#[test]
fn phrase_stdin_reads_a_pipe() {
    let signer = account(2);
    let run = Run::new(
        "phrase_stdin_reads_a_pipe",
        &link_message(&signer, now_s() - 5),
    );
    let piped = format!("{}\n", phrase().phrase());
    let output = run.sign(
        &["--phrase-stdin", "--index", "2", "--yes"],
        piped.as_bytes(),
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let record = LinkRecord::from_json(&run.record()).unwrap();
    assert_eq!(record.public_key, signer.public_key().to_hex());
    assert_no_secret("stdin", &all_output(&output, &run.out));
}

/// A terminal on standard input is refused before anything is read: the phrase would be echoed.
/// `script` gives the program a terminal of its own.
#[cfg(target_os = "linux")]
#[test]
fn phrase_stdin_refuses_a_terminal() {
    let signer = account(0);
    let run = Run::new(
        "phrase_stdin_refuses_a_terminal",
        &link_message(&signer, now_s() - 5),
    );
    let quoted: Vec<String> = std::iter::once(BIN)
        .chain(run.arguments("sign", &["--phrase-stdin", "--yes"]))
        .map(|argument| format!("'{argument}'"))
        .collect();
    let output = Command::new("script")
        .args(["-q", "-e", "-c", &quoted.join(" "), "/dev/null"])
        .stdin(Stdio::null())
        .output()
        .expect("script, from util-linux, runs the program on a terminal");
    let shown = format!("{}{}", text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(1), "{shown}");
    assert!(shown.contains("never a terminal"), "{shown}");
    assert!(!run.out.exists());

    // The same command line with a pipe signs, so the refusal above is the terminal's.
    let piped = format!("{}\n", phrase().phrase());
    let output = run.sign(&["--phrase-stdin", "--yes"], piped.as_bytes());
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
}

#[test]
fn passphrase_file_signs_with_the_legacy_key() {
    let signer = Account::from_legacy_passphrase(&devnet(), PASSPHRASE).unwrap();
    let run = Run::new("passphrase_file", &link_message(&signer, now_s() - 5));
    let output = run.sign(
        &["--passphrase-file", Run::path(&run.passphrase), "--yes"],
        b"",
    );
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let record = LinkRecord::from_json(&run.record()).unwrap();
    assert_eq!(record.public_key, signer.public_key().to_hex());
    assert_no_secret("passphrase", &all_output(&output, &run.out));
}

#[test]
fn passphrase_file_only_on_profiles_in_today_s_formats() {
    let signer = account(0);
    let run = Run::new("passphrase_file_only", &link_message(&signer, now_s() - 5));
    for network in ["devnet-pq", "id-devnet"] {
        let mut arguments = run.arguments("sign", &[]);
        arguments[2] = network;
        arguments.extend(["--passphrase-file", Run::path(&run.passphrase), "--yes"]);
        let output = exec(&arguments, b"");
        assert_refused(
            &output,
            1,
            "--passphrase-file is only for profiles in today's formats",
        );
        assert!(!run.out.exists());
    }
}

#[test]
fn a_message_that_is_not_a_link_is_refused() {
    let signer = account(0);
    let link = link_message(&signer, now_s() - 5);
    let other_network = Profile::devnet(DevnetOptions::default()).with_network_byte(30);
    let other_account =
        Account::from_phrase(&other_network, &phrase(), &AccountOptions::default()).unwrap();
    let other_network_link = link::build(
        &other_network,
        &LinkRequest {
            github_id: GITHUB_ID,
            public_key: other_account.public_key(),
            issued_at: now_s() - 5,
        },
    )
    .unwrap();
    let cases: Vec<(String, &str)> = vec![
        (
            "Sign in to the portal\nnonce: 1".to_owned(),
            "(reason: format)",
        ),
        (String::new(), "(reason: format)"),
        ("hello".to_owned(), "(reason: format)"),
        (
            format!("{link}\n"),
            "save the message without a final line break",
        ),
        (link.replace('\n', "\r\n"), "(reason: format)"),
        (link.replace("Version: 1", "Version: 2"), "(reason: format)"),
        (
            link.replace(&GITHUB_ID.to_string(), "09999999001"),
            "(reason: github-id)",
        ),
        (link_message(&signer, now_s() + 600), "(reason: future)"),
        (other_network_link, "(reason: network)"),
        (format!("{link}{}", " ".repeat(5000)), "(reason: format)"),
    ];
    let run = Run::new("a_message_that_is_not_a_link", "");
    // The secret file is one the program would refuse: the message is checked first, so the
    // refusal is the message's.
    fs::set_permissions(&run.phrase, fs::Permissions::from_mode(0o644)).unwrap();
    for (message, reason) in cases {
        fs::write(&run.message, &message).unwrap();
        let output = run.with_phrase_file();
        assert_refused(&output, 1, reason);
        assert!(text(&output.stderr).contains("is not a valid account link message"));
        assert!(!run.out.exists());
    }
    fs::write(&run.message, [0xff, 0xfe]).unwrap();
    assert_refused(&run.with_phrase_file(), 1, "not UTF-8");
}

#[test]
fn a_message_for_another_account_is_not_signed() {
    let run = Run::new("another_account", &link_message(&account(1), now_s() - 5));
    let output = run.with_phrase_file();
    assert_refused(
        &output,
        1,
        "the message names another account than this secret's key",
    );
    assert!(text(&output.stderr).contains(&account(0).address().to_string()));
    assert!(!run.out.exists());
    assert_no_secret("mismatch", &all_output(&output, &run.out));
}

#[test]
fn the_whole_message_is_shown_and_confirmed() {
    let signer = account(0);
    let message = link_message(&signer, now_s() - 5);
    let run = Run::new("the_whole_message_is_shown", &message);
    let source = ["--phrase-file", Run::path(&run.phrase)];

    for answer in ["no\n", "\n", "", "yes please\n", "sign\n"] {
        let output = run.sign(&source, answer.as_bytes());
        assert_refused(&output, 1, "not confirmed: nothing was signed");
        assert!(text(&output.stderr).contains(&format!("\n{message}\n")));
        assert!(!run.out.exists(), "{answer:?}");
    }

    let output = run.sign(&source, b"yes\n");
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    // The message in full, on its own lines, before the question.
    let shown = stderr
        .find(&format!("\n{message}\n"))
        .expect("the whole message");
    let asked = stderr.find("Type yes to sign").unwrap();
    assert!(shown < asked);
    assert!(run.out.exists());

    // --yes still shows the message, without asking.
    fs::remove_file(&run.out).unwrap();
    let output = run.sign(&[source[0], source[1], "--yes"], b"");
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains(&format!("\n{message}\n")));
    assert!(!stderr.contains("Type yes to sign"));
}

/// With the phrase on standard input, the answer comes from the terminal; a process without one
/// is refused unless --yes is given. `setsid` starts the program without a terminal.
#[cfg(target_os = "linux")]
#[test]
fn phrase_stdin_without_a_terminal_needs_yes() {
    let signer = account(0);
    let run = Run::new(
        "phrase_stdin_without_a_terminal",
        &link_message(&signer, now_s() - 5),
    );
    let piped = format!("{}\n", phrase().phrase());
    let output = run_command(
        Command::new("setsid")
            .arg("--wait")
            .arg(BIN)
            .args(run.arguments("sign", &["--phrase-stdin"])),
        piped.as_bytes(),
    );
    assert_refused(&output, 1, "there is no terminal to confirm on");
    assert!(!run.out.exists());
    assert_no_secret("no terminal", &all_output(&output, &run.out));
}

#[test]
fn an_existing_out_file_is_never_replaced() {
    let signer = account(0);
    let run = Run::new("an_existing_out_file", &link_message(&signer, now_s() - 5));
    fs::write(&run.out, "earlier record").unwrap();
    let output = run.with_phrase_file();
    assert_refused(&output, 1, "the --out file already exists");
    assert_eq!(run.record(), "earlier record");
}

#[test]
fn verify_refuses_a_tampered_record() {
    let signer = account(0);
    let issued = now_s() - 5;
    let run = Run::new(
        "verify_refuses_a_tampered_record",
        &link_message(&signer, issued),
    );
    assert_eq!(run.with_phrase_file().status.code(), Some(0));
    let json = run.record();
    let record = LinkRecord::from_json(&json).unwrap();

    let flipped = {
        let mut signature = record.signature.clone().into_bytes();
        signature[10] = if signature[10] == b'0' { b'1' } else { b'0' };
        String::from_utf8(signature).unwrap()
    };
    let other_key = account(1).public_key().to_hex();
    let with = |change: &dyn Fn(&mut LinkRecord)| {
        let mut changed = record.clone();
        change(&mut changed);
        changed.to_json()
    };
    let cases: Vec<(String, &str)> = vec![
        (
            with(&|r| r.message = r.message.replace("9999999001", "9999999002")),
            "(reason: signature)",
        ),
        (
            with(&|r| r.signature = flipped.clone()),
            "(reason: signature)",
        ),
        (
            with(&|r| r.signature = r.signature.to_uppercase()),
            "(reason: signature)",
        ),
        (
            with(&|r| r.public_key = other_key.clone()),
            "(reason: record)",
        ),
        (
            with(&|r| r.network = "heartwood-devnet-v30".to_owned()),
            "(reason: record)",
        ),
        (
            with(&|r| r.algorithm = "other".to_owned()),
            "(reason: record)",
        ),
        (json.replacen('{', "{\"extra\":\"x\",", 1), "(reason: json)"),
        (
            json.replacen(
                "{\"message\"",
                "{\"message\":\"IceRoot account link\",\"message\"",
                1,
            ),
            "(reason: json)",
        ),
        (format!("{json}x"), "(reason: json)"),
        ("[]".to_owned(), "(reason: json)"),
    ];
    let tampered = run.dir.join("tampered.json");
    for (text_of_record, reason) in cases {
        fs::write(&tampered, &text_of_record).unwrap();
        let output = exec(&["verify", Run::path(&tampered)], b"");
        assert_refused(&output, 1, reason);
    }

    // The verifier's time: a record issued later than 30 seconds after it is refused.
    let early = format_time(issued - 31);
    let output = exec(&["verify", Run::path(&run.out), "--now", &early], b"");
    assert_refused(&output, 1, "(reason: future)");
    let close = format_time(issued - 30);
    let output = exec(&["verify", Run::path(&run.out), "--now", &close], b"");
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let output = exec(&["verify", Run::path(&run.out), "--now", "yesterday"], b"");
    assert_refused(&output, 2, "--now takes a UTC time");
    // Another profile's network is refused.
    let output = exec(
        &["verify", Run::path(&run.out), "--network", "devnet-pq"],
        b"",
    );
    assert_eq!(output.status.code(), Some(1));

    // The original still verifies, and a copy with a final line break verifies with a note.
    let output = exec(&["verify", Run::path(&run.out)], b"");
    assert_eq!(output.status.code(), Some(0));
    fs::write(&tampered, format!("{json}\n")).unwrap();
    let output = exec(&["verify", Run::path(&tampered)], b"");
    assert_eq!(output.status.code(), Some(0));
    assert!(text(&output.stderr).contains("not byte for byte the record a signer writes"));
}

/// `YYYY-MM-DDTHH:MM:SSZ` of `seconds`, read back from the link format the SDK writes.
fn format_time(seconds: i64) -> String {
    let message = link_message(&account(0), seconds);
    let line = message
        .lines()
        .find_map(|line| line.strip_prefix("Issued at: "))
        .unwrap();
    line.to_owned()
}

#[test]
fn no_secret_in_any_output() {
    let signer = account(0);
    let run = Run::new(
        "no_secret_in_any_output",
        &link_message(&signer, now_s() - 5),
    );
    let mut outputs: Vec<(String, String)> = Vec::new();

    let output = run.with_phrase_file();
    assert_eq!(output.status.code(), Some(0));
    outputs.push(("phrase file".into(), all_output(&output, &run.out)));
    let verified = exec(&["verify", Run::path(&run.out)], b"");
    outputs.push(("verify".into(), all_output(&verified, &run.out)));
    fs::remove_file(&run.out).unwrap();

    let piped = format!("{}\n", phrase().phrase());
    let output = run.sign(&["--phrase-stdin", "--yes"], piped.as_bytes());
    assert_eq!(output.status.code(), Some(0));
    outputs.push(("phrase stdin".into(), all_output(&output, &run.out)));
    fs::remove_file(&run.out).unwrap();

    // A phrase with a bad checksum, an unknown word and too few words: the refusals name
    // positions and counts, never words.
    let phrase_text = phrase().phrase().to_owned();
    let words: Vec<&str> = phrase_text.split(' ').collect();
    let mut swapped = words.clone();
    swapped.swap(0, 1);
    let mut unknown = words.clone();
    unknown[3] = "quokkazephyr";
    let bad = [
        swapped.join(" "),
        unknown.join(" "),
        words[..12].join(" "),
        Mnemonic::from_entropy(&[0x3c; 32])
            .unwrap()
            .phrase()
            .replace(' ', "  "),
    ];
    // The last is a valid phrase of another account: refused as a mismatch, never signed.
    for bad_phrase in bad {
        write_mode(&run.phrase, bad_phrase.as_bytes(), 0o600);
        let output = run.with_phrase_file();
        assert_eq!(output.status.code(), Some(1));
        assert!(!run.out.exists());
        outputs.push(("bad phrase".into(), all_output(&output, &run.out)));
        let output = run.sign(&["--phrase-stdin", "--yes"], bad_phrase.as_bytes());
        assert_eq!(output.status.code(), Some(1));
        assert!(!run.out.exists());
        outputs.push(("bad phrase stdin".into(), all_output(&output, &run.out)));
    }

    for (label, haystack) in &outputs {
        assert_no_secret(label, haystack);
    }
}

#[test]
fn the_command_line_is_checked() {
    let output = exec(&["sign", "--network", "mainnet-of-nowhere"], b"");
    assert_eq!(output.status.code(), Some(2));
    let signer = account(0);
    let run = Run::new(
        "the_command_line_is_checked",
        &link_message(&signer, now_s() - 5),
    );
    let mut arguments = run.arguments("sign", &["--phrase-file", Run::path(&run.phrase), "--yes"]);
    arguments[2] = "mainnet-of-nowhere";
    let output = exec(&arguments, b"");
    assert_refused(&output, 2, "--network names no profile of this SDK");
    assert!(!text(&output.stderr).contains("mainnet-of-nowhere"));
    let help = exec(&["help"], b"");
    assert_eq!(help.status.code(), Some(0));
    assert!(text(&help.stdout).contains("--phrase-stdin"));
    assert_eq!(exec(&[], b"").status.code(), Some(0));
    assert_eq!(exec(&["unknown"], b"").status.code(), Some(2));
}

/// Signing goes through the SDK's checked path only: the program never calls plain message
/// signing or the SDK's lower-level signature functions.
#[test]
fn signing_is_only_through_link_sign() {
    let sources = [
        include_str!("../src/main.rs"),
        include_str!("../src/args.rs"),
        include_str!("../src/secret.rs"),
        include_str!("../src/clock.rs"),
    ];
    let calls: usize = sources
        .iter()
        .map(|source| source.matches("link::sign(").count())
        .sum();
    assert_eq!(calls, 1);
    for source in sources {
        for other in [
            "message::sign",
            "sign_with",
            "sign_bytes",
            "signature_of",
            "test_seam",
            "Aux::",
            "std::env::var",
            "env::var",
        ] {
            assert!(!source.contains(other), "{other}");
        }
    }
}
