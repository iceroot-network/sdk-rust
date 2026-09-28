//! The public API beyond the vectors: randomness, password changes, re-encryption, bounds chosen
//! by the caller, errors, and a change to every bit of a keystore. Runs natively and in
//! WebAssembly (see `tests/vectors.rs`).

// Tests may panic: that is how they fail.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use iceroot_keystore::{
    ARMOR_PREFIX, Bounds, Error, HEADER_LEN, Header, Malformed, Param, Params, Payload,
    PayloadKind, Preset, SALT_LEN, TAG_LEN, armor, change_password, change_password_with_bounds,
    dearmor, decrypt, decrypt_with_bounds, encrypt, encrypt_with_salt_and_nonce, inspect,
    reencrypt, reencrypt_with_bounds,
};

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

/// The lowest parameters the format accepts: every keystore here that `decrypt` must open uses
/// them, to keep the tests quick.
const FLOOR: Params = Params::new(19 * 1024, 2, 1);
/// Parameters far below the floor, under `Bounds::TEST`.
const TINY: Params = Params::new(8, 1, 1);

fn entropy() -> Payload {
    Payload::bip39_entropy(&[0x42; 32]).unwrap()
}

/// Neither the salt nor the nonce of `after` is the one of `before`.
fn fresh(before: &[u8], after: &[u8]) {
    let (before, after): (Header, Header) = (inspect(before).unwrap(), inspect(after).unwrap());
    assert_ne!(before.salt(), after.salt());
    assert_ne!(before.nonce(), after.nonce());
}

#[test]
fn encrypt_and_decrypt_with_the_system_generator() {
    let keystore = encrypt(&entropy(), "hunter2 hunter2", FLOOR).unwrap();
    assert_eq!(keystore.len(), HEADER_LEN + 32 + TAG_LEN);
    assert_eq!(decrypt(&keystore, "hunter2 hunter2").unwrap(), entropy());
    assert_eq!(
        decrypt(&keystore, "hunter3 hunter3").unwrap_err(),
        Error::WrongPasswordOrCorrupt
    );
    // Two encryptions of the same payload share no salt or nonce, and the two are not equal.
    let again = encrypt(&entropy(), "hunter2 hunter2", FLOOR).unwrap();
    fresh(&keystore, &again);
    let header = inspect(&keystore).unwrap();
    assert_ne!(header.salt(), &[0; SALT_LEN]);
    assert_ne!(header.salt().as_slice(), &header.nonce()[..SALT_LEN]);
}

#[test]
fn the_explicit_salt_and_nonce_are_the_headers() {
    let salt: [u8; 16] = std::array::from_fn(|i| i as u8 + 1);
    let nonce: [u8; 24] = std::array::from_fn(|i| i as u8 + 17);
    let keystore = encrypt_with_salt_and_nonce(
        &entropy(),
        "password",
        FLOOR,
        &salt,
        &nonce,
        &Bounds::STANDARD,
    )
    .unwrap();
    let header = inspect(&keystore).unwrap();
    assert_eq!(header.salt(), &salt);
    assert_eq!(header.nonce(), &nonce);
    assert_eq!(decrypt(&keystore, "password").unwrap(), entropy());
}

#[test]
fn encrypt_takes_a_preset_or_explicit_parameters() {
    // Presets are checked like explicit parameters; this one is refused under a tight ceiling.
    let tight = Bounds::STANDARD.with_memory_ceiling_kib(64 * 1024);
    assert!(tight.check(&Preset::Web.into()).is_ok());
    assert_eq!(
        tight.check(&Preset::Desktop.into()).unwrap_err().code(),
        "ParamsOutOfRange"
    );
    let below = encrypt(&entropy(), "password", Params::new(19 * 1024 - 1, 2, 1));
    assert_eq!(
        below.unwrap_err(),
        Error::ParamsOutOfRange {
            param: Param::Memory,
            value: 19 * 1024 - 1,
            minimum: 19 * 1024,
            maximum: 512 * 1024,
        }
    );
}

#[test]
fn change_password_and_reencrypt() {
    let keystore = encrypt(&entropy(), "old password", FLOOR).unwrap();
    let changed = change_password(&keystore, "old password", "new password", FLOOR).unwrap();
    fresh(&keystore, &changed);
    assert_eq!(decrypt(&changed, "new password").unwrap(), entropy());
    assert_eq!(
        decrypt(&changed, "old password").unwrap_err(),
        Error::WrongPasswordOrCorrupt
    );
    assert_eq!(
        change_password(&keystore, "wrong", "new password", FLOOR).unwrap_err(),
        Error::WrongPasswordOrCorrupt
    );
    // The new password and parameters are refused before the old password is tried.
    assert_eq!(
        change_password(&keystore, "wrong", "", FLOOR)
            .unwrap_err()
            .code(),
        "InvalidPassword"
    );
    assert_eq!(
        change_password(&keystore, "wrong", "new", Params::new(8, 1, 1))
            .unwrap_err()
            .code(),
        "ParamsOutOfRange"
    );

    let stronger = Params::new(20 * 1024, 3, 2);
    assert!(
        inspect(&keystore)
            .unwrap()
            .params()
            .is_weaker_than(&stronger)
    );
    let upgraded = reencrypt(&keystore, "old password", stronger).unwrap();
    let header = inspect(&upgraded).unwrap();
    assert_eq!(header.params(), stronger);
    assert!(!header.params().is_weaker_than(&stronger));
    fresh(&keystore, &upgraded);
    assert_eq!(decrypt(&upgraded, "old password").unwrap(), entropy());
    // Re-encrypting with the same parameters still draws a new salt and nonce.
    let again = reencrypt(&keystore, "old password", FLOOR).unwrap();
    fresh(&keystore, &again);
    assert_eq!(decrypt(&again, "old password").unwrap(), entropy());
}

#[test]
fn a_tighter_memory_ceiling_refuses_before_deriving() {
    let keystore = encrypt(&entropy(), "password", Params::new(24 * 1024, 2, 1)).unwrap();
    let tight = Bounds::STANDARD.with_memory_ceiling_kib(20 * 1024);
    assert_eq!(
        decrypt_with_bounds(&keystore, "password", &tight).unwrap_err(),
        Error::ParamsOutOfRange {
            param: Param::Memory,
            value: 24 * 1024,
            minimum: 19 * 1024,
            maximum: 20 * 1024,
        }
    );
}

#[test]
fn a_tighter_memory_ceiling_holds_for_a_password_change_and_a_reencryption() {
    let keystore = encrypt(&entropy(), "password", Params::new(24 * 1024, 2, 1)).unwrap();
    let tight = Bounds::STANDARD.with_memory_ceiling_kib(20 * 1024);
    let refused = Error::ParamsOutOfRange {
        param: Param::Memory,
        value: 24 * 1024,
        minimum: 19 * 1024,
        maximum: 20 * 1024,
    };
    // The old keystore asks for more memory than the platform can spare: refused before any
    // key derivation, whatever the password.
    assert_eq!(
        change_password_with_bounds(&keystore, "wrong", "new password", FLOOR, &tight).unwrap_err(),
        refused
    );
    assert_eq!(
        reencrypt_with_bounds(&keystore, "password", FLOOR, &tight).unwrap_err(),
        refused
    );
    // New parameters above the ceiling are refused too.
    let within = encrypt(&entropy(), "password", FLOOR).unwrap();
    assert_eq!(
        reencrypt_with_bounds(&within, "password", Params::new(24 * 1024, 2, 1), &tight)
            .unwrap_err(),
        refused
    );
    // Within the ceiling both work as without it.
    let changed =
        change_password_with_bounds(&within, "password", "new password", FLOOR, &tight).unwrap();
    assert_eq!(decrypt(&changed, "new password").unwrap(), entropy());
    let again = reencrypt_with_bounds(&within, "password", FLOOR, &tight).unwrap();
    fresh(&within, &again);
    assert_eq!(decrypt(&again, "password").unwrap(), entropy());
}

#[test]
fn every_bit_flip_is_refused() {
    let keystore = encrypt_with_salt_and_nonce(
        &entropy(),
        "password",
        TINY,
        &[1; SALT_LEN],
        &[2; 24],
        &Bounds::TEST,
    )
    .unwrap();
    // A memory ceiling of 1 MiB keeps every flipped memory size cheap to derive.
    let bounds = Bounds::TEST.with_memory_ceiling_kib(1024);
    assert_eq!(
        decrypt_with_bounds(&keystore, "password", &bounds).unwrap(),
        entropy()
    );
    for bit in 0..keystore.len() * 8 {
        let mut changed = keystore.clone();
        changed[bit / 8] ^= 1 << (bit % 8);
        let error = decrypt_with_bounds(&changed, "password", &bounds).unwrap_err();
        let byte = bit / 8;
        // Past the parameters, any change is found by the tag alone: one answer for all.
        if (18..58).contains(&byte) || byte >= HEADER_LEN {
            assert_eq!(error, Error::WrongPasswordOrCorrupt, "bit {bit}");
        }
    }
}

#[test]
fn errors_have_codes_and_details() {
    let error = Error::ParamsOutOfRange {
        param: Param::Work,
        value: 3,
        minimum: 1,
        maximum: 2,
    };
    assert_eq!(error.code(), "ParamsOutOfRange");
    assert_eq!(
        error.details(),
        serde_json::json!({ "param": "work", "value": 3, "minimum": 1, "maximum": 2 })
    );
    let error = Error::Malformed {
        problem: Malformed::ArmorEncoding,
    };
    assert_eq!(error.code(), "Malformed");
    assert_eq!(
        error.details(),
        serde_json::json!({ "reason": "armor-encoding" })
    );
    assert_eq!(
        Error::WrongPasswordOrCorrupt.to_string(),
        "wrong password, or the keystore was changed or damaged"
    );
    let error = Payload::bip39_entropy(&[0; 16]).unwrap_err();
    assert_eq!(
        error.to_string(),
        "bip39-entropy is 24, 28 or 32 bytes (18, 21 or 24 words); got 16 bytes"
    );
}

#[test]
fn the_reserved_kind_is_inspected_but_not_decrypted() {
    let mut keystore = encrypt(&entropy(), "password", FLOOR).unwrap();
    keystore[58] = PayloadKind::MlDsa65Seed.code();
    let header = inspect(&keystore).unwrap();
    assert_eq!(header.payload_kind(), PayloadKind::MlDsa65Seed);
    assert!(!header.payload_kind().is_supported());
    assert_eq!(
        decrypt(&keystore, "password").unwrap_err(),
        Error::UnsupportedPayload { kind: 2 }
    );
}

#[test]
fn text_form() {
    let keystore = encrypt(&entropy(), "password", FLOOR).unwrap();
    let text = armor(&keystore);
    assert!(text.starts_with(ARMOR_PREFIX));
    assert!(
        text[ARMOR_PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    );
    assert_eq!(dearmor(&text).unwrap(), keystore);
    assert_eq!(
        decrypt(&dearmor(&text).unwrap(), "password").unwrap(),
        entropy()
    );
}

#[test]
fn payload_debug_hides_the_secret() {
    let payload = Payload::bip39_entropy(&[0x99; 28]).unwrap();
    assert_eq!(
        format!("{payload:?}"),
        "Payload { kind: Bip39Entropy, len: 28, .. }"
    );
}
