//! Message signatures in today's format: BIP340 over the SHA-256 of the message's bytes.

use iceroot_sdk::PublicKey;
use iceroot_sdk::message::{self, MessageSignature};
use sha2::{Digest, Sha256};

/// The SHA-256 of `data` (32 bytes).
pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// Whether `signature` (hex) is a message signature of `message` by `public_key` (hex) with the
/// algorithm `algorithm`.
///
/// The public key must be a valid secp256k1 key (33 or 65 bytes) and the signature 64 bytes;
/// anything else fails the check and is never an error.
pub fn verify_message(message: &[u8], public_key: &str, signature: &str, algorithm: &str) -> bool {
    if PublicKey::from_hex(public_key).is_err() {
        return false;
    }
    message::verify_bytes(
        message,
        &MessageSignature {
            public_key: public_key.to_ascii_lowercase(),
            signature: signature.to_ascii_lowercase(),
            algorithm: algorithm.to_owned(),
            network: String::new(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "03f83f83227e28add5598d2c75c20f72b4bfb0328957ef27e2da2ff73779fa4bd2";
    const ALGORITHM: &str = "secp256k1-bip340-sha256";

    #[test]
    fn digest() {
        assert_eq!(
            hex::encode(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn malformed_inputs_fail_the_check() {
        let zeros = "00".repeat(64);
        assert!(!verify_message(b"m", KEY, &"00".repeat(63), ALGORITHM));
        assert!(!verify_message(b"m", KEY, &zeros, ALGORITHM));
        assert!(!verify_message(b"m", &KEY[..64], &zeros, ALGORITHM));
        assert!(!verify_message(
            b"m",
            &format!("05{}", &KEY[2..]),
            &zeros,
            ALGORITHM
        ));
        assert!(!verify_message(b"m", "", &zeros, ALGORITHM));
        assert!(!verify_message(b"m", KEY, "zz", ALGORITHM));
        assert!(!verify_message(b"m", KEY, &zeros, "ml-dsa-65"));
    }
}
