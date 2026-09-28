//! Message signing: off-chain messages signed by an account, and their verification.
//!
//! In today's format a message signature is the reference implementation's: BIP340 Schnorr over
//! the SHA-256 of the message's exact UTF-8 bytes, algorithm `secp256k1-bip340-sha256`, signed in
//! `heartwood-crypto`'s off-chain message domain. The SDK always hashes first and signs the 32-byte
//! digest. (`heartwood-crypto` signs a 32-byte input as it is and hashes every other length, so
//! passing the message itself would silently differ from the reference for any message of exactly
//! 32 bytes.)
//!
//! Only text is signed here. In today's format the message domain changes no bytes, so a message
//! signature is exactly a transaction signature over the same bytes: a message made of a
//! transaction's unsigned bytes would sign that transaction. Every transaction of today's formats
//! starts with the header byte 0xff, which UTF-8 text never contains, so a message is signed and
//! verified only when it is UTF-8 text ([`sign_bytes`] refuses anything else with
//! [`Error::InvalidArgument`], and [`verify_bytes`] fails it), and no public function signs a
//! digest the caller chooses. The reference implementation signs only text, so nothing it signs is
//! lost. A wallet still shows the holder the text it signs; from the post-quantum formats on the
//! message domain carries its own tag, so that the separation holds whatever the bytes are.

use heartwood_crypto::crypto::hash::sha256;
use heartwood_crypto::crypto::sig::{self, SchemeId, Signature, SigningDomain};
use heartwood_crypto::errors::SigError;
use heartwood_crypto::identities::KeyPair;
use heartwood_crypto::utils::hex;
use heartwood_crypto::{Aux, PublicKey};

use crate::error::{Error, MismatchProblem};
use crate::keys::Account;
use crate::profile::{Capability, Profile};

/// The algorithm name of message signatures in today's format.
pub const ALGORITHM: &str = "secp256k1-bip340-sha256";

/// The signing domain of off-chain messages. In today's format the domain changes no bytes; from
/// the post-quantum formats on it carries the off-chain message tag, so that a message signature
/// can never pass as a transaction's.
const MESSAGE_DOMAIN: SigningDomain = SigningDomain::Message;

/// A signed message's signature, in the form wallets and websites exchange.
///
/// Only the signature covers the message; the other fields are labels. [`verify`] checks the
/// algorithm name and the signature under the public key, and the network is the caller's to
/// compare. Every devnet with the same network byte has the same network name, so a protocol that
/// must bind a signature to one chain names the chain inside the signed text itself, as the
/// sign-in message does ([`crate::signin`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MessageSignature {
    /// The signer's public key, lowercase hex (33 bytes, compressed).
    pub public_key: String,
    /// The signature, lowercase hex (64 bytes).
    pub signature: String,
    /// The algorithm: [`ALGORITHM`].
    pub algorithm: String,
    /// The network the signer's account belongs to, for example `heartwood-devnet-v90`.
    pub network: String,
}

/// Sign `message` with `account` on the network of `profile`, with fresh randomness.
pub fn sign(
    profile: &Profile,
    account: &Account,
    message: &str,
) -> Result<MessageSignature, Error> {
    sign_with(profile, account, message, Aux::random())
}

/// [`sign`] with the auxiliary randomness `aux`. Outside tests only [`Aux::random`] exists.
pub fn sign_with(
    profile: &Profile,
    account: &Account,
    message: &str,
    aux: Aux,
) -> Result<MessageSignature, Error> {
    sign_bytes_with(profile, account, message.as_bytes(), aux)
}

/// [`sign`] for a message given as bytes: the signature covers the SHA-256 of exactly these
/// bytes. The bytes must be UTF-8 text, which a text message is signed as, so for text both
/// functions agree.
///
/// # Errors
///
/// [`Error::InvalidArgument`] when the bytes are not UTF-8 text: such bytes may be a transaction's
/// (see the module documentation). [`Error::UnsupportedOnNetwork`] without message signing, and
/// [`Error::NetworkMismatch`] for an account of another profile.
pub fn sign_bytes(
    profile: &Profile,
    account: &Account,
    message: &[u8],
) -> Result<MessageSignature, Error> {
    sign_bytes_with(profile, account, message, Aux::random())
}

/// [`sign_bytes`] with the auxiliary randomness `aux`. Outside tests only [`Aux::random`] exists.
pub fn sign_bytes_with(
    profile: &Profile,
    account: &Account,
    message: &[u8],
    aux: Aux,
) -> Result<MessageSignature, Error> {
    profile.require(Capability::MessageSigning)?;
    if account.profile() != profile.id() {
        return Err(Error::NetworkMismatch {
            problem: MismatchProblem::Profile {
                expected: profile.id().to_owned(),
                actual: account.profile().to_owned(),
            },
        });
    }
    if !is_text(message) {
        return Err(Error::InvalidArgument { reason: NOT_TEXT });
    }
    let signature = sign_digest(account, &sha256(message), aux)?;
    Ok(MessageSignature {
        public_key: account.public_key().to_hex(),
        signature: signature.to_hex(),
        algorithm: ALGORITHM.to_owned(),
        network: profile.message_network()?,
    })
}

/// Why a message given as bytes is refused.
const NOT_TEXT: &str = "a message is signed only as UTF-8 text";

/// Whether a message's bytes are UTF-8 text. A transaction's bytes never are: they start with the
/// header byte 0xff.
fn is_text(message: &[u8]) -> bool {
    std::str::from_utf8(message).is_ok()
}

/// The BIP340 signature of the 32-byte `digest` by `account`, signed as it is, in the message
/// domain.
///
/// Crate-private: a digest the caller chooses could be a transaction's signing digest, so the
/// public functions sign only the SHA-256 of a message. The test builds reach it through
/// `test_seam::sign_digest`.
pub(crate) fn sign_digest(
    account: &Account,
    digest: &[u8; 32],
    aux: Aux,
) -> Result<Signature, Error> {
    sign_digest_with_keys(account.keys(), digest, aux)
}

/// [`sign_digest`] with a key pair that belongs to no account: the Solar key of an ownership
/// proof ([`crate::ownership`]).
pub(crate) fn sign_digest_with_keys(
    keys: &KeyPair,
    digest: &[u8; 32],
    aux: Aux,
) -> Result<Signature, Error> {
    sig::sign(
        SchemeId::Secp256k1Bip340,
        MESSAGE_DOMAIN,
        digest,
        keys.secret_key(),
        aux,
    )
    .map_err(|error| match error {
        SigError::Randomness => Error::RandomnessUnavailable,
        other => Error::SigningFailed {
            reason: other.to_string(),
        },
    })
}

/// Test seam of the feature `fixed-aux`, which only test builds enable: signing a chosen digest,
/// for the vector runners that compare the reference's raw BIP340 signatures.
#[cfg(feature = "fixed-aux")]
#[doc(hidden)]
pub mod test_seam {
    use heartwood_crypto::Aux;
    use heartwood_crypto::crypto::sig::Signature;

    use crate::error::Error;
    use crate::keys::Account;

    /// The BIP340 signature of the 32-byte `digest` by `account`, signed as it is.
    pub fn sign_digest(account: &Account, digest: &[u8; 32], aux: Aux) -> Result<Signature, Error> {
        super::sign_digest(account, digest, aux)
    }
}

/// Whether `signature` signs `message`: the algorithm is [`ALGORITHM`], and the signature
/// verifies for the SHA-256 of the message under the public key. Malformed hex is a failed check,
/// never an error. The network is the caller's to compare.
pub fn verify(message: &str, signature: &MessageSignature) -> bool {
    verify_bytes(message.as_bytes(), signature)
}

/// [`verify`] for a message given as bytes. Bytes that are not UTF-8 text fail the check, since
/// they may be a transaction's, whose signature is not a message signature.
pub fn verify_bytes(message: &[u8], signature: &MessageSignature) -> bool {
    if signature.algorithm != ALGORITHM || !is_text(message) {
        return false;
    }
    let Ok(public_key) = hex::decode(&signature.public_key) else {
        return false;
    };
    let Ok(signature) = Signature::from_hex(&signature.signature) else {
        return false;
    };
    verify_digest(&sha256(message), &signature, &public_key)
}

/// Whether `signature` is a BIP340 signature of the 32-byte `digest` for `public_key`, read as
/// the reference implementation reads it: a 33-byte key by its x coordinate, a 32-byte key as an
/// x-only key; any other key fails.
pub fn verify_digest(digest: &[u8; 32], signature: &Signature, public_key: &[u8]) -> bool {
    sig::verify(
        SchemeId::Secp256k1Bip340,
        MESSAGE_DOMAIN,
        digest,
        signature,
        public_key,
    )
}

/// The public key in `hex`, if it is a valid compressed key (`02` or `03` and 32 bytes).
pub(crate) fn compressed_key(text: &str) -> Option<PublicKey> {
    let valid_form = text.len() == 66
        && (text.starts_with("02") || text.starts_with("03"))
        && crate::utils::is_lower_hex(text);
    if !valid_form {
        return None;
    }
    PublicKey::from_hex(text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::DevnetOptions;

    /// Messages signed by the reference implementation with the passphrase key of
    /// `heartwood message domain`: its `Message.sign` (random aux) and the BIP340 signature of the
    /// same digest with the aux 0x42 × 32. The last message is 32 bytes long.
    const MESSAGES: [(&str, &str, &str); 4] = [
        (
            "Hello from Heartwood",
            "1fc4f1dd9e261d77db661915ac1762f856176d8831425a4c46777fdab6401b75657609d68aaa755e5237dcdbbf0eac543621657def7dca07886b1767f97667f9",
            "f25d1a5b3165bab0a01deb04d3c6357fd73e9b78c988ccf0988b11f0375b34cddd672a1538a702c5b4c7715a1d4a45df3d46f61855dfe6008f21b796360dd049",
        ),
        (
            "",
            "9691bc0ea053f90039012f895927575e9a7f5bd5c9de882bea86e0b1374bcf045de7fa64358ae63846856d2772c8a201c144ad46cf010a7b754bf9d04ef68aea",
            "c6f8b7c03c0851e0cf5e6be6e41b153e5d5dd621b7f8247b6da96a2ffa969203a310d75fb03be4c83b64e371539dce5ff3d4954cdbd50828420892c7421f0a57",
        ),
        (
            "ünïcödé ✓",
            "8aab6bef4f2087b0f49fc8dc77cc99db2597f278bf2d5b5c5c5292a3061a88da6dce61785fe053be0c4870483c51f34993314ee6a6689060b2edad2d09272d12",
            "1f8f9bd7be2457203fc7891a20713843e1addb208808b7b4ac38ebdc06cefb93968edbd89c694d49cca106011f7c1df97b0a55834cedac144cc2ae1c634b1586",
        ),
        (
            "0123456789abcdef0123456789abcdef",
            "3045020e6280cf11ceaa87f2b5827011ffb4a4099b8a0b6eeef969298f9d3ce61d9e5b9461c5357a961286863a8538716b62a0fab7094d06aba0e431105ccb55",
            "04a94fa3b288597586c13ef926fe9bee1772da865259b4e5353a935bce8c7c998934e7d0a0dc163ae5d58730a21ab69ee902eb63e9177c68bf01ed5f9c568d0d",
        ),
    ];

    #[test]
    fn reference_signatures() {
        let profile = Profile::devnet(DevnetOptions::default());
        let account =
            Account::from_legacy_passphrase(&profile, "heartwood message domain").unwrap();
        assert_eq!(
            account.public_key().to_hex(),
            "02cf05d38330aeddf8f5a668111881167458f86e325077c4911b0037cacc58c1a0"
        );
        for (message, signed, fixed) in MESSAGES {
            let ours = sign_with(&profile, &account, message, Aux::fixed([0x42; 32])).unwrap();
            assert_eq!(ours.signature, fixed, "{message:?}");
            assert_eq!(ours.algorithm, ALGORITHM);
            assert_eq!(ours.network, "heartwood-devnet-v90");
            assert!(verify(message, &ours));
            let reference = MessageSignature {
                signature: signed.to_owned(),
                ..ours.clone()
            };
            assert!(verify(message, &reference), "{message:?}");
            assert!(!verify(&format!("{message}."), &reference));
            let other_algorithm = MessageSignature {
                algorithm: "ml-dsa-65".to_owned(),
                ..ours
            };
            assert!(!verify(message, &other_algorithm));
        }
        let random = sign(&profile, &account, "fresh").unwrap();
        assert!(verify("fresh", &random));
        let bytes = sign_bytes(&profile, &account, b"bytes of text").unwrap();
        assert!(verify_bytes(b"bytes of text", &bytes));
        assert!(!verify_bytes(b"bytes of tex", &bytes));
        // Bytes that are not UTF-8 text are refused, and never verify: a transaction starts with
        // the header byte 0xff.
        assert_eq!(
            sign_bytes(&profile, &account, &[0xff, 0x00]).unwrap_err(),
            Error::InvalidArgument { reason: NOT_TEXT }
        );
        let over_digest = MessageSignature {
            signature: sign_digest(&account, &sha256(&[0xff, 0x00]), Aux::fixed([0x42; 32]))
                .unwrap()
                .to_hex(),
            ..bytes
        };
        assert!(!verify_bytes(&[0xff, 0x00], &over_digest));
    }

    #[test]
    fn malformed_input_fails_the_check() {
        let signature = MessageSignature {
            public_key: "zz".to_owned(),
            signature: "00".to_owned(),
            algorithm: ALGORITHM.to_owned(),
            network: "heartwood-devnet-v90".to_owned(),
        };
        assert!(!verify("x", &signature));
        assert!(
            compressed_key("02cf05d38330aeddf8f5a668111881167458f86e325077c4911b0037cacc58c1a0")
                .is_some()
        );
        assert!(
            compressed_key("04cf05d38330aeddf8f5a668111881167458f86e325077c4911b0037cacc58c1a0")
                .is_none()
        );
        assert!(
            compressed_key("02CF05D38330AEDDF8F5A668111881167458F86E325077C4911B0037CACC58C1A0")
                .is_none()
        );
    }
}
