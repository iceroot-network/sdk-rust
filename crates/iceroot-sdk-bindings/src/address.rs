//! Addresses, always checked against a network profile.

use iceroot_sdk::{Address, Profile, PublicKey};

use crate::error::{BindingError, Result};

/// The bytes of the address in `text`, which must belong to the network of `profile`: 21 bytes,
/// the network byte and the key hash, in today's format.
///
/// A refusal is `InvalidAddress` with the reason `format` (and the position of the first bad
/// character, when one is to blame), `checksum`, `length` or `wrong-network`.
pub fn parse_address(text: &str, profile: &Profile) -> Result<Vec<u8>> {
    Ok(Address::parse(text, profile)?.as_bytes().to_vec())
}

/// The address of `public_key` (33 or 65 bytes) on the network of `profile`.
pub fn address_from_public_key(public_key: &[u8], profile: &Profile) -> Result<String> {
    let key = PublicKey::from_bytes(public_key)
        .map_err(|_| BindingError::new("InvalidKey", "the bytes are not a secp256k1 public key"))?;
    Ok(Address::from_public_key(&key, profile)?.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The key and address of the passphrase "probe passphrase" on network byte 90.
    const PUBLIC_KEY: &str = "03f83f83227e28add5598d2c75c20f72b4bfb0328957ef27e2da2ff73779fa4bd2";
    const ADDRESS: &str = "dDSccdbPRhfrcbUeFLMbGC1rtnfCsjJcNF";

    fn profile(network_byte: u8) -> Profile {
        crate::profile::from_json(&format!(
            r#"{{"id":"devnet","backend":"solar-compat","api":{{"relays":[]}},"chain":{{"networkByte":{network_byte}}},"keyScheme":"bip32-secp256k1"}}"#
        ))
        .unwrap()
    }

    #[test]
    fn from_public_key() {
        let key = hex::decode(PUBLIC_KEY).unwrap();
        assert_eq!(
            address_from_public_key(&key, &profile(90)).unwrap(),
            ADDRESS
        );
        let error = address_from_public_key(&key[..32], &profile(90)).unwrap_err();
        assert_eq!(error.code(), "InvalidKey");
    }

    #[test]
    fn parse() {
        let bytes = parse_address(ADDRESS, &profile(90)).unwrap();
        assert_eq!(bytes.len(), 21);
        assert_eq!(bytes[0], 90);

        let wrong = parse_address(ADDRESS, &profile(30)).unwrap_err();
        assert_eq!(wrong.code(), "InvalidAddress");
        assert_eq!(wrong.details()["reason"], "wrong-network");

        let mut typo = ADDRESS.to_owned();
        typo.replace_range(5..6, "0");
        let format = parse_address(&typo, &profile(90)).unwrap_err();
        assert_eq!(format.details()["reason"], "format");
        assert_eq!(format.details()["position"], 5);

        let mut swapped = ADDRESS.to_owned();
        swapped.replace_range(33..34, "G");
        let checksum = parse_address(&swapped, &profile(90)).unwrap_err();
        assert_eq!(checksum.details()["reason"], "checksum");
        let empty = parse_address("", &profile(90)).unwrap_err();
        assert_eq!(empty.code(), "InvalidAddress");
    }
}
