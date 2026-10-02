//! Addresses.
//!
//! In today's formats an address is a network byte and the RIPEMD-160 of the account's public key,
//! written in Base58Check: 34 characters starting with `d` on devnets. Parsing is always against a
//! profile, so an address of another network is refused with
//! [`AddressProblem::WrongNetwork`] rather than accepted and sent to the wrong chain.

use std::fmt;

use heartwood_crypto::errors::{AddressError, Base58Error};
use heartwood_crypto::identities::{self, PublicKey};

use crate::error::{AddressProblem, Error};
use crate::profile::Profile;

/// An address in today's format: a network byte and a 20-byte key hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address(identities::Address);

/// The result of [`Address::check`], for feedback while an address is typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressCheck {
    /// The problem, or `None` for a valid address of the profile's network.
    pub problem: Option<AddressProblem>,
}

impl AddressCheck {
    /// Whether the address is valid on the profile's network.
    pub fn is_ok(&self) -> bool {
        self.problem.is_none()
    }

    /// The 0-based index of the character to blame, when one is.
    pub fn position(&self) -> Option<usize> {
        match self.problem {
            Some(AddressProblem::Format { position }) => position,
            _ => None,
        }
    }
}

impl Address {
    /// The address in `text`, which must belong to the network of `profile`.
    pub fn parse(text: &str, profile: &Profile) -> Result<Address, Error> {
        Address::parse_for_network_byte(text, profile.network_byte()?)
    }

    /// What is wrong with `text` as an address of the network of `profile`.
    pub fn check(text: &str, profile: &Profile) -> Result<AddressCheck, Error> {
        let network = profile.network_byte()?;
        Ok(AddressCheck {
            problem: Address::parse_for_network_byte(text, network)
                .err()
                .and_then(|error| match error {
                    Error::InvalidAddress { problem } => Some(problem),
                    _ => None,
                }),
        })
    }

    /// The address in the Base58Check `text`, which must have the network byte `network`.
    pub fn parse_for_network_byte(text: &str, network: u8) -> Result<Address, Error> {
        let address = Address::parse_any_network(text)?;
        if address.network_byte() == network {
            Ok(address)
        } else {
            Err(Error::InvalidAddress {
                problem: AddressProblem::WrongNetwork {
                    expected: network,
                    actual: address.network_byte(),
                },
            })
        }
    }

    /// The address in the Base58Check `text` with any network byte, for tools that show which
    /// network an address belongs to. Wallets use [`Address::parse`].
    pub fn parse_any_network(text: &str) -> Result<Address, Error> {
        identities::Address::from_base58(text)
            .map(Address)
            .map_err(|error| Error::InvalidAddress {
                problem: match error {
                    AddressError::Base58(Base58Error::InvalidCharacter { index }) => {
                        AddressProblem::Format {
                            position: Some(index),
                        }
                    }
                    AddressError::Base58(Base58Error::InvalidChecksum) => AddressProblem::Checksum,
                    AddressError::Base58(Base58Error::TooShort) => {
                        AddressProblem::Format { position: None }
                    }
                    AddressError::InvalidLength { actual } => {
                        AddressProblem::Length { bytes: actual }
                    }
                    AddressError::WrongNetwork { expected, actual } => {
                        AddressProblem::WrongNetwork { expected, actual }
                    }
                },
            })
    }

    /// The address of `public_key` on the network of `profile`.
    pub fn from_public_key(public_key: &PublicKey, profile: &Profile) -> Result<Address, Error> {
        Ok(Address::from_public_key_for_network_byte(
            public_key,
            profile.network_byte()?,
        ))
    }

    /// The address of `public_key` with the network byte `network`. The hash covers the key in
    /// the encoding it was given in.
    pub fn from_public_key_for_network_byte(public_key: &PublicKey, network: u8) -> Address {
        Address(identities::Address::from_public_key(public_key, network))
    }

    /// The network byte.
    pub fn network_byte(&self) -> u8 {
        self.0.network()
    }

    /// The 21 bytes: the network byte, then the key hash.
    pub fn as_bytes(&self) -> &[u8; 21] {
        self.0.as_bytes()
    }

    /// The address as `heartwood-crypto` holds it.
    pub(crate) fn inner(&self) -> identities::Address {
        self.0
    }

    /// The address that `heartwood-crypto` holds as `address`.
    pub(crate) fn from_inner(address: identities::Address) -> Address {
        Address(address)
    }
}

impl fmt::Display for Address {
    /// The Base58Check text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_base58())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::DevnetOptions;

    const KEY: &str = "034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192";
    const DEVNET_ADDRESS: &str = "dEHxjxZybRiykTqqZUgfQoMqZZ3RxVj1dt";

    fn devnet() -> Profile {
        Profile::devnet(DevnetOptions::default())
    }

    fn problem(text: &str) -> AddressProblem {
        match Address::parse(text, &devnet()) {
            Err(Error::InvalidAddress { problem }) => problem,
            other => panic!("{text}: {other:?}"),
        }
    }

    #[test]
    fn parse_and_derive() {
        let key = PublicKey::from_hex(KEY).unwrap();
        let address = Address::from_public_key(&key, &devnet()).unwrap();
        assert_eq!(address.to_string(), DEVNET_ADDRESS);
        assert_eq!(Address::parse(DEVNET_ADDRESS, &devnet()), Ok(address));
        assert_eq!(address.network_byte(), 90);
        assert!(Address::check(DEVNET_ADDRESS, &devnet()).unwrap().is_ok());
    }

    #[test]
    fn problems() {
        assert_eq!(
            problem("SNAgA2XCRZDKfm5Vu9h4KR1bZw5xn9EiC3"),
            AddressProblem::WrongNetwork {
                expected: 90,
                actual: 63
            }
        );
        assert_eq!(
            problem("dEHxjxZybRiykTqqZUgfQoMqZZ3RxVj1d1"),
            AddressProblem::Checksum
        );
        assert_eq!(
            problem("d0OIlxZybRiykTqqZUgfQoMqZZ3RxVj1dt"),
            AddressProblem::Format { position: Some(1) }
        );
        assert_eq!(
            Address::check("d0OIlx", &devnet()).unwrap().position(),
            Some(1)
        );
        assert_eq!(problem(""), AddressProblem::Format { position: None });
        assert_eq!(
            problem("9DEG5VoLtwU2reBFs5mpiXajwrM97ik9q"),
            AddressProblem::Length { bytes: 20 }
        );
    }
}
