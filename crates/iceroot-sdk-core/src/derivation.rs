//! Hardened-only BIP32 derivation of secp256k1 keys.
//!
//! New accounts on networks in today's formats derive their key from the BIP39 seed of their
//! phrase: the BIP32 master key (HMAC-SHA512 keyed with `"Bitcoin seed"`, which is also
//! SLIP-0010's secp256k1 master), then hardened steps only, at `m/44'/coin'/account'/0'/index'`.
//! A hardened step is `I = HMAC-SHA512(chain code, 0x00 || key || index + 2^31)`, and the child key
//! is `I[0..32] + key` modulo the curve order, with `I[32..64]` as its chain code.
//!
//! Non-hardened steps do not exist here: there are no extended public keys, so an address pool is
//! generated with the keys. In the negligible case of an invalid step (probability below 2^-127)
//! the derivation fails instead of moving to another index, so a path always names one key.
//!
//! The secp256k1 library is used for one operation only, the scalar addition of a step; the key
//! itself is then handed to `heartwood-crypto`, which makes every public key, address and
//! signature.

use std::fmt;

use heartwood_crypto::identities::{PublicKey, SecretKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::error::Error;

/// The first hardened index, `2^31`.
pub const HARDENED: u32 = 0x8000_0000;

/// The BIP44 purpose of the wallet path.
const PURPOSE: u32 = 44;

/// The HMAC key of the BIP32 master key.
const MASTER_KEY: &[u8] = b"Bitcoin seed";

/// A wallet path `m/44'/coin'/account'/0'/index'`, every step hardened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DerivationPath {
    coin_type: u32,
    account: u32,
    index: u32,
}

impl DerivationPath {
    /// The path of `account` and `index` under `coin_type`. Each must be below `2^31`: they become
    /// hardened steps.
    pub fn new(coin_type: u32, account: u32, index: u32) -> Result<DerivationPath, Error> {
        if account >= HARDENED || index >= HARDENED || coin_type >= HARDENED {
            return Err(Error::InvalidPath { account, index });
        }
        Ok(DerivationPath {
            coin_type,
            account,
            index,
        })
    }

    /// The coin type.
    pub fn coin_type(&self) -> u32 {
        self.coin_type
    }

    /// The account number.
    pub fn account(&self) -> u32 {
        self.account
    }

    /// The address index.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The five steps, as hardened indexes.
    pub fn steps(&self) -> [u32; 5] {
        [PURPOSE, self.coin_type, self.account, 0, self.index].map(|step| step | HARDENED)
    }
}

impl fmt::Display for DerivationPath {
    /// `m/44'/1'/0'/0'/0'`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "m/{PURPOSE}'/{}'/{}'/0'/{}'",
            self.coin_type, self.account, self.index
        )
    }
}

/// A secp256k1 scalar and chain code, wiped when dropped.
struct Node {
    key: Scalar,
    chain_code: Zeroizing<[u8; 32]>,
}

/// A secp256k1 secret scalar that the library wipes when it is dropped.
struct Scalar(secp256k1::SecretKey);

impl Drop for Scalar {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

/// `HMAC-SHA512(key, data)`, wiped when dropped.
fn hmac_sha512(key: &[u8], data: &[&[u8]]) -> Result<Zeroizing<[u8; 64]>, Error> {
    let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(key).map_err(|_| failed())?;
    for part in data {
        mac.update(part);
    }
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

fn failed() -> Error {
    Error::SigningFailed {
        reason: "the key derivation failed".to_owned(),
    }
}

/// The two halves of `i`: a scalar (checked to be a valid secret key, in constant time) and a
/// chain code.
fn split(i: &[u8; 64]) -> Result<(Scalar, Zeroizing<[u8; 32]>), Error> {
    let mut left = Zeroizing::new([0u8; 32]);
    let mut right = Zeroizing::new([0u8; 32]);
    let (l, r) = i.split_at(32);
    left.copy_from_slice(l);
    right.copy_from_slice(r);
    let key = secp256k1::SecretKey::from_secret_bytes(*left).map_err(|_| failed())?;
    Ok((Scalar(key), right))
}

impl Node {
    /// The BIP32 master node of `seed`, which must be 16 to 64 bytes long.
    fn master(seed: &[u8]) -> Result<Node, Error> {
        if !(16..=64).contains(&seed.len()) {
            return Err(failed());
        }
        let i = hmac_sha512(MASTER_KEY, &[seed])?;
        let (key, chain_code) = split(&i)?;
        Ok(Node { key, chain_code })
    }

    /// The hardened child at `index` (already carrying the hardened bit).
    fn child(&self, index: u32) -> Result<Node, Error> {
        if index < HARDENED {
            return Err(failed());
        }
        let parent = Zeroizing::new(self.key.0.to_secret_bytes());
        let i = hmac_sha512(
            self.chain_code.as_slice(),
            &[&[0], parent.as_slice(), &index.to_be_bytes()],
        )?;
        let (tweak, chain_code) = split(&i)?;
        let key = self
            .key
            .0
            .add_tweak(&secp256k1::Scalar::from(tweak.0))
            .map_err(|_| failed())?;
        Ok(Node {
            key: Scalar(key),
            chain_code,
        })
    }
}

/// The secret key at the hardened `steps` below the master key of `seed` (16 to 64 bytes).
pub(crate) fn derive(seed: &[u8], steps: &[u32]) -> Result<SecretKey, Error> {
    let mut node = Node::master(seed)?;
    for &step in steps {
        node = node.child(step)?;
    }
    SecretKey::from_bytes(node.key.0.to_secret_bytes()).map_err(|_| failed())
}

/// The public key at the hardened `steps` (each carrying the hardened bit) below the master key
/// of `seed` (16 to 64 bytes). This is the published BIP32 derivation restricted to hardened
/// steps, for checking against other implementations; accounts come from
/// [`crate::keys::Account::from_phrase`].
pub fn public_key_at(seed: &[u8], steps: &[u32]) -> Result<PublicKey, Error> {
    let secret = derive(seed, steps)?;
    Ok(PublicKey::from_secret_key(&secret))
}

#[cfg(test)]
mod tests {
    use heartwood_crypto::utils::hex;

    use super::*;

    #[test]
    fn paths() {
        let path = DerivationPath::new(1, 0, 7).unwrap();
        assert_eq!(path.to_string(), "m/44'/1'/0'/0'/7'");
        assert_eq!(
            path.steps(),
            [
                44 | HARDENED,
                1 | HARDENED,
                HARDENED,
                HARDENED,
                7 | HARDENED
            ]
        );
        assert_eq!(
            DerivationPath::new(1, HARDENED, 0),
            Err(Error::InvalidPath {
                account: HARDENED,
                index: 0
            })
        );
        assert!(DerivationPath::new(1, 0, u32::MAX).is_err());
    }

    #[test]
    fn bip32_test_vector_1_hardened_steps() {
        // BIP32 test vector 1: seed 000102...0f; m and m/0H.
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        assert_eq!(
            public_key_at(&seed, &[]).unwrap().to_hex(),
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
        );
        assert_eq!(
            public_key_at(&seed, &[HARDENED]).unwrap().to_hex(),
            "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"
        );
    }

    #[test]
    fn refusals() {
        assert!(public_key_at(&[0; 15], &[]).is_err());
        assert!(public_key_at(&[0; 65], &[]).is_err());
        assert!(
            public_key_at(&[0; 16], &[0]).is_err(),
            "a non-hardened step"
        );
    }
}
