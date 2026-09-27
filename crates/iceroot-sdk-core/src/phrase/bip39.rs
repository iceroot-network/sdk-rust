//! The BIP39 standard with the English word list: entropy to words, words to entropy with the
//! checksum, and the seed.
//!
//! This module is the standard itself and accepts every length it defines, 12 to 24 words. Keys
//! are only made from phrases of 18 words or more, which [`super::Mnemonic`] enforces.
//!
//! Input is normalized as BIP39 requires (Unicode NFKD) and, for the words, leniently: any run of
//! white space separates words, and letters may be upper or lower case. The seed is always computed
//! from the canonical phrase, the list's own words joined by single spaces.

use hmac::Hmac;
use sha2::{Digest, Sha256, Sha512};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::{Error, PhraseProblem};

/// The BIP39 English word list, one word per line.
pub const WORDLIST: &str = include_str!("english.txt");

/// The number of words in the list.
const WORD_COUNT: usize = 2048;

/// The PBKDF2 rounds of the seed.
const SEED_ROUNDS: u32 = 2048;

/// The words of [`WORDLIST`], split at compile time. A list without exactly 2,048 non-empty lines
/// fails the build.
static WORDS: [&str; WORD_COUNT] = split_lines(WORDLIST);

#[allow(
    clippy::indexing_slicing,
    reason = "evaluated at compile time, where an index out of range is a build error"
)]
const fn split_lines(text: &'static str) -> [&'static str; WORD_COUNT] {
    let mut words = [""; WORD_COUNT];
    let mut rest = text;
    let mut count = 0;
    while count < WORD_COUNT {
        let bytes = rest.as_bytes();
        let mut len = 0;
        while len < bytes.len() && bytes[len] != b'\n' {
            len += 1;
        }
        let (word, tail) = rest.split_at(len);
        assert!(!word.is_empty(), "the word list has an empty line");
        words[count] = word;
        rest = tail.split_at(if tail.is_empty() { 0 } else { 1 }).1;
        count += 1;
    }
    assert!(rest.is_empty(), "the word list has more than 2,048 lines");
    words
}

/// The word with the 11-bit index `index`.
pub fn word(index: u16) -> &'static str {
    WORDS
        .get(usize::from(index) & (WORD_COUNT - 1))
        .copied()
        .unwrap_or_default()
}

/// The index of `word` in the list, comparing ASCII letters without regard to case.
pub fn index_of(word: &str) -> Option<u16> {
    if !word.is_ascii() {
        return None;
    }
    WORDS
        .binary_search_by(|candidate| {
            candidate
                .bytes()
                .cmp(word.bytes().map(|byte| byte.to_ascii_lowercase()))
        })
        .ok()
        .and_then(|index| u16::try_from(index).ok())
}

/// The words of the English mnemonic of `entropy`, which must be 16, 20, 24, 28 or 32 bytes long
/// (12, 15, 18, 21 or 24 words), joined by single spaces.
pub fn entropy_to_mnemonic(entropy: &[u8]) -> Result<Zeroizing<String>, Error> {
    let length = entropy.len();
    if !(16..=32).contains(&length) || !length.is_multiple_of(4) {
        return Err(Error::InvalidPhrase {
            problem: PhraseProblem::WordCount {
                words: length * 3 / 4,
            },
        });
    }
    let [checksum, ..] = <[u8; 32]>::from(Sha256::digest(entropy));
    // One checksum bit per 32 bits of entropy: at most 8, so the hash's first byte holds them.
    let checksum_bits = u32::try_from(length / 4).unwrap_or(8);
    let mut mnemonic = Zeroizing::new(String::with_capacity(length * 9));
    // Bits not yet written, right-aligned: fewer than 11 between pushes, so at most 19 in use.
    let mut pending = Zeroizing::new(0u32);
    let mut pending_bits = 0u32;
    let mut push = |value: u32, width: u32| {
        *pending = (*pending << width) | value;
        pending_bits += width;
        while pending_bits >= 11 {
            pending_bits -= 11;
            if !mnemonic.is_empty() {
                mnemonic.push(' ');
            }
            let index = u16::try_from((*pending >> pending_bits) & 0x7ff).unwrap_or_default();
            mnemonic.push_str(word(index));
            *pending &= (1 << pending_bits) - 1;
        }
    };
    for &byte in entropy {
        push(u32::from(byte), 8);
    }
    push(u32::from(checksum) >> (8 - checksum_bits), checksum_bits);
    Ok(mnemonic)
}

/// A phrase read and checked: the canonical words and the entropy they encode.
pub(crate) struct Decoded {
    /// The list's words joined by single spaces.
    pub(crate) canonical: Zeroizing<String>,
    /// The number of words.
    pub(crate) words: usize,
    /// The entropy.
    pub(crate) entropy: Zeroizing<Vec<u8>>,
}

/// Read `text` as an English mnemonic of any length BIP39 defines and check its checksum. The
/// problems are reported in this order: no words, an unknown word (the first), a word count BIP39
/// does not define, a bad checksum.
pub(crate) fn decode(text: &str) -> Result<Decoded, PhraseProblem> {
    let normalized = nfkd(text);
    let mut indexes = Zeroizing::new(Vec::with_capacity(24));
    for (position, word) in normalized.split_whitespace().enumerate() {
        match index_of(word) {
            Some(index) => indexes.push(index),
            None => {
                return Err(PhraseProblem::UnknownWord {
                    position: position + 1,
                });
            }
        }
    }
    let words = indexes.len();
    if words == 0 {
        return Err(PhraseProblem::Empty);
    }
    if !(12..=24).contains(&words) || !words.is_multiple_of(3) {
        return Err(PhraseProblem::WordCount { words });
    }

    // 11 bits per word: the entropy (32 bits per 3 words), then its checksum (1 bit per 3 words).
    let entropy_bytes = words / 3 * 4;
    let checksum_bits = u32::try_from(words / 3).unwrap_or(8);
    let mut bytes = Zeroizing::new(Vec::with_capacity(entropy_bytes + 1));
    let mut pending = Zeroizing::new(0u32);
    let mut pending_bits = 0u32;
    for &index in indexes.iter() {
        *pending = (*pending << 11) | u32::from(index);
        pending_bits += 11;
        while pending_bits >= 8 {
            pending_bits -= 8;
            bytes.push(u8::try_from((*pending >> pending_bits) & 0xff).unwrap_or_default());
            *pending &= (1 << pending_bits) - 1;
        }
    }
    // With 24 words the 8 checksum bits made a whole byte; otherwise they are still pending.
    let stated = match bytes.get(entropy_bytes) {
        Some(&byte) => u32::from(byte),
        None => *pending,
    };
    bytes.truncate(entropy_bytes);
    let [first, ..] = <[u8; 32]>::from(Sha256::digest(bytes.as_slice()));
    if u32::from(first) >> (8 - checksum_bits) != stated {
        return Err(PhraseProblem::Checksum);
    }

    let mut canonical = Zeroizing::new(String::with_capacity(words * 9));
    for &index in indexes.iter() {
        if !canonical.is_empty() {
            canonical.push(' ');
        }
        canonical.push_str(word(index));
    }
    Ok(Decoded {
        canonical,
        words,
        entropy: bytes,
    })
}

/// The entropy of the English mnemonic `text` of any length BIP39 defines (12 to 24 words), with
/// its checksum checked.
pub fn mnemonic_to_entropy(text: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    decode(text)
        .map(|decoded| decoded.entropy)
        .map_err(|problem| Error::InvalidPhrase { problem })
}

/// A BIP39 seed: 64 bytes, wiped when dropped.
pub struct Seed(Zeroizing<[u8; 64]>);

impl Seed {
    /// The 64 seed bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Seed(..)")
    }
}

/// The BIP39 seed of the English mnemonic `text` (12 to 24 words, checksum checked) with the
/// optional BIP39 passphrase `passphrase` (empty for none): PBKDF2-HMAC-SHA512 over the NFKD form
/// of the canonical phrase, salt `"mnemonic"` followed by the NFKD form of the passphrase, 2,048
/// rounds.
pub fn mnemonic_to_seed(text: &str, passphrase: &str) -> Result<Seed, Error> {
    let decoded = decode(text).map_err(|problem| Error::InvalidPhrase { problem })?;
    seed(&decoded.canonical, passphrase)
}

/// The seed of the canonical phrase `canonical` (ASCII words joined by single spaces).
pub(crate) fn seed(canonical: &str, passphrase: &str) -> Result<Seed, Error> {
    let mut salt = Zeroizing::new(String::with_capacity(8 + passphrase.len() * 2));
    salt.push_str("mnemonic");
    salt.extend(passphrase.nfkd());
    let mut out = Zeroizing::new([0u8; 64]);
    // HMAC accepts keys of every length, so PBKDF2 does not fail; the error is still passed on.
    pbkdf2::pbkdf2::<Hmac<Sha512>>(
        canonical.as_bytes(),
        salt.as_bytes(),
        SEED_ROUNDS,
        out.as_mut_slice(),
    )
    .map_err(|_| Error::SigningFailed {
        reason: "the BIP39 seed could not be computed".to_owned(),
    })?;
    Ok(Seed(out))
}

/// The NFKD form of `text`, wiped when dropped.
fn nfkd(text: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(text.len() * 2));
    out.extend(text.nfkd());
    out
}

#[cfg(test)]
mod tests {
    use heartwood_crypto::utils::hex;

    use super::*;

    #[test]
    fn word_list_is_the_standard_list() {
        assert_eq!(
            hex::encode(&<[u8; 32]>::from(Sha256::digest(WORDLIST.as_bytes()))),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        assert_eq!(WORDS.first(), Some(&"abandon"));
        assert_eq!(WORDS.last(), Some(&"zoo"));
        assert!(WORDS.windows(2).all(|pair| pair[0] < pair[1]), "sorted");
        for (index, word) in WORDS.iter().enumerate() {
            assert_eq!(index_of(word), Some(index as u16));
            assert_eq!(index_of(&word.to_uppercase()), Some(index as u16));
        }
        assert_eq!(index_of("abandonx"), None);
        assert_eq!(index_of("ábandon"), None);
        assert_eq!(index_of(""), None);
    }

    #[test]
    fn round_trip_every_length() {
        for length in [16usize, 20, 24, 28, 32] {
            let entropy: Vec<u8> = (0..length).map(|i| (i * 37 + 11) as u8).collect();
            let words = entropy_to_mnemonic(&entropy).unwrap();
            assert_eq!(words.split(' ').count(), length * 3 / 4);
            let decoded = decode(&words).unwrap();
            assert_eq!(decoded.entropy.as_slice(), entropy.as_slice());
            assert_eq!(decoded.canonical.as_str(), words.as_str());
        }
        assert!(entropy_to_mnemonic(&[0; 15]).is_err());
        assert!(entropy_to_mnemonic(&[0; 36]).is_err());
    }

    #[test]
    fn lenient_input_same_seed() {
        let canonical =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let messy = "  Legal\u{3000}WINNER thank\tyear wave sausage worth useful legal winner thank yellow\n";
        let a = mnemonic_to_seed(canonical, "TREZOR").unwrap();
        let b = mnemonic_to_seed(messy, "TREZOR").unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_eq!(
            hex::encode(a.as_bytes()),
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"
        );
    }

    #[test]
    fn problems_in_order() {
        assert_eq!(decode("").err(), Some(PhraseProblem::Empty));
        assert_eq!(decode(" \n ").err(), Some(PhraseProblem::Empty));
        assert_eq!(
            decode("abandon abandonx").err(),
            Some(PhraseProblem::UnknownWord { position: 2 })
        );
        assert_eq!(
            decode("abandon abandon").err(),
            Some(PhraseProblem::WordCount { words: 2 })
        );
        assert_eq!(
            decode(&["abandon"; 12].join(" ")).err(),
            Some(PhraseProblem::Checksum)
        );
        assert_eq!(
            decode(&["zoo"; 27].join(" ")).err(),
            Some(PhraseProblem::WordCount { words: 27 })
        );
    }
}
