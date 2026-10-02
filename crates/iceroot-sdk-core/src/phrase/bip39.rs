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
use icu_normalizer::DecomposingNormalizerBorrowed;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::error::{Error, PhraseProblem};

/// The BIP39 English word list, one word per line.
pub const WORDLIST: &str = include_str!("english.txt");

/// The number of words in the list.
const WORD_COUNT: usize = 2048;

/// The PBKDF2 rounds of the seed.
const SEED_ROUNDS: u32 = 2048;

/// Where each word of [`WORDLIST`] starts, and after the last entry the length of the list plus
/// one: word `i` is `WORDLIST[OFFSETS[i]..OFFSETS[i + 1] - 1]`, without its line break. Computed at
/// compile time; a list without exactly 2,048 non-empty lines fails the build. Two bytes per word
/// instead of a string slice each keeps the WebAssembly module small.
static OFFSETS: [u16; WORD_COUNT + 1] = line_offsets(WORDLIST);

#[allow(
    clippy::indexing_slicing,
    reason = "evaluated at compile time, where an index out of range is a build error"
)]
const fn line_offsets(text: &str) -> [u16; WORD_COUNT + 1] {
    let bytes = text.as_bytes();
    assert!(
        bytes.len() < u16::MAX as usize,
        "the word list is too long for 16-bit offsets"
    );
    let mut offsets = [0u16; WORD_COUNT + 1];
    let mut count = 0;
    let mut start = 0;
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'\n' {
            assert!(at > start, "the word list has an empty line");
            assert!(
                count < WORD_COUNT,
                "the word list has more than 2,048 lines"
            );
            count += 1;
            offsets[count] = (at + 1) as u16;
            start = at + 1;
        }
        at += 1;
    }
    // A last line without a line break ends at the end of the text.
    if start < bytes.len() {
        assert!(
            count < WORD_COUNT,
            "the word list has more than 2,048 lines"
        );
        count += 1;
        offsets[count] = (bytes.len() + 1) as u16;
    }
    assert!(
        count == WORD_COUNT,
        "the word list has fewer than 2,048 lines"
    );
    offsets
}

/// The word with the 11-bit index `index`.
pub fn word(index: u16) -> &'static str {
    let index = usize::from(index) & (WORD_COUNT - 1);
    match (OFFSETS.get(index), OFFSETS.get(index + 1)) {
        (Some(&start), Some(&end)) => WORDLIST
            .get(usize::from(start)..usize::from(end).saturating_sub(1))
            .unwrap_or_default(),
        _ => "",
    }
}

/// The index of `word` in the list, comparing ASCII letters without regard to case.
pub fn index_of(word: &str) -> Option<u16> {
    if !word.is_ascii() {
        return None;
    }
    // The list is sorted: a binary search over the indexes.
    let (mut low, mut high) = (0u16, WORD_COUNT as u16);
    while low < high {
        let middle = low + (high - low) / 2;
        match self::word(middle)
            .bytes()
            .cmp(word.bytes().map(|byte| byte.to_ascii_lowercase()))
        {
            std::cmp::Ordering::Less => low = middle + 1,
            std::cmp::Ordering::Greater => high = middle,
            std::cmp::Ordering::Equal => return Some(middle),
        }
    }
    None
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
    push_nfkd(&mut salt, passphrase);
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
    push_nfkd(&mut out, text);
    out
}

/// Append the NFKD form of `text` to `out`.
fn push_nfkd(out: &mut String, text: &str) {
    // Writing to a String never fails, so the result carries nothing.
    let _ = DecomposingNormalizerBorrowed::new_nfkd().normalize_to(text, out);
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
        let words: Vec<&str> = (0..WORD_COUNT as u16).map(word).collect();
        assert_eq!(words, WORDLIST.lines().collect::<Vec<_>>());
        assert_eq!(words.first(), Some(&"abandon"));
        assert_eq!(words.last(), Some(&"zoo"));
        assert!(words.windows(2).all(|pair| pair[0] < pair[1]), "sorted");
        for (index, word) in words.iter().enumerate() {
            assert_eq!(index_of(word), Some(index as u16));
            assert_eq!(index_of(&word.to_uppercase()), Some(index as u16));
        }
        assert_eq!(word(2048), "abandon", "an index wraps to 11 bits");
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

    /// The normaliser against a second implementation: every code point alone, each after a
    /// starter and before a combining mark (so that canonical reordering runs), and runs of
    /// combining marks out of order.
    #[test]
    fn nfkd_equals_a_second_implementation() {
        use unicode_normalization::UnicodeNormalization;

        let check = |text: &str| {
            let expected: String = text.nfkd().collect();
            assert_eq!(nfkd(text).as_str(), expected, "NFKD of {text:?}");
        };
        for scalar in (0..=0x10ffff_u32).filter_map(char::from_u32) {
            check(&scalar.to_string());
            check(&format!("a{scalar}\u{301}\u{316}"));
        }
        check("e\u{301}\u{316}\u{327}\u{300}\u{31b}x");
        check("\u{1100}\u{1161}\u{11a8}\u{ac00}\u{d7a3}");
        check("\u{fb01}\u{2126}\u{212b}\u{3000}\u{ff21}\u{2460}\u{1d400}");
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
