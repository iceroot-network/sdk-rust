//! Recovery phrases.
//!
//! A [`Mnemonic`] is a checked BIP39 English phrase of 18, 21 or 24 words, the only phrases keys
//! are made from: new phrases have 24 words from 256 bits of fresh randomness, and imports of
//! fewer than 18 words are refused with [`Error::PhraseTooShort`]. [`Mnemonic::check`] gives the
//! problem of a phrase being typed, for form feedback. The standard itself, for every length it
//! defines, is in [`bip39`].
//!
//! A phrase is secret. The SDK holds it in memory that is wiped when released, never prints it in
//! `Debug` output or errors, and accepts it as bytes ([`Mnemonic::parse_utf8`]) so that callers
//! can wipe their own copy.

pub mod bip39;

use std::fmt;

use zeroize::Zeroizing;

pub use self::bip39::Seed;
use crate::error::{Error, PhraseProblem};

/// The fewest words a phrase for keys may have.
pub const MIN_WORDS: usize = 18;

/// The words of a new phrase.
pub const NEW_PHRASE_WORDS: usize = 24;

/// A checked BIP39 English recovery phrase of 18, 21 or 24 words.
pub struct Mnemonic {
    canonical: Zeroizing<String>,
    words: usize,
}

impl Mnemonic {
    /// A new 24-word phrase from 256 bits of the operating system's randomness.
    pub fn generate() -> Result<Mnemonic, Error> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        getrandom::fill(entropy.as_mut_slice()).map_err(|_| Error::RandomnessUnavailable)?;
        Mnemonic::from_entropy(entropy.as_slice())
    }

    /// The phrase of `entropy`: 24, 28 or 32 bytes give 18, 21 or 24 words. Shorter entropy is
    /// refused with [`Error::PhraseTooShort`].
    pub fn from_entropy(entropy: &[u8]) -> Result<Mnemonic, Error> {
        let canonical = bip39::entropy_to_mnemonic(entropy)?;
        let words = entropy.len() * 3 / 4;
        if words < MIN_WORDS {
            return Err(Error::PhraseTooShort {
                words,
                minimum: MIN_WORDS,
            });
        }
        Ok(Mnemonic { canonical, words })
    }

    /// The phrase in `text`, with its checksum checked.
    ///
    /// Words may be separated by any white space and written in any case; the phrase is kept in
    /// its canonical form. A valid phrase of 12 or 15 words is refused with
    /// [`Error::PhraseTooShort`]; every other problem is [`Error::InvalidPhrase`].
    pub fn parse(text: &str) -> Result<Mnemonic, Error> {
        match bip39::decode(text) {
            Ok(decoded) if decoded.words < MIN_WORDS => Err(Error::PhraseTooShort {
                words: decoded.words,
                minimum: MIN_WORDS,
            }),
            Ok(decoded) => Ok(Mnemonic {
                canonical: decoded.canonical,
                words: decoded.words,
            }),
            Err(problem) => Err(Error::InvalidPhrase { problem }),
        }
    }

    /// The phrase in the UTF-8 bytes `bytes`, as [`Mnemonic::parse`] reads text. The caller keeps
    /// its buffer and can wipe it.
    pub fn parse_utf8(bytes: &[u8]) -> Result<Mnemonic, Error> {
        let text = std::str::from_utf8(bytes).map_err(|_| Error::InvalidPhrase {
            problem: PhraseProblem::NotText,
        })?;
        Mnemonic::parse(text)
    }

    /// What is wrong with `text` as a phrase for keys, for feedback while it is typed.
    pub fn check(text: &str) -> PhraseCheck {
        let words = text.split_whitespace().count();
        let problem = match bip39::decode(text) {
            Ok(decoded) if decoded.words < MIN_WORDS => Some(PhraseProblem::TooShort {
                words: decoded.words,
            }),
            Ok(_) => None,
            Err(problem) => Some(problem),
        };
        PhraseCheck { words, problem }
    }

    /// The canonical phrase: the list's words joined by single spaces. Show it to the holder only
    /// to write it down.
    pub fn phrase(&self) -> &str {
        &self.canonical
    }

    /// The number of words: 18, 21 or 24.
    pub fn word_count(&self) -> usize {
        self.words
    }

    /// The BIP39 seed of the phrase with the BIP39 passphrase `passphrase` (empty for none).
    pub fn seed(&self, passphrase: &str) -> Result<Seed, Error> {
        bip39::seed(&self.canonical, passphrase)
    }
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mnemonic({} words)", self.words)
    }
}

/// The result of [`Mnemonic::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PhraseCheck {
    /// The words typed so far.
    pub words: usize,
    /// The first problem, or `None` for a phrase keys can be made from.
    pub problem: Option<PhraseProblem>,
}

impl PhraseCheck {
    /// Whether keys can be made from the phrase.
    pub fn is_ok(&self) -> bool {
        self.problem.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORDS_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    const WORDS_12: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn generate() {
        let first = Mnemonic::generate().unwrap();
        let second = Mnemonic::generate().unwrap();
        assert_eq!(first.word_count(), 24);
        assert_ne!(first.phrase(), second.phrase());
        assert!(Mnemonic::check(first.phrase()).is_ok());
        assert_eq!(format!("{first:?}"), "Mnemonic(24 words)");
    }

    #[test]
    fn lengths() {
        assert_eq!(Mnemonic::parse(WORDS_24).unwrap().word_count(), 24);
        assert_eq!(
            Mnemonic::parse(WORDS_12).unwrap_err(),
            Error::PhraseTooShort {
                words: 12,
                minimum: 18
            }
        );
        assert_eq!(
            Mnemonic::check(WORDS_12).problem,
            Some(PhraseProblem::TooShort { words: 12 })
        );
        for bytes in [24usize, 28, 32] {
            let mnemonic = Mnemonic::from_entropy(&vec![7; bytes]).unwrap();
            assert_eq!(mnemonic.word_count(), bytes * 3 / 4);
            assert_eq!(
                Mnemonic::parse(mnemonic.phrase()).unwrap().phrase(),
                mnemonic.phrase()
            );
        }
        assert!(matches!(
            Mnemonic::from_entropy(&[7; 20]),
            Err(Error::PhraseTooShort { words: 15, .. })
        ));
    }

    #[test]
    fn problems() {
        let swapped = WORDS_24.replace("art", "about");
        assert_eq!(
            Mnemonic::parse(&swapped).unwrap_err(),
            Error::InvalidPhrase {
                problem: PhraseProblem::Checksum
            }
        );
        let check = Mnemonic::check("abandon abandn");
        assert_eq!(check.words, 2);
        assert_eq!(
            check.problem,
            Some(PhraseProblem::UnknownWord { position: 2 })
        );
        assert_eq!(
            Mnemonic::parse_utf8(&[0xff, 0xfe]).unwrap_err(),
            Error::InvalidPhrase {
                problem: PhraseProblem::NotText
            }
        );
        // An error never names a word.
        let error = Mnemonic::parse("abandon secretword").unwrap_err();
        assert!(!error.to_string().contains("secretword"));
        assert!(!error.details().to_string().contains("secretword"));
    }
}
