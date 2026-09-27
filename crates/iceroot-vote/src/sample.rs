//! The per-account seed and the deterministic stream that selections draw from.

use sha2::{Digest, Sha256};

use crate::mode::Mode;

/// The domain tag at the start of every selection seed.
pub const SEED_TAG: &[u8] = b"iceroot/vote-select/v1";

/// The seed of a selection:
///
/// ```text
/// SHA-256( "iceroot/vote-select/v1"
///        ‖ u32 length of the account address ‖ the address (UTF-8)
///        ‖ u32 length of the mode id ‖ the mode id (for example "maximum-rewards")
///        ‖ u64 snapshot height ‖ u32 draw )
/// ```
///
/// with every integer big-endian. Anyone with the same account, mode, snapshot height, draw number
/// and library version draws the same selection.
pub fn seed(account: &str, mode: Mode, height: u64, draw: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SEED_TAG);
    update_with_length(&mut hasher, account.as_bytes());
    update_with_length(&mut hasher, mode.id().as_bytes());
    hasher.update(height.to_be_bytes());
    hasher.update(draw.to_be_bytes());
    hasher.finalize().into()
}

fn update_with_length(hasher: &mut Sha256, bytes: &[u8]) {
    // An address or mode id longer than u32::MAX bytes cannot exist in memory on any target the
    // library supports; saturating keeps the function total.
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
}

/// A SHA-256 counter stream: block `i` is `SHA-256(seed ‖ u64 i)`, big-endian `i` from 0, read as
/// two big-endian 128-bit numbers.
#[derive(Debug, Clone)]
pub(crate) struct Stream {
    seed: [u8; 32],
    counter: u64,
    /// The second number of the current block, not yet used.
    pending: Option<u128>,
}

impl Stream {
    /// A stream over `seed`, at its start.
    pub(crate) fn new(seed: [u8; 32]) -> Stream {
        Stream {
            seed,
            counter: 0,
            pending: None,
        }
    }

    /// The next 128-bit number.
    pub(crate) fn next_u128(&mut self) -> u128 {
        if let Some(value) = self.pending.take() {
            return value;
        }
        let mut hasher = Sha256::new();
        hasher.update(self.seed);
        hasher.update(self.counter.to_be_bytes());
        let block: [u8; 32] = hasher.finalize().into();
        self.counter = self.counter.wrapping_add(1);
        let first = block
            .first_chunk::<16>()
            .map_or(0, |c| u128::from_be_bytes(*c));
        self.pending = Some(
            block
                .last_chunk::<16>()
                .map_or(0, |c| u128::from_be_bytes(*c)),
        );
        first
    }

    /// A number uniformly distributed in `0..bound`, by rejection: numbers from the incomplete
    /// last multiple of `bound` below 2^128 are skipped. `bound` 0 gives 0.
    pub(crate) fn below(&mut self, bound: u128) -> u128 {
        if bound == 0 {
            return 0;
        }
        // 2^128 mod bound.
        let excess = (u128::MAX % bound + 1) % bound;
        loop {
            let value = self.next_u128();
            if excess == 0 || value < 0u128.wrapping_sub(excess) {
                return value % bound;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn seed_layout() {
        // The same bytes hashed directly.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"iceroot/vote-select/v1");
        bytes.extend_from_slice(&[0, 0, 0, 5]);
        bytes.extend_from_slice(b"holdr");
        bytes.extend_from_slice(&[0, 0, 0, 9]);
        bytes.extend_from_slice(b"diversity");
        bytes.extend_from_slice(&7u64.to_be_bytes());
        bytes.extend_from_slice(&3u32.to_be_bytes());
        let direct: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(seed("holdr", Mode::Diversity, 7, 3), direct);
        assert_ne!(
            seed("holdr", Mode::Diversity, 7, 3),
            seed("holdr", Mode::Diversity, 7, 4)
        );
        assert_ne!(
            seed("holdr", Mode::Diversity, 7, 3),
            seed("holdr", Mode::Reliability, 7, 3)
        );
    }

    #[test]
    fn stream_blocks() {
        let seed = [0x11; 32];
        let mut stream = Stream::new(seed);
        let mut first = seed.to_vec();
        first.extend_from_slice(&0u64.to_be_bytes());
        let block = Sha256::digest(&first);
        let a = stream.next_u128();
        let b = stream.next_u128();
        assert_eq!(hex(&a.to_be_bytes()), hex(&block[..16]));
        assert_eq!(hex(&b.to_be_bytes()), hex(&block[16..]));
        let mut second = seed.to_vec();
        second.extend_from_slice(&1u64.to_be_bytes());
        let block = Sha256::digest(&second);
        assert_eq!(hex(&stream.next_u128().to_be_bytes()), hex(&block[..16]));
    }

    #[test]
    fn below_bounds() {
        let mut stream = Stream::new([7; 32]);
        for bound in [1u128, 2, 3, 10, 1 << 64, u128::MAX, (1 << 127) + 1] {
            for _ in 0..50 {
                assert!(stream.below(bound) < bound);
            }
        }
        assert_eq!(stream.below(0), 0);
        let mut counts = [0u32; 3];
        for _ in 0..3_000 {
            counts[usize::try_from(stream.below(3)).unwrap()] += 1;
        }
        assert!(
            counts.iter().all(|&c| (900..1_100).contains(&c)),
            "{counts:?}"
        );
    }
}
