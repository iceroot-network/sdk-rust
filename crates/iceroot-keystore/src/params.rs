//! Argon2id parameters: the presets per platform, and the bounds every keystore's parameters must
//! keep.
//!
//! The parameters are stored in each keystore's header and authenticated with it, so a keystore
//! always opens with the parameters it was written with. Presets may rise in later releases;
//! the floor of [`Bounds::STANDARD`] belongs to format version 1 and never rises within it, so a
//! keystore written by an earlier release always opens. [`Params::is_weaker_than`] tells an app
//! when to re-encrypt a keystore with a newer preset after the next successful unlock.

use crate::error::{Error, Param};

/// Argon2id cost parameters.
///
/// [`Params::new`] takes any values; they are checked against [`Bounds`] when a keystore is
/// written or read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Params {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl Params {
    /// Parameters with `memory_kib` KiB of memory, `iterations` passes and `parallelism` lanes.
    pub const fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Params {
        Params {
            memory_kib,
            iterations,
            parallelism,
        }
    }

    /// Memory, in KiB (Argon2's `m`).
    pub const fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    /// Passes over the memory (Argon2's `t`).
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }

    /// Lanes (Argon2's `p`). This implementation computes the lanes one after another, so more
    /// lanes cost the same time; the value only has to match the one the keystore was written
    /// with.
    pub const fn parallelism(&self) -> u32 {
        self.parallelism
    }

    /// Memory times iterations: the KiB of memory filled over all passes, which is what the time
    /// of the derivation grows with.
    pub const fn work(&self) -> u64 {
        self.memory_kib as u64 * self.iterations as u64
    }

    /// Whether a keystore with these parameters should move to `other`, the parameters an app
    /// writes now: when they have less memory, or the same memory and fewer passes. An app
    /// re-encrypts a keystore whose parameters are weaker than its platform's preset.
    ///
    /// Memory comes first, since it is what makes an attacker's guesses expensive, and a keystore
    /// never moves to less memory: one written with the desktop preset (256 MiB, 3 passes) and
    /// opened by a web app is not weaker than the web preset (64 MiB, 4 passes) and keeps its
    /// 256 MiB.
    pub const fn is_weaker_than(&self, other: &Params) -> bool {
        self.memory_kib < other.memory_kib
            || (self.memory_kib == other.memory_kib && self.iterations < other.iterations)
    }
}

/// The parameter presets, one per kind of platform. Each takes roughly 0.5 to 1.5 seconds on a
/// mid-range device of its kind; the crate's README records the measurements behind them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Preset {
    /// Native code on a desktop or laptop (the Tauri plugin on Linux, macOS and Windows):
    /// 256 MiB, 3 passes, 4 lanes.
    Desktop,
    /// Native code on a phone or tablet (the Tauri plugin on Android and iOS): 128 MiB, 3 passes,
    /// 4 lanes.
    Mobile,
    /// WebAssembly in a browser page, a browser extension or a webview, where hundreds of MiB may
    /// not be available: 64 MiB, 4 passes, 4 lanes (the memory of RFC 9106's second recommended
    /// option, with one pass more).
    Web,
}

impl Preset {
    /// Every preset.
    pub const ALL: [Preset; 3] = [Preset::Desktop, Preset::Mobile, Preset::Web];

    /// The preset's parameters.
    pub const fn params(self) -> Params {
        match self {
            Preset::Desktop => Params::new(256 * 1024, 3, 4),
            Preset::Mobile => Params::new(128 * 1024, 3, 4),
            Preset::Web => Params::new(64 * 1024, 4, 4),
        }
    }

    /// The stable string form: `desktop`, `mobile` or `web`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Preset::Desktop => "desktop",
            Preset::Mobile => "mobile",
            Preset::Web => "web",
        }
    }
}

impl From<Preset> for Params {
    fn from(preset: Preset) -> Params {
        preset.params()
    }
}

/// The range a keystore's parameters must lie in, when it is written and when it is read.
///
/// The floor refuses weak keystores; the ceilings stop a crafted keystore from demanding
/// gigabytes of memory or minutes of work before its password is even checked. Argon2's own rule,
/// at least 8 KiB of memory per lane, applies on top of the floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bounds {
    floor: Params,
    ceiling: Params,
    max_work: u64,
}

impl Bounds {
    /// The bounds of format version 1.
    ///
    /// - Memory from 19,456 KiB (19 MiB, the OWASP minimum for Argon2id) to 524,288 KiB
    ///   (512 MiB, twice the desktop preset).
    /// - Iterations from 2 (the OWASP minimum at 19 MiB) to 16.
    /// - Parallelism from 1 to 16.
    /// - Work (memory in KiB times iterations) at most 2,097,152: 2 GiB filled in all, under
    ///   three times the desktop preset's work.
    pub const STANDARD: Bounds = Bounds {
        floor: Params::new(19 * 1024, 2, 1),
        ceiling: Params::new(512 * 1024, 16, 16),
        max_work: 2 * 1024 * 1024,
    };

    /// Tests only (feature `testing`): the standard ceilings with the floor lowered to Argon2's
    /// own minimums (8 KiB, 1 iteration, 1 lane), so that vectors run in milliseconds. A keystore
    /// written under these bounds below the standard floor never opens with [`crate::decrypt`].
    #[cfg(feature = "testing")]
    pub const TEST: Bounds = Bounds {
        floor: Params::new(8, 1, 1),
        ceiling: Bounds::STANDARD.ceiling,
        max_work: Bounds::STANDARD.max_work,
    };

    /// The smallest value of each parameter.
    pub const fn floor(&self) -> Params {
        self.floor
    }

    /// The largest value of each parameter.
    pub const fn ceiling(&self) -> Params {
        self.ceiling
    }

    /// The largest work (memory in KiB times iterations).
    pub const fn max_work(&self) -> u64 {
        self.max_work
    }

    /// These bounds with the memory ceiling lowered to `memory_kib`, for a platform that cannot
    /// spare the standard ceiling. The ceiling never rises and never drops below the floor.
    pub const fn with_memory_ceiling_kib(mut self, memory_kib: u32) -> Bounds {
        let mut kib = memory_kib;
        if kib > self.ceiling.memory_kib {
            kib = self.ceiling.memory_kib;
        }
        if kib < self.floor.memory_kib {
            kib = self.floor.memory_kib;
        }
        self.ceiling.memory_kib = kib;
        self
    }

    /// Check `params` against the bounds. The parameters are checked in the order parallelism,
    /// memory, iterations, work, and the first one out of range is reported.
    pub fn check(&self, params: &Params) -> Result<(), Error> {
        let parallelism = params.parallelism;
        in_range(
            Param::Parallelism,
            u64::from(parallelism),
            u64::from(self.floor.parallelism),
            u64::from(self.ceiling.parallelism),
        )?;
        // Argon2 needs at least 8 KiB per lane.
        let memory_floor = u64::from(self.floor.memory_kib).max(8 * u64::from(parallelism));
        in_range(
            Param::Memory,
            u64::from(params.memory_kib),
            memory_floor,
            u64::from(self.ceiling.memory_kib),
        )?;
        in_range(
            Param::Iterations,
            u64::from(params.iterations),
            u64::from(self.floor.iterations),
            u64::from(self.ceiling.iterations),
        )?;
        in_range(Param::Work, params.work(), self.floor.work(), self.max_work)
    }
}

impl Default for Bounds {
    fn default() -> Bounds {
        Bounds::STANDARD
    }
}

fn in_range(param: Param, value: u64, minimum: u64, maximum: u64) -> Result<(), Error> {
    if (minimum..=maximum).contains(&value) {
        Ok(())
    } else {
        Err(Error::ParamsOutOfRange {
            param,
            value,
            minimum,
            maximum,
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn presets_are_within_the_standard_bounds() {
        for preset in Preset::ALL {
            Bounds::STANDARD.check(&preset.params()).unwrap();
        }
    }

    #[test]
    fn presets_meet_the_published_minimums() {
        for preset in Preset::ALL {
            let params = preset.params();
            // RFC 9106 section 4, second recommended option: 64 MiB, 3 passes.
            assert!(params.memory_kib() >= 64 * 1024 && params.iterations() >= 3);
            // OWASP: 19 MiB and 2 passes at the least.
            assert!(!params.is_weaker_than(&Bounds::STANDARD.floor()));
        }
    }

    #[test]
    fn the_first_parameter_out_of_range_is_reported() {
        let bounds = Bounds::STANDARD;
        let error = bounds.check(&Params::new(0, 0, 0)).unwrap_err();
        assert!(matches!(
            error,
            Error::ParamsOutOfRange {
                param: Param::Parallelism,
                ..
            }
        ));
        let error = bounds.check(&Params::new(0, 0, 1)).unwrap_err();
        assert!(matches!(
            error,
            Error::ParamsOutOfRange {
                param: Param::Memory,
                ..
            }
        ));
        let error = bounds.check(&Params::new(19 * 1024, 0, 1)).unwrap_err();
        assert!(matches!(
            error,
            Error::ParamsOutOfRange {
                param: Param::Iterations,
                ..
            }
        ));
        let error = bounds.check(&Params::new(512 * 1024, 5, 1)).unwrap_err();
        assert_eq!(
            error,
            Error::ParamsOutOfRange {
                param: Param::Work,
                value: 512 * 1024 * 5,
                minimum: 19 * 1024 * 2,
                maximum: 2 * 1024 * 1024,
            }
        );
        bounds.check(&Params::new(512 * 1024, 4, 1)).unwrap();
    }

    #[test]
    fn a_keystore_never_moves_to_less_memory() {
        let [desktop, mobile, web] = Preset::ALL.map(Preset::params);
        // Across platforms: up in memory only.
        assert!(web.is_weaker_than(&desktop) && web.is_weaker_than(&mobile));
        assert!(mobile.is_weaker_than(&desktop));
        assert!(!desktop.is_weaker_than(&web) && !mobile.is_weaker_than(&web));
        assert!(!desktop.is_weaker_than(&mobile));
        // A preset that rises in passes only, or in memory only.
        assert!(desktop.is_weaker_than(&Params::new(256 * 1024, 4, 4)));
        assert!(desktop.is_weaker_than(&Params::new(384 * 1024, 2, 4)));
        // Lanes play no part, and equal parameters are not weaker.
        for preset in Preset::ALL {
            let params = preset.params();
            assert!(!params.is_weaker_than(&params));
            assert!(!params.is_weaker_than(&Params::new(
                params.memory_kib(),
                params.iterations(),
                1
            )));
        }
    }

    #[test]
    fn a_lower_memory_ceiling_never_rises_or_crosses_the_floor() {
        let standard = Bounds::STANDARD;
        let tight = standard.with_memory_ceiling_kib(64 * 1024);
        assert_eq!(tight.ceiling().memory_kib(), 64 * 1024);
        assert!(tight.check(&Preset::Web.params()).is_ok());
        assert!(tight.check(&Preset::Mobile.params()).is_err());
        assert_eq!(standard.with_memory_ceiling_kib(u32::MAX), standard);
        assert_eq!(
            standard.with_memory_ceiling_kib(1).ceiling().memory_kib(),
            standard.floor().memory_kib()
        );
    }

    #[test]
    fn test_bounds_keep_argon2s_memory_per_lane() {
        let bounds = Bounds::TEST;
        assert!(bounds.check(&Params::new(8, 1, 1)).is_ok());
        assert!(bounds.check(&Params::new(16, 1, 2)).is_ok());
        assert_eq!(
            bounds.check(&Params::new(15, 1, 2)),
            Err(Error::ParamsOutOfRange {
                param: Param::Memory,
                value: 15,
                minimum: 16,
                maximum: 512 * 1024,
            })
        );
    }
}
