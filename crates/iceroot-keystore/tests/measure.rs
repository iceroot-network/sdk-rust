//! Timings of the presets: one decryption (the key derivation dominates) per preset, five times,
//! reported as the median. Ignored by default; run it on a release build:
//!
//! ```sh
//! cargo test -p iceroot-keystore --release --test measure -- --ignored --nocapture
//! CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
//!   cargo test -p iceroot-keystore --release --target wasm32-unknown-unknown --test measure \
//!   -- --include-ignored
//! ```
//!
//! The crate's README records the results and the presets chosen from them.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use iceroot_keystore::{Params, Payload, Preset, SystemRng, decrypt, encrypt};

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn now_ms() -> f64 {
    js_sys::Date::now()
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn now_ms() -> f64 {
    use std::sync::LazyLock;
    use std::time::Instant;
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    START.elapsed().as_secs_f64() * 1000.0
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
macro_rules! report {
    ($($arg:tt)*) => { wasm_bindgen_test::console_log!($($arg)*) };
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
macro_rules! report {
    ($($arg:tt)*) => { println!($($arg)*) };
}

const RUNS: usize = 5;

fn median_ms(params: Params) -> (f64, f64, f64) {
    let payload = Payload::bip39_entropy(&[0x33; 32]).unwrap();
    let keystore = encrypt(&payload, "measure", params, &mut SystemRng).unwrap();
    let mut times = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let start = now_ms();
        let opened = decrypt(&keystore, "measure").unwrap();
        times.push(now_ms() - start);
        assert_eq!(opened, payload);
    }
    times.sort_by(f64::total_cmp);
    (times[RUNS / 2], times[0], times[RUNS - 1])
}

#[test]
#[ignore = "timings; run on a release build with --ignored"]
fn presets() {
    let target = if cfg!(target_arch = "wasm32") {
        "wasm32"
    } else {
        "native"
    };
    let mut rows = Vec::new();
    for (name, params) in [
        ("desktop", Preset::Desktop.params()),
        ("mobile", Preset::Mobile.params()),
        ("web", Preset::Web.params()),
        ("floor", Params::new(19 * 1024, 2, 1)),
    ] {
        let (median, min, max) = median_ms(params);
        rows.push(format!(
            "{target} {name:8} m={:>4} MiB t={} p={}: median {median:>5.0} ms (min {min:.0}, max {max:.0})",
            params.memory_kib() / 1024,
            params.iterations(),
            params.parallelism(),
        ));
    }
    for row in rows {
        report!("{}", row);
    }
}
