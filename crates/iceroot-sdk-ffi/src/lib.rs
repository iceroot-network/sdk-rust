//! JSON exports over the shared SDK bindings, hosted by Go through WASI.
//!
//! The host owns one serialized session. Keys stay here until released or the instance closes.
//! The ABI accepts no caller-supplied pointers: allocation owns the one input buffer, call reads
//! it, and clear wipes both buffers. Results pack an output pointer in the high 32 bits and its
//! length in the low 32 bits. Requests and responses are limited to 16 MiB.

mod abi;
mod dispatch;
pub use dispatch::Session;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests;
