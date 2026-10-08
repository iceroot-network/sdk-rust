//! Native JSON-lines endpoint for differential tests.
use std::io::{self, BufRead};
fn main() -> io::Result<()> {
    let mut session = iceroot_sdk_ffi::Session::default();
    for line in io::stdin().lock().lines() {
        println!("{}", session.call(line?.as_bytes()));
    }
    Ok(())
}
