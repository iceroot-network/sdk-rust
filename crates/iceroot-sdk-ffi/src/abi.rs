use crate::Session;
use std::cell::RefCell;
use zeroize::Zeroize;

const MAX_BYTES: usize = 16 * 1024 * 1024;
#[derive(Default)]
struct State {
    session: Session,
    input: Vec<u8>,
    output: Vec<u8>,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }

// These exports only exchange offsets into buffers owned here. No offset received from a host
// is dereferenced, and an allocation invalidates any earlier input or output view.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn sdk_alloc(len: u32) -> u32 {
    STATE.with_borrow_mut(|s| {
        s.input.zeroize();
        s.output.zeroize();
        if len == 0 || len as usize > MAX_BYTES {
            return 0;
        }
        s.input.resize(len as usize, 0);
        s.input.as_mut_ptr() as usize as u32
    })
}
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn sdk_call() -> u64 {
    STATE.with_borrow_mut(|s| {
        s.output.zeroize();
        s.output = s.session.call(&s.input).into_bytes();
        s.input.zeroize();
        if s.output.len() > MAX_BYTES {
            s.output.zeroize();
            return 0;
        }
        ((s.output.as_ptr() as usize as u64) << 32) | s.output.len() as u64
    })
}
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn sdk_clear() {
    STATE.with_borrow_mut(|s| {
        s.input.zeroize();
        s.output.zeroize();
    });
}
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn sdk_wipe_stack() {
    let mut stack = [0u8; 65536];
    stack.zeroize();
    std::hint::black_box(&mut stack);
}
