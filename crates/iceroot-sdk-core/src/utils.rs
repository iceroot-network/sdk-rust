//! Small helpers.

/// Whether `text` is non-empty and only lowercase hex digits.
pub(crate) fn is_lower_hex(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_hex() {
        assert!(is_lower_hex("00ff"));
        assert!(!is_lower_hex("00FF"));
        assert!(!is_lower_hex(""));
        assert!(!is_lower_hex("0g"));
    }
}
