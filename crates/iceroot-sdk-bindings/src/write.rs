//! A JSON writer for the vote library's and the keystore's answers.
//!
//! The answers are written in one pass into one string, rather than built as a `serde_json::Value`
//! tree and then serialized: per field that is a few calls of a handful of small functions instead
//! of a map insertion through serde's machinery, which keeps the WebAssembly module small.

use core::fmt::Write as _;

/// JSON text being written. Keys are written by [`Json::key`] and the typed helpers; commas are
/// placed automatically.
pub(crate) struct Json {
    out: String,
    comma: bool,
}

impl Json {
    /// An empty text.
    pub(crate) fn new() -> Json {
        Json {
            out: String::with_capacity(256),
            comma: false,
        }
    }

    /// The text written.
    pub(crate) fn finish(self) -> String {
        self.out
    }

    fn separate(&mut self) {
        if self.comma {
            self.out.push(',');
        }
    }

    fn after_value(&mut self) -> &mut Json {
        self.comma = true;
        self
    }

    /// `{`, as a value.
    pub(crate) fn open(&mut self) -> &mut Json {
        self.separate();
        self.out.push('{');
        self.comma = false;
        self
    }

    /// `}`.
    pub(crate) fn close(&mut self) -> &mut Json {
        self.out.push('}');
        self.after_value()
    }

    /// `[`, as a value.
    pub(crate) fn open_list(&mut self) -> &mut Json {
        self.separate();
        self.out.push('[');
        self.comma = false;
        self
    }

    /// `]`.
    pub(crate) fn close_list(&mut self) -> &mut Json {
        self.out.push(']');
        self.after_value()
    }

    /// `"key":`, before a value.
    pub(crate) fn key(&mut self, key: &str) -> &mut Json {
        self.separate();
        self.quoted(key);
        self.out.push(':');
        self.comma = false;
        self
    }

    /// A string value.
    pub(crate) fn string(&mut self, value: &str) -> &mut Json {
        self.separate();
        self.quoted(value);
        self.after_value()
    }

    /// A number value.
    pub(crate) fn number(&mut self, value: u64) -> &mut Json {
        self.separate();
        let _ = write!(self.out, "{value}");
        self.after_value()
    }

    /// A 64- or 128-bit integer as the wrapper reads it: a decimal string.
    pub(crate) fn big(&mut self, value: u128) -> &mut Json {
        self.separate();
        let _ = write!(self.out, "\"{value}\"");
        self.after_value()
    }

    /// `true` or `false`.
    pub(crate) fn boolean(&mut self, value: bool) -> &mut Json {
        self.separate();
        self.out.push_str(if value { "true" } else { "false" });
        self.after_value()
    }

    /// `null`.
    pub(crate) fn null(&mut self) -> &mut Json {
        self.separate();
        self.out.push_str("null");
        self.after_value()
    }

    /// JSON text that is already written, as a value.
    pub(crate) fn raw(&mut self, text: &str) -> &mut Json {
        self.separate();
        self.out.push_str(text);
        self.after_value()
    }

    /// `"key":"value"`.
    pub(crate) fn field_str(&mut self, key: &str, value: &str) -> &mut Json {
        self.key(key).string(value)
    }

    /// `"key":value`, a number.
    pub(crate) fn field_num(&mut self, key: &str, value: impl Into<u64>) -> &mut Json {
        self.key(key).number(value.into())
    }

    /// `"key":"value"`, a decimal string.
    pub(crate) fn field_big(&mut self, key: &str, value: impl Into<u128>) -> &mut Json {
        self.key(key).big(value.into())
    }

    /// `"key":true` or `false`.
    pub(crate) fn field_bool(&mut self, key: &str, value: bool) -> &mut Json {
        self.key(key).boolean(value)
    }

    /// `"key":value` or `null`, a number.
    pub(crate) fn field_opt_num(&mut self, key: &str, value: Option<impl Into<u64>>) -> &mut Json {
        self.key(key);
        match value {
            Some(value) => self.number(value.into()),
            None => self.null(),
        }
    }

    /// `"key":"value"` or `null`, a decimal string.
    pub(crate) fn field_opt_big(&mut self, key: &str, value: Option<impl Into<u128>>) -> &mut Json {
        self.key(key);
        match value {
            Some(value) => self.big(value.into()),
            None => self.null(),
        }
    }

    /// `"key":"value"` or `null`.
    pub(crate) fn field_opt_str(&mut self, key: &str, value: Option<&str>) -> &mut Json {
        self.key(key);
        match value {
            Some(value) => self.string(value),
            None => self.null(),
        }
    }

    fn quoted(&mut self, text: &str) {
        self.out.push('"');
        for c in text.chars() {
            match c {
                '"' => self.out.push_str("\\\""),
                '\\' => self.out.push_str("\\\\"),
                '\n' => self.out.push_str("\\n"),
                c if u32::from(c) < 0x20 => {
                    let _ = write!(self.out, "\\u{:04x}", u32::from(c));
                }
                c => self.out.push(c),
            }
        }
        self.out.push('"');
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn writes_valid_json() {
        let mut json = Json::new();
        json.open()
            .field_str("name", "a \"quoted\" \\ name\n\u{1}\u{7f}é")
            .field_num("n", 7u32)
            .field_big("big", u128::MAX)
            .field_opt_num("none", None::<u32>)
            .field_opt_str("some", Some("x"))
            .field_bool("yes", true)
            .key("list")
            .open_list();
        json.open().close();
        json.number(1).null().open_list().close_list();
        json.close_list().key("raw").raw("{\"a\":[]}").close();
        let value: Value = serde_json::from_str(&json.finish()).unwrap();
        assert_eq!(
            value,
            json!({
                "name": "a \"quoted\" \\ name\n\u{1}\u{7f}é", "n": 7, "big": u128::MAX.to_string(),
                "none": null, "some": "x", "yes": true, "list": [{}, 1, null, []], "raw": { "a": [] },
            })
        );
    }
}
