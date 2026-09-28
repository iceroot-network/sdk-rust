//! Errors that cross the boundary.
//!
//! A [`BindingError`] carries a stable code, a message and structured details. A binding hands it
//! to its host as the host's own error: the WebAssembly module as a JavaScript `Error` whose
//! `name` is the code and whose `details` object carries the fields, the Tauri plugin as the
//! rejection of the call. Errors of the core, the vote library and the keystore keep their crate's
//! code and details exactly; the bindings add only `InvalidArgument` (a code the core also raises,
//! for an argument whose value it refuses), for a call whose arguments do not have the documented
//! shape, and raise the core's `InvalidProfile` for a profile they cannot read. The TypeScript wrappers map every code to their own error classes, so the codes are part
//! of the contract between the two halves.

use iceroot_sdk::Error;
use serde_json::{Value, json};

/// An error with a stable code, a message and structured details.
#[derive(Debug, Clone, PartialEq)]
pub struct BindingError {
    code: &'static str,
    message: String,
    details: Value,
}

impl BindingError {
    /// An error with `code`, `message` and no details.
    pub fn new(code: &'static str, message: impl Into<String>) -> BindingError {
        BindingError {
            code,
            message: message.into(),
            details: json!({}),
        }
    }

    /// An error of another crate of the SDK, with its stable code and structured details.
    pub fn with_details(
        code: &'static str,
        message: impl Into<String>,
        details: Value,
    ) -> BindingError {
        BindingError {
            code,
            message: message.into(),
            details,
        }
    }

    /// A call whose arguments do not have the documented shape.
    pub fn argument(message: impl Into<String>) -> BindingError {
        BindingError::new("InvalidArgument", message)
    }

    /// A network profile the bindings cannot use.
    pub fn profile(message: impl Into<String>) -> BindingError {
        BindingError::new("InvalidProfile", message)
    }

    /// The stable code.
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// The human-readable message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The structured details, a JSON object.
    pub fn details(&self) -> &Value {
        &self.details
    }
}

impl From<Error> for BindingError {
    fn from(error: Error) -> BindingError {
        BindingError {
            code: error.code().as_str(),
            message: error.to_string(),
            details: error.details(),
        }
    }
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for BindingError {}

/// A JavaScript `Error` whose `name` is the code and whose `details` property is the structured
/// details, for the WebAssembly module's exports (feature `wasm-bindgen`).
#[cfg(feature = "wasm-bindgen")]
impl From<BindingError> for wasm_bindgen::JsValue {
    fn from(error: BindingError) -> wasm_bindgen::JsValue {
        let js_error = js_sys::Error::new(&error.message);
        js_error.set_name(error.code);
        // The details are a JSON object the SDK made, so parsing cannot fail; a failure would only
        // drop the details, never the error itself.
        let details = js_sys::JSON::parse(&error.details.to_string())
            .unwrap_or_else(|_| js_sys::Object::new().into());
        let _ = js_sys::Reflect::set(
            &js_error,
            &wasm_bindgen::JsValue::from_str("details"),
            &details,
        );
        js_error.into()
    }
}

/// The result type of every fallible binding.
pub type Result<T> = std::result::Result<T, BindingError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_errors_keep_their_code_and_details() {
        let error = BindingError::from(Error::PhraseTooShort {
            words: 12,
            minimum: 18,
        });
        assert_eq!(error.code(), "PhraseTooShort");
        assert_eq!(error.details(), &json!({ "words": 12, "minimum": 18 }));
        assert_eq!(BindingError::argument("x").code(), "InvalidArgument");
        assert_eq!(BindingError::profile("x").details(), &json!({}));
    }
}
