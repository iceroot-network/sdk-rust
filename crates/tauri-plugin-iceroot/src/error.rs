//! The refusals of the plugin's commands.

use iceroot_sdk_bindings::BindingError;
use serde::Serialize;
use serde_json::{Value, json};

/// A refusal of a command, as the webview receives it: the stable code of the SDK error, its
/// message and its structured details. The TypeScript guest code turns it into the SDK's own
/// error class of that code, as the WebAssembly module's errors are.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Error {
    code: &'static str,
    message: String,
    details: Value,
}

impl Error {
    /// The stable code, one of the SDK's error codes.
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

    /// A call whose arguments do not have the documented shape.
    pub(crate) fn argument(message: impl Into<String>) -> Error {
        BindingError::argument(message).into()
    }

    /// A key handle that was released, or never belonged to the calling webview.
    pub(crate) fn key_released() -> Error {
        iceroot_sdk::Error::KeyReleased.into()
    }

    /// A command whose page loaded another page (or whose window closed) before it was done: what
    /// it made is dropped, and nobody is left to receive this refusal.
    pub(crate) fn page_gone() -> Error {
        Error::argument("the page that made the call has gone: it loaded another page")
    }

    /// A relay the application's capabilities do not allow the plugin to reach.
    pub(crate) fn relay_not_allowed(relay: &str) -> Error {
        Error {
            code: "InvalidProfile",
            message: format!(
                "the relay {relay} is not allowed: add it to the iceroot plugin's scope in the \
                 application's capabilities"
            ),
            details: json!({ "relay": relay, "reason": "not-allowed" }),
        }
    }
}

impl From<BindingError> for Error {
    fn from(error: BindingError) -> Error {
        Error {
            code: error.code(),
            message: error.message().to_owned(),
            details: error.details().clone(),
        }
    }
}

impl From<iceroot_sdk::Error> for Error {
    fn from(error: iceroot_sdk::Error) -> Error {
        BindingError::from(error).into()
    }
}

impl From<iceroot_sdk::api::ApiError> for Error {
    fn from(error: iceroot_sdk::api::ApiError) -> Error {
        iceroot_sdk::Error::from(error).into()
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

/// The result of every command.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_keep_the_core_code_and_details() {
        let error = Error::from(iceroot_sdk::Error::PhraseTooShort {
            words: 12,
            minimum: 18,
        });
        assert_eq!(error.code(), "PhraseTooShort");
        assert_eq!(error.details(), &json!({ "words": 12, "minimum": 18 }));
        let text = serde_json::to_value(&error).unwrap();
        assert_eq!(text["code"], "PhraseTooShort");
        assert_eq!(text["details"]["minimum"], 18);
        assert_eq!(Error::key_released().code(), "KeyReleased");
        assert_eq!(Error::argument("x").code(), "InvalidArgument");
        let refused = Error::relay_not_allowed("http://h/api");
        assert_eq!(refused.details()["reason"], "not-allowed");
    }
}
