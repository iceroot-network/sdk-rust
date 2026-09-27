//! The sign-in message, version 1: built by a website's server, checked by the wallet.

use iceroot_sdk::signin::{self, SignInExpected, SignInRequest};
use iceroot_sdk::{Profile, PublicKey};
use serde_json::json;

use crate::error::{BindingError, Result};
use crate::json;

/// The sign-in message of `request` on the network of `profile`. `request` is JSON:
/// `{ origin, publicKey, nonce, issuedAt, expiresAt }`, the times in whole seconds since
/// 1970-01-01T00:00:00Z.
pub fn build_sign_in(profile: &Profile, request: &str) -> Result<String> {
    let request = json::parse_object(request, "the sign-in request")?;
    let public_key = PublicKey::from_hex(json::string(&request, "publicKey")?)
        .map_err(|_| BindingError::new("InvalidKey", "the public key is not a valid key"))?;
    let seconds = |key: &str| -> Result<i64> {
        json::member(&request, key)?.as_i64().ok_or_else(|| {
            BindingError::argument(format!("{key} is not a whole number of seconds"))
        })
    };
    Ok(signin::build(
        profile,
        &SignInRequest {
            origin: json::string(&request, "origin")?,
            public_key: &public_key,
            nonce: json::string(&request, "nonce")?,
            issued_at: seconds("issuedAt")?,
            expires_at: seconds("expiresAt")?,
        },
    )?)
}

/// The fields of the sign-in `message` after every check, at the time `now_ms` (milliseconds since
/// 1970-01-01T00:00:00Z). `expected` is JSON: `{ origin?, publicKey?, address? }`, the fields the
/// reader expects. Returns JSON: `{ origin, uri, network, publicKey, address, nonce, issuedAtMs,
/// expiresAtMs }`; a refusal is `InvalidSignIn` with the reason.
pub fn parse_sign_in(
    profile: &Profile,
    message: &str,
    expected: &str,
    now_ms: f64,
) -> Result<String> {
    let expected = json::parse_object(expected, "the expected fields")?;
    if !now_ms.is_finite() || now_ms.fract() != 0.0 || now_ms.abs() > 9_007_199_254_740_991.0 {
        return Err(BindingError::argument(
            "now is not a whole number of milliseconds",
        ));
    }
    // The check above keeps the value within the integers a double holds exactly.
    #[allow(clippy::cast_possible_truncation)]
    let now_ms = now_ms as i64;
    let challenge = signin::parse(
        profile,
        message,
        &SignInExpected {
            origin: json::optional_string(&expected, "origin")?,
            public_key: json::optional_string(&expected, "publicKey")?,
            address: json::optional_string(&expected, "address")?,
        },
        now_ms,
    )?;
    Ok(json!({
        "origin": challenge.origin,
        "uri": challenge.uri,
        "network": challenge.network,
        "publicKey": challenge.public_key,
        "address": challenge.address,
        "nonce": challenge.nonce,
        "issuedAtMs": challenge.issued_at_ms,
        "expiresAtMs": challenge.expires_at_ms,
    })
    .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Key;
    use serde_json::Value;

    #[test]
    fn build_then_parse() {
        let profile = crate::profile::from_json(
            r#"{"id":"devnet","backend":"solar-compat","api":{"relays":[]},"chain":{"networkByte":90},"keyScheme":"bip32-secp256k1"}"#,
        )
        .unwrap();
        let key = Key::from_legacy_passphrase(&profile, "probe passphrase".to_owned()).unwrap();
        let public_key = hex::encode(key.public_key().unwrap());
        let nonce = "ab".repeat(32);
        let message = build_sign_in(
            &profile,
            &json!({
                "origin": "https://validators.example",
                "publicKey": public_key,
                "nonce": nonce,
                "issuedAt": 1_790_000_000,
                "expiresAt": 1_790_000_300,
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(message.lines().count(), 12);
        let expected =
            json!({ "origin": "https://validators.example", "address": key.address().unwrap() })
                .to_string();
        let fields: Value = serde_json::from_str(
            &parse_sign_in(&profile, &message, &expected, 1_790_000_010_000.0).unwrap(),
        )
        .unwrap();
        assert_eq!(fields["nonce"], nonce);
        assert_eq!(fields["network"], "heartwood-devnet-v90");
        let late = parse_sign_in(&profile, &message, &expected, 1_790_001_000_000.0).unwrap_err();
        assert_eq!(late.code(), "InvalidSignIn");
        let other = json!({ "origin": "https://other.example" }).to_string();
        assert_eq!(
            parse_sign_in(&profile, &message, &other, 1_790_000_010_000.0)
                .unwrap_err()
                .code(),
            "InvalidSignIn"
        );
        assert_eq!(
            parse_sign_in(&profile, &message, "{}", f64::NAN)
                .unwrap_err()
                .code(),
            "InvalidArgument"
        );
    }
}
