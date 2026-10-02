//! Test seams of the plugin's test build (feature `test-seams`), which no build that ships has:
//! the same seams as the WebAssembly module's test build, so the SDK's TypeScript tests compare
//! the plugin with native Rust byte for byte. Signatures and ownership proofs take fixed
//! auxiliary randomness, keystores the vectors' salts and nonces under the vectors' lowered
//! bounds, and the vote library and the keystore give their constants.

use iceroot_sdk_bindings::draft::fixed_aux;
use iceroot_sdk_bindings::keystore::testing as keystore;
use iceroot_sdk_bindings::vote::testing as vote;
use tauri::{Runtime, State, Webview, command};

use crate::codec::{from_hex, to_hex};
use crate::commands::{SignedInfo, sign_draft};
use crate::error::Result;
use crate::state::Iceroot;

/// The SHA-256 of bytes (hex), as hex.
#[command]
pub(crate) async fn seam_sha256(data: String) -> Result<String> {
    Ok(to_hex(&iceroot_sdk_bindings::messages::sha256(&from_hex(
        &data, "the data",
    )?)))
}

/// A message signature with fixed auxiliary bytes (hex).
#[command]
pub(crate) async fn seam_key_sign_message_with_aux<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    key: u64,
    message: String,
    aux: String,
) -> Result<String> {
    let message = from_hex(&message, "the message")?;
    let aux = fixed_aux(&from_hex(&aux, "the auxiliary bytes")?)?;
    state.with_key(webview.label(), key, |key| {
        Ok(key.sign_message_with(&message, aux)?)
    })
}

/// A serialized draft signed with fixed auxiliary bytes (hex) for every signature.
#[command]
pub(crate) async fn seam_draft_sign_with_aux<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    bytes: String,
    profile: String,
    key: u64,
    second_key: Option<u64>,
    aux: String,
) -> Result<SignedInfo> {
    let aux = fixed_aux(&from_hex(&aux, "the auxiliary bytes")?)?;
    sign_draft(
        &state,
        webview.label(),
        &bytes,
        &profile,
        key,
        second_key,
        aux,
    )
}

/// An ownership proof signed with fixed auxiliary bytes (hex).
#[command]
pub(crate) async fn seam_proof_key_sign_with_aux<R: Runtime>(
    webview: Webview<R>,
    state: State<'_, Iceroot>,
    key: u64,
    message: String,
    now_ms: f64,
    aux: String,
) -> Result<String> {
    let aux = fixed_aux(&from_hex(&aux, "the auxiliary bytes")?)?;
    state.with_proof_key(webview.label(), key, |key| {
        Ok(key.sign_proof_with(&message, now_ms, aux)?)
    })
}

/// The vote library's constants, in JSON.
#[command]
pub(crate) async fn seam_vote_library() -> Result<String> {
    Ok(vote::vote_library())
}

/// A vote snapshot of relay data in the library's relay form, in JSON.
#[command]
pub(crate) async fn seam_vote_snapshot_from_relay(relay: String) -> Result<String> {
    Ok(vote::vote_snapshot_from_relay(&relay)?)
}

/// The keystore format's constants, in JSON.
#[command]
pub(crate) async fn seam_keystore_constants() -> Result<String> {
    Ok(keystore::keystore_constants())
}

/// A keystore (hex) of a raw payload with the given salt and nonce, under `standard` or `test`
/// bounds.
#[command]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn seam_keystore_encrypt_with_salt_and_nonce(
    kind: String,
    secret: String,
    password: String,
    params: String,
    salt: String,
    nonce: String,
    bounds: String,
) -> Result<String> {
    let secret = from_hex(&secret, "the secret")?;
    let salt = from_hex(&salt, "the salt")?;
    let nonce = from_hex(&nonce, "the nonce")?;
    tauri::async_runtime::spawn_blocking(move || {
        keystore::keystore_encrypt_with_salt_and_nonce(
            &kind, &secret, &password, &params, &salt, &nonce, &bounds,
        )
        .map(|stored| to_hex(&stored))
        .map_err(Into::into)
    })
    .await
    .map_err(|error| crate::error::Error::argument(format!("the call did not complete: {error}")))?
}

/// A keystore's payload under `standard` or `test` bounds, in the vectors' JSON.
#[command]
pub(crate) async fn seam_keystore_decrypt_with_bounds(
    keystore: String,
    password: String,
    bounds: String,
) -> Result<String> {
    let stored = from_hex(&keystore, "the keystore")?;
    tauri::async_runtime::spawn_blocking(move || {
        self::keystore::keystore_decrypt_with_bounds(&stored, &password, &bounds)
            .map_err(Into::into)
    })
    .await
    .map_err(|error| crate::error::Error::argument(format!("the call did not complete: {error}")))?
}

/// Checks keystore parameters against `standard` or `test` bounds.
#[command]
pub(crate) async fn seam_keystore_check_params_with_bounds(
    params: String,
    bounds: String,
) -> Result<()> {
    Ok(keystore::keystore_check_params_with_bounds(
        &params, &bounds,
    )?)
}
