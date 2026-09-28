//! The IceRoot SDK as a Tauri 2 plugin, for the desktop and mobile wallets.
//!
//! The plugin is the native implementation of the SDK's TypeScript interface: the application's
//! webview imports `@iceroot-network/sdk/tauri` instead of `@iceroot-network/sdk`, and the same
//! calls run here, in Rust, instead of in WebAssembly inside the webview.
//!
//! - **Keys stay in Rust.** Keys from recovery phrases, legacy passphrases and keystores, and the
//!   Solar keys of ownership proofs, are held by the plugin; the webview holds opaque numbers and
//!   receives public keys, addresses and signatures only. Keys are held for the webview that
//!   opened them, and wiped when it releases them, when it loads another page and when its window
//!   closes (the window it was in when it last opened a key, loaded a chain or connected).
//! - **Drafts cross as serialized bytes.** A draft is built by the core, and signing reads its
//!   serialized form again under the network's pinned profile, so what is signed is what the plugin
//!   read, never what the webview said it was.
//! - **Node requests leave from Rust.** The SDK's node API client, the same request builders and
//!   answer decoders as in WebAssembly, over reqwest, to the relays the application's
//!   capabilities allow and nowhere else: a redirect is never followed ([`network`]); a proxy is
//!   used only when the application's environment names one (`HTTP_PROXY` and the like). The
//!   webview's content security policy needs no node origin and no `'wasm-unsafe-eval'`.
//! - **One implementation.** Arguments are read and answers written by `iceroot-sdk-bindings`,
//!   the code the WebAssembly module uses, and every key, address, signature, transaction, vote
//!   selection, keystore and proof comes from the SDK's core and through it from
//!   `heartwood-crypto`.
//!
//! # Use
//!
//! ```no_run
//! fn register<R: tauri::Runtime>(builder: tauri::Builder<R>) -> tauri::Builder<R> {
//!     // In the application: tauri::Builder::default().plugin(tauri_plugin_iceroot::init())
//!     builder.plugin(tauri_plugin_iceroot::init())
//! }
//! ```
//!
//! The application's capability grants the plugin's commands (`iceroot:default`, every command
//! but `net_connect`) and the relays it may reach, as an `allow` scope of
//! `iceroot:allow-net-connect`:
//!
//! ```json
//! {
//!   "identifier": "main",
//!   "windows": ["main"],
//!   "permissions": [
//!     "iceroot:default",
//!     { "identifier": "iceroot:allow-net-connect", "allow": [{ "url": "http://127.0.0.1:6003/api" }] }
//!   ]
//! }
//! ```

use tauri::plugin::{Builder, TauriPlugin};
use tauri::webview::PageLoadEvent;
use tauri::{Manager, RunEvent, Runtime, WindowEvent};

mod codec;
mod commands;
mod error;
pub mod network;
#[cfg(feature = "test-seams")]
mod seams;
mod state;

pub use crate::codec::Secret;
pub use crate::error::{Error, Result};
pub use crate::state::Iceroot;

/// The plugin's commands, with the test seams' in the test build.
macro_rules! handler {
    ($($seam:path),* $(,)?) => {
        tauri::generate_handler![
            commands::version,
            commands::profile_capabilities,
            commands::profile_message_network,
            commands::profile_message_algorithm,
            commands::phrase_generate,
            commands::phrase_check,
            commands::address_parse,
            commands::address_from_public_key,
            commands::amount_parse,
            commands::amount_format,
            commands::message_verify,
            commands::signin_build,
            commands::signin_parse,
            commands::key_from_phrase,
            commands::key_from_legacy_passphrase,
            commands::key_from_keystore,
            commands::key_sign_message,
            commands::key_release,
            commands::chain_load,
            commands::chain_stage_at,
            commands::chain_rules,
            commands::chain_economics,
            commands::chain_free,
            commands::draft_build,
            commands::draft_deserialize,
            commands::draft_online_facts,
            commands::draft_sign,
            commands::signed_deserialize,
            commands::signed_from_json,
            commands::signed_decode,
            commands::signed_verify_second_signature,
            commands::net_connect,
            commands::net_read,
            commands::net_node_configuration,
            commands::net_submit,
            commands::net_close,
            commands::vote_call,
            commands::vote_rules_at,
            commands::vote_snapshot_from_validators,
            commands::keystore_encrypt,
            commands::keystore_decrypt,
            commands::keystore_inspect,
            commands::keystore_change_password,
            commands::keystore_reencrypt,
            commands::keystore_armor,
            commands::keystore_dearmor,
            commands::keystore_check_params,
            commands::keystore_is_weaker,
            commands::ownership_call,
            commands::proof_key_from_passphrase,
            commands::proof_key_sign,
            commands::proof_key_release,
            $($seam,)*
        ]
    };
}

/// The plugin, named `iceroot`: register it with `tauri::Builder::plugin`.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    let builder = Builder::new("iceroot");
    #[cfg(not(feature = "test-seams"))]
    let builder = builder.invoke_handler(handler!());
    #[cfg(feature = "test-seams")]
    let builder = builder.invoke_handler(handler!(
        seams::seam_sha256,
        seams::seam_key_sign_message_with_aux,
        seams::seam_draft_sign_with_aux,
        seams::seam_proof_key_sign_with_aux,
        seams::seam_vote_library,
        seams::seam_vote_snapshot_from_relay,
        seams::seam_keystore_constants,
        seams::seam_keystore_encrypt_with_salt_and_nonce,
        seams::seam_keystore_decrypt_with_bounds,
        seams::seam_keystore_check_params_with_bounds,
    ));
    builder
        .setup(|app, _api| {
            app.manage(Iceroot::default());
            Ok(())
        })
        // A page that starts loading in a webview drops everything the previous page held there.
        .on_page_load(|webview, payload| {
            if payload.event() == PageLoadEvent::Started
                && let Some(state) = webview.try_state::<Iceroot>()
            {
                state.clear(webview.label());
            }
        })
        // A destroyed window drops everything its webviews held: the webview with its label and
        // any other webview recorded in it (a multi-webview window).
        .on_event(|app, event| {
            if let RunEvent::WindowEvent {
                label,
                event: WindowEvent::Destroyed,
                ..
            } = event
                && let Some(state) = app.try_state::<Iceroot>()
            {
                state.clear_window(label);
            }
        })
        .build()
}

#[cfg(test)]
mod tests {
    /// The default permission set lets a page open keys from a keystore, never read the recovery
    /// phrase out of one: an application that shows the phrase grants `keystore_decrypt` itself.
    #[test]
    fn the_default_permission_set_never_hands_the_page_a_phrase_from_a_keystore() {
        let default = include_str!("../permissions/default.toml");
        assert!(default.contains("\"allow-key-from-keystore\""));
        assert!(!default.contains("\"allow-keystore-decrypt\""));
    }
}
