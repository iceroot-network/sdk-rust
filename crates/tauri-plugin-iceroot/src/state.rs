//! What the plugin holds for each webview: keys, Solar keys, loaded chains and connected networks.
//!
//! Every value is held for the webview that made it and is reachable only from that webview,
//! through an opaque number. When the webview loads a page (a navigation or a reload) or its
//! window is destroyed, everything it held is dropped, which wipes its keys: a key never outlives
//! the page that opened it. A command that was still working when its page went away (deriving a
//! key, connecting) finds a new page and drops what it made instead of handing it over ([`Page`]).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use iceroot_sdk::Chain;
use iceroot_sdk_bindings::keys::Key;
use iceroot_sdk_bindings::ownership::ProofKey;

use crate::error::{Error, Result};
use crate::network::Session;

/// The page a command was called from: the webview's label and the number of the page it showed
/// when the command started. Values are held only for the page that is still there.
#[derive(Debug, Clone)]
pub(crate) struct Page {
    label: String,
    number: u64,
}

/// The values one page of a webview holds.
#[derive(Default)]
pub(crate) struct Handles {
    /// The page's number, never used for another page in this process.
    page: u64,
    pub(crate) keys: HashMap<u64, Key>,
    pub(crate) proof_keys: HashMap<u64, ProofKey>,
    pub(crate) chains: HashMap<u64, Arc<Chain>>,
    pub(crate) sessions: HashMap<u64, Arc<Session>>,
}

/// The plugin's state: the handles of every webview.
#[derive(Default)]
pub struct Iceroot {
    next: AtomicU64,
    webviews: Mutex<HashMap<String, Handles>>,
}

impl Iceroot {
    /// A new number for a handle, never used before in this process.
    pub(crate) fn next_id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed).saturating_add(1)
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Handles>> {
        // A panic while the lock was held leaves the maps consistent: every change is one
        // insertion or removal.
        self.webviews.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `f` with the handles of the webview `label`.
    pub(crate) fn with<T>(&self, label: &str, f: impl FnOnce(&mut Handles) -> T) -> T {
        let mut webviews = self.lock();
        let handles = webviews.entry(label.to_owned()).or_insert_with(|| Handles {
            page: self.next_id(),
            ..Handles::default()
        });
        f(handles)
    }

    /// The page the webview `label` shows now, for a command that holds a value when it is done.
    pub(crate) fn page(&self, label: &str) -> Page {
        Page {
            label: label.to_owned(),
            number: self.with(label, |handles| handles.page),
        }
    }

    /// Runs `insert` with the handles of `page` if the webview still shows it, and returns a new
    /// number for the value; otherwise the value is dropped (a key is wiped) and the refusal is
    /// `gone`.
    fn hold<T>(
        &self,
        page: &Page,
        value: T,
        insert: impl FnOnce(&mut Handles, u64, T),
        gone: impl FnOnce() -> Error,
    ) -> Result<u64> {
        let id = self.next_id();
        let held = self.with(&page.label, |handles| {
            if handles.page == page.number {
                insert(handles, id, value);
                None
            } else {
                Some(value)
            }
        });
        match held {
            None => Ok(id),
            Some(value) => {
                drop(value);
                Err(gone())
            }
        }
    }

    /// Drops everything the webview `label` holds; its keys are wiped.
    pub(crate) fn clear(&self, label: &str) {
        let removed = self.lock().remove(label);
        drop(removed);
    }

    /// Holds `key` for `page` and returns its number; a page that has gone gets `KeyReleased`, and
    /// the key is wiped.
    pub(crate) fn add_key(&self, page: &Page, key: Key) -> Result<u64> {
        self.hold(
            page,
            key,
            |handles, id, key| drop(handles.keys.insert(id, key)),
            Error::key_released,
        )
    }

    /// Runs `f` with the key `id` of the webview `label`; `KeyReleased` when it has none.
    pub(crate) fn with_key<T>(
        &self,
        label: &str,
        id: u64,
        f: impl FnOnce(&Key) -> Result<T>,
    ) -> Result<T> {
        self.with(label, |handles| match handles.keys.get(&id) {
            Some(key) => f(key),
            None => Err(Error::key_released()),
        })
    }

    /// Runs `f` with the keys `first` and, when given, `second` of the webview `label`.
    pub(crate) fn with_keys<T>(
        &self,
        label: &str,
        first: u64,
        second: Option<u64>,
        f: impl FnOnce(&Key, Option<&Key>) -> Result<T>,
    ) -> Result<T> {
        self.with(label, |handles| {
            let key = handles.keys.get(&first).ok_or_else(Error::key_released)?;
            let second = match second {
                Some(id) => Some(handles.keys.get(&id).ok_or_else(Error::key_released)?),
                None => None,
            };
            f(key, second)
        })
    }

    /// Drops the key `id` of the webview `label`, which wipes it. Nothing happens when it has none.
    pub(crate) fn release_key(&self, label: &str, id: u64) {
        let removed = self.with(label, |handles| handles.keys.remove(&id));
        drop(removed);
    }

    /// Holds a Solar key for `page` and returns its number; a page that has gone gets
    /// `KeyReleased`, and the key is wiped.
    pub(crate) fn add_proof_key(&self, page: &Page, key: ProofKey) -> Result<u64> {
        self.hold(
            page,
            key,
            |handles, id, key| drop(handles.proof_keys.insert(id, key)),
            Error::key_released,
        )
    }

    /// Runs `f` with the Solar key `id` of the webview `label`; `KeyReleased` when it has none.
    pub(crate) fn with_proof_key<T>(
        &self,
        label: &str,
        id: u64,
        f: impl FnOnce(&ProofKey) -> Result<T>,
    ) -> Result<T> {
        self.with(label, |handles| match handles.proof_keys.get(&id) {
            Some(key) => f(key),
            None => Err(Error::key_released()),
        })
    }

    /// Drops the Solar key `id` of the webview `label`, which wipes it.
    pub(crate) fn release_proof_key(&self, label: &str, id: u64) {
        let removed = self.with(label, |handles| handles.proof_keys.remove(&id));
        drop(removed);
    }

    /// Holds `chain` for `page` and returns its number.
    pub(crate) fn add_chain(&self, page: &Page, chain: Arc<Chain>) -> Result<u64> {
        self.hold(
            page,
            chain,
            |handles, id, chain| drop(handles.chains.insert(id, chain)),
            Error::page_gone,
        )
    }

    /// The chain `id` of the webview `label`.
    pub(crate) fn chain(&self, label: &str, id: u64) -> Result<Arc<Chain>> {
        self.with(label, |handles| handles.chains.get(&id).cloned())
            .ok_or_else(|| Error::argument("not a chain this page loaded, or one it freed"))
    }

    /// Drops the chain `id` of the webview `label`.
    pub(crate) fn free_chain(&self, label: &str, id: u64) {
        let removed = self.with(label, |handles| handles.chains.remove(&id));
        drop(removed);
    }

    /// Holds a connected network and its chain for `page`, and returns their numbers.
    pub(crate) fn add_session(&self, page: &Page, session: Arc<Session>) -> Result<(u64, u64)> {
        let chain = Arc::clone(&session.chain);
        let chain_id = self.next_id();
        let session_id = self.hold(
            page,
            session,
            |handles, id, session| {
                drop(handles.chains.insert(chain_id, chain));
                drop(handles.sessions.insert(id, session));
            },
            Error::page_gone,
        )?;
        Ok((session_id, chain_id))
    }

    /// The connected network `id` of the webview `label`.
    pub(crate) fn session(&self, label: &str, id: u64) -> Result<Arc<Session>> {
        self.with(label, |handles| handles.sessions.get(&id).cloned())
            .ok_or_else(|| {
                Error::argument("not a network this page connected to, or one it closed")
            })
    }

    /// Drops the connected network `id` of the webview `label`.
    pub(crate) fn close_session(&self, label: &str, id: u64) {
        let removed = self.with(label, |handles| handles.sessions.remove(&id));
        drop(removed);
    }
}

impl std::fmt::Debug for Iceroot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never shows key material: only how many values each webview holds.
        let webviews = self.lock();
        let mut out = f.debug_map();
        for (label, handles) in webviews.iter() {
            out.entry(
                label,
                &(
                    handles.keys.len(),
                    handles.proof_keys.len(),
                    handles.chains.len(),
                    handles.sessions.len(),
                ),
            );
        }
        out.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> iceroot_sdk::Profile {
        iceroot_sdk_bindings::profile::from_json(
            r#"{"id":"devnet","backend":"solar-compat","api":{"relays":["http://127.0.0.1:4003/api"]},"chain":{"networkByte":90},"keyScheme":"bip32-secp256k1"}"#,
        )
        .unwrap()
    }

    #[test]
    fn keys_belong_to_their_webview_and_go_with_its_page() {
        let state = Iceroot::default();
        let key = Key::from_legacy_passphrase(&profile(), "probe passphrase".to_owned()).unwrap();
        let id = state.add_key(&state.page("main"), key).unwrap();
        let address = state
            .with_key("main", id, |key| Ok(key.address()?))
            .unwrap();
        assert_eq!(address, "dDSccdbPRhfrcbUeFLMbGC1rtnfCsjJcNF");
        // Another webview cannot use it.
        let error = state.with_key("other", id, |_| Ok(())).unwrap_err();
        assert_eq!(error.code(), "KeyReleased");
        // A new page drops it.
        state.clear("main");
        let error = state.with_key("main", id, |_| Ok(())).unwrap_err();
        assert_eq!(error.code(), "KeyReleased");

        let key = Key::from_legacy_passphrase(&profile(), "x".to_owned()).unwrap();
        let second = state.add_key(&state.page("main"), key).unwrap();
        assert_ne!(second, id);
        state.release_key("main", second);
        assert!(state.with_key("main", second, |_| Ok(())).is_err());
        assert!(format!("{state:?}").contains("main"));
    }

    #[test]
    fn a_command_whose_page_went_away_holds_nothing() {
        let state = Iceroot::default();
        // A command starts on a page, which loads another page before the key is derived.
        let page = state.page("main");
        state.clear("main");
        let key = Key::from_legacy_passphrase(&profile(), "late".to_owned()).unwrap();
        assert_eq!(state.add_key(&page, key).unwrap_err().code(), "KeyReleased");
        let chain = Arc::new(
            iceroot_sdk_bindings::chain::load(
                &profile(),
                include_str!("../../iceroot-sdk-bindings/tests/data/devnet-configuration.json"),
            )
            .unwrap(),
        );
        assert!(state.add_chain(&page, Arc::clone(&chain)).is_err());
        assert!(format!("{state:?}").contains("(0, 0, 0, 0)"));
        // The new page holds what it asks for.
        let fresh = state.page("main");
        let id = state.add_chain(&fresh, chain).unwrap();
        assert!(state.chain("main", id).is_ok());
        // A window with the same label later is another page too.
        state.clear("main");
        assert!(state.chain("main", id).is_err());
        assert_ne!(state.page("main").number, fresh.number);
    }
}
