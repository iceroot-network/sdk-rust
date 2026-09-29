use iceroot_sdk::api::{Backoff, MAX_RESPONSE_BYTES};
use iceroot_sdk::{Aux, Profile};
use iceroot_sdk_bindings::{self as b, BindingError, Result, keys::Key};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

/// An isolated set of opaque keys. Calls must be serialized by the host.
#[derive(Default)]
pub struct Session {
    keys: BTreeMap<u32, Box<Key>>,
    next: u32,
}

fn field<'a>(v: &'a Value, name: &str) -> Result<&'a Value> {
    v.get(name)
        .ok_or_else(|| BindingError::argument(format!("missing {name}")))
}
fn text<'a>(v: &'a Value, name: &str) -> Result<&'a str> {
    field(v, name)?
        .as_str()
        .ok_or_else(|| BindingError::argument(format!("{name} must be text")))
}
fn number(v: &Value, name: &str) -> Result<u32> {
    field(v, name)?
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| BindingError::argument(format!("{name} must be a u32")))
}
/// A u32 argument that may be left out, or given as null.
fn optional_number(v: &Value, name: &str) -> Result<Option<u32>> {
    match v.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => number(v, name).map(Some),
    }
}
fn bytes(v: &Value, name: &str) -> Result<Vec<u8>> {
    hex::decode(text(v, name)?).map_err(|_| BindingError::argument(format!("{name} must be hex")))
}
fn secret_bytes(v: &Value, name: &str) -> Result<Zeroizing<Vec<u8>>> {
    bytes(v, name).map(Zeroizing::new)
}
fn raw(v: &Value, name: &str) -> Result<String> {
    Ok(field(v, name)?.to_string())
}
/// A wait in whole milliseconds.
fn milliseconds(wait: Duration) -> u64 {
    u64::try_from(wait.as_millis()).unwrap_or(u64::MAX)
}
fn parsed(s: String) -> Result<Value> {
    serde_json::from_str(&s).map_err(|_| BindingError::argument("invalid JSON response"))
}
fn profile(v: &Value) -> Result<Profile> {
    b::profile::from_json(&raw(v, "profile")?)
}
fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(o) => o.values_mut().for_each(wipe),
        _ => (),
    }
}
fn aux(v: &Value) -> Result<Aux> {
    #[cfg(feature = "test-seams")]
    if v.get("aux").is_some() {
        return b::draft::fixed_aux(&bytes(v, "aux")?);
    }
    if v.get("aux").is_some() {
        return Err(BindingError::argument("fixed randomness is unavailable"));
    }
    Ok(Aux::random())
}

impl Session {
    /// Calls a JSON request `{op, ...arguments}` and returns `{result}` or `{error}`.
    /// Parsed strings are wiped before returning. The host must wipe its original input too.
    pub fn call(&mut self, input: &[u8]) -> String {
        let result = match serde_json::from_slice::<Value>(input) {
            Ok(mut v) => {
                let result = self.dispatch(&v);
                wipe(&mut v);
                result
            }
            Err(_) => Err(BindingError::argument("invalid JSON request")),
        };
        let mut envelope = match result {
            Ok(result) => {
                Value::Object(serde_json::Map::from_iter([("result".to_owned(), result)]))
            }
            Err(e) => {
                json!({"error":{"code":e.code(),"message":e.message(),"details":e.details()}})
            }
        };
        let output = envelope.to_string();
        wipe(&mut envelope);
        output
    }

    fn key(&self, v: &Value, name: &str) -> Result<&Key> {
        self.keys
            .get(&number(v, name)?)
            .map(Box::as_ref)
            .ok_or_else(|| {
                BindingError::new(
                    "KeyReleased",
                    "key is released or belongs to another session",
                )
            })
    }
    fn dispatch(&mut self, v: &Value) -> Result<Value> {
        match text(v, "op")? {
            "profile" => {
                let p = profile(v)?;
                Ok(
                    json!({"profile":parsed(b::profile::to_json(&p))?,"capabilities":b::profile::capabilities(&p)}),
                )
            }
            "phraseGenerate" => Ok(Value::String(
                b::phrase::generate_phrase()?.phrase().to_owned(),
            )),
            "phraseCheck" => parsed(b::phrase::check_phrase(text(v, "phrase")?.into())),
            "keyPhrase" | "keyLegacy" => {
                let p = profile(v)?;
                let key = if text(v, "op")? == "keyPhrase" {
                    let (account, index) = (number(v, "account")?, number(v, "index")?);
                    let passphrase = text(v, "passphrase")?.into();
                    // A host that holds the phrase as bytes sends them as `phraseHex`, so that it
                    // never has to make a string of them.
                    if v.get("phraseHex").is_some() {
                        Key::from_phrase_bytes(
                            &p,
                            &mut secret_bytes(v, "phraseHex")?,
                            account,
                            index,
                            passphrase,
                        )?
                    } else {
                        Key::from_phrase(&p, text(v, "phrase")?.into(), account, index, passphrase)?
                    }
                } else {
                    Key::from_legacy_passphrase(&p, text(v, "passphrase")?.into())?
                };
                self.next = self
                    .next
                    .checked_add(1)
                    .ok_or_else(|| BindingError::argument("key handles exhausted"))?;
                let result = json!({"handle":self.next,"address":key.address()?,"publicKey":hex::encode(key.public_key()?),"path":key.path(),"legacy":key.legacy()});
                self.keys.insert(self.next, Box::new(key));
                Ok(result)
            }
            "keyKeystore" => {
                let key = Key::from_keystore(
                    &profile(v)?,
                    &bytes(v, "keystore")?,
                    &mut secret_bytes(v, "password")?,
                    number(v, "account")?,
                    number(v, "index")?,
                    text(v, "passphrase")?.into(),
                    Some(number(v, "maxMemoryKib")?),
                )?;
                self.next = self
                    .next
                    .checked_add(1)
                    .ok_or_else(|| BindingError::argument("key handles exhausted"))?;
                let result = json!({"handle":self.next,"address":key.address()?,"publicKey":hex::encode(key.public_key()?),"path":key.path(),"legacy":key.legacy()});
                self.keys.insert(self.next, Box::new(key));
                Ok(result)
            }
            "keystoreEncrypt" => Ok(json!(hex::encode(b::keystore::keystore_encrypt(
                &mut secret_bytes(v, "phrase")?,
                &mut secret_bytes(v, "password")?,
                &raw(v, "params")?
            )?))),
            "keystoreInspect" => parsed(b::keystore::keystore_inspect(&bytes(v, "keystore")?)?),
            "keystoreReencrypt" => Ok(json!(hex::encode(
                b::keystore::keystore_reencrypt_with_bounds(
                    &bytes(v, "keystore")?,
                    &mut secret_bytes(v, "password")?,
                    &raw(v, "params")?,
                    optional_number(v, "maxMemoryKib")?,
                )?
            ))),
            "keystoreChangePassword" => Ok(json!(hex::encode(
                b::keystore::keystore_change_password_with_bounds(
                    &bytes(v, "keystore")?,
                    &mut secret_bytes(v, "password")?,
                    &mut secret_bytes(v, "newPassword")?,
                    &raw(v, "params")?,
                    optional_number(v, "maxMemoryKib")?,
                )?
            ))),
            "keystoreArmor" => Ok(json!(b::keystore::keystore_armor(&bytes(v, "keystore")?))),
            "keystoreDearmor" => Ok(json!(hex::encode(b::keystore::keystore_dearmor(text(
                v, "text"
            )?)?))),
            "keyRelease" => {
                let id = number(v, "key")?;
                if let Some(key) = self.keys.get_mut(&id) {
                    key.release();
                }
                self.keys.remove(&id);
                Ok(Value::Null)
            }
            "signMessage" => parsed(
                self.key(v, "key")?
                    .sign_message_with(&bytes(v, "message")?, aux(v)?)?,
            ),
            // A website's sign-in message, signed only once it passes its checks against the
            // origin of the page that asks and the key's identity.
            "signinSign" => parsed(
                self.key(v, "key")?.sign_sign_in_with(
                    text(v, "message")?,
                    text(v, "origin")?,
                    field(v, "now")?
                        .as_f64()
                        .ok_or_else(|| BindingError::argument("now must be milliseconds"))?,
                    aux(v)?,
                )?,
            ),
            "verifyMessage" => Ok(json!(b::messages::verify_message(
                &bytes(v, "message")?,
                text(v, "publicKey")?,
                text(v, "signature")?,
                text(v, "algorithm")?
            ))),
            "addressParse" => Ok(json!(hex::encode(b::address::parse_address(
                text(v, "address")?,
                &profile(v)?
            )?))),
            "addressFromKey" => Ok(json!(b::address::address_from_public_key(
                &bytes(v, "publicKey")?,
                &profile(v)?
            )?)),
            "amountParse" => Ok(json!(b::amount::parse_amount(
                text(v, "text")?,
                u8::try_from(number(v, "decimals")?)
                    .map_err(|_| BindingError::argument("decimals out of range"))?
            )?)),
            "amountFormat" => Ok(json!(b::amount::format_amount(
                text(v, "amount")?,
                u8::try_from(number(v, "decimals")?)
                    .map_err(|_| BindingError::argument("decimals out of range"))?,
                None,
                false
            )?)),
            "signinBuild" => Ok(json!(b::signin::build_sign_in(
                &profile(v)?,
                &raw(v, "request")?
            )?)),
            "signinParse" => parsed(b::signin::parse_sign_in(
                &profile(v)?,
                text(v, "message")?,
                &raw(v, "expected")?,
                field(v, "now")?
                    .as_f64()
                    .ok_or_else(|| BindingError::argument("now must be milliseconds"))?,
            )?),
            "vote" => {
                let result = b::vote::vote_call(
                    text(v, "operation")?,
                    text(v, "first")?,
                    text(v, "second")?,
                    text(v, "third")?,
                )?;
                if result.is_empty() {
                    Ok(Value::Null)
                } else {
                    parsed(result)
                }
            }
            "ownership" => parsed(b::ownership::ownership_call(
                text(v, "operation")?,
                text(v, "first")?,
                text(v, "second")?,
                field(v, "now")?
                    .as_f64()
                    .ok_or_else(|| BindingError::argument("now must be milliseconds"))?,
            )?),
            "relay" => Ok(json!(b::api::check_relay(text(v, "url")?)?)),
            // The host's transport keeps to the client's bounds: it reads at most
            // `maxResponseBytes` of an answer, and waits after HTTP 429 as `backoffDelay` says.
            "transportLimits" => Ok(json!({
                "maxResponseBytes": MAX_RESPONSE_BYTES,
                "maxRetryAfterMs": milliseconds(Backoff::MAX_RETRY_AFTER),
            })),
            "backoffDelay" => {
                let retry_after = match v.get("retryAfterMs") {
                    None | Some(Value::Null) => None,
                    Some(ms) => Some(Duration::from_millis(ms.as_u64().ok_or_else(|| {
                        BindingError::argument("retryAfterMs must be whole milliseconds")
                    })?)),
                };
                Ok(Backoff::default()
                    .delay(number(v, "attempt")?, retry_after)
                    .map_or(Value::Null, |wait| json!(milliseconds(wait))))
            }
            "apiPrepare" | "apiDecode" => {
                let call = b::api::PreparedCall::prepare(
                    number(v, "seats")?,
                    text(v, "operation")?,
                    &raw(v, "args")?,
                )?;
                if text(v, "op")? == "apiPrepare" {
                    parsed(call.request())
                } else {
                    parsed(
                        call.decode(
                            u16::try_from(number(v, "status")?)
                                .map_err(|_| BindingError::argument("invalid status"))?,
                            &raw(v, "headers")?,
                            text(v, "body")?.as_bytes(),
                        )?,
                    )
                }
            }
            "chainLoad" | "chainNode" | "chainCheck" | "chainInfo" | "onlineFacts"
            | "draftBuild" => {
                let p = profile(v)?;
                let chain = if text(v, "op")? == "chainNode" {
                    b::chain::from_node(
                        &p,
                        number(v, "status")?
                            .try_into()
                            .map_err(|_| BindingError::argument("invalid status"))?,
                        &raw(v, "headers")?,
                        text(v, "body")?.as_bytes(),
                    )?
                } else {
                    b::chain::load(&p, &raw(v, "configuration")?)?
                };
                match text(v, "op")? {
                    "chainCheck" => parsed(b::chain::check_node(
                        &chain,
                        number(v, "status")?
                            .try_into()
                            .map_err(|_| BindingError::argument("invalid status"))?,
                        &raw(v, "headers")?,
                        text(v, "body")?.as_bytes(),
                    )?),
                    "onlineFacts" => parsed(b::draft::online_facts(
                        &chain,
                        text(v, "sender")?,
                        v.get("account")
                            .filter(|x| !x.is_null())
                            .map(Value::to_string)
                            .as_deref(),
                        &raw(v, "status")?,
                    )?),
                    "draftBuild" => {
                        let d = b::draft::build(&chain, &raw(v, "request")?, &raw(v, "facts")?)?;
                        Ok(
                            json!({"serialized":hex::encode(d.serialize()),"summary":parsed(b::draft::summary(&d))?}),
                        )
                    }
                    _ => {
                        // The rules, economics and vote rules in force at `height`, the first
                        // block when it is absent.
                        let h = match v.get("height") {
                            None => 1,
                            Some(_) => number(v, "height")?,
                        };
                        Ok(
                            json!({"profile":parsed(b::profile::to_json(chain.profile()))?,"token":parsed(b::chain::token(&chain))?,"rules":parsed(b::chain::rules(&chain,h))?,"economics":parsed(b::chain::economics(&chain,h))?,"voteRules":parsed(b::vote::vote_rules_at(&chain,h))?}),
                        )
                    }
                }
            }
            "draftRead" | "draftSign" => {
                // With the host's connected chain (`configuration`), the draft is read on it: a
                // draft built under another configuration is refused, and a fee at the floor is
                // the floor. With the profile alone, such a fee is unverified.
                let serialized = bytes(v, "serialized")?;
                let d = match v.get("configuration") {
                    None | Some(Value::Null) => b::draft::deserialize(&serialized, &profile(v)?)?,
                    Some(_) => b::draft::deserialize_on(
                        &serialized,
                        &b::chain::load(&profile(v)?, &raw(v, "configuration")?)?,
                    )?,
                };
                if text(v, "op")? == "draftRead" {
                    return parsed(b::draft::summary(&d));
                }
                let second = if v.get("second").is_some_and(|x| !x.is_null()) {
                    Some(self.key(v, "second")?)
                } else {
                    None
                };
                let s = b::draft::sign(&d, self.key(v, "key")?, second, aux(v)?)?;
                Ok(
                    json!({"serialized":hex::encode(s.serialize()),"id":s.id(),"bytes":hex::encode(s.bytes()),"json":s.json(),"summary":parsed(b::draft::signed_summary(&s))?,"verified":s.is_verified()}),
                )
            }
            "signedRead" => {
                let s = b::draft::signed_deserialize(&bytes(v, "serialized")?, &profile(v)?)?;
                parsed(b::draft::signed_summary(&s))
            }
            "submitPrepare" | "submitDecode" => {
                let p = profile(v)?;
                let mut plan =
                    b::api::Submission::new(number(v, "maxTransactions")?, number(v, "maxBytes")?);
                for s in field(v, "transactions")?
                    .as_array()
                    .ok_or_else(|| BindingError::argument("transactions must be an array"))?
                {
                    let bytes = hex::decode(
                        s.as_str()
                            .ok_or_else(|| BindingError::argument("transaction must be hex"))?,
                    )
                    .map_err(|_| BindingError::argument("transaction must be hex"))?;
                    plan.add(&b::draft::signed_deserialize(&bytes, &p)?)?;
                }
                let count = plan.plan()?;
                if text(v, "op")? == "submitPrepare" {
                    let requests = (0..count)
                        .map(|i| plan.request(i).and_then(parsed))
                        .collect::<Result<Vec<_>>>()?;
                    Ok(json!({"requests":requests,"refused":parsed(plan.refused()?)?}))
                } else {
                    for (i, r) in field(v, "responses")?
                        .as_array()
                        .ok_or_else(|| BindingError::argument("responses must be an array"))?
                        .iter()
                        .enumerate()
                    {
                        plan.decode(
                            u32::try_from(i)
                                .map_err(|_| BindingError::argument("too many responses"))?,
                            number(r, "status")?
                                .try_into()
                                .map_err(|_| BindingError::argument("invalid status"))?,
                            &raw(r, "headers")?,
                            text(r, "body")?.as_bytes(),
                        )?;
                    }
                    parsed(plan.finish()?)
                }
            }
            _ => Err(BindingError::argument("unknown operation")),
        }
    }
}
