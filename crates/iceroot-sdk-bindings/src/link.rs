//! Account links and revocations in the TypeScript API's JSON forms.

use crate::error::{BindingError, Result};
use crate::{json, keys::Key, signin::milliseconds};
use iceroot_sdk::link::{
    self, LinkExpected, LinkKind, LinkMessage, LinkRecord, LinkRequest, Recorded, RecordedEvent,
};
use iceroot_sdk::{Aux, Profile, PublicKey};
use serde_json::{Map, Value, json};

fn kind(value: &str) -> Result<LinkKind> {
    match value {
        "link" => Ok(LinkKind::Link),
        "revocation" => Ok(LinkKind::Revocation),
        _ => Err(BindingError::argument("kind must be link or revocation")),
    }
}

fn integer(value: &Map<String, Value>, name: &str) -> Result<i64> {
    json::member(value, name)?
        .as_i64()
        .ok_or_else(|| BindingError::argument(format!("{name} must be whole seconds")))
}

fn id(value: &Map<String, Value>) -> Result<u64> {
    json::member(value, "githubId")?
        .as_u64()
        .filter(|id| *id <= link::MAX_GITHUB_ID)
        .ok_or_else(|| {
            iceroot_sdk::Error::InvalidLink {
                problem: iceroot_sdk::error::LinkProblem::GithubId,
            }
            .into()
        })
}

fn expected(value: &Map<String, Value>) -> Result<LinkExpected<'_>> {
    Ok(LinkExpected {
        kind: json::optional_string(value, "kind")?
            .map(kind)
            .transpose()?,
        github_id: if value.get("githubId").is_some() {
            Some(id(value)?)
        } else {
            None
        },
        public_key: json::optional_string(value, "publicKey")?,
        address: json::optional_string(value, "address")?,
    })
}

fn fields(value: LinkMessage) -> String {
    let mut result = json!({"kind": value.kind.as_str(), "network": value.network,
        "githubId": value.github_id, "account": value.account, "publicKey": value.public_key,
        "issuedAt": value.issued_at, "issuedAtMs": value.issued_at_ms});
    if value.kind == LinkKind::Revocation
        && let Some(object) = result.as_object_mut()
    {
        object.insert(
            "endsLinkIssuedAt".to_owned(),
            json!(value.ends_link_issued_at),
        );
        object.insert(
            "endsLinkIssuedAtMs".to_owned(),
            json!(value.ends_link_issued_at_ms),
        );
    }
    result.to_string()
}

/// Build `{ kind?, githubId, publicKey, issuedAt, endsLinkIssuedAt? }`, with times in seconds.
pub fn build_link(profile: &Profile, request: &str) -> Result<String> {
    let value = json::parse_object(request, "the link request")?;
    let key = PublicKey::from_hex(json::string(&value, "publicKey")?)
        .map_err(|_| BindingError::new("InvalidKey", "the public key is not valid"))?;
    let request = LinkRequest {
        github_id: id(&value)?,
        public_key: &key,
        issued_at: integer(&value, "issuedAt")?,
    };
    Ok(
        match kind(json::optional_string(&value, "kind")?.unwrap_or("link"))? {
            LinkKind::Link => link::build(profile, &request)?,
            LinkKind::Revocation => {
                link::build_revocation(profile, &request, integer(&value, "endsLinkIssuedAt")?)?
            }
        },
    )
}

/// Parse exact message text, optional expected fields as JSON, and a clock in milliseconds.
pub fn parse_link(
    profile: &Profile,
    message: &str,
    expectations: &str,
    now_ms: f64,
) -> Result<String> {
    let value = json::parse_object(expectations, "the expected link fields")?;
    Ok(fields(link::parse(
        profile,
        message,
        &expected(&value)?,
        milliseconds(now_ms)?,
    )?))
}

/// Verify record JSON, preserving duplicate-member detection before parsing the object.
pub fn verify_link(
    profile: &Profile,
    record: &str,
    expectations: &str,
    now_ms: f64,
) -> Result<String> {
    let record = LinkRecord::from_json(record)?;
    let value = json::parse_object(expectations, "the expected link fields")?;
    Ok(fields(link::verify(
        profile,
        &record,
        &expected(&value)?,
        milliseconds(now_ms)?,
    )?))
}

/// Read and write the record in its canonical member order and escaping.
pub fn link_record_json(record: &str) -> Result<String> {
    Ok(LinkRecord::from_json(record)?.to_json())
}

/// Check a parsed message against verified history. Entries use `{ network, githubId, account,
/// event, at }`, where event is link, revocation or github-unlink and at is milliseconds.
pub fn check_link_history(
    profile: &Profile,
    message: &str,
    history: &str,
    now_ms: f64,
) -> Result<()> {
    let parsed = link::parse(
        profile,
        message,
        &LinkExpected::default(),
        milliseconds(now_ms)?,
    )?;
    let value: Value = serde_json::from_str(history)
        .map_err(|_| BindingError::argument("history must be JSON"))?;
    let entries = value
        .as_array()
        .ok_or_else(|| BindingError::argument("history must be an array"))?;
    let history = entries
        .iter()
        .map(|entry| {
            let entry = entry
                .as_object()
                .ok_or_else(|| BindingError::argument("history entry must be an object"))?;
            let at = milliseconds(
                json::member(entry, "at")?
                    .as_f64()
                    .ok_or_else(|| BindingError::argument("at must be milliseconds"))?,
            )?;
            Ok(Recorded {
                network: json::string(entry, "network")?.to_owned(),
                github_id: id(entry)?,
                account: json::string(entry, "account")?.to_owned(),
                event: match json::string(entry, "event")? {
                    "link" => RecordedEvent::Link { issued_at_ms: at },
                    "revocation" => RecordedEvent::Revocation { issued_at_ms: at },
                    "github-unlink" => RecordedEvent::GithubUnlink { posted_at_ms: at },
                    _ => return Err(BindingError::argument("unknown history event")),
                },
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(link::check_history(&parsed, &history)?)
}

impl Key {
    /// Check the message against this key and clock, then sign with fresh randomness.
    pub fn sign_link(&self, message: &str, now_ms: f64) -> Result<String> {
        self.sign_link_with(message, now_ms, Aux::random())
    }

    /// Checked signing with explicit auxiliary randomness for reproducible tests.
    pub fn sign_link_with(&self, message: &str, now_ms: f64, aux: Aux) -> Result<String> {
        Ok(link::sign_with(
            self.profile(),
            self.account()?,
            message,
            milliseconds(now_ms)?,
            aux,
        )?
        .to_json())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_signing_and_record_bytes() {
        let profile = crate::profile::from_json(r#"{"id":"devnet","backend":"solar-compat","api":{"relays":[]},"chain":{"networkByte":90},"keyScheme":"bip32-secp256k1"}"#).unwrap();
        let mut key = Key::from_legacy_passphrase(&profile, "example link holder".into()).unwrap();
        let request = json!({"githubId": 9_999_999_001_u64, "publicKey": hex::encode(key.public_key().unwrap()), "issuedAt": 1_790_426_096});
        let message = build_link(&profile, &request.to_string()).unwrap();
        let now = 1_790_426_097_000.0;
        let signed = key.sign_link(&message, now).unwrap();
        assert_eq!(link_record_json(&signed).unwrap(), signed);
        assert_eq!(
            verify_link(&profile, &signed, "{}", now).unwrap(),
            parse_link(&profile, &message, "{}", now).unwrap()
        );
        assert_eq!(
            key.sign_message(message.as_bytes()).unwrap_err().code(),
            "InvalidArgument"
        );
        assert_eq!(
            key.sign_link(&message, now - 32_000.0)
                .unwrap_err()
                .details(),
            &json!({"reason":"future"})
        );
        for time in [f64::NAN, f64::INFINITY, 0.5, 9_007_199_254_740_992.0] {
            assert_eq!(
                key.sign_link(&message, time).unwrap_err().code(),
                "InvalidArgument"
            );
        }
        let doubled = signed.replacen('{', "{\"message\":\"decoy\",", 1);
        assert_eq!(
            verify_link(&profile, &doubled, "{}", now)
                .unwrap_err()
                .details(),
            &json!({"reason":"json"})
        );
        key.release();
        assert_eq!(
            key.sign_link(&message, now).unwrap_err().code(),
            "KeyReleased"
        );
    }
}
