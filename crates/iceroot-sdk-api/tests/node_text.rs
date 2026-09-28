//! Text a node chooses (its error messages, its codes, the values a decoder refuses) reaches the
//! client's errors bounded and escaped, and never their `Display` text, which applications show.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use iceroot_sdk_api::{ApiError, PoolLimits, Response, SolarCompat, SubmitStatus, SubmitTx};
use serde_json::json;

const PHISH: &str =
    "Wallet locked by the network. Restore it at https://recovery.example with your 24 words.";

/// A node message: the phishing text, a character that reorders text, a line break and padding.
fn hostile() -> String {
    format!("{PHISH}\u{202e}\n{}", "x".repeat(8_000))
}

#[test]
fn a_node_s_error_message_is_bounded_escaped_and_kept_out_of_the_display_text() {
    let call = SolarCompat::new(53).node_status();
    for status in [404u16, 422, 500] {
        let body = json!({ "statusCode": status, "error": hostile(), "message": hostile() });
        let error = call
            .decode(&Response::new(status, body.to_string()))
            .unwrap_err();
        let (message, name) = match &error {
            ApiError::NotFound { message } => (message.clone(), String::new()),
            ApiError::Refused { message, error, .. } => (message.clone(), error.clone()),
            other => panic!("{other:?}"),
        };
        for text in [&message, &name] {
            if status == 404 && text.is_empty() {
                continue;
            }
            assert!(text.starts_with(PHISH), "{status}");
            assert!(text.contains("\\u{202e}\\u{a}x"), "{status}");
            assert!(!text.contains('\u{202e}') && !text.contains('\n'));
            assert!(text.chars().count() <= 201, "{}", text.chars().count());
            assert!(text.ends_with('…'));
        }
        let shown = error.to_string();
        assert!(!shown.contains("Restore"), "{status}");
        assert!(!shown.contains("xxx"), "{status}");
    }
}

#[test]
fn a_rejected_transaction_s_node_text_is_bounded_and_escaped() {
    let limits = PoolLimits {
        max_transactions_in_pool: 15_000,
        max_transactions_per_sender: 150,
        max_transactions_per_request: 40,
        max_transaction_age: 2_700,
        max_transaction_bytes: 2_000_000,
    };
    let id = "aa".repeat(32);
    let tx = SubmitTx::new(id.clone(), &format!(r#"{{"id":"{id}"}}"#), 154).unwrap();
    let plan = SolarCompat::new(53).submit(&[tx], &limits).unwrap();
    let answer = json!({
        "data": { "accept": [], "broadcast": [], "excess": [], "invalid": [id] },
        "errors": { id.clone(): { "type": hostile(), "message": hostile() } }
    });
    let report = plan.calls()[0]
        .decode(&Response::new(200, answer.to_string()))
        .unwrap();
    match &report.outcomes[0].status {
        SubmitStatus::Rejected {
            node_code, message, ..
        } => {
            for text in [node_code, message] {
                assert!(text.starts_with(PHISH));
                assert!(text.chars().count() <= 201);
                assert!(!text.contains('\n'));
            }
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_refused_value_is_never_echoed_at_length() {
    let call = SolarCompat::new(53)
        .account("dW84xVtbupBGDKm73pewS4hqhDqcJoyhzv")
        .unwrap();
    let balance = format!("{PHISH}{}", "x".repeat(1 << 20));
    let body = json!({ "data": {
        "address": "dW84xVtbupBGDKm73pewS4hqhDqcJoyhzv",
        "balance": balance,
        "nonce": "0",
        "attributes": {},
        "votingFor": {}
    }});
    let error = call
        .decode(&Response::new(200, body.to_string()))
        .unwrap_err();
    let ApiError::BadResponse { detail, .. } = &error else {
        panic!("{error:?}");
    };
    assert!(detail.chars().count() <= 301, "{}", detail.chars().count());
    assert!(error.to_string().chars().count() < 400);
}
