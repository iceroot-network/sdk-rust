//! The reqwest transport against a scripted local server: relay failover, 429 backoff and
//! submission bodies.

#![cfg(feature = "http")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use iceroot_sdk_api::{
    ApiError, Backoff, HttpClient, HttpOptions, PoolLimits, RateLimit, Relay, SolarCompat,
    SubmitStatus, SubmitTx,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const STATUS: &str = r#"{"data":{"synced":true,"now":42,"blocksCount":0,"timestamp":330}}"#;
const TOO_MANY: &str =
    r#"{"statusCode":429,"error":"Too Many Requests","message":"Too Many Requests"}"#;

/// Serves the scripted answers in order, one per connection, and records each request.
async fn server(answers: Vec<(u16, &'static str)>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/api", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        for (status, body) in answers {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let n = socket.read(&mut buffer).await.unwrap();
                request.extend_from_slice(&buffer[..n]);
                let text = String::from_utf8_lossy(&request).to_string();
                if let Some(end) = text.find("\r\n\r\n") {
                    let length = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length || n == 0 {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            log.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&request).to_string());
            let reason = if status == 200 {
                "OK"
            } else {
                "Too Many Requests"
            };
            let answer = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\nx-block-height: 42\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(answer.as_bytes()).await.unwrap();
            socket.shutdown().await.ok();
        }
    });
    (url, seen)
}

/// A relay URL on which nothing listens.
async fn dead_relay() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/api", listener.local_addr().unwrap());
    drop(listener);
    url
}

fn options(retries: u32) -> HttpOptions {
    HttpOptions {
        timeout: Duration::from_secs(5),
        rate_limit: RateLimit::REFERENCE_DEFAULT,
        backoff: Backoff {
            initial: Duration::from_millis(10),
            max: Duration::from_millis(20),
            max_retries: retries,
        },
        ..HttpOptions::default()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn fails_over_and_retries_after_429() {
    let dead = dead_relay().await;
    let (live, seen) = server(vec![(429, TOO_MANY), (200, STATUS)]).await;
    let relays = vec![Relay::parse(&dead).unwrap(), Relay::parse(&live).unwrap()];
    let client = HttpClient::with_options(relays, options(2)).unwrap();
    let status = client
        .send(&SolarCompat::new(53).node_status())
        .await
        .unwrap();
    assert_eq!(status.height, 42);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].starts_with("GET /api/node/status HTTP/1.1"));
    assert!(
        seen[0]
            .to_ascii_lowercase()
            .contains("accept: application/json")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn exchanges_a_request_with_the_host_s_own_decoder() {
    // A host that keeps its calls in another form (the SDK's bindings write each answer as
    // JSON) gets the same failover and backoff; its decoder sees every answer, the 429 included.
    let dead = dead_relay().await;
    let (live, seen) = server(vec![(429, TOO_MANY), (200, STATUS)]).await;
    let relays = vec![Relay::parse(&dead).unwrap(), Relay::parse(&live).unwrap()];
    let client = HttpClient::with_options(relays, options(2)).unwrap();
    let call = SolarCompat::new(53).node_status();
    let answers = Mutex::new(Vec::new());
    let height = client
        .exchange(call.request(), |response| {
            answers
                .lock()
                .unwrap()
                .push((response.status(), response.block_height()));
            call.decode(response)
                .map(|status| status.height.to_string())
        })
        .await
        .unwrap();
    assert_eq!(height, "42");
    assert_eq!(*answers.lock().unwrap(), [(429, Some(42)), (200, Some(42))]);
    assert_eq!(seen.lock().unwrap().len(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn reports_the_rate_limit_when_retries_are_spent() {
    let (live, _) = server(vec![(429, TOO_MANY), (429, TOO_MANY)]).await;
    let client = HttpClient::with_options(vec![Relay::parse(&live).unwrap()], options(1)).unwrap();
    let error = client
        .send(&SolarCompat::new(53).node_status())
        .await
        .unwrap_err();
    assert_eq!(error, ApiError::RateLimited { retry_after: None });
}

#[tokio::test(flavor = "current_thread")]
async fn no_relay_answers() {
    let client =
        HttpClient::with_options(vec![Relay::parse(&dead_relay().await).unwrap()], options(0))
            .unwrap();
    let error = client
        .send(&SolarCompat::new(53).node_status())
        .await
        .unwrap_err();
    assert_eq!(error.code(), "NodeUnavailable");
    assert!(HttpClient::new(Vec::new()).is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn submits_the_transactions_json() {
    let accepted = r#"{"data":{"accept":["aa"],"broadcast":["aa"],"excess":[],"invalid":[]}}"#;
    let (live, seen) = server(vec![(200, accepted)]).await;
    let client = HttpClient::with_options(vec![Relay::parse(&live).unwrap()], options(0)).unwrap();
    let limits = PoolLimits {
        max_transactions_in_pool: 15_000,
        max_transactions_per_sender: 150,
        max_transactions_per_request: 40,
        max_transaction_age: 2_700,
        max_transaction_bytes: 2_000_000,
    };
    let tx = SubmitTx::new("aa", r#"{"id":"aa","version":3}"#, 154).unwrap();
    let plan = SolarCompat::new(53).submit(&[tx], &limits).unwrap();
    let report = client.submit(&plan).await.unwrap();
    assert_eq!(
        report.outcomes[0].status,
        SubmitStatus::Accepted { broadcast: true }
    );
    let seen = seen.lock().unwrap();
    assert!(seen[0].starts_with("POST /api/transactions HTTP/1.1"));
    assert!(
        seen[0]
            .to_ascii_lowercase()
            .contains("content-type: application/json")
    );
    assert!(seen[0].ends_with(r#"{"transactions":[{"id":"aa","version":3}]}"#));
}

#[tokio::test(flavor = "current_thread")]
async fn sends_the_extra_headers_and_never_shows_their_values() {
    let (live, seen) = server(vec![(200, STATUS)]).await;
    let secret = "Bearer s3cret-t0ken";
    let with_token = HttpOptions {
        headers: vec![("authorization".to_owned(), secret.to_owned())],
        ..options(0)
    };
    let client = HttpClient::with_options(vec![Relay::parse(&live).unwrap()], with_token).unwrap();
    assert!(!format!("{client:?}").contains("s3cret"));
    client
        .send(&SolarCompat::new(53).node_status())
        .await
        .unwrap();
    let seen = seen.lock().unwrap();
    assert!(
        seen[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer s3cret-t0ken")
    );

    let relays = || vec![Relay::parse(&live).unwrap()];
    for (name, value) in [("bad name", "x"), ("x-token", "line\nbreak s3cret")] {
        let options = HttpOptions {
            headers: vec![(name.to_owned(), value.to_owned())],
            ..options(0)
        };
        let error = HttpClient::with_options(relays(), options).unwrap_err();
        assert_eq!(error.code(), "InvalidRequest", "{name}");
        assert!(!error.to_string().contains("s3cret"), "{error}");
    }
}
