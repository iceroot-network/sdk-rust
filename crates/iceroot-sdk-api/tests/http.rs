//! The reqwest transport against a scripted local server: relay failover, 429 backoff,
//! submission bodies and redirects, which are never followed.

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

/// A relay that answers every request with `status` and a `location` header naming `target`, and
/// records each request line.
async fn redirecting_relay(status: u16, target: String) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/api", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let n = socket.read(&mut buffer).await.unwrap();
            let text = String::from_utf8_lossy(&buffer[..n]).to_string();
            log.lock()
                .unwrap()
                .push(text.lines().next().unwrap_or("").to_owned());
            let answer = format!(
                "HTTP/1.1 {status} Moved\r\nlocation: {target}/node/status\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
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

#[tokio::test(flavor = "current_thread")]
async fn never_follows_a_redirect_and_skips_the_relay_that_answers_one() {
    // A host the relay list does not name, which would answer if it were reached.
    let (elsewhere, reached) = server(vec![(200, STATUS), (200, STATUS)]).await;
    for status in [301, 302, 303, 307, 308] {
        let (redirecting, asked) = redirecting_relay(status, elsewhere.clone()).await;
        let (live, served) = server(vec![(200, STATUS)]).await;
        let with_token = HttpOptions {
            headers: vec![("x-api-key".to_owned(), "s3cret".to_owned())],
            ..options(0)
        };
        let relays = vec![
            Relay::parse(&redirecting).unwrap(),
            Relay::parse(&live).unwrap(),
        ];
        let client = HttpClient::with_options(relays, with_token).unwrap();
        // The next relay answers.
        let answer = client
            .send(&SolarCompat::new(53).node_status())
            .await
            .unwrap();
        assert_eq!(answer.height, 42, "{status}");
        assert_eq!(asked.lock().unwrap().len(), 1, "{status}");
        assert_eq!(served.lock().unwrap().len(), 1, "{status}");

        // A relay that only redirects is unavailable, and a submission's body goes nowhere else.
        let only = HttpClient::with_options(vec![Relay::parse(&redirecting).unwrap()], options(0))
            .unwrap();
        let limits = PoolLimits {
            max_transactions_in_pool: 15_000,
            max_transactions_per_sender: 150,
            max_transactions_per_request: 40,
            max_transaction_age: 2_700,
            max_transaction_bytes: 2_000_000,
        };
        let tx = SubmitTx::new("aa", r#"{"id":"aa","version":3}"#, 154).unwrap();
        let plan = SolarCompat::new(53).submit(&[tx], &limits).unwrap();
        let error = only.submit(&plan).await.unwrap_err();
        assert_eq!(error.code(), "NodeUnavailable", "{status}");
        assert!(error.to_string().contains("redirect"), "{error}");
        let asked = asked.lock().unwrap();
        assert!(asked[1].starts_with("POST /api/transactions "), "{asked:?}");
    }
    assert!(reached.lock().unwrap().is_empty());
}

/// A relay that answers every request with a node status padded to `size` bytes, with a
/// `content-length` header or, when `chunked`, in chunks of 64 KiB without one, and counts the
/// requests.
async fn padded_relay(size: usize, chunked: bool) -> (String, Arc<Mutex<usize>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/api", listener.local_addr().unwrap());
    let asked = Arc::new(Mutex::new(0));
    let count = Arc::clone(&asked);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            *count.lock().unwrap() += 1;
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                let _ = socket.read(&mut buffer).await;
                let head =
                    r#"{"data":{"synced":true,"now":7,"blocksCount":0,"timestamp":330},"pad":""#;
                let tail = r#""}"#;
                let pad = size.saturating_sub(head.len() + tail.len());
                let body = format!("{head}{}{tail}", "x".repeat(pad));
                let header = if chunked {
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n".to_owned()
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    )
                };
                if socket.write_all(header.as_bytes()).await.is_err() {
                    return;
                }
                if chunked {
                    for chunk in body.as_bytes().chunks(64 * 1024) {
                        let framed =
                            [format!("{:x}\r\n", chunk.len()).as_bytes(), chunk, b"\r\n"].concat();
                        if socket.write_all(&framed).await.is_err() {
                            return;
                        }
                    }
                    let _ = socket.write_all(b"0\r\n\r\n").await;
                } else if socket.write_all(body.as_bytes()).await.is_err() {
                    return;
                }
                socket.shutdown().await.ok();
            });
        }
    });
    (url, asked)
}

#[tokio::test(flavor = "current_thread")]
async fn an_answer_larger_than_the_limit_is_refused_and_the_next_relay_asked() {
    use iceroot_sdk_api::MAX_RESPONSE_BYTES;

    // Within the limit, the padded answer is read.
    let (small, _) = padded_relay(64 * 1024, false).await;
    let client = HttpClient::with_options(vec![Relay::parse(&small).unwrap()], options(0)).unwrap();
    let status = client
        .send(&SolarCompat::new(53).node_status())
        .await
        .unwrap();
    assert_eq!(status.height, 7);

    for chunked in [false, true] {
        let (large, asked) = padded_relay(MAX_RESPONSE_BYTES + 1, chunked).await;
        let (live, served) = server(vec![(200, STATUS)]).await;
        let relays = vec![Relay::parse(&large).unwrap(), Relay::parse(&live).unwrap()];
        let client = HttpClient::with_options(relays, options(0)).unwrap();
        let status = client
            .send(&SolarCompat::new(53).node_status())
            .await
            .unwrap();
        assert_eq!(status.height, 42, "chunked: {chunked}");
        assert_eq!(*asked.lock().unwrap(), 1);
        assert_eq!(served.lock().unwrap().len(), 1);

        // A relay that only answers so is unavailable.
        let only =
            HttpClient::with_options(vec![Relay::parse(&large).unwrap()], options(0)).unwrap();
        let error = only
            .send(&SolarCompat::new(53).node_status())
            .await
            .unwrap_err();
        assert_eq!(error.code(), "NodeUnavailable", "chunked: {chunked}");
        assert!(error.to_string().contains("bytes"), "{error}");
    }
}
