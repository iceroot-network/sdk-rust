use crate::Session;
use serde_json::{Value, json};

fn call(session: &mut Session, request: Value) -> Value {
    serde_json::from_str(&session.call(request.to_string().as_bytes())).unwrap()
}
fn profile() -> Value {
    json!({"id":"devnet","backend":"solar-compat","api":{"relays":[]},"chain":{"networkByte":90},"keyScheme":"bip32-secp256k1"})
}
#[test]
fn opaque_handles_are_not_recycled() {
    let mut session = Session::default();
    let a = call(
        &mut session,
        json!({"op":"keyLegacy","profile":profile(),"passphrase":"example"}),
    );
    assert_eq!(a["result"]["handle"], 1);
    call(&mut session, json!({"op":"keyRelease","key":1}));
    let b = call(
        &mut session,
        json!({"op":"keyLegacy","profile":profile(),"passphrase":"example"}),
    );
    assert_eq!(b["result"]["handle"], 2);
    let result = call(
        &mut session,
        json!({"op":"signMessage","key":1,"message":"00"}),
    );
    assert_eq!(result["error"]["code"], "KeyReleased");
}
#[test]
fn malformed_requests_fail_with_stable_errors() {
    let mut session = Session::default();
    for request in [
        json!(null),
        json!([]),
        json!({"op":"missing"}),
        json!({"op":"keyRelease","key":4294967296u64}),
    ] {
        assert_eq!(
            call(&mut session, request)["error"]["code"],
            "InvalidArgument"
        );
    }
    assert!(session.call(b"{").contains("InvalidArgument"));
}
#[cfg(not(feature = "test-seams"))]
#[test]
fn production_refuses_fixed_randomness() {
    let mut session = Session::default();
    call(
        &mut session,
        json!({"op":"keyLegacy","profile":profile(),"passphrase":"example"}),
    );
    assert_eq!(
        call(
            &mut session,
            json!({"op":"signMessage","key":1,"message":"00","aux":"42".repeat(32)})
        )["error"]["code"],
        "InvalidArgument"
    );
}
#[test]
fn a_phrase_given_as_bytes_derives_the_same_key() {
    let mut session = Session::default();
    let phrase = format!("{}art", "abandon ".repeat(23));
    let text = call(
        &mut session,
        json!({"op":"keyPhrase","profile":profile(),"phrase":phrase,"account":0,"index":1,"passphrase":""}),
    );
    let bytes = call(
        &mut session,
        json!({"op":"keyPhrase","profile":profile(),"phraseHex":hex::encode(&phrase),"account":0,"index":1,"passphrase":""}),
    );
    assert_eq!(text["result"]["address"], bytes["result"]["address"]);
    assert_eq!(text["result"]["path"], "m/44'/1'/0'/0'/1'");
    let bad = call(
        &mut session,
        json!({"op":"keyPhrase","profile":profile(),"phraseHex":"zz","account":0,"index":1,"passphrase":""}),
    );
    assert_eq!(bad["error"]["code"], "InvalidArgument");
}
#[test]
fn chain_facts_are_those_of_the_height_asked_for() {
    let mut session = Session::default();
    let configuration: Value = serde_json::from_str(include_str!(
        "../../iceroot-sdk-bindings/tests/data/devnet-configuration.json"
    ))
    .unwrap();
    let request = |height: Value| json!({"op":"chainInfo","profile":profile(),"configuration":configuration,"height":height});
    // The first block has no donations; the second block's milestone adds two.
    let first = call(
        &mut session,
        json!({"op":"chainInfo","profile":profile(),"configuration":configuration}),
    );
    let second = call(&mut session, request(json!(2)));
    assert_eq!(
        first["result"]["economics"],
        call(&mut session, request(json!(1)))["result"]["economics"]
    );
    assert_ne!(first["result"]["economics"], second["result"]["economics"]);
    for height in [json!(-1), json!(4294967296u64), json!("2")] {
        assert_eq!(
            call(&mut session, request(height))["error"]["code"],
            "InvalidArgument"
        );
    }
}
#[test]
fn a_password_change_keeps_to_a_lowered_memory_ceiling() {
    let mut session = Session::default();
    let phrase = hex::encode(
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
    );
    let params = json!({"memoryKib":24576,"iterations":2,"parallelism":1});
    let low = json!({"memoryKib":19456,"iterations":2,"parallelism":1});
    let stored = call(
        &mut session,
        json!({"op":"keystoreEncrypt","phrase":phrase,"password":hex::encode("pw"),"params":params}),
    )["result"]
        .clone();
    for request in [
        json!({"op":"keystoreReencrypt","keystore":stored,"password":hex::encode("pw"),"params":low,"maxMemoryKib":20480}),
        json!({"op":"keystoreChangePassword","keystore":stored,"password":hex::encode("pw"),"newPassword":hex::encode("new"),"params":low,"maxMemoryKib":20480}),
    ] {
        let refused = call(&mut session, request);
        assert_eq!(refused["error"]["code"], "ParamsOutOfRange", "{refused}");
    }
    // Without a ceiling, or with a null one, the standard bounds apply.
    for ceiling in [json!(null), json!(24576)] {
        let changed = call(
            &mut session,
            json!({"op":"keystoreReencrypt","keystore":stored,"password":hex::encode("pw"),"params":low,"maxMemoryKib":ceiling}),
        );
        assert!(changed["result"].is_string(), "{changed}");
    }
    let changed = call(
        &mut session,
        json!({"op":"keystoreChangePassword","keystore":stored,"password":hex::encode("pw"),"newPassword":hex::encode("new"),"params":low}),
    );
    assert!(changed["result"].is_string(), "{changed}");
}
#[test]
fn the_host_waits_after_429_as_the_client_does() {
    let mut session = Session::default();
    let mut delay = |mut request: Value| {
        request["op"] = json!("backoffDelay");
        call(&mut session, request)
    };
    // 2 s doubling up to 30 s, three retries, or the node's longer Retry-After up to a minute.
    for (request, wait) in [
        (json!({"attempt":0}), json!(2000)),
        (json!({"attempt":1}), json!(4000)),
        (json!({"attempt":2,"retryAfterMs":null}), json!(8000)),
        (json!({"attempt":1,"retryAfterMs":9000}), json!(9000)),
        (json!({"attempt":0,"retryAfterMs":60000}), json!(60000)),
        // Retries spent, or a longer wait asked for: the host tries the next relay instead.
        (json!({"attempt":3}), Value::Null),
        (json!({"attempt":0,"retryAfterMs":60001}), Value::Null),
        (
            json!({"attempt":0,"retryAfterMs":3_000_000_000_000u64}),
            Value::Null,
        ),
    ] {
        let answer = delay(request.clone());
        assert_eq!(answer, json!({"result":wait}), "{request}");
    }
    for request in [
        json!({}),
        json!({"attempt":-1}),
        json!({"attempt":0,"retryAfterMs":"5"}),
        json!({"attempt":0,"retryAfterMs":1.5}),
    ] {
        assert_eq!(
            delay(request.clone())["error"]["code"],
            "InvalidArgument",
            "{request}"
        );
    }
}
#[test]
fn the_host_reads_the_client_s_answer_limit() {
    let mut session = Session::default();
    let limits = call(&mut session, json!({"op":"transportLimits"}));
    assert_eq!(
        limits,
        json!({"result":{"maxResponseBytes":8_388_608,"maxRetryAfterMs":60_000}})
    );
    // An answer the host read past the limit is refused when decoded too.
    let body = format!(
        "{{\"data\":{{\"synced\":true,\"now\":1,\"blocksCount\":0,\"timestamp\":1}},\"pad\":\"{}\"}}",
        "x".repeat(8 * 1024 * 1024)
    );
    let refused = call(
        &mut session,
        json!({"op":"apiDecode","seats":53,"operation":"nodeStatus","args":{},"status":200,"headers":[],"body":body}),
    );
    assert_eq!(refused["error"]["code"], "BadResponse");
}
#[test]
fn a_sign_in_message_is_signed_only_once_it_passes_its_checks() {
    let mut session = Session::default();
    let key = call(
        &mut session,
        json!({"op":"keyLegacy","profile":profile(),"passphrase":"example"}),
    )["result"]
        .clone();
    let origin = "https://validators.example";
    let message = call(
        &mut session,
        json!({"op":"signinBuild","profile":profile(),"request":{"origin":origin,"publicKey":key["publicKey"],"nonce":"ab".repeat(32),"issuedAt":1_790_000_000,"expiresAt":1_790_000_300}}),
    )["result"]
        .clone();
    let signed = call(
        &mut session,
        json!({"op":"signinSign","key":key["handle"],"message":message,"origin":origin,"now":1_790_000_010_000u64}),
    );
    let verified = call(
        &mut session,
        json!({"op":"verifyMessage","message":hex::encode(message.as_str().unwrap()),"publicKey":signed["result"]["publicKey"],"signature":signed["result"]["signature"],"algorithm":signed["result"]["algorithm"]}),
    );
    assert_eq!(verified, json!({"result":true}), "{signed}");
    let phished = call(
        &mut session,
        json!({"op":"signinSign","key":key["handle"],"message":message,"origin":"https://phish.example","now":1_790_000_010_000u64}),
    );
    assert_eq!(phished["error"]["code"], "InvalidSignIn");
    let text = message.as_str().unwrap();
    // The same challenge with its times written in another form the parser accepts.
    let times = |zone: &str| {
        text.split('\n')
            .map(|line| {
                if line.starts_with("Issued at: ") || line.starts_with("Expires at: ") {
                    line.replace('Z', zone)
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    for text in [text.to_owned(), times(".000Z"), times("+00:00")] {
        let mut requests =
            vec![json!({"op":"signMessage","key":key["handle"],"message":hex::encode(&text)})];
        if cfg!(feature = "test-seams") {
            requests.push(json!({"op":"signMessage","key":key["handle"],"message":hex::encode(&text),"aux":"42".repeat(32)}));
        }
        for request in requests {
            let refused = call(&mut session, request);
            assert_eq!(refused["error"]["code"], "InvalidArgument");
            assert_eq!(
                refused["error"]["details"],
                json!({"reason":
                    "a sign-in message is signed only for the page that asks for it, never as a plain message"
                })
            );
        }
    }
    for text in [
        "About sign-in".to_owned(),
        format!(" {text}"),
        format!("\u{feff}{text}"),
        text.replace('\n', "\r\n"),
        format!("{text}\n"),
    ] {
        let signed = call(
            &mut session,
            json!({"op":"signMessage","key":key["handle"],"message":hex::encode(&text)}),
        );
        assert_eq!(
            call(
                &mut session,
                json!({"op":"verifyMessage","message":hex::encode(&text),"publicKey":signed["result"]["publicKey"],"signature":signed["result"]["signature"],"algorithm":signed["result"]["algorithm"]})
            ),
            json!({"result":true})
        );
    }
    let other = call(
        &mut session,
        json!({"op":"keyLegacy","profile":profile(),"passphrase":"other"}),
    )["result"]
        .clone();
    let refused = call(
        &mut session,
        json!({"op":"signinSign","key":other["handle"],"message":message,"origin":origin,"now":1_790_000_010_000u64}),
    );
    assert_eq!(refused["error"]["code"], "InvalidSignIn");
    // An ownership proof's text is never signed as a message.
    let proof = call(
        &mut session,
        json!({"op":"signMessage","key":key["handle"],"message":hex::encode("IceRoot migration ownership proof\nVersion: 1")}),
    );
    assert_eq!(proof["error"]["code"], "InvalidArgument");
}
#[test]
fn a_draft_is_read_on_the_host_s_chain_when_the_host_gives_it() {
    let mut session = Session::default();
    let configuration: Value = serde_json::from_str(include_str!(
        "../../iceroot-sdk-bindings/tests/data/devnet-configuration.json"
    ))
    .unwrap();
    let key = call(
        &mut session,
        json!({"op":"keyLegacy","profile":profile(),"passphrase":"example"}),
    )["result"]
        .clone();
    let pinned = call(
        &mut session,
        json!({"op":"chainInfo","profile":profile(),"configuration":configuration}),
    )["result"]["profile"]
        .clone();
    let built = call(
        &mut session,
        json!({"op":"draftBuild","profile":pinned,"configuration":configuration,"request":{"operation":{"kind":"vote","entries":[{"validator":"a","basisPoints":10000}]}},"facts":{"sender":key["publicKey"],"nonce":"1","height":2}}),
    )["result"]
        .clone();
    let fee = built["summary"]["fee"].clone();
    assert_eq!(fee["source"], "floor");
    let serialized = built["serialized"].clone();

    // With the profile alone, the floor of the configuration the draft carries is unverified.
    let read = call(
        &mut session,
        json!({"op":"draftRead","profile":pinned,"serialized":serialized}),
    );
    assert_eq!(read["result"]["fee"]["source"], "unverified", "{read}");
    assert_eq!(read["result"]["fee"]["floor"], fee["floor"]);
    // On the host's chain it is the floor.
    let on_chain = call(
        &mut session,
        json!({"op":"draftRead","profile":pinned,"serialized":serialized,"configuration":configuration}),
    );
    assert_eq!(on_chain["result"]["fee"], fee, "{on_chain}");

    // A draft that carries a fee table of its own is refused on the host's chain, to read or
    // to sign.
    let text = String::from_utf8(hex::decode(serialized.as_str().unwrap()).unwrap()).unwrap();
    let tampered = hex::encode(text.replace(r#""minFee":6173"#, r#""minFee":61730"#));
    assert_ne!(tampered, serialized.as_str().unwrap());
    for request in [
        json!({"op":"draftRead","profile":pinned,"serialized":tampered,"configuration":configuration}),
        json!({"op":"draftSign","profile":pinned,"serialized":tampered,"configuration":configuration,"key":key["handle"]}),
    ] {
        let refused = call(&mut session, request);
        assert_eq!(refused["error"]["code"], "NetworkMismatch", "{refused}");
        assert_eq!(refused["error"]["details"]["reason"], "configuration");
    }
    let signed = call(
        &mut session,
        json!({"op":"draftSign","profile":pinned,"serialized":serialized,"configuration":configuration,"key":key["handle"]}),
    );
    assert_eq!(signed["result"]["verified"], true, "{signed}");
}

#[test]
fn a_draft_read_on_the_host_s_chain_is_judged_at_the_host_s_height() {
    let mut session = Session::default();
    // The devnet chain with fees lowered at height 100.
    let mut configuration: Value = serde_json::from_str(include_str!(
        "../../iceroot-sdk-bindings/tests/data/devnet-configuration.json"
    ))
    .unwrap();
    let milestones = configuration["milestones"].as_array_mut().unwrap();
    let mut lowered = milestones.last().unwrap().clone();
    lowered["height"] = json!(100);
    lowered["dynamicFees"]["minFee"] = json!(3000);
    milestones.push(lowered);
    let key = call(
        &mut session,
        json!({"op":"keyLegacy","profile":profile(),"passphrase":"example"}),
    )["result"]
        .clone();
    let pinned = call(
        &mut session,
        json!({"op":"chainInfo","profile":profile(),"configuration":configuration}),
    )["result"]["profile"]
        .clone();
    let built = call(
        &mut session,
        json!({"op":"draftBuild","profile":pinned,"configuration":configuration,"request":{"operation":{"kind":"vote","entries":[{"validator":"a","basisPoints":10000}]}},"facts":{"sender":key["publicKey"],"nonce":"1","height":2}}),
    )["result"]
        .clone();
    assert_eq!(built["summary"]["fee"]["source"], "floor");
    let serialized = built["serialized"].clone();

    // The host's next height: the floor holds before the change, and is unverified past it.
    for (height, source) in [
        (Some(99), "floor"),
        (Some(100), "unverified"),
        (None, "unverified"),
    ] {
        let mut request = json!({"op":"draftRead","profile":pinned,"serialized":serialized,"configuration":configuration});
        if let Some(height) = height {
            request["height"] = json!(height);
        }
        let read = call(&mut session, request);
        assert_eq!(read["result"]["fee"]["source"], source, "{height:?} {read}");
        assert_eq!(
            read["result"]["fee"]["floor"],
            built["summary"]["fee"]["floor"]
        );
    }
    // A height without the host's chain is refused, as is a height that is not a u32.
    let refused = call(
        &mut session,
        json!({"op":"draftRead","profile":pinned,"serialized":serialized,"height":99}),
    );
    assert_eq!(refused["error"]["code"], "InvalidArgument", "{refused}");
    let refused = call(
        &mut session,
        json!({"op":"draftSign","profile":pinned,"serialized":serialized,"configuration":configuration,"height":-1,"key":key["handle"]}),
    );
    assert_eq!(refused["error"]["code"], "InvalidArgument", "{refused}");
    let signed = call(
        &mut session,
        json!({"op":"draftSign","profile":pinned,"serialized":serialized,"configuration":configuration,"height":150,"key":key["handle"]}),
    );
    assert_eq!(signed["result"]["verified"], true, "{signed}");
}
