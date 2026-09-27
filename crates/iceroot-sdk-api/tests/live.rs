//! Runs every call against a live node. Ignored by default; run it with
//! `ICEROOT_SDK_LIVE_RELAY=http://127.0.0.1:4003/api cargo test -p iceroot-sdk-api --features http --test live -- --ignored`.

#![cfg(feature = "http")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use iceroot_sdk_api::{
    BlockRef, HistoryDirection, HttpClient, PageRequest, Relay, SolarCompat, TxFilter, TxKind,
};

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs a live node: set ICEROOT_SDK_LIVE_RELAY"]
async fn every_call_against_a_live_node() {
    let Ok(url) = std::env::var("ICEROOT_SDK_LIVE_RELAY") else {
        eprintln!("ICEROOT_SDK_LIVE_RELAY is not set; nothing to do");
        return;
    };
    let client = HttpClient::new(vec![Relay::parse(&url).unwrap()]).unwrap();
    let configuration = client
        .send(&SolarCompat::new(0).node_configuration())
        .await
        .unwrap();
    let api = SolarCompat::for_configuration(&configuration);
    let page = PageRequest::first(5);

    let status = client.send(&api.node_status()).await.unwrap();
    assert!(status.height > 1);
    let crypto = client.send(&api.crypto_configuration()).await.unwrap();
    assert_eq!(crypto.nethash, configuration.network.nethash);
    client
        .send(&api.fee_statistics(Some(30)).unwrap())
        .await
        .unwrap();
    client
        .send(&api.fee_statistics(None).unwrap())
        .await
        .unwrap();
    let supply = client.send(&api.supply()).await.unwrap();
    assert!(supply.supply > 0);

    let validators = client
        .send(&api.validators(PageRequest::first(100)))
        .await
        .unwrap();
    let top = validators.items.first().unwrap().clone();
    assert!(
        client
            .send(&api.validator(&top.name).unwrap())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        client
            .send(&api.resolve_name(&top.name).unwrap())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        client
            .send(&api.resolve_name(&top.address).unwrap())
            .await
            .unwrap()
            .is_none()
    );
    client
        .send(&api.voters(&top.name, page).unwrap())
        .await
        .unwrap();
    let produced = client
        .send(&api.validator_blocks(&top.name, page).unwrap())
        .await
        .unwrap();
    assert!(produced.items.windows(2).all(|w| w[0].height > w[1].height));
    client
        .send(&api.validator_missed_slots(&top.name, page).unwrap())
        .await
        .unwrap();
    client.send(&api.missed_slots(page)).await.unwrap();
    let round = client
        .send(&api.round_validators(1).unwrap())
        .await
        .unwrap();
    assert_eq!(round.len(), usize::try_from(configuration.seats).unwrap());

    let latest = client.send(&api.latest_block()).await.unwrap();
    let genesis = client.send(&api.genesis_block()).await.unwrap();
    assert_eq!(genesis.height, 1);
    assert!(genesis.previous.is_none());
    let blocks = client.send(&api.blocks(page)).await.unwrap();
    assert!(blocks.items.windows(2).all(|w| w[0].height > w[1].height));
    assert!(
        client
            .send(&api.block(&BlockRef::Height(latest.height)).unwrap())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        client
            .send(&api.block(&BlockRef::Id(latest.id.clone())).unwrap())
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        client
            .send(&api.block(&BlockRef::Height(u64::from(u32::MAX))).unwrap())
            .await
            .unwrap()
            .is_none()
    );

    let transfers = client
        .send(&api.transactions(
            &TxFilter {
                kind: Some(TxKind::Transfer),
                ..TxFilter::default()
            },
            page,
        ))
        .await
        .unwrap();
    let tx = transfers.items.first().unwrap().clone();
    assert!(transfers.items.iter().all(|t| t.kind() == TxKind::Transfer));
    let block = tx.block.clone().unwrap();
    client
        .send(
            &api.block_transactions(&BlockRef::Id(block.id), page)
                .unwrap(),
        )
        .await
        .unwrap();
    let found = client
        .find_transaction(&api, &tx.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.id, tx.id);
    assert!(
        client
            .send(&api.unconfirmed_transaction(&tx.id).unwrap())
            .await
            .unwrap()
            .is_none()
    );
    client
        .send(&api.unconfirmed_transactions(page))
        .await
        .unwrap();
    let oldest = client
        .send(&api.transactions(
            &TxFilter {
                sender: Some(tx.sender.clone()),
                oldest_first: true,
                ..TxFilter::default()
            },
            page,
        ))
        .await
        .unwrap();
    assert!(oldest.items.iter().all(|t| t.sender == tx.sender));

    for direction in [
        HistoryDirection::All,
        HistoryDirection::Sent,
        HistoryDirection::Received,
    ] {
        let history = client
            .send(&api.history(&tx.sender, direction, page).unwrap())
            .await
            .unwrap();
        assert!(history.items.iter().all(|t| t.direction.is_some()));
    }
    let account = client
        .send(&api.account(&tx.sender).unwrap())
        .await
        .unwrap();
    assert_eq!(account.address, tx.sender);
    client
        .send(&api.account_votes(&tx.sender, page).unwrap())
        .await
        .unwrap();
    let votes = client.send(&api.votes(page)).await.unwrap();
    if let Some(vote) = votes.items.first() {
        assert!(
            client
                .send(&api.vote(&vote.id).unwrap())
                .await
                .unwrap()
                .is_some()
        );
    }
}
