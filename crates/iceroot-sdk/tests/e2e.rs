//! The devnet end-to-end test of the Rust SDK.
//!
//! Against a running devnet it connects and pins the chain, imports a genesis wallet with the
//! legacy passphrase import, creates an account from a new recovery phrase (and restores it from
//! the phrase's words), funds it, sends a transfer with a memo and a vote from it, waits until each
//! is forged and reads it back through the node API client, checks the fee floor at its edge, and
//! verifies the signed messages and transactions that the tests of another language left for it.
//!
//! It runs only with the `e2e` feature, and only when asked for, against a devnet that
//! `tools/e2e/devnet.sh` starts and stops:
//!
//! ```sh
//! ICEROOT_DEVNET_TOOLS=<devnet tooling> tools/e2e/devnet.sh run -- \
//!     cargo test -p iceroot-sdk --features e2e --test e2e -- --ignored
//! ```
//!
//! The harness sets `ICEROOT_E2E_RELAY`, `ICEROOT_E2E_WALLETS`, `ICEROOT_E2E_MAX_HEIGHT` and
//! `ICEROOT_E2E_ARTIFACTS`. `ICEROOT_E2E_FUNDER` picks the genesis wallet that funds the test
//! (`team-placeholder-1` by default, so that the TypeScript tests can use `genesis-1` and
//! `genesis-2` on the same chain). The TypeScript tests' runner (sdk-typescript's
//! `npm run test:e2e`) runs this test after its own and sets `ICEROOT_E2E_EXPECT_ARTIFACTS` to the
//! number of files they left.

#![cfg(feature = "e2e")]
// Tests may panic: that is how they fail.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use iceroot_sdk::address::Address;
use iceroot_sdk::amount::Amount;
use iceroot_sdk::api::{
    AccountInfo, AssetId, HttpClient, NodeConfiguration, NodeStatus, PageRequest, RejectReason,
    Relay, SolarCompat, TxDetails, TxKind, TxRecord, TxStatus, ValidatorStatus,
};
use iceroot_sdk::error::MismatchProblem;
use iceroot_sdk::fee::{FeeChoice, FeeSource};
use iceroot_sdk::keys::{Account, AccountOptions};
use iceroot_sdk::message::{self, MessageSignature};
use iceroot_sdk::node::submit_result;
use iceroot_sdk::phrase::Mnemonic;
use iceroot_sdk::profile::DevnetOptions;
use iceroot_sdk::transaction::{Operation, Recipient, VoteEntry};
use iceroot_sdk::{
    Chain, Draft, DraftRequest, Error, OnlineFacts, OperationKind, Profile, SignedTransaction,
};
use serde_json::Value;

/// One ROOT in base units, on today's devnet (8 decimals).
const ROOT: u64 = 100_000_000;

fn env(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} is not set: run this test through tools/e2e/devnet.sh"))
}

/// The devnet: the node API client, the node's configuration and the chain it serves.
struct Devnet {
    client: HttpClient,
    api: SolarCompat,
    configuration: NodeConfiguration,
    chain: Chain,
    relay: String,
    max_height: u64,
}

impl Devnet {
    /// Connects as an application does: the node's configuration, then its chain, loaded for
    /// the devnet profile and pinned.
    async fn connect() -> Devnet {
        let relay = env("ICEROOT_E2E_RELAY");
        let max_height = env("ICEROOT_E2E_MAX_HEIGHT").parse().expect("a height");
        let client = HttpClient::new(vec![Relay::parse(&relay).expect("a relay")]).unwrap();
        let configuration = client
            .send(&SolarCompat::new(0).node_configuration())
            .await
            .unwrap();
        let api = SolarCompat::for_configuration(&configuration);
        let crypto = client.send(&api.crypto_configuration()).await.unwrap();
        let profile = Profile::devnet(DevnetOptions {
            relays: vec![relay.clone()],
            nethash: None,
        });
        let chain = Chain::from_node(&profile, &crypto).expect("the devnet's chain loads");
        chain
            .check_node(&configuration)
            .expect("the node serves the chain");
        assert_eq!(
            chain.profile().chain().nethash.as_deref(),
            Some(chain.nethash())
        );
        Devnet {
            client,
            api,
            configuration,
            chain,
            relay,
            max_height,
        }
    }

    async fn status(&self) -> NodeStatus {
        let status = self.client.send(&self.api.node_status()).await.unwrap();
        assert!(
            status.height <= self.max_height,
            "the chain passed its last height {}",
            self.max_height
        );
        status
    }

    async fn account(&self, address: &Address) -> AccountInfo {
        let call = self.api.account(&address.to_string()).unwrap();
        self.client.send(&call).await.unwrap()
    }

    async fn balance(&self, address: &Address) -> u128 {
        self.account(address).await.balance(AssetId::ROOT)
    }

    /// The fee floor of a transaction of `kind` that is `size` bytes long, computed here from the
    /// fees the node's pool reports, not by the SDK: `(addonBytes + ceil(size / 2)) × minFee`,
    /// and nothing for burns and resignations.
    fn node_floor(&self, kind: OperationKind, size: usize) -> u64 {
        let fees = &self.configuration.pool_fees;
        if !fees.dynamic || matches!(kind, OperationKind::Burn | OperationKind::ResignValidator) {
            return 0;
        }
        let addon = fees
            .addon_bytes
            .iter()
            .find(|(entry, _)| *entry == kind.tx_kind())
            .map_or(0, |(_, bytes)| *bytes);
        let half = u64::try_from(size.div_ceil(2)).unwrap();
        (addon + half) * fees.min_fee_pool.max(1)
    }

    /// A draft of `operation` by `sender`, with the facts the node reports and the fee floor.
    ///
    /// The draft takes the default fee choice and must come out at the floor the node's fees
    /// give. With `below` above zero, the same transaction is built again with an exact fee that
    /// many base units under the floor.
    async fn draft(
        &self,
        operation: Operation,
        memo: Option<&str>,
        sender: &Account,
        below: u64,
    ) -> Draft {
        let status = self.status().await;
        let account = self.account(sender.address()).await;
        let facts =
            OnlineFacts::from_node(&self.chain, sender.public_key(), Some(&account), &status)
                .expect("the node's facts");
        let request = |fee| DraftRequest {
            operation: operation.clone(),
            memo: memo.map(str::to_owned),
            fee,
        };
        assert!(self.chain.rules(facts.height).fees.floor_available);
        let draft = Draft::build(&self.chain, &request(FeeChoice::Minimum), &facts, None)
            .expect("a draft at the floor");
        let floor = self.node_floor(draft.kind(), draft.size());
        assert_eq!(draft.fee().source, FeeSource::Floor);
        assert_eq!(draft.fee().amount, Amount::from(floor));
        if below == 0 {
            return draft;
        }
        // The size does not depend on the fee, whose field has a fixed width.
        let exact = request(FeeChoice::Exact(Amount::from(floor - below)));
        let below_floor = Draft::build(&self.chain, &exact, &facts, None).unwrap();
        assert_eq!(below_floor.size(), draft.size());
        below_floor
    }

    /// Submits one signed transaction and returns the node's verdict.
    async fn submit(&self, signed: &SignedTransaction) -> Result<(), Error> {
        let plan = self
            .api
            .submit(&[signed.to_submit().unwrap()], &self.configuration.pool)
            .unwrap();
        let report = self.client.submit(&plan).await.unwrap();
        let [outcome] = report.outcomes.as_slice() else {
            panic!("one outcome per transaction: {report:?}");
        };
        assert_eq!(outcome.id, signed.id());
        submit_result(outcome)
    }

    /// Waits until the transaction `id` is in a block, at most a few block times.
    async fn forged(&self, id: &str) -> TxRecord {
        let block_time = u64::from(self.configuration.block_time);
        let deadline = Instant::now() + Duration::from_secs(block_time * 8);
        loop {
            if let Some(record) = self
                .client
                .send(&self.api.transaction(id).unwrap())
                .await
                .unwrap()
            {
                assert_eq!(record.status, TxStatus::Confirmed);
                return record;
            }
            assert!(Instant::now() < deadline, "{id} was not forged in time");
            self.status().await;
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }

    /// Signs, submits and waits: the transaction as the node then reports it.
    async fn send(&self, draft: &Draft, sender: &Account) -> (SignedTransaction, TxRecord) {
        let signed = draft.sign(sender, None).expect("signed");
        assert!(signed.is_verified());
        self.submit(&signed).await.expect("accepted");
        let record = self.forged(&signed.id()).await;
        check_record(&record, &signed);
        (signed, record)
    }

    /// Validators that operate a node, which the node requires of the validators a vote names.
    /// Validators announce themselves as the chain runs, so this waits for `count` of them.
    async fn operating_validators(&self, count: usize) -> Vec<String> {
        let deadline = Instant::now()
            + Duration::from_secs(
                u64::from(self.configuration.block_time) * u64::from(self.configuration.seats) * 2,
            );
        loop {
            let page = self
                .client
                .send(&self.api.validators(PageRequest::first(100)))
                .await
                .unwrap();
            let names: Vec<String> = page
                .items
                .into_iter()
                .filter(|v| v.status == ValidatorStatus::Active && v.version.is_some())
                .map(|v| v.name)
                .take(count)
                .collect();
            if names.len() == count {
                return names;
            }
            assert!(
                Instant::now() < deadline,
                "too few validators operate a node"
            );
            self.status().await;
            tokio::time::sleep(Duration::from_secs(16)).await;
        }
    }
}

/// The node's record of a transaction is the signed transaction: id, sender, nonce, fee, memo,
/// signatures and content.
fn check_record(record: &TxRecord, signed: &SignedTransaction) {
    assert_eq!(record.id, signed.id());
    assert_eq!(record.sender, signed.sender().to_string());
    assert_eq!(
        record.sender_public_key,
        signed.sender_public_key().to_hex()
    );
    assert_eq!(record.nonce, signed.nonce());
    assert_eq!(record.fee, signed.fee().base_units());
    assert_eq!(record.memo.as_deref(), signed.memo());
    assert_eq!(record.second_signed, signed.has_second_signature());
    assert_eq!(record.version, 3);
    match (&record.details, signed.operation()) {
        (TxDetails::Transfer { recipients }, Operation::Transfer { recipients: ours }) => {
            let theirs: Vec<(String, u128)> = recipients
                .iter()
                .map(|p| (p.address.clone(), p.amount))
                .collect();
            let ours: Vec<(String, u128)> = ours
                .iter()
                .map(|r| (r.address.to_string(), r.amount.base_units()))
                .collect();
            assert_eq!(theirs, ours);
        }
        (TxDetails::Vote { entries }, Operation::Vote { entries: ours }) => {
            assert_eq!(entries, &ours);
        }
        (details, operation) => panic!("the node reports {details:?} for {operation:?}"),
    }
}

/// The passphrase of a genesis wallet of the generated devnet.
fn genesis_passphrase(label: &str) -> String {
    let text = std::fs::read_to_string(env("ICEROOT_E2E_WALLETS")).expect("the wallets file");
    let wallets: Value = serde_json::from_str(&text).expect("JSON");
    wallets["genesis"]
        .as_array()
        .expect("genesis wallets")
        .iter()
        .find(|wallet| wallet["label"] == label)
        .and_then(|wallet| wallet["passphrase"].as_str())
        .unwrap_or_else(|| panic!("no genesis wallet {label}"))
        .to_owned()
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "needs a devnet: run it through tools/e2e/devnet.sh"]
async fn devnet_end_to_end() {
    let devnet = Devnet::connect().await;
    let chain = &devnet.chain;
    let profile = chain.profile();
    let token = chain.token();
    assert_eq!((token.decimals, chain.network_byte()), (8, 90));

    // A profile pinned to another chain is refused.
    let other = Profile::devnet(DevnetOptions {
        relays: vec![devnet.relay.clone()],
        nethash: Some("00".repeat(32)),
    });
    let crypto = devnet
        .client
        .send(&devnet.api.crypto_configuration())
        .await
        .unwrap();
    assert!(matches!(
        Chain::from_node(&other, &crypto),
        Err(Error::NetworkMismatch {
            problem: MismatchProblem::Nethash { .. }
        })
    ));

    // A genesis wallet by the legacy import, and a new account from a new recovery phrase.
    let funder_label =
        std::env::var("ICEROOT_E2E_FUNDER").unwrap_or_else(|_| "team-placeholder-1".to_owned());
    let funder = Account::from_legacy_passphrase(profile, &genesis_passphrase(&funder_label))
        .expect("the genesis wallet");
    assert!(funder.is_legacy());
    let phrase = Mnemonic::generate().expect("a phrase");
    assert_eq!(phrase.word_count(), 24);
    let holder = Account::from_phrase(profile, &phrase, &AccountOptions::default()).unwrap();
    let second_address = AccountOptions {
        index: 1,
        ..AccountOptions::default()
    };
    let payee = Account::from_phrase(profile, &phrase, &second_address).unwrap();
    // Restored from its words, typed with other spacing and case, the phrase gives the same keys.
    let typed = phrase.phrase().to_uppercase().replace(' ', "  ");
    let restored = Account::from_phrase(
        profile,
        &Mnemonic::parse(&typed).unwrap(),
        &AccountOptions::default(),
    )
    .unwrap();
    assert_eq!(restored.address(), holder.address());
    assert_eq!(devnet.account(holder.address()).await.nonce, 0);

    // Fund both addresses from the genesis wallet.
    let funder_before = devnet.account(funder.address()).await;
    let funding = Operation::Transfer {
        recipients: vec![
            Recipient {
                address: *holder.address(),
                amount: Amount::from(250 * ROOT),
            },
            Recipient {
                address: *payee.address(),
                amount: Amount::from(ROOT),
            },
        ],
    };
    let draft = devnet
        .draft(funding, Some("sdk-rust e2e: funding"), &funder, 0)
        .await;
    let (signed, _) = devnet.send(&draft, &funder).await;
    let funder_after = devnet.account(funder.address()).await;
    assert_eq!(funder_after.nonce, funder_before.nonce + 1);
    assert_eq!(
        funder_after.balance(AssetId::ROOT),
        funder_before.balance(AssetId::ROOT) - u128::from(251 * ROOT) - signed.fee().base_units()
    );
    assert_eq!(
        devnet.balance(holder.address()).await,
        u128::from(250 * ROOT)
    );
    assert_eq!(devnet.balance(payee.address()).await, u128::from(ROOT));

    // A transfer with a memo from the new account, its first transaction.
    let transfer = Operation::Transfer {
        recipients: vec![Recipient {
            address: *payee.address(),
            amount: Amount::parse("1.5", token.decimals).unwrap(),
        }],
    };
    let memo = "sdk-rust e2e: \u{2713} first transfer";
    let draft = devnet.draft(transfer, Some(memo), &holder, 0).await;
    assert_eq!(draft.nonce(), 1);
    let (signed, record) = devnet.send(&draft, &holder).await;
    assert_eq!(record.memo.as_deref(), Some(memo));
    let holder_info = devnet.account(holder.address()).await;
    assert_eq!(holder_info.nonce, 1);
    assert_eq!(
        holder_info.public_key.as_deref(),
        Some(holder.public_key().to_hex().as_str())
    );
    assert_eq!(
        holder_info.balance(AssetId::ROOT),
        u128::from(250 * ROOT - 150_000_000) - signed.fee().base_units()
    );
    assert_eq!(
        devnet.balance(payee.address()).await,
        u128::from(ROOT + 150_000_000)
    );

    // A vote for two validators that operate a node, given out of order.
    let names = devnet.operating_validators(2).await;
    let entries = vec![
        VoteEntry {
            validator: names[1].clone(),
            basis_points: 4_000,
        },
        VoteEntry {
            validator: names[0].clone(),
            basis_points: 6_000,
        },
    ];
    let draft = devnet
        .draft(Operation::Vote { entries }, None, &holder, 0)
        .await;
    let Operation::Vote { entries: canonical } = draft.operation() else {
        panic!("a vote");
    };
    let (_, record) = devnet.send(&draft, &holder).await;
    assert_eq!(record.kind(), TxKind::Vote);
    assert_eq!(devnet.account(holder.address()).await.vote, canonical);

    // One base unit below the floor is refused, with the node's own code.
    let transfer = Operation::Transfer {
        recipients: vec![Recipient {
            address: *payee.address(),
            amount: Amount::from(1u64),
        }],
    };
    let draft = devnet.draft(transfer, None, &holder, 1).await;
    let signed = draft.sign(&holder, None).unwrap();
    match devnet.submit(&signed).await {
        Err(Error::TxRejected {
            reason, node_code, ..
        }) => {
            assert_eq!(reason, RejectReason::LowFee);
            assert_eq!(node_code, "ERR_LOW_FEE");
        }
        other => panic!("a fee below the floor was not refused as too low: {other:?}"),
    }
    assert_eq!(devnet.account(holder.address()).await.nonce, 2);

    // What the tests of another language signed on this chain, checked natively.
    check_artifacts(&devnet).await;
    devnet.status().await;
}

/// Checks the files other tests left in `ICEROOT_E2E_ARTIFACTS`: each `*.message.json` holds a
/// signed message that must verify here, and must fail once changed; each
/// `*.transactions.json` lists transactions that must be in blocks with the sender and nonce given.
async fn check_artifacts(devnet: &Devnet) {
    let dir = PathBuf::from(env("ICEROOT_E2E_ARTIFACTS"));
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("the artifacts directory")
        .map(|entry| entry.unwrap().path())
        .collect();
    files.sort();
    let mut checked = 0;
    for file in files {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        let value: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        if name.ends_with(".message.json") {
            let text = value["message"].as_str().expect("a message");
            let signature = MessageSignature {
                public_key: value["publicKey"].as_str().unwrap().to_owned(),
                signature: value["signature"].as_str().unwrap().to_owned(),
                algorithm: value["algorithm"].as_str().unwrap().to_owned(),
                network: value["network"].as_str().unwrap().to_owned(),
            };
            assert_eq!(signature.algorithm, message::ALGORITHM, "{name}");
            assert_eq!(
                signature.network,
                devnet.chain.profile().message_network().unwrap(),
                "{name}"
            );
            assert!(message::verify(text, &signature), "{name}: does not verify");
            assert!(
                !message::verify(&format!("{text}."), &signature),
                "{name}: verifies a changed message"
            );
            checked += 1;
        } else if name.ends_with(".transactions.json") {
            for entry in value.as_array().expect("a list") {
                let id = entry["id"].as_str().unwrap();
                let record = devnet
                    .client
                    .send(&devnet.api.transaction(id).unwrap())
                    .await
                    .unwrap()
                    .unwrap_or_else(|| panic!("{name}: {id} is not in a block"));
                assert_eq!(record.sender, entry["sender"].as_str().unwrap(), "{name}");
                assert_eq!(
                    record.nonce.to_string(),
                    entry["nonce"].as_str().unwrap(),
                    "{name}"
                );
            }
            checked += 1;
        }
    }
    eprintln!("e2e: {checked} artifact files of other tests checked");
    // The TypeScript tests' runner says how many files they left.
    if let Ok(expected) = std::env::var("ICEROOT_E2E_EXPECT_ARTIFACTS") {
        assert_eq!(
            checked.to_string(),
            expected,
            "artifact files of other tests"
        );
    }
}
