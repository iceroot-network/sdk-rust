//! Drafts end to end: building every operation, the rules applied before signing, signing with
//! one and two keys, and the serialized forms, on the devnet chain of the vector files.

// Tests may panic on a broken vector or fixture: that is how they fail.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use common::DEVNET;
use heartwood_crypto::Aux;
use iceroot_sdk_core::address::Address;
use iceroot_sdk_core::amount::Amount;
use iceroot_sdk_core::error::{
    AddressProblem, AmountProblem, MismatchProblem, TransactionProblem, VoteProblem,
};
use iceroot_sdk_core::fee::{FeeChoice, FeeSource};
use iceroot_sdk_core::keys::{Account, AccountOptions};
use iceroot_sdk_core::phrase::Mnemonic;
use iceroot_sdk_core::profile::DevnetOptions;
use iceroot_sdk_core::transaction::{
    Draft, DraftRequest, OnlineFacts, Operation, OperationKind, Recipient, Resignation,
    SignedTransaction, VoteEntry, vote_from_percentages,
};
use iceroot_sdk_core::{Chain, Error, Profile, PublicKeyBytes};

const HEIGHT: u32 = 2;
const AUX: Aux = Aux::fixed([7; 32]);

fn chain() -> &'static Chain {
    &DEVNET.chain
}

fn phrase_account(index: u32) -> Account {
    let phrase = Mnemonic::from_entropy(&[0x5a; 32]).expect("a phrase");
    Account::from_phrase(
        chain().profile(),
        &phrase,
        &AccountOptions {
            account: 0,
            index,
            passphrase: "",
        },
    )
    .expect("an account")
}

fn facts(sender: &Account) -> OnlineFacts {
    OnlineFacts {
        sender: sender.public_key().clone(),
        nonce: 1,
        height: HEIGHT,
        second_key: None,
    }
}

fn build(sender: &Account, operation: Operation) -> Result<Draft, Error> {
    Draft::build(chain(), &DraftRequest::new(operation), &facts(sender))
}

fn transfer(to: &Account, amount: u64) -> Operation {
    Operation::Transfer {
        recipients: vec![Recipient {
            address: *to.address(),
            amount: Amount::from(amount),
        }],
    }
}

fn names(count: usize) -> Vec<String> {
    (1..=count).map(|n| format!("genesis_{n}")).collect()
}

fn vote(count: usize) -> Operation {
    let each = u16::try_from(10_000 / count).expect("a share");
    let mut entries: Vec<VoteEntry> = names(count)
        .into_iter()
        .map(|validator| VoteEntry {
            validator,
            basis_points: each,
        })
        .collect();
    let rest = 10_000 - each * u16::try_from(count).expect("a count");
    entries[0].basis_points += rest;
    Operation::Vote { entries }
}

#[test]
fn a_transfer_from_build_to_bytes() {
    let sender = phrase_account(0);
    let recipient = phrase_account(1);
    let request = DraftRequest {
        operation: transfer(&recipient, 150_000_000),
        memo: Some("invoice 42".to_owned()),
        fee: FeeChoice::Minimum,
    };
    let draft = Draft::build(chain(), &request, &facts(&sender)).unwrap();
    let summary = draft.summary();
    assert_eq!(summary.profile, "devnet");
    assert_eq!(summary.network_byte, 90);
    assert_eq!(summary.nethash, chain().nethash());
    assert_eq!(summary.sender, *sender.address());
    assert_eq!(summary.nonce, 1);
    // The exact floor: (85 + ceil(size / 2)) × 6173.
    let floor = (85 + u64::try_from(draft.size().div_ceil(2)).unwrap()) * 6173;
    assert_eq!(summary.fee.amount, Amount::from(floor));
    assert_eq!(summary.fee.source, FeeSource::Floor);
    assert_eq!(summary.fee.floor, Some(Amount::from(floor)));
    assert_eq!(summary.memo.as_deref(), Some("invoice 42"));
    assert_eq!(summary.total_amount, Amount::from(150_000_000u64));
    assert!(!summary.second_signature);

    let signed = draft.sign(&sender, None).unwrap();
    assert_eq!(signed.bytes().len(), draft.size());
    assert!(signed.is_verified());
    assert_eq!(signed.id().len(), 64);
    let json = signed.json();
    assert_eq!(json["senderId"], sender.address().to_string());
    assert_eq!(json["memo"], "invoice 42");
    assert_eq!(json["fee"], floor.to_string());
    assert_eq!(json["asset"]["transfers"][0]["amount"], "150000000");

    // A node reads the same transaction back, from bytes and from JSON.
    let decoded = SignedTransaction::decode(chain(), signed.bytes(), HEIGHT).unwrap();
    assert_eq!(decoded.id(), signed.id());
    assert!(decoded.is_verified());
    assert_eq!(decoded.operation(), draft.operation());
    let from_json = SignedTransaction::from_json(chain(), &json, HEIGHT).unwrap();
    assert_eq!(from_json.bytes(), signed.bytes());

    // Fresh randomness per signature: another id, both valid.
    let again = draft.sign(&sender, None).unwrap();
    assert_ne!(again.id(), signed.id());
    assert!(again.is_verified());
}

#[test]
fn every_operation_builds_and_signs() {
    let sender = phrase_account(0);
    let recipient = phrase_account(1);
    let second = phrase_account(2).public_key().to_compressed();
    let many: Vec<Recipient> = (0..256)
        .map(|n| Recipient {
            address: *recipient.address(),
            amount: Amount::from(n + 1),
        })
        .collect();
    let operations = [
        transfer(&recipient, 1),
        Operation::Transfer { recipients: many },
        vote(1),
        vote(20),
        vote(53),
        Operation::Vote {
            entries: Vec::new(),
        },
        Operation::Burn {
            amount: Amount::from(2_000_000u64),
        },
        Operation::RegisterSecondKey {
            public_key: PublicKeyBytes::from_array(*second.as_bytes()),
        },
        Operation::RegisterValidator {
            name: "sdk_validator".to_owned(),
        },
        Operation::ResignValidator {
            kind: Resignation::Temporary,
        },
        Operation::ResignValidator {
            kind: Resignation::Permanent,
        },
        Operation::ResignValidator {
            kind: Resignation::Revoke,
        },
    ];
    for operation in operations {
        let draft = build(&sender, operation.clone())
            .unwrap_or_else(|error| panic!("{operation:?}: {error}"));
        let signed = draft.sign_with(&sender, None, AUX).unwrap();
        assert!(signed.is_verified(), "{operation:?}");
        assert_eq!(signed.bytes().len(), draft.size());
        assert_eq!(signed.kind(), operation.kind());
        let decoded = SignedTransaction::decode(chain(), signed.bytes(), HEIGHT).unwrap();
        assert_eq!(decoded.operation(), draft.operation());
        if let Operation::Vote { entries } = &operation {
            // Canonical order: largest share first, then by name.
            let Operation::Vote { entries: sorted } = draft.operation() else {
                panic!("a vote");
            };
            assert_eq!(sorted.len(), entries.len());
            assert!(
                sorted
                    .windows(2)
                    .all(|pair| pair[0].basis_points >= pair[1].basis_points)
            );
        }
    }
}

#[test]
fn rules_before_signing() {
    let sender = phrase_account(0);
    let recipient = phrase_account(1);
    let refused = |operation: Operation| build(&sender, operation).unwrap_err();

    assert_eq!(
        refused(Operation::Transfer {
            recipients: Vec::new()
        }),
        Error::NoRecipients { minimum: 1 }
    );
    let too_many: Vec<Recipient> = (0..257)
        .map(|_| Recipient {
            address: *recipient.address(),
            amount: Amount::from(1u64),
        })
        .collect();
    assert_eq!(
        refused(Operation::Transfer {
            recipients: too_many
        }),
        Error::TooManyRecipients {
            count: 257,
            maximum: 256
        }
    );
    assert_eq!(
        refused(transfer(&recipient, 0)),
        Error::InvalidAmount {
            problem: AmountProblem::Zero
        }
    );
    assert_eq!(
        refused(Operation::Transfer {
            recipients: vec![Recipient {
                address: *recipient.address(),
                amount: Amount::from_base_units(1 << 63),
            }]
        }),
        Error::InvalidAmount {
            problem: AmountProblem::TooLarge
        }
    );
    let other_network = Address::parse_any_network("SNAgA2XCRZDKfm5Vu9h4KR1bZw5xn9EiC3").unwrap();
    assert_eq!(
        refused(Operation::Transfer {
            recipients: vec![Recipient {
                address: other_network,
                amount: Amount::from(1u64),
            }]
        }),
        Error::InvalidAddress {
            problem: AddressProblem::WrongNetwork {
                expected: 90,
                actual: 63
            }
        }
    );

    let entry = |validator: &str, basis_points| VoteEntry {
        validator: validator.to_owned(),
        basis_points,
    };
    assert_eq!(
        refused(Operation::Vote {
            entries: vec![entry("a", 5000), entry("b", 4999)]
        }),
        Error::InvalidVote {
            problem: VoteProblem::Sum { basis_points: 9999 }
        }
    );
    assert_eq!(
        refused(Operation::Vote {
            entries: vec![entry("a", 5000), entry("a", 5000)]
        }),
        Error::InvalidVote {
            problem: VoteProblem::Duplicate {
                validator: "a".into()
            }
        }
    );
    assert_eq!(
        refused(Operation::Vote {
            entries: vec![entry("Not_A_Name", 10_000)]
        }),
        Error::InvalidVote {
            problem: VoteProblem::Name {
                validator: "Not_A_Name".into()
            }
        }
    );
    assert_eq!(
        refused(Operation::Vote {
            entries: vec![entry("a", 0), entry("b", 10_000)]
        }),
        Error::InvalidVote {
            problem: VoteProblem::Share {
                validator: "a".into(),
                basis_points: 0
            }
        }
    );
    assert_eq!(
        refused(vote(54)),
        Error::InvalidVote {
            problem: VoteProblem::TooManyEntries {
                count: 54,
                maximum: 53
            }
        }
    );
    // 53 entries with 20-character names do not fit 1,024 bytes.
    let long: Vec<VoteEntry> = (0..53)
        .map(|n| {
            entry(
                &format!("validator_name_{n:05}"),
                if n == 0 { 10_000 - 52 * 188 } else { 188 },
            )
        })
        .collect();
    assert!(matches!(
        refused(Operation::Vote { entries: long }),
        Error::InvalidVote {
            problem: VoteProblem::TooLarge { maximum: 1024, .. }
        }
    ));
    assert_eq!(
        refused(Operation::Burn {
            amount: Amount::from(1_999_999u64)
        }),
        Error::InvalidAmount {
            problem: AmountProblem::BelowMinimum { minimum: 2_000_000 }
        }
    );
    assert!(matches!(
        refused(Operation::RegisterValidator {
            name: "Upper".to_owned()
        }),
        Error::InvalidName { .. }
    ));
    assert_eq!(
        refused(Operation::RegisterSecondKey {
            public_key: PublicKeyBytes::from_array([0; 33])
        }),
        Error::InvalidKey
    );

    // Memos: 255 bytes fit, 256 do not; an empty memo is none.
    let with_memo = |memo: &str| {
        Draft::build(
            chain(),
            &DraftRequest {
                operation: transfer(&recipient, 1),
                memo: Some(memo.to_owned()),
                fee: FeeChoice::Minimum,
            },
            &facts(&sender),
        )
    };
    assert!(with_memo(&"é".repeat(127)).is_ok());
    assert_eq!(
        with_memo(&"x".repeat(256)).unwrap_err(),
        Error::MemoTooLong {
            bytes: 256,
            maximum: 255
        }
    );
    assert_eq!(with_memo("").unwrap().memo(), None);
}

#[test]
fn fees() {
    let sender = phrase_account(0);
    let recipient = phrase_account(1);
    let with_fee = |fee: FeeChoice| {
        Draft::build(
            chain(),
            &DraftRequest {
                operation: transfer(&recipient, 1),
                memo: None,
                fee,
            },
            &facts(&sender),
        )
    };
    // A 154-byte transfer: (85 + 77) × 6173.
    let floor = Amount::from(1_000_026u64);
    let minimum = with_fee(FeeChoice::Minimum).unwrap();
    assert_eq!(minimum.size(), 154);
    assert_eq!(
        (
            minimum.fee().amount,
            minimum.fee().source,
            minimum.fee().floor
        ),
        (floor, FeeSource::Floor, Some(floor))
    );
    let exact = with_fee(FeeChoice::Exact(Amount::from(1_000_025u64))).unwrap();
    assert_eq!(exact.fee().amount, Amount::from(1_000_025u64));
    assert_eq!(exact.fee().source, FeeSource::Explicit);
    assert_eq!(exact.fee().floor, Some(floor));
    let scaled = with_fee(FeeChoice::Multiplier {
        basis_points: 12_500,
    })
    .unwrap();
    assert_eq!(scaled.fee().amount, Amount::from(1_250_033u64));
    assert_eq!(scaled.fee().source, FeeSource::Explicit);
    assert!(matches!(
        with_fee(FeeChoice::Exact(Amount::ZERO)),
        Err(Error::InvalidFee { .. })
    ));
    // A burn may carry no fee.
    let burn = Draft::build(
        chain(),
        &DraftRequest {
            operation: Operation::Burn {
                amount: Amount::from(2_000_000u64),
            },
            memo: None,
            fee: FeeChoice::Exact(Amount::ZERO),
        },
        &facts(&sender),
    )
    .unwrap();
    assert!(burn.sign(&sender, None).unwrap().is_verified());
    assert_eq!(burn.fee().floor, Some(Amount::ZERO));
    assert!(chain().rules(HEIGHT).fees.floor_available);
    assert_eq!(
        chain().fee_floor(OperationKind::Transfer, 154, HEIGHT),
        Some(floor)
    );
    // The registration surcharge is part of the floor.
    let registration = Draft::build(
        chain(),
        &DraftRequest::new(Operation::RegisterValidator {
            name: "sdk_validator".to_owned(),
        }),
        &facts(&sender),
    )
    .unwrap();
    let half = u64::try_from(registration.size().div_ceil(2)).unwrap();
    assert_eq!(
        registration.fee().amount,
        Amount::from((1_214_968 + half) * 6173)
    );
}

#[test]
fn a_serialized_fee_source_is_checked() {
    let sender = phrase_account(0);
    let recipient = phrase_account(1);
    let profile = chain().profile();
    let with_fee = |fee: FeeChoice| {
        Draft::build(
            chain(),
            &DraftRequest {
                operation: transfer(&recipient, 1),
                memo: None,
                fee,
            },
            &facts(&sender),
        )
        .unwrap()
    };
    let form = |draft: &Draft| String::from_utf8(draft.serialize()).unwrap();
    let floor = Amount::from(1_000_026u64);

    // The floor stays the floor, and an explicit fee stays explicit, even at the floor.
    for (fee, source) in [
        (FeeChoice::Minimum, FeeSource::Floor),
        (FeeChoice::Exact(floor), FeeSource::Explicit),
        (
            FeeChoice::Exact(Amount::from(2_000_000u64)),
            FeeSource::Explicit,
        ),
        (
            FeeChoice::Multiplier {
                basis_points: 15_000,
            },
            FeeSource::Explicit,
        ),
    ] {
        let draft = with_fee(fee);
        assert_eq!(draft.fee().source, source, "{fee:?}");
        let again = Draft::deserialize(form(&draft).as_bytes(), profile).unwrap();
        assert_eq!(again.summary(), draft.summary(), "{fee:?}");
    }

    // A fee above the floor that the form calls the floor reads as explicit, beside the floor.
    let above = with_fee(FeeChoice::Exact(Amount::from(2_000_000u64)));
    let text = form(&above);
    assert!(text.contains(r#""source":"explicit""#), "{text}");
    let claimed = text.replace(r#""source":"explicit""#, r#""source":"floor""#);
    let shown = Draft::deserialize(claimed.as_bytes(), profile).unwrap();
    assert_eq!(shown.fee().amount, Amount::from(2_000_000u64));
    assert_eq!(shown.fee().source, FeeSource::Explicit);
    assert_eq!(shown.fee().floor, Some(floor));

    // The floor in the form is never read; any source other than the floor reads as explicit.
    let minimum = form(&with_fee(FeeChoice::Minimum));
    let lowered = minimum.replace(r#""floor":"1000026""#, r#""floor":"1""#);
    assert_ne!(lowered, minimum);
    let again = Draft::deserialize(lowered.as_bytes(), profile).unwrap();
    assert_eq!(
        (again.fee().source, again.fee().floor),
        (FeeSource::Floor, Some(floor))
    );
    for claim in ["node-statistics", "cheapest", "explicit", ""] {
        let claimed = minimum.replace(r#""source":"floor""#, &format!(r#""source":"{claim}""#));
        assert_ne!(claimed, minimum);
        let again = Draft::deserialize(claimed.as_bytes(), profile).unwrap();
        assert_eq!(
            (again.fee().amount, again.fee().source, again.fee().floor),
            (floor, FeeSource::Explicit, Some(floor)),
            "{claim}"
        );
    }
    // A form without a source is malformed.
    let unsourced = minimum.replace(r#""source":"floor","#, "");
    assert_ne!(unsourced, minimum);
    assert!(matches!(
        Draft::deserialize(unsourced.as_bytes(), profile),
        Err(Error::InvalidDraft { .. })
    ));
}

/// The devnet chain with no dynamic fee table in any milestone.
fn chain_without_fee_table() -> Chain {
    let network = serde_json::to_string(&chain().network().to_json()).unwrap();
    let milestones: Vec<serde_json::Value> = chain()
        .milestones()
        .all()
        .iter()
        .map(|params| {
            let mut milestone = params.as_json().clone();
            milestone.remove("dynamicFees");
            serde_json::Value::Object(milestone)
        })
        .collect();
    let milestones = serde_json::to_string(&milestones).unwrap();
    Chain::from_parts(chain().profile(), &network, &milestones).unwrap()
}

#[test]
fn no_minimum_fee_without_a_fee_table() {
    let chain = chain_without_fee_table();
    let rules = chain.rules(HEIGHT);
    assert_eq!(rules.fees.dynamic, None);
    assert!(!rules.fees.floor_available);
    let sender = phrase_account(0);
    let recipient = phrase_account(1);
    let with_fee = |operation: Operation, fee: FeeChoice| {
        Draft::build(
            &chain,
            &DraftRequest {
                operation,
                memo: None,
                fee,
            },
            &facts(&sender),
        )
    };
    let burn = || Operation::Burn {
        amount: Amount::from(2_000_000u64),
    };

    // No floor is in force, so neither the minimum nor a multiple of it resolves: never a zero
    // fee labelled as the floor, whatever the operation.
    for operation in [transfer(&recipient, 1), burn(), vote(1)] {
        let kind = operation.kind();
        assert_eq!(chain.fee_floor(kind, 154, HEIGHT), None);
        for fee in [
            FeeChoice::Minimum,
            FeeChoice::Multiplier {
                basis_points: 15_000,
            },
        ] {
            assert_eq!(
                with_fee(operation.clone(), fee).unwrap_err(),
                Error::FeeUnavailable { operation: kind }
            );
        }
    }

    // An exact fee works, and has no floor beside it.
    let exact = with_fee(
        transfer(&recipient, 1),
        FeeChoice::Exact(Amount::from(1_000_000u64)),
    )
    .unwrap();
    assert_eq!(
        (exact.fee().amount, exact.fee().source, exact.fee().floor),
        (Amount::from(1_000_000u64), FeeSource::Explicit, None)
    );
    assert!(exact.sign(&sender, None).unwrap().is_verified());

    // A burn with no fee, serialized and claimed to be at the floor, stays explicit.
    let free = with_fee(burn(), FeeChoice::Exact(Amount::ZERO)).unwrap();
    assert_eq!(free.fee().source, FeeSource::Explicit);
    let text = String::from_utf8(free.serialize()).unwrap();
    let claimed = text.replace(r#""source":"explicit""#, r#""source":"floor""#);
    assert_ne!(claimed, text);
    let again = Draft::deserialize(claimed.as_bytes(), chain.profile()).unwrap();
    assert_eq!(
        (again.fee().amount, again.fee().source, again.fee().floor),
        (Amount::ZERO, FeeSource::Explicit, None)
    );
}

#[test]
fn keys_that_sign() {
    let sender = phrase_account(0);
    let recipient = phrase_account(1);
    let second = phrase_account(2);
    let stranger = phrase_account(3);

    let draft = build(&sender, transfer(&recipient, 5)).unwrap();
    assert!(matches!(
        draft.sign(&stranger, None),
        Err(Error::WrongKey { .. })
    ));
    assert!(matches!(
        draft.sign(&sender, Some(&second)),
        Err(Error::WrongKey { .. })
    ));

    let request = DraftRequest::new(transfer(&recipient, 5));
    let facts = OnlineFacts {
        second_key: Some(second.public_key().clone()),
        ..facts(&sender)
    };
    let draft = Draft::build(chain(), &request, &facts).unwrap();
    assert!(draft.summary().second_signature);
    assert!(matches!(
        draft.sign(&sender, None),
        Err(Error::WrongKey { .. })
    ));
    assert!(matches!(
        draft.sign(&sender, Some(&stranger)),
        Err(Error::WrongKey { .. })
    ));
    let signed = draft.sign(&sender, Some(&second)).unwrap();
    assert!(signed.is_verified());
    assert!(signed.has_second_signature());
    assert!(signed.verify_second_signature(second.public_key()));
    assert!(!signed.verify_second_signature(stranger.public_key()));
    assert_eq!(signed.bytes().len(), draft.size());
}

#[test]
fn serialized_drafts() {
    let sender = phrase_account(0);
    let recipient = phrase_account(1);
    let draft = build(&sender, transfer(&recipient, 42)).unwrap();
    let bytes = draft.serialize();
    let profile = chain().profile();

    let again = Draft::deserialize(&bytes, profile).unwrap();
    assert_eq!(again.summary(), draft.summary());
    let signed = again.sign_with(&sender, None, AUX).unwrap();
    assert_eq!(
        signed.id(),
        draft.sign_with(&sender, None, AUX).unwrap().id(),
        "the same transaction is signed on either side"
    );

    // The signed transaction travels back the same way.
    let back = SignedTransaction::deserialize(&signed.serialize(), profile).unwrap();
    assert_eq!(back.id(), signed.id());
    assert_eq!(back.bytes(), signed.bytes());

    // Another network, another profile, or a profile with nothing pinned is refused.
    let unpinned = Profile::devnet(DevnetOptions::default());
    assert_eq!(
        Draft::deserialize(&bytes, &unpinned).unwrap_err(),
        Error::NetworkMismatch {
            problem: MismatchProblem::NotPinned
        }
    );
    let other = unpinned.clone().with_nethash(&"ab".repeat(32)).unwrap();
    assert!(matches!(
        Draft::deserialize(&bytes, &other),
        Err(Error::NetworkMismatch {
            problem: MismatchProblem::Nethash { .. }
        })
    ));
    let renamed = profile.clone().with_id("devnet-2");
    assert!(matches!(
        Draft::deserialize(&bytes, &renamed),
        Err(Error::NetworkMismatch {
            problem: MismatchProblem::Profile { .. }
        })
    ));
    // A transaction whose own header names another network, inside a form for this one.
    let form = String::from_utf8(bytes.clone()).unwrap();
    let unsigned = iceroot_hex(draft.unsigned_bytes());
    assert!(unsigned.starts_with("ff035a"), "{unsigned}");
    let elsewhere = form.replace(&unsigned, &unsigned.replacen("ff035a", "ff031e", 1));
    assert_eq!(
        Draft::deserialize(elsewhere.as_bytes(), profile).unwrap_err(),
        Error::NetworkMismatch {
            problem: MismatchProblem::NetworkByte {
                expected: 90,
                actual: 30
            }
        }
    );
    let signed_form = String::from_utf8(signed.serialize()).unwrap();
    let signed_bytes = iceroot_hex(signed.bytes());
    let signed_elsewhere =
        signed_form.replace(&signed_bytes, &signed_bytes.replacen("ff035a", "ff031e", 1));
    assert_eq!(
        SignedTransaction::deserialize(signed_elsewhere.as_bytes(), profile).unwrap_err(),
        Error::NetworkMismatch {
            problem: MismatchProblem::NetworkByte {
                expected: 90,
                actual: 30
            }
        }
    );

    // The summary is computed from the transaction's own fields.
    let text = String::from_utf8(bytes.clone()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    let hex = value["transaction"].as_str().unwrap().to_owned();
    let raised = hex.replacen(
        &format!("{:016x}", 42u64.swap_bytes()),
        &format!("{:016x}", 4200u64.swap_bytes()),
        1,
    );
    assert_ne!(raised, hex);
    let tampered = text.replace(&hex, &raised);
    let shown = Draft::deserialize(tampered.as_bytes(), profile).unwrap();
    assert_eq!(shown.summary().total_amount, Amount::from(4200u64));

    // Malformed forms.
    for bad in [&b"not json"[..], b"{}", b"[]", &[0xff; 4][..]] {
        assert!(matches!(
            Draft::deserialize(bad, profile),
            Err(Error::InvalidDraft { .. })
        ));
    }
    let signed_as_draft = text.replace(&hex, &iceroot_hex(signed.bytes()));
    assert_eq!(
        Draft::deserialize(signed_as_draft.as_bytes(), profile).unwrap_err(),
        Error::InvalidTransaction {
            problem: TransactionProblem::Signatures
        }
    );
    assert!(matches!(
        SignedTransaction::deserialize(&bytes, profile),
        Err(Error::InvalidDraft { .. })
    ));
    let signed_text = String::from_utf8(signed.serialize()).unwrap();
    let signed_hex = iceroot_hex(signed.bytes());
    let mut forged = signed_hex.clone().into_bytes();
    let last = forged.len() - 1;
    forged[last] = if forged[last] == b'0' { b'1' } else { b'0' };
    let forged = signed_text.replace(&signed_hex, std::str::from_utf8(&forged).unwrap());
    assert_eq!(
        SignedTransaction::deserialize(forged.as_bytes(), profile).unwrap_err(),
        Error::InvalidTransaction {
            problem: TransactionProblem::Signatures
        }
    );
}

fn iceroot_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn legacy_and_phrase_accounts_sign_the_same_way() {
    let legacy = Account::from_legacy_passphrase(
        chain().profile(),
        "tell echo jelly teach melody company vital stone decade coral spatial glare",
    )
    .unwrap();
    assert!(legacy.is_legacy());
    let draft = build(&legacy, transfer(&phrase_account(0), 1)).unwrap();
    assert!(draft.sign(&legacy, None).unwrap().is_verified());
}

#[test]
fn votes_in_the_relay_form() {
    let votes: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(r#"{"genesis_1": 50.5, "genesis_2": 49.5, "0": 12}"#).unwrap();
    let entries = vote_from_percentages(&votes).unwrap();
    assert_eq!(
        entries,
        vec![
            VoteEntry {
                validator: "genesis_1".into(),
                basis_points: 5050
            },
            VoteEntry {
                validator: "genesis_2".into(),
                basis_points: 4950
            },
        ]
    );
    let bad: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(r#"{"genesis_1": 50.005, "genesis_2": 49.995}"#).unwrap();
    assert!(matches!(
        vote_from_percentages(&bad),
        Err(Error::InvalidVote {
            problem: VoteProblem::Percentage { .. }
        })
    ));
}

/// In today's format a message signature and a transaction signature are the same BIP340
/// signature over the SHA-256 of the bytes, so a message made of a draft's unsigned bytes would
/// sign the transaction. Such bytes start with the transaction header 0xff, which UTF-8 text never
/// does: signing refuses a message that is not text, and a transaction's signature never verifies
/// as the signature of a message made of its bytes.
#[test]
fn a_message_signature_never_signs_a_transaction() {
    use iceroot_sdk_core::message::{self, ALGORITHM, MessageSignature};

    let sender = phrase_account(0);
    let recipient = phrase_account(1);
    let draft = build(&sender, transfer(&recipient, 10_000_000_000)).unwrap();
    let unsigned = draft.unsigned_bytes();
    assert_eq!(unsigned.first(), Some(&0xff));

    let refused = message::sign_bytes(chain().profile(), &sender, unsigned).unwrap_err();
    assert_eq!(refused.code().as_str(), "InvalidArgument");
    assert!(message::sign_bytes(chain().profile(), &sender, &[0xff, 0x00]).is_err());

    let signed = draft.sign_with(&sender, None, AUX).unwrap();
    let signature = &signed.bytes()[unsigned.len()..unsigned.len() + 64];
    let claimed = MessageSignature {
        public_key: sender.public_key().to_hex(),
        signature: hex::encode(signature),
        algorithm: ALGORITHM.to_owned(),
        network: chain().profile().message_network().unwrap(),
    };
    assert!(!message::verify_bytes(unsigned, &claimed));

    // Text is signed and verified as before, given as text or as its UTF-8 bytes.
    let text = message::sign_bytes(chain().profile(), &sender, "ünïcödé ✓".as_bytes()).unwrap();
    assert!(message::verify("ünïcödé ✓", &text));
    assert!(message::verify_bytes("ünïcödé ✓".as_bytes(), &text));
}

/// The token's symbol and name come from the network configuration, which a serialized draft
/// carries and the pinned network hash does not cover. A configuration whose symbol could write
/// text of its own into a review line, such as a recipient padded out of sight, is refused, from
/// a draft and from a node alike.
#[test]
fn a_draft_s_configuration_cannot_rewrite_the_token_s_labels() {
    use serde_json::Value;

    let sender = phrase_account(0);
    let recipient = phrase_account(1);
    let draft = build(&sender, transfer(&recipient, 10_000_000_000)).unwrap();
    let profile = chain().profile();
    let form: Value = serde_json::from_slice(&draft.serialize()).unwrap();
    let with_client = |key: &str, text: &str| {
        let mut tampered = form.clone();
        tampered["configuration"]["network"]["client"][key] = Value::from(text);
        serde_json::to_vec(&tampered).unwrap()
    };
    assert_eq!(chain().token().symbol, "dRT");
    assert!(Draft::deserialize(&with_client("symbol", "dRT"), profile).is_ok());

    let padded = format!("dRT to {}{}", recipient.address(), " ".repeat(400));
    let spaced = format!("dRT{}", "\u{3000}".repeat(40));
    for symbol in [padded.as_str(), spaced.as_str(), "", "d\tRT", "ABCDEFGHIJK"] {
        assert!(
            matches!(
                Draft::deserialize(&with_client("symbol", symbol), profile),
                Err(Error::BadResponse { .. })
            ),
            "{symbol:?}"
        );
    }
    for name in ["", " dROOT", "dROOT\n", &"n".repeat(33), "d  ROOT"] {
        assert!(
            matches!(
                Draft::deserialize(&with_client("token", name), profile),
                Err(Error::BadResponse { .. })
            ),
            "{name:?}"
        );
    }
    let named = Draft::deserialize(&with_client("token", "Dev ROOT-2.0"), profile).unwrap();
    assert_eq!(named.chain().token().name, "Dev ROOT-2.0");

    // The same configuration from a node is refused when the chain is loaded.
    let mut configuration = form["configuration"].clone();
    configuration["network"]["client"]["symbol"] = Value::from(padded.as_str());
    assert!(matches!(
        Chain::load(profile, &configuration.to_string()),
        Err(Error::BadResponse { .. })
    ));
}
