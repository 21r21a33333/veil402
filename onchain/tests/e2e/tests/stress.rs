use std::thread;

use anchor_lang::prelude::borsh;
use anchor_lang::AnchorDeserialize;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use light_hasher::{Hasher, Poseidon};
use pool_e2e::{
    harness::{confirmed_transaction, mint_to, tree_state, Result},
    scenario::{field, transact_instruction, Fixture},
};
use serial_test::serial;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    compute_budget::ComputeBudgetInstruction,
    signature::{Signature, Signer},
    transaction::Transaction as SolanaTransaction,
};
use solana_transaction_status_client_types::option_serializer::OptionSerializer;

const TREE_DEPTH: usize = 20;

struct ReferenceTree {
    filled: [[u8; 32]; TREE_DEPTH],
    next_index: usize,
    root: [u8; 32],
}

#[derive(AnchorDeserialize)]
struct CommitmentEvent {
    commitment: [u8; 32],
    leaf_index: u64,
    _encrypted_note: Vec<u8>,
}

impl ReferenceTree {
    fn new() -> Self {
        let zeros = Poseidon::zero_bytes();
        Self {
            filled: std::array::from_fn(|level| zeros[level]),
            next_index: 0,
            root: zeros[TREE_DEPTH],
        }
    }

    fn append(&mut self, leaf: [u8; 32]) -> Result<[u8; 32]> {
        let zeros = Poseidon::zero_bytes();
        let mut node = leaf;
        let mut index = self.next_index;
        for (level, zero) in zeros.iter().take(TREE_DEPTH).enumerate() {
            node = if index & 1 == 0 {
                self.filled[level] = node;
                Poseidon::hashv(&[&node, zero])?
            } else {
                Poseidon::hashv(&[&self.filled[level], &node])?
            };
            index >>= 1;
        }
        self.next_index += 1;
        self.root = node;
        Ok(node)
    }
}

fn commitment_event(client: &RpcClient, signature: &Signature) -> Result<CommitmentEvent> {
    let transaction = confirmed_transaction(client, signature)?;
    let meta = transaction
        .transaction
        .meta
        .ok_or("successful transaction has no metadata")?;
    let logs = match meta.log_messages {
        OptionSerializer::Some(logs) => logs,
        OptionSerializer::None | OptionSerializer::Skip => {
            return Err("successful transaction has no logs".into());
        }
    };
    let discriminator = solana_sdk::hash::hash(b"event:NewCommitment").to_bytes();
    for log in logs {
        let Some(encoded) = log.strip_prefix("Program data: ") else {
            continue;
        };
        let bytes = STANDARD.decode(encoded)?;
        if bytes.starts_with(&discriminator[..8]) {
            return Ok(CommitmentEvent::try_from_slice(&bytes[8..])?);
        }
    }
    Err("transaction did not emit NewCommitment".into())
}

#[test]
#[serial]
#[ignore = "stress: submits 96 validator transactions"]
fn ninety_six_appends_match_an_independent_reference() -> Result<()> {
    let mut fixture = Fixture::start()?;
    mint_to(
        &fixture.client,
        &fixture.payer,
        &fixture.mint,
        &fixture.depositor_ata,
        96,
    )?;

    // Recompute every expected root from Poseidon primitives instead of using
    // Light's tree implementation as its own oracle.
    let mut reference = ReferenceTree::new();
    let asset = fixture.config.asset().to_bytes();
    let amount = field(1);
    eprintln!("append stress: starting 96 transactions");
    for value in 1..=96 {
        let npk = field(value);
        let commitment = Poseidon::hashv(&[&npk, &asset, &amount])?;
        let expected_root = reference.append(commitment)?;
        fixture.shield(npk, 1, Vec::new())?;
        let actual = tree_state(&fixture.client, &fixture.config.tree())?;
        assert_eq!(actual.next_index, value as usize);
        assert_eq!(actual.root, expected_root);
        if value % 8 == 0 {
            eprintln!(
                "append stress: {value}/96 verified, root={:02x?}",
                actual.root
            );
        }
    }
    Ok(())
}

#[test]
#[serial]
#[ignore = "stress: submits 20 writes concurrently"]
fn concurrent_spends_emit_unique_indices_and_match_reference() -> Result<()> {
    let fixture = Fixture::start()?;
    let initial = tree_state(&fixture.client, &fixture.config.tree())?;
    let blockhash = fixture.client.get_latest_blockhash()?;
    let mut transactions = Vec::with_capacity(20);
    for unique in 10_000..10_020 {
        let values = fixture.transaction(unique)?;
        let instruction = transact_instruction(&fixture.config, fixture.payer.pubkey(), &values);
        transactions.push(SolanaTransaction::new_signed_with_payer(
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(650_000),
                ComputeBudgetInstruction::set_compute_unit_price(unique),
                instruction,
            ],
            Some(&fixture.payer.pubkey()),
            &[&fixture.payer],
            blockhash,
        ));
    }

    // Sign first, then release all RPC submissions from separate clients so
    // the validator sees genuinely concurrent writes to the same tree account.
    let rpc_url = fixture.rpc_url().to_owned();
    let signatures = thread::scope(|scope| -> Result<Vec<Signature>> {
        let handles: Vec<_> = transactions
            .into_iter()
            .map(|transaction| {
                let rpc_url = rpc_url.clone();
                scope.spawn(move || {
                    RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed())
                        .send_and_confirm_transaction(&transaction)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| "concurrent sender panicked")?
                    .map_err(Into::into)
            })
            .collect()
    })?;

    let mut events = signatures
        .iter()
        .map(|signature| commitment_event(&fixture.client, signature))
        .collect::<Result<Vec<_>>>()?;
    events.sort_unstable_by_key(|event| event.leaf_index);
    assert_eq!(events.len(), 20);

    let mut reference = ReferenceTree::new();
    for (offset, event) in events.iter().enumerate() {
        assert_eq!(event.leaf_index, initial.next_index as u64 + offset as u64);
        reference.append(event.commitment)?;
    }
    let final_tree = tree_state(&fixture.client, &fixture.config.tree())?;
    assert_eq!(final_tree.next_index, initial.next_index + 20);
    assert_eq!(final_tree.root, reference.root);
    Ok(())
}
