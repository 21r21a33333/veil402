use solana_address_v1::Address;
use solana_commitment_config_v1::CommitmentConfig;
use solana_instruction_v1::{AccountMeta as V1AccountMeta, Instruction as V1Instruction};
use solana_keypair_v1::Keypair as V1Keypair;
use solana_message_v1::{v1, VersionedMessage};
use solana_rpc_client_v1::rpc_client::RpcClient as V1Client;
use solana_signer_v1::Signer as _;
use solana_transaction_v1::versioned::VersionedTransaction;

use solana_sdk::{
    instruction::Instruction,
    signature::{Keypair, Signature},
};

use crate::harness::Result;

const COMPUTE_UNIT_LIMIT: u32 = 700_000;
const LOADED_ACCOUNTS_LIMIT: u32 = 64 * 1024 * 1024;

pub struct Transaction(VersionedTransaction);

impl Transaction {
    pub fn wire_size(&self) -> Result<usize> {
        Ok(wincode::serialize(&self.0)?.len())
    }
}

pub fn build(
    rpc_url: &str,
    instruction: Instruction,
    payer: &Keypair,
    priority_fee: u64,
) -> Result<Transaction> {
    let client = client(rpc_url);
    let payer = V1Keypair::try_from(payer.to_bytes().as_slice())?;
    let config = v1::TransactionConfig::empty()
        .with_compute_unit_limit(COMPUTE_UNIT_LIMIT)
        .with_loaded_accounts_data_size_limit(LOADED_ACCOUNTS_LIMIT)
        .with_priority_fee(priority_fee);
    let message = v1::Message::try_compile_with_config(
        &payer.pubkey(),
        &[convert(instruction)],
        client.get_latest_blockhash()?,
        config,
    )?;
    let transaction = Transaction(VersionedTransaction::try_new(
        VersionedMessage::V1(message),
        &[&payer],
    )?);
    let size = transaction.wire_size()?;
    if size > v1::MAX_TRANSACTION_SIZE {
        return Err(format!(
            "v1 transaction is {size} bytes; maximum is {}",
            v1::MAX_TRANSACTION_SIZE
        )
        .into());
    }
    Ok(transaction)
}

pub fn send(rpc_url: &str, transaction: &Transaction) -> Result<Signature> {
    let signature = client(rpc_url).send_and_confirm_transaction(&transaction.0)?;
    Ok(Signature::try_from(signature.as_ref())?)
}

fn client(rpc_url: &str) -> V1Client {
    V1Client::new_with_commitment(rpc_url.to_owned(), CommitmentConfig::confirmed())
}

fn convert(instruction: Instruction) -> V1Instruction {
    V1Instruction {
        program_id: Address::from(instruction.program_id.to_bytes()),
        accounts: instruction
            .accounts
            .into_iter()
            .map(|account| V1AccountMeta {
                pubkey: Address::from(account.pubkey.to_bytes()),
                is_signer: account.is_signer,
                is_writable: account.is_writable,
            })
            .collect(),
        data: instruction.data,
    }
}
