use std::path::Path;

use anchor_lang::{InstructionData, ToAccountMetas};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    instruction::Instruction,
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use solana_system_interface::program as system_program;
use veil402_sdk::Pool as VeilPool;

use crate::harness::{
    airdrop, create_mint, create_token_account, repository, send, token_balance, tree_state,
    Result, TreeState, Validator,
};

pub const PROOF_BYTES: usize = 388;

pub fn field(value: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    bytes
}

pub fn nullifier_address(pool_address: Pubkey, nullifier: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"nullifier", pool_address.as_ref(), nullifier], &pool::ID).0
}

pub fn init_instruction(
    config: &VeilPool,
    mint: Pubkey,
    verifier: Pubkey,
    authority: Pubkey,
    domain: [u8; 32],
) -> Instruction {
    Instruction {
        program_id: pool::ID,
        accounts: pool::accounts::InitPool {
            pool: config.address(),
            tree: config.tree(),
            mint,
            vault: config.vault(),
            verifier_program: verifier,
            authority,
            token_program: spl_token::id(),
            associated_token_program: spl_associated_token_account::id(),
            system_program: system_program::id(),
        }
        .to_account_metas(None),
        data: pool::instruction::InitPool { domain }.data(),
    }
}

pub fn shield_instruction(
    config: &VeilPool,
    mint: Pubkey,
    depositor: Pubkey,
    depositor_ata: Pubkey,
    npk: [u8; 32],
    amount: u64,
    encrypted_note: Vec<u8>,
) -> Instruction {
    Instruction {
        program_id: pool::ID,
        accounts: pool::accounts::Shield {
            pool: config.address(),
            tree: config.tree(),
            vault: config.vault(),
            mint,
            depositor,
            depositor_ata,
            token_program: spl_token::id(),
        }
        .to_account_metas(None),
        data: pool::instruction::Shield {
            npk,
            amount,
            encrypted_note,
        }
        .data(),
    }
}

#[derive(Clone, Debug)]
pub struct Transaction {
    pub proof: Vec<u8>,
    pub root: [u8; 32],
    pub nullifier: [u8; 32],
    pub out_commitment: [u8; 32],
    pub amount: i64,
    pub recipient: Pubkey,
    pub encrypted_note: Vec<u8>,
    pub recipient_ata: Pubkey,
    pub verifier: Pubkey,
    pub mint: Pubkey,
    pub tree: Pubkey,
    pub vault: Pubkey,
}

pub fn transact_instruction(config: &VeilPool, payer: Pubkey, tx: &Transaction) -> Instruction {
    Instruction {
        program_id: pool::ID,
        accounts: pool::accounts::Transact {
            pool: config.address(),
            tree: tx.tree,
            vault: tx.vault,
            mint: tx.mint,
            nullifier_record: nullifier_address(config.address(), &tx.nullifier),
            recipient_ata: tx.recipient_ata,
            verifier_program: tx.verifier,
            payer,
            token_program: spl_token::id(),
            system_program: system_program::id(),
        }
        .to_account_metas(None),
        data: pool::instruction::Transact {
            proof: tx.proof.clone(),
            root: tx.root,
            nullifier: tx.nullifier,
            out_commitment: tx.out_commitment,
            ext_amount: tx.amount,
            ext_data: pool::ExtData {
                recipient: tx.recipient,
                encrypted_note: tx.encrypted_note.clone(),
            },
        }
        .data(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub tree: TreeState,
    pub vault: u64,
    pub depositor: u64,
    pub recipient: u64,
}

pub struct Fixture {
    _validator: Validator,
    pub client: RpcClient,
    pub payer: Keypair,
    pub mint: Pubkey,
    pub config: VeilPool,
    pub depositor_ata: Pubkey,
    pub recipient: Pubkey,
    pub recipient_ata: Pubkey,
    pub verifier: Pubkey,
    nonce: u64,
}

impl Fixture {
    pub fn start(verifier: Pubkey, verifier_path: &Path, domain: [u8; 32]) -> Result<Self> {
        let repository = repository()?;
        let validator = Validator::start(&repository, &[(verifier, verifier_path)])?;
        let client = validator.client();
        let payer = Keypair::new();
        airdrop(&client, &payer.pubkey(), 100 * LAMPORTS_PER_SOL)?;
        let mint = create_mint(&client, &payer)?;
        let config = VeilPool::new(pool::ID, verifier, mint, domain)?;
        send(
            &client,
            init_instruction(&config, mint, verifier, payer.pubkey(), domain),
            &payer,
            1,
        )?;
        let depositor_ata = create_token_account(&client, &payer, &payer.pubkey(), &mint)?;
        let recipient = Keypair::new().pubkey();
        let recipient_ata = create_token_account(&client, &payer, &recipient, &mint)?;
        Ok(Self {
            _validator: validator,
            client,
            payer,
            mint,
            config,
            depositor_ata,
            recipient,
            recipient_ata,
            verifier,
            nonce: 2,
        })
    }

    pub fn transaction(&self, unique: u64) -> Result<Transaction> {
        Ok(Transaction {
            proof: success_proof(),
            root: tree_state(&self.client, &self.config.tree())?.root,
            nullifier: field(unique),
            out_commitment: field(unique + 1_000),
            amount: 0,
            recipient: self.recipient,
            encrypted_note: Vec::new(),
            recipient_ata: self.recipient_ata,
            verifier: self.verifier,
            mint: self.mint,
            tree: self.config.tree(),
            vault: self.config.vault(),
        })
    }

    pub fn rpc_url(&self) -> &str {
        self._validator.rpc_url()
    }

    pub fn shield(&mut self, npk: [u8; 32], amount: u64, encrypted_note: Vec<u8>) -> Result<()> {
        self.submit(shield_instruction(
            &self.config,
            self.mint,
            self.payer.pubkey(),
            self.depositor_ata,
            npk,
            amount,
            encrypted_note,
        ))
    }

    pub fn transact(&mut self, tx: &Transaction) -> Result<()> {
        self.submit(transact_instruction(&self.config, self.payer.pubkey(), tx))
    }

    pub fn submit(&mut self, instruction: Instruction) -> Result<()> {
        self.nonce += 1;
        send(&self.client, instruction, &self.payer, self.nonce)
    }

    pub fn snapshot(&self, recipient_ata: Pubkey) -> Result<Snapshot> {
        Ok(Snapshot {
            tree: tree_state(&self.client, &self.config.tree())?,
            vault: token_balance(&self.client, &self.config.vault())?,
            depositor: token_balance(&self.client, &self.depositor_ata)?,
            recipient: token_balance(&self.client, &recipient_ata)?,
        })
    }

    pub fn assert_rejected(
        &mut self,
        instruction: Instruction,
        recipient_ata: Pubkey,
    ) -> Result<()> {
        let before = self.snapshot(recipient_ata)?;
        if self.submit(instruction).is_ok() {
            return Err("instruction unexpectedly succeeded".into());
        }
        if self.snapshot(recipient_ata)? != before {
            return Err("rejected instruction changed pool state".into());
        }
        Ok(())
    }

    pub fn assert_transaction_rejected(&mut self, tx: &Transaction) -> Result<()> {
        let nullifier = nullifier_address(self.config.address(), &tx.nullifier);
        let nullifier_before = self.client.get_account(&nullifier).ok().map(|a| a.data);
        self.assert_rejected(
            transact_instruction(&self.config, self.payer.pubkey(), tx),
            tx.recipient_ata,
        )?;
        let nullifier_after = self.client.get_account(&nullifier).ok().map(|a| a.data);
        if nullifier_after != nullifier_before {
            return Err("rejected transaction changed its nullifier account".into());
        }
        Ok(())
    }
}

pub fn success_proof() -> Vec<u8> {
    let mut proof = vec![0; PROOF_BYTES];
    proof[0] = 1;
    proof
}
