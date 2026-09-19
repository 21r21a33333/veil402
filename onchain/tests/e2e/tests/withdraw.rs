use std::{
    error::Error as StdError,
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anchor_lang::{InstructionData, ToAccountMetas};
use light_hasher::{Hasher, Poseidon};
use serial_test::serial;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    compute_budget::ComputeBudgetInstruction,
    instruction::Instruction,
    native_token::LAMPORTS_PER_SOL,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction as SolanaTransaction,
};
use solana_system_interface::{instruction as system_instruction, program as system_program};
use spl_associated_token_account::{
    get_associated_token_address, instruction::create_associated_token_account,
};
use veil402_sdk::solana::MAX_ENCRYPTED_NOTE_LEN;
use veil402_sdk::{
    Config, Field, MerklePath, Note, Output, Owner, Pool as VeilPool, Secret, Spend, Veil,
    Withdrawal, TREE_DEPTH,
};

type Result<T> = std::result::Result<T, Box<dyn StdError>>;

const VERIFIER: Pubkey = Pubkey::from_str_const("9jpnLceL3ahFfi5JmXdXNT1rZ1zLmfUcBkKbqCvquo19");
const DOMAIN: [u8; 32] = [7; 32];

fn root() -> Result<&'static Path> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| "repository root is unavailable".into())
}

fn field(value: u64) -> Field {
    Field::from(value)
}

fn secret(value: u64) -> Result<Secret> {
    Ok(Secret::from_bytes(field(value).to_bytes())?)
}

fn free_port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

struct Validator {
    child: Child,
    rpc_url: String,
    _ledger: tempfile::TempDir,
}

impl Validator {
    fn start(repository: &Path) -> Result<Self> {
        let rpc_port = free_port()?;
        let faucet_port = free_port()?;
        let ledger = tempfile::tempdir()?;
        let pool = repository.join("onchain/target/deploy/pool.so");
        let verifier = repository.join("circuits/transaction/target/transaction.so");
        if !pool.is_file() || !verifier.is_file() {
            return Err("build the pool and verifier programs before running e2e tests".into());
        }

        let child = Command::new("solana-test-validator")
            .args(["--reset", "--quiet", "--ledger"])
            .arg(ledger.path())
            .args(["--rpc-port", &rpc_port.to_string()])
            .args(["--faucet-port", &faucet_port.to_string()])
            .args(["--bpf-program", &pool::ID.to_string()])
            .arg(&pool)
            .args(["--bpf-program", &VERIFIER.to_string()])
            .arg(&verifier)
            .args(["--limit-ledger-size", "10000"])
            .env("NO_DNA", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;

        let validator = Self {
            child,
            rpc_url: format!("http://127.0.0.1:{rpc_port}"),
            _ledger: ledger,
        };
        let client = validator.client();
        let deadline = Instant::now() + Duration::from_secs(60);
        while client.get_latest_blockhash().is_err() {
            if Instant::now() >= deadline {
                return Err("validator did not become ready in time".into());
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        Ok(validator)
    }

    fn client(&self) -> RpcClient {
        RpcClient::new_with_commitment(self.rpc_url.clone(), CommitmentConfig::confirmed())
    }
}

impl Drop for Validator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn airdrop(client: &RpcClient, recipient: &Pubkey, lamports: u64) -> Result<()> {
    let signature = client.request_airdrop(recipient, lamports)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if client.confirm_transaction(&signature)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("airdrop did not confirm in time".into());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn send(client: &RpcClient, instruction: Instruction, payer: &Keypair, nonce: u64) -> Result<()> {
    let blockhash = client.get_latest_blockhash()?;
    let instructions = [
        ComputeBudgetInstruction::set_compute_unit_limit(650_000),
        ComputeBudgetInstruction::set_compute_unit_price(nonce),
        instruction,
    ];
    let transaction = SolanaTransaction::new_signed_with_payer(
        &instructions,
        Some(&payer.pubkey()),
        &[payer],
        blockhash,
    );
    client.send_and_confirm_transaction(&transaction)?;
    Ok(())
}

fn send_all(
    client: &RpcClient,
    instructions: &[Instruction],
    payer: &Keypair,
    signers: &[&Keypair],
) -> Result<()> {
    let blockhash = client.get_latest_blockhash()?;
    let transaction = SolanaTransaction::new_signed_with_payer(
        instructions,
        Some(&payer.pubkey()),
        signers,
        blockhash,
    );
    client.send_and_confirm_transaction(&transaction)?;
    Ok(())
}

fn token_balance(client: &RpcClient, address: &Pubkey) -> Result<u64> {
    let account = client.get_account(address)?;
    Ok(spl_token::state::Account::unpack(&account.data)?.amount)
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn withdrawal_is_bound_and_single_use() -> Result<()> {
    let repository = root()?;
    let worker = repository.join("target/veil402-gnark-e2e");
    let status = Command::new("go")
        .args(["build", "-o"])
        .arg(&worker)
        .arg(".")
        .current_dir(repository.join("prover/veil402-gnark"))
        .status()?;
    if !status.success() {
        return Err("Go worker build failed".into());
    }

    let validator = Validator::start(repository)?;
    let client = validator.client();
    let payer = Keypair::new();
    airdrop(&client, &payer.pubkey(), 100 * LAMPORTS_PER_SOL)?;

    let mint_keypair = Keypair::new();
    let mint = mint_keypair.pubkey();
    let rent = client.get_minimum_balance_for_rent_exemption(spl_token::state::Mint::LEN)?;
    send_all(
        &client,
        &[
            system_instruction::create_account(
                &payer.pubkey(),
                &mint,
                rent,
                spl_token::state::Mint::LEN as u64,
                &spl_token::id(),
            ),
            spl_token::instruction::initialize_mint2(
                &spl_token::id(),
                &mint,
                &payer.pubkey(),
                None,
                6,
            )?,
        ],
        &payer,
        &[&payer, &mint_keypair],
    )?;

    let pool = VeilPool::new(pool::ID, VERIFIER, mint, DOMAIN)?;
    let init = Instruction {
        program_id: pool::ID,
        accounts: pool::accounts::InitPool {
            pool: pool.address(),
            tree: pool.tree(),
            mint,
            vault: pool.vault(),
            verifier_program: VERIFIER,
            authority: payer.pubkey(),
            token_program: spl_token::id(),
            associated_token_program: spl_associated_token_account::id(),
            system_program: system_program::id(),
        }
        .to_account_metas(None),
        data: pool::instruction::InitPool { domain: DOMAIN }.data(),
    };
    send(&client, init, &payer, 1)?;

    let recipient = Keypair::new();
    let attacker = Keypair::new();
    let depositor_ata = get_associated_token_address(&payer.pubkey(), &mint);
    let recipient_ata = get_associated_token_address(&recipient.pubkey(), &mint);
    let attacker_ata = get_associated_token_address(&attacker.pubkey(), &mint);
    send_all(
        &client,
        &[
            create_associated_token_account(
                &payer.pubkey(),
                &payer.pubkey(),
                &mint,
                &spl_token::id(),
            ),
            create_associated_token_account(
                &payer.pubkey(),
                &recipient.pubkey(),
                &mint,
                &spl_token::id(),
            ),
            create_associated_token_account(
                &payer.pubkey(),
                &attacker.pubkey(),
                &mint,
                &spl_token::id(),
            ),
            spl_token::instruction::mint_to(
                &spl_token::id(),
                &mint,
                &depositor_ata,
                &payer.pubkey(),
                &[],
                1_000,
            )?,
        ],
        &payer,
        &[&payer],
    )?;

    let owner = Owner {
        spend: secret(11)?,
        view: secret(22)?,
    };
    let note = Note {
        value: 1_000,
        asset: pool.asset(),
        random: secret(33)?,
    };
    let shield = Instruction {
        program_id: pool::ID,
        accounts: pool::accounts::Shield {
            pool: pool.address(),
            tree: pool.tree(),
            vault: pool.vault(),
            mint,
            depositor: payer.pubkey(),
            depositor_ata,
            token_program: spl_token::id(),
        }
        .to_account_metas(None),
        data: pool::instruction::Shield {
            npk: note.public_key(&owner)?.to_bytes(),
            amount: note.value,
            encrypted_note: vec![1; 32],
        }
        .data(),
    };
    send(&client, shield, &payer, 2)?;

    let mut siblings = [Field::ZERO; TREE_DEPTH];
    for (field, zero) in siblings.iter_mut().zip(Poseidon::zero_bytes()) {
        *field = Field::from_bytes(zero)?;
    }
    let output_owner = Owner {
        spend: secret(44)?,
        view: secret(55)?,
    };
    let withdrawal = Withdrawal::new(recipient.pubkey(), 300, vec![2; MAX_ENCRYPTED_NOTE_LEN])?;
    let veil = Veil::open(Config::new(
        worker,
        repository.join("prover/veil402-gnark/artifacts/transaction-v2"),
    ))?;
    let prepared = veil
        .withdraw(
            &pool,
            Spend {
                note,
                owner,
                merkle: MerklePath { index: 0, siblings },
            },
            Output {
                owner: output_owner.public()?,
                value: 700,
                random: secret(66)?,
            },
            withdrawal,
            payer.pubkey(),
        )
        .await?;

    let (nullifier_record, _) = Pubkey::find_program_address(
        &[
            b"nullifier",
            pool.address().as_ref(),
            prepared.proof.public.nullifier.to_bytes().as_ref(),
        ],
        &pool::ID,
    );
    let tampered = Instruction {
        program_id: pool::ID,
        accounts: pool::accounts::Transact {
            pool: pool.address(),
            tree: pool.tree(),
            vault: pool.vault(),
            mint,
            nullifier_record,
            recipient_ata: attacker_ata,
            verifier_program: VERIFIER,
            payer: payer.pubkey(),
            token_program: spl_token::id(),
            system_program: system_program::id(),
        }
        .to_account_metas(None),
        data: pool::instruction::Transact {
            proof: prepared.proof.bytes.clone(),
            root: prepared.proof.public.root.to_bytes(),
            nullifier: prepared.proof.public.nullifier.to_bytes(),
            out_commitment: prepared.proof.public.commitment.to_bytes(),
            ext_amount: -300,
            ext_data: pool::ExtData {
                recipient: attacker.pubkey(),
                encrypted_note: vec![2; MAX_ENCRYPTED_NOTE_LEN],
            },
        }
        .data(),
    };
    if send(&client, tampered, &payer, 3).is_ok() {
        return Err("proof accepted a mutated recipient".into());
    }
    if token_balance(&client, &pool.vault())? != 1_000 {
        return Err("failed withdrawal changed the vault".into());
    }

    send(&client, prepared.instruction.clone(), &payer, 4)?;
    assert_eq!(token_balance(&client, &recipient_ata)?, 300);
    assert_eq!(token_balance(&client, &pool.vault())?, 700);

    if send(&client, prepared.instruction, &payer, 5).is_ok() {
        return Err("spent nullifier was accepted twice".into());
    }
    assert_eq!(token_balance(&client, &recipient_ata)?, 300);
    drop(validator);
    Ok(())
}
