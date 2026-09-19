//! End-to-end tests for the Veil402 pool program against a real `solana-test-validator`.
//!
//! Each test spawns its own validator (fresh chain state — the pool PDA is a singleton) with the
//! program preloaded as bytecode, and drives it over RPC. Tests are `#[serial]` so only one
//! validator runs at a time. Requires `solana-test-validator` on PATH.
//!
//! Run: `cargo test -p pool-e2e`

use anchor_lang::{InstructionData, ToAccountMetas};
use serial_test::serial;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::Instruction,
    native_token::LAMPORTS_PER_SOL,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};
use spl_associated_token_account::{
    get_associated_token_address, instruction::create_associated_token_account,
};
use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn pool_so() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy/pool.so")
}

/// Grab an ephemeral free TCP port (released immediately; good enough under serial execution).
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A `solana-test-validator` child with the pool program preloaded. Killed on drop.
struct Validator {
    child: Child,
    rpc_url: String,
    _ledger: tempfile::TempDir,
}

impl Validator {
    fn start() -> Validator {
        let rpc_port = free_port();
        let faucet_port = free_port();
        let ledger = tempfile::tempdir().unwrap();
        let child = Command::new("solana-test-validator")
            .args([
                "--reset",
                "--quiet",
                "--ledger",
                ledger.path().to_str().unwrap(),
                "--rpc-port",
                &rpc_port.to_string(),
                "--faucet-port",
                &faucet_port.to_string(),
                "--bpf-program",
                &pool::ID.to_string(),
                pool_so().to_str().unwrap(),
                "--limit-ledger-size",
                "10000",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("solana-test-validator should be on PATH and start");

        let validator = Validator {
            child,
            rpc_url: format!("http://127.0.0.1:{rpc_port}"),
            _ledger: ledger,
        };

        // Wait for the RPC to produce blocks.
        let client = validator.client();
        let deadline = Instant::now() + Duration::from_secs(60);
        while client.get_latest_blockhash().is_err() {
            assert!(
                Instant::now() < deadline,
                "validator did not become ready in time"
            );
            std::thread::sleep(Duration::from_millis(300));
        }
        validator
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

struct Ctx {
    _validator: Validator,
    client: RpcClient,
    payer: Keypair,
    mint: Pubkey,
    pool: Pubkey,
    tree: Pubkey,
    vault: Pubkey,
}

fn airdrop(client: &RpcClient, to: &Pubkey, lamports: u64) {
    let sig = client.request_airdrop(to, lamports).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !client.confirm_transaction(&sig).unwrap_or(false) {
        assert!(Instant::now() < deadline, "airdrop not confirmed in time");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn send(client: &RpcClient, ixs: &[Instruction], payer: &Keypair, signers: &[&Keypair]) {
    let bh = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(ixs, Some(&payer.pubkey()), signers, bh);
    client.send_and_confirm_transaction(&tx).unwrap();
}

fn token_account(client: &RpcClient, addr: &Pubkey) -> spl_token::state::Account {
    let acc = client.get_account(addr).expect("account should exist");
    spl_token::state::Account::unpack(&acc.data).expect("valid token account")
}

/// Fresh validator + funded payer + SPL mint + initialized pool (config, tree, vault).
fn setup() -> Ctx {
    let validator = Validator::start();
    let client = validator.client();

    let payer = Keypair::new();
    airdrop(&client, &payer.pubkey(), 100 * LAMPORTS_PER_SOL);

    // Create + initialize an SPL mint (payer is the mint authority).
    let mint_kp = Keypair::new();
    let mint = mint_kp.pubkey();
    let rent = client
        .get_minimum_balance_for_rent_exemption(spl_token::state::Mint::LEN)
        .unwrap();
    send(
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
            )
            .unwrap(),
        ],
        &payer,
        &[&payer, &mint_kp],
    );

    let (pool, _) = Pubkey::find_program_address(&[b"pool"], &pool::ID);
    let (tree, _) = Pubkey::find_program_address(&[b"tree"], &pool::ID);
    let vault = get_associated_token_address(&pool, &mint);

    let ix = Instruction {
        program_id: pool::ID,
        accounts: pool::accounts::InitPool {
            pool,
            tree,
            mint,
            vault,
            verifier_program: Pubkey::new_unique(), // stored; unused until `transact`
            authority: payer.pubkey(),
            token_program: spl_token::id(),
            associated_token_program: spl_associated_token_account::id(),
            system_program: solana_sdk::system_program::id(),
        }
        .to_account_metas(None),
        data: pool::instruction::InitPool {}.data(),
    };
    send(&client, &[ix], &payer, &[&payer]);

    Ctx {
        _validator: validator,
        client,
        payer,
        mint,
        pool,
        tree,
        vault,
    }
}

#[test]
#[serial]
fn init_pool_creates_empty_vault() {
    let ctx = setup();
    let vault = token_account(&ctx.client, &ctx.vault);
    assert_eq!(vault.amount, 0, "vault starts empty");
    assert_eq!(vault.mint, ctx.mint, "vault holds the pool's mint");
    assert_eq!(vault.owner, ctx.pool, "vault is owned by the pool PDA");
}

#[test]
#[serial]
fn shield_pulls_tokens_into_vault() {
    let ctx = setup();
    let amount = 1_000_000u64;

    // Fund the depositor's ATA with freshly minted tokens.
    let depositor_ata = get_associated_token_address(&ctx.payer.pubkey(), &ctx.mint);
    send(
        &ctx.client,
        &[
            create_associated_token_account(
                &ctx.payer.pubkey(),
                &ctx.payer.pubkey(),
                &ctx.mint,
                &spl_token::id(),
            ),
            spl_token::instruction::mint_to(
                &spl_token::id(),
                &ctx.mint,
                &depositor_ata,
                &ctx.payer.pubkey(),
                &[],
                amount,
            )
            .unwrap(),
        ],
        &ctx.payer,
        &[&ctx.payer],
    );

    // shield: deposit `amount` into the pool.
    let ix = Instruction {
        program_id: pool::ID,
        accounts: pool::accounts::Shield {
            pool: ctx.pool,
            tree: ctx.tree,
            vault: ctx.vault,
            mint: ctx.mint,
            depositor: ctx.payer.pubkey(),
            depositor_ata,
            token_program: spl_token::id(),
        }
        .to_account_metas(None),
        data: pool::instruction::Shield {
            npk: [0u8; 32],
            amount,
            encrypted_note: vec![],
        }
        .data(),
    };
    send(&ctx.client, &[ix], &ctx.payer, &[&ctx.payer]);

    assert_eq!(
        token_account(&ctx.client, &ctx.vault).amount,
        amount,
        "vault holds the deposit"
    );
    assert_eq!(
        token_account(&ctx.client, &depositor_ata).amount,
        0,
        "depositor was debited"
    );
}
