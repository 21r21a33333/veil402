use std::{
    error::Error as StdError,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use light_concurrent_merkle_tree::zero_copy::ConcurrentMerkleTreeZeroCopy;
use light_hasher::Poseidon;
use solana_client::{rpc_client::RpcClient, rpc_config::RpcTransactionConfig};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    compute_budget::ComputeBudgetInstruction,
    instruction::Instruction,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    transaction::Transaction,
};
use solana_system_interface::instruction as system_instruction;
use solana_transaction_status_client_types::{
    EncodedConfirmedTransactionWithStatusMeta, UiTransactionEncoding,
};
use spl_associated_token_account::{
    get_associated_token_address, instruction::create_associated_token_account,
};

pub type Result<T> = std::result::Result<T, Box<dyn StdError>>;

const TREE_HEIGHT: usize = 20;
const DISCRIMINATOR: usize = 8;
const TRANSACTION_HISTORY_TIMEOUT: Duration = Duration::from_secs(10);
const TRANSACTION_HISTORY_POLL_INTERVAL: Duration = Duration::from_millis(100);

pub fn repository() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "repository root is unavailable".into())
}

fn free_port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

pub struct Validator {
    child: Child,
    rpc_url: String,
    _ledger: tempfile::TempDir,
}

impl Validator {
    pub fn start(repository: &Path, programs: &[(Pubkey, &Path)]) -> Result<Self> {
        let rpc_port = free_port()?;
        let faucet_port = free_port()?;
        let ledger = tempfile::tempdir()?;
        let pool = repository.join("onchain/target/deploy/pool.so");
        if !pool.is_file() || programs.iter().any(|(_, path)| !path.is_file()) {
            return Err("build every test program before running e2e tests".into());
        }

        let mut command = Command::new("solana-test-validator");
        command
            .args(["--reset", "--quiet", "--ledger"])
            .arg(ledger.path())
            .args(["--rpc-port", &rpc_port.to_string()])
            .args(["--faucet-port", &faucet_port.to_string()])
            .args(["--bpf-program", &pool::ID.to_string()])
            .arg(pool);
        for (id, path) in programs {
            command.args(["--bpf-program", &id.to_string()]).arg(path);
        }
        let child = command
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

    pub fn client(&self) -> RpcClient {
        RpcClient::new_with_commitment(self.rpc_url.clone(), CommitmentConfig::confirmed())
    }

    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }
}

impl Drop for Validator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn airdrop(client: &RpcClient, recipient: &Pubkey, lamports: u64) -> Result<()> {
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

pub fn send(
    client: &RpcClient,
    instruction: Instruction,
    payer: &Keypair,
    nonce: u64,
) -> Result<()> {
    send_with_signature(client, instruction, payer, nonce).map(|_| ())
}

pub fn send_with_signature(
    client: &RpcClient,
    instruction: Instruction,
    payer: &Keypair,
    nonce: u64,
) -> Result<Signature> {
    send_all_with_signature(
        client,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(650_000),
            ComputeBudgetInstruction::set_compute_unit_price(nonce),
            instruction,
        ],
        payer,
        &[payer],
    )
}

pub fn send_all(
    client: &RpcClient,
    instructions: &[Instruction],
    payer: &Keypair,
    signers: &[&Keypair],
) -> Result<()> {
    send_all_with_signature(client, instructions, payer, signers).map(|_| ())
}

pub fn send_all_with_signature(
    client: &RpcClient,
    instructions: &[Instruction],
    payer: &Keypair,
    signers: &[&Keypair],
) -> Result<Signature> {
    let blockhash = client.get_latest_blockhash()?;
    let transaction =
        Transaction::new_signed_with_payer(instructions, Some(&payer.pubkey()), signers, blockhash);
    Ok(client.send_and_confirm_transaction(&transaction)?)
}

pub fn confirmed_transaction(
    client: &RpcClient,
    signature: &Signature,
) -> Result<EncodedConfirmedTransactionWithStatusMeta> {
    let deadline = Instant::now() + TRANSACTION_HISTORY_TIMEOUT;
    loop {
        match client.get_transaction_with_config(
            signature,
            RpcTransactionConfig {
                encoding: Some(UiTransactionEncoding::Json),
                commitment: Some(CommitmentConfig::confirmed()),
                max_supported_transaction_version: Some(0),
            },
        ) {
            Ok(transaction) => return Ok(transaction),
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(TRANSACTION_HISTORY_POLL_INTERVAL);
            }
            Err(error) => return Err(error.into()),
        }
    }
}

pub fn token_balance(client: &RpcClient, address: &Pubkey) -> Result<u64> {
    let account = client.get_account(address)?;
    Ok(spl_token::state::Account::unpack(&account.data)?.amount)
}

pub fn create_mint(client: &RpcClient, payer: &Keypair) -> Result<Pubkey> {
    let mint = Keypair::new();
    let rent = client.get_minimum_balance_for_rent_exemption(spl_token::state::Mint::LEN)?;
    send_all(
        client,
        &[
            system_instruction::create_account(
                &payer.pubkey(),
                &mint.pubkey(),
                rent,
                spl_token::state::Mint::LEN as u64,
                &spl_token::id(),
            ),
            spl_token::instruction::initialize_mint2(
                &spl_token::id(),
                &mint.pubkey(),
                &payer.pubkey(),
                Some(&payer.pubkey()),
                6,
            )?,
        ],
        payer,
        &[payer, &mint],
    )?;
    Ok(mint.pubkey())
}

pub fn create_token_account(
    client: &RpcClient,
    payer: &Keypair,
    owner: &Pubkey,
    mint: &Pubkey,
) -> Result<Pubkey> {
    let address = get_associated_token_address(owner, mint);
    send(
        client,
        create_associated_token_account(&payer.pubkey(), owner, mint, &spl_token::id()),
        payer,
        0,
    )?;
    Ok(address)
}

pub fn mint_to(
    client: &RpcClient,
    payer: &Keypair,
    mint: &Pubkey,
    recipient: &Pubkey,
    amount: u64,
) -> Result<()> {
    send(
        client,
        spl_token::instruction::mint_to(
            &spl_token::id(),
            mint,
            recipient,
            &payer.pubkey(),
            &[],
            amount,
        )?,
        payer,
        0,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeState {
    pub root: [u8; 32],
    pub next_index: usize,
}

pub fn tree_state(client: &RpcClient, address: &Pubkey) -> Result<TreeState> {
    let data = client.get_account_data(address)?;
    let tree = ConcurrentMerkleTreeZeroCopy::<Poseidon, TREE_HEIGHT>::from_bytes_zero_copy(
        &data[DISCRIMINATOR..],
    )?;
    Ok(TreeState {
        root: tree.root(),
        next_index: tree.next_index(),
    })
}
