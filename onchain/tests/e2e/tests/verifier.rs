use std::process::Command;

use anchor_lang::{AnchorDeserialize, InstructionData, ToAccountMetas};
use light_hasher::{Hasher, Poseidon};
use num_bigint::BigUint;
use pool_e2e::harness::{
    airdrop, create_mint, create_token_account, mint_to, repository, send, token_balance, Result,
    Validator,
};
use serial_test::serial;
use solana_client::rpc_client::RpcClient;
use solana_keccak_hasher::hashv;
use solana_sdk::{
    compute_budget::ComputeBudgetInstruction,
    instruction::Instruction,
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction as SolanaTransaction,
};
use solana_system_interface::program as system_program;
use spl_associated_token_account::get_associated_token_address;
use veil402_sdk::solana::MAX_ENCRYPTED_NOTE_LEN;
use veil402_sdk::{
    Config, Field, MerklePath, Note, Output, Owner, Pool as VeilPool, Public, Secret, Spend,
    Transaction as VeilTransaction, Veil, Withdrawal, TREE_DEPTH,
};

const VERIFIER: Pubkey = Pubkey::from_str_const("9jpnLceL3ahFfi5JmXdXNT1rZ1zLmfUcBkKbqCvquo19");
const DOMAIN: [u8; 32] = [7; 32];

fn field(value: u64) -> Field {
    Field::from(value)
}

fn secret(value: u64) -> Result<Secret> {
    Ok(Secret::from_bytes(field(value).to_bytes())?)
}

fn mutate_instruction(
    instruction: &Instruction,
    mutate: impl FnOnce(&mut pool::instruction::Transact),
) -> Result<Instruction> {
    let encoded = instruction
        .data
        .get(8..)
        .ok_or("transaction instruction is missing its discriminator")?;
    let mut arguments = pool::instruction::Transact::try_from_slice(encoded)?;
    mutate(&mut arguments);
    let mut instruction = instruction.clone();
    instruction.data = arguments.data();
    Ok(instruction)
}

fn nullifier_address(config: &VeilPool, nullifier: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(
        &[b"nullifier", config.address().as_ref(), nullifier],
        &pool::ID,
    )
    .0
}

fn scalar_modulus() -> Result<BigUint> {
    BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .ok_or_else(|| "BN254 scalar modulus is invalid".into())
}

fn field_bytes(value: BigUint) -> Result<[u8; 32]> {
    let encoded = value.to_bytes_be();
    if encoded.len() > 32 {
        return Err("field value exceeds 32 bytes".into());
    }
    let mut bytes = [0; 32];
    bytes[32 - encoded.len()..].copy_from_slice(&encoded);
    Ok(bytes)
}

fn add_scalar_modulus(value: [u8; 32]) -> Result<[u8; 32]> {
    field_bytes(BigUint::from_bytes_be(&value) + scalar_modulus()?)
}

fn binding_hash(
    domain: &[u8; 32],
    program: &Pubkey,
    pool: &Pubkey,
    mint: &Pubkey,
    recipient: &Pubkey,
    amount: i64,
    encrypted_note: &[u8],
) -> Result<Field> {
    let amount = amount.to_be_bytes();
    let length = u32::try_from(encrypted_note.len())?.to_be_bytes();
    let digest = hashv(&[
        b"veil402:transact:v1",
        domain,
        program.as_ref(),
        pool.as_ref(),
        mint.as_ref(),
        recipient.as_ref(),
        &amount,
        &length,
        encrypted_note,
    ]);
    Field::from_bytes(field_bytes(
        BigUint::from_bytes_be(digest.as_ref()) % scalar_modulus()?,
    )?)
    .map_err(Into::into)
}

fn proof_transaction(asset: Field, hash: Field) -> Result<VeilTransaction> {
    let owner = Owner {
        spend: secret(11)?,
        view: secret(22)?,
    };
    let note = Note {
        value: 1_000,
        asset,
        random: secret(33)?,
    };
    let mut siblings = [Field::ZERO; TREE_DEPTH];
    for (field, zero) in siblings.iter_mut().zip(Poseidon::zero_bytes()) {
        *field = Field::from_bytes(zero)?;
    }
    let output_owner = Owner {
        spend: secret(44)?,
        view: secret(55)?,
    };
    Ok(VeilTransaction {
        input: Spend {
            note,
            owner,
            merkle: MerklePath { index: 0, siblings },
        },
        send: Output {
            owner: output_owner.public()?,
            value: 700,
            random: secret(66)?,
        },
        public: Public { amount: -300, hash },
    })
}

#[derive(Debug, Eq, PartialEq)]
struct PoolState {
    tree: Vec<u8>,
    vault: u64,
    recipient: u64,
    attacker: u64,
    nullifier: Option<Vec<u8>>,
}

fn pool_state(
    client: &RpcClient,
    config: &VeilPool,
    recipient: &Pubkey,
    attacker: &Pubkey,
    nullifier: &Pubkey,
) -> Result<PoolState> {
    Ok(PoolState {
        tree: client.get_account_data(&config.tree())?,
        vault: token_balance(client, &config.vault())?,
        recipient: token_balance(client, recipient)?,
        attacker: token_balance(client, attacker)?,
        nullifier: client
            .get_account(nullifier)
            .ok()
            .map(|account| account.data),
    })
}

struct Assertions<'a> {
    client: &'a RpcClient,
    payer: &'a Keypair,
    pool: &'a VeilPool,
    recipient: &'a Pubkey,
    attacker: &'a Pubkey,
}

impl Assertions<'_> {
    fn rejects_without_changes(
        &self,
        nonce: u64,
        instruction: Instruction,
        nullifier: &Pubkey,
        case: &str,
    ) -> Result<()> {
        let before = pool_state(
            self.client,
            self.pool,
            self.recipient,
            self.attacker,
            nullifier,
        )?;
        if send(self.client, instruction, self.payer, nonce).is_ok() {
            return Err(format!("{case} was accepted").into());
        }
        if pool_state(
            self.client,
            self.pool,
            self.recipient,
            self.attacker,
            nullifier,
        )? != before
        {
            return Err(format!("{case} changed pool state").into());
        }
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn real_verifier_binds_every_public_input() -> Result<()> {
    // Build the same bundled prover used by clients; this test deliberately
    // crosses the Rust SDK -> Go prover -> Sunspot verifier boundary.
    let repository = repository()?;
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

    // Run the real pool and verifier programs under a local validator.
    let verifier = repository.join("circuits/transaction/target/transaction.so");
    let validator = Validator::start(&repository, &[(VERIFIER, verifier.as_path())])?;
    let client = validator.client();
    let payer = Keypair::new();
    airdrop(&client, &payer.pubkey(), 100 * LAMPORTS_PER_SOL)?;

    let mint = create_mint(&client, &payer)?;

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
    create_token_account(&client, &payer, &payer.pubkey(), &mint)?;
    create_token_account(&client, &payer, &recipient.pubkey(), &mint)?;
    create_token_account(&client, &payer, &attacker.pubkey(), &mint)?;
    mint_to(&client, &payer, &mint, &depositor_ata, 1_000)?;

    // Shield one note whose commitment becomes leaf zero of the on-chain tree.
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

    // The first leaf's Merkle path is the circuit's zero path. Generate a real
    // proof that spends 1,000 into a 300 withdrawal plus a 700 change note.
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
        repository.join("prover/veil402-gnark/artifacts/transaction-v3"),
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

    let nullifier = prepared.proof.public.nullifier.to_bytes();
    let nullifier_record = nullifier_address(&pool, &nullifier);
    let mut cases = Vec::new();

    // Mutating any one of the five verifier inputs must invalidate the same
    // proof. A changed nullifier also needs its matching PDA account so the
    // failure reaches proof verification instead of stopping at seed checks.
    cases.push((
        "mutated root",
        mutate_instruction(&prepared.instruction, |args| {
            args.root = field(901).to_bytes();
        })?,
        nullifier_record,
    ));
    let changed_nullifier = field(902).to_bytes();
    let changed_nullifier_record = nullifier_address(&pool, &changed_nullifier);
    let mut instruction = mutate_instruction(&prepared.instruction, |args| {
        args.nullifier = changed_nullifier;
    })?;
    instruction.accounts[4].pubkey = changed_nullifier_record;
    cases.push(("mutated nullifier", instruction, changed_nullifier_record));
    cases.push((
        "mutated output commitment",
        mutate_instruction(&prepared.instruction, |args| {
            args.out_commitment = field(903).to_bytes();
        })?,
        nullifier_record,
    ));
    cases.push((
        "mutated public amount",
        mutate_instruction(&prepared.instruction, |args| {
            args.ext_amount = -301;
        })?,
        nullifier_record,
    ));

    // ext_data_hash is recomputed on-chain. Mutate its recipient, ciphertext
    // contents, and encoded length independently while keeping each value valid.
    let mut instruction = mutate_instruction(&prepared.instruction, |args| {
        args.ext_data.recipient = attacker.pubkey();
    })?;
    instruction.accounts[5].pubkey = attacker_ata;
    cases.push(("mutated recipient", instruction, nullifier_record));
    cases.push((
        "mutated encrypted-note byte",
        mutate_instruction(&prepared.instruction, |args| {
            args.ext_data.encrypted_note[0] ^= 1;
        })?,
        nullifier_record,
    ));
    cases.push((
        "mutated encrypted-note length",
        mutate_instruction(&prepared.instruction, |args| {
            args.ext_data.encrypted_note.pop();
        })?,
        nullifier_record,
    ));

    // These remain structurally valid 388-byte and truncated proofs, but no
    // longer verify against the canonical public witness.
    cases.push((
        "mutated proof byte",
        mutate_instruction(&prepared.instruction, |args| {
            args.proof[0] ^= 1;
        })?,
        nullifier_record,
    ));
    cases.push((
        "truncated proof",
        mutate_instruction(&prepared.instruction, |args| {
            args.proof.pop();
        })?,
        nullifier_record,
    ));

    // Generate valid proofs for deliberately wrong binding hashes. Transplanting
    // only their proof bytes into the canonical instruction isolates each
    // configuration input checked by the contract's ext_data_hash.
    let encrypted_note = vec![2; MAX_ENCRYPTED_NOTE_LEN];
    let canonical_hash = binding_hash(
        &DOMAIN,
        &pool::ID,
        &pool.address(),
        &mint,
        &recipient.pubkey(),
        -300,
        &encrypted_note,
    )?;
    assert_eq!(canonical_hash, prepared.proof.public.hash);
    let bindings = [
        (
            "mutated domain binding",
            binding_hash(
                &[8; 32],
                &pool::ID,
                &pool.address(),
                &mint,
                &recipient.pubkey(),
                -300,
                &encrypted_note,
            )?,
        ),
        (
            "mutated program binding",
            binding_hash(
                &DOMAIN,
                &Pubkey::new_unique(),
                &pool.address(),
                &mint,
                &recipient.pubkey(),
                -300,
                &encrypted_note,
            )?,
        ),
        (
            "mutated pool binding",
            binding_hash(
                &DOMAIN,
                &pool::ID,
                &Pubkey::new_unique(),
                &mint,
                &recipient.pubkey(),
                -300,
                &encrypted_note,
            )?,
        ),
        (
            "mutated mint binding",
            binding_hash(
                &DOMAIN,
                &pool::ID,
                &pool.address(),
                &Pubkey::new_unique(),
                &recipient.pubkey(),
                -300,
                &encrypted_note,
            )?,
        ),
    ];
    for (case, hash) in bindings {
        let wrong_proof = veil.prove(proof_transaction(pool.asset(), hash)?).await?;
        let instruction = mutate_instruction(&prepared.instruction, |args| {
            args.proof = wrong_proof.bytes;
        })?;
        cases.push((case, instruction, nullifier_record));
    }

    // Preserve the canonical-encoding defenses in the real-verifier path too.
    let non_canonical = add_scalar_modulus(nullifier)?;
    let non_canonical_record = nullifier_address(&pool, &non_canonical);
    let mut instruction = mutate_instruction(&prepared.instruction, |args| {
        args.nullifier = non_canonical;
    })?;
    instruction.accounts[4].pubkey = non_canonical_record;
    cases.push(("non-canonical nullifier", instruction, non_canonical_record));
    let zero_record = nullifier_address(&pool, &[0; 32]);
    let mut instruction = mutate_instruction(&prepared.instruction, |args| {
        args.nullifier = [0; 32];
    })?;
    instruction.accounts[4].pubkey = zero_record;
    cases.push(("zero nullifier", instruction, zero_record));

    // Every rejection must preserve token balances, the tree, and the watched
    // nullifier account—not merely return an RPC error.
    let assertions = Assertions {
        client: &client,
        payer: &payer,
        pool: &pool,
        recipient: &recipient_ata,
        attacker: &attacker_ata,
    };
    let mut nonce = 3;
    for (case, instruction, watched_nullifier) in cases {
        assertions.rejects_without_changes(nonce, instruction, &watched_nullifier, case)?;
        nonce += 1;
    }

    // The production transaction, including the compute-budget instructions
    // used by send(), must remain below Solana's 1,232-byte packet limit.
    let blockhash = client.get_latest_blockhash()?;
    let packet = SolanaTransaction::new_signed_with_payer(
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(650_000),
            ComputeBudgetInstruction::set_compute_unit_price(nonce),
            prepared.instruction.clone(),
        ],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let packet_bytes = 1 + packet.signatures.len() * 64 + packet.message_data().len();
    assert!(packet_bytes <= solana_sdk::packet::PACKET_DATA_SIZE);

    // The unmodified proof pays exactly 300 and leaves 700 in the vault.
    send(&client, prepared.instruction.clone(), &payer, nonce)?;
    assert_eq!(token_balance(&client, &recipient_ata)?, 300);
    assert_eq!(token_balance(&client, &pool.vault())?, 700);
    nonce += 1;

    // Replaying the identical instruction must fail on the existing nullifier
    // and must not pay the recipient a second time.
    assertions.rejects_without_changes(
        nonce,
        prepared.instruction,
        &nullifier_record,
        "spent-nullifier replay",
    )?;
    drop(validator);
    Ok(())
}
