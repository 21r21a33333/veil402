use std::process::Command;

use anchor_lang::{AnchorDeserialize, InstructionData, ToAccountMetas};
use light_hasher::{Hasher, Poseidon};
use num_bigint::BigUint;
use pool_e2e::harness::{
    airdrop, confirmed_transaction, create_mint, create_token_account, mint_to, repository, send,
    token_balance, Result, Validator,
};
use pool_e2e::v1;
use serial_test::serial;
use solana_client::rpc_client::RpcClient;
use solana_keccak_hasher::hashv;
use solana_sdk::{
    instruction::Instruction,
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use solana_system_interface::program as system_program;
use solana_transaction_status_client_types::option_serializer::OptionSerializer;
use spl_associated_token_account::get_associated_token_address;
use veil402_sdk::solana::MAX_ENCRYPTED_NOTE_LEN;
use veil402_sdk::{
    Config, Field, MerklePath, Note, Owner, Pool as VeilPool, Secret, Send, Spend,
    Transaction as VeilTransaction, Veil, Withdrawal, TREE_DEPTH,
};

const VERIFIER: Pubkey = Pubkey::from_str_const("9jpnLceL3ahFfi5JmXdXNT1rZ1zLmfUcBkKbqCvquo19");
const DOMAIN: [u8; 32] = [7; 32];
// Baseline: 597,080-603,173 units across fresh proofs on Agave 4.2.1.
// The 650K regression ceiling stays below the v1 transaction's 700K limit.
const COMPUTE_CEILING: u64 = 650_000;

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

struct Binding<'a> {
    domain: &'a [u8; 32],
    program: &'a Pubkey,
    pool: &'a Pubkey,
    mint: &'a Pubkey,
    verifier: &'a Pubkey,
    recipient: &'a Pubkey,
}

fn binding_hash(
    binding: Binding<'_>,
    amount: i64,
    encrypted_notes: &[Vec<u8>; 2],
) -> Result<Field> {
    let amount = amount.to_be_bytes();
    let first_len = u32::try_from(encrypted_notes[0].len())?.to_be_bytes();
    let second_len = u32::try_from(encrypted_notes[1].len())?.to_be_bytes();
    let digest = hashv(&[
        b"veil402:transact:v4",
        binding.domain,
        binding.program.as_ref(),
        binding.pool.as_ref(),
        binding.mint.as_ref(),
        binding.verifier.as_ref(),
        binding.recipient.as_ref(),
        &amount,
        &first_len,
        &encrypted_notes[0],
        &second_len,
        &encrypted_notes[1],
    ]);
    Field::from_bytes(field_bytes(
        BigUint::from_bytes_be(digest.as_ref()) % scalar_modulus()?,
    )?)
    .map_err(Into::into)
}

#[derive(Debug, Eq, PartialEq)]
struct PoolState {
    tree: Vec<u8>,
    vault: u64,
    recipient: u64,
    attacker: u64,
    nullifiers: [Option<Vec<u8>>; 2],
}

fn pool_state(
    client: &RpcClient,
    config: &VeilPool,
    recipient: &Pubkey,
    attacker: &Pubkey,
    nullifiers: &[Pubkey; 2],
) -> Result<PoolState> {
    Ok(PoolState {
        tree: client.get_account_data(&config.tree())?,
        vault: token_balance(client, &config.vault())?,
        recipient: token_balance(client, recipient)?,
        attacker: token_balance(client, attacker)?,
        nullifiers: nullifiers
            .each_ref()
            .map(|address| client.get_account(address).ok().map(|account| account.data)),
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
        nullifiers: &[Pubkey; 2],
        case: &str,
    ) -> Result<()> {
        let before = pool_state(
            self.client,
            self.pool,
            self.recipient,
            self.attacker,
            nullifiers,
        )?;
        if send(self.client, instruction, self.payer, nonce).is_ok() {
            return Err(format!("{case} was accepted").into());
        }
        if pool_state(
            self.client,
            self.pool,
            self.recipient,
            self.attacker,
            nullifiers,
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
    let payer = Keypair::new();
    let validator = Validator::start(
        &repository,
        payer.pubkey(),
        &[(VERIFIER, verifier.as_path())],
    )?;
    let client = validator.client();
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
            pool_program: pool::ID,
            program_data: solana_sdk::bpf_loader_upgradeable::get_program_data_address(&pool::ID),
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
    let withdrawal = Withdrawal::new(recipient.pubkey(), 300)?;
    let veil = Veil::open(Config::new(
        worker,
        repository.join("prover/veil402-gnark/artifacts/transaction-v4"),
    ))?;
    let prepared = veil
        .withdraw(
            &pool,
            VeilTransaction::new(
                vec![Spend {
                    note,
                    owner,
                    merkle: MerklePath { index: 0, siblings },
                }],
                vec![Send::new(
                    output_owner.public()?,
                    700,
                    secret(66)?,
                    vec![2; MAX_ENCRYPTED_NOTE_LEN],
                )?],
            )?,
            withdrawal,
            payer.pubkey(),
        )
        .await?;

    let nullifiers = prepared.proof.public.nullifiers.map(Field::to_bytes);
    let nullifier_records = nullifiers.map(|nullifier| nullifier_address(&pool, &nullifier));
    let mut cases = Vec::new();

    // Mutating any one of the seven verifier inputs must invalidate the same
    // proof. A changed nullifier also needs its matching PDA account so the
    // failure reaches proof verification instead of stopping at seed checks.
    cases.push((
        "mutated root",
        mutate_instruction(&prepared.instruction, |args| {
            args.root = field(901).to_bytes();
        })?,
        nullifier_records,
    ));
    let changed_nullifier = field(902).to_bytes();
    let changed_nullifier_record = nullifier_address(&pool, &changed_nullifier);
    let mut instruction = mutate_instruction(&prepared.instruction, |args| {
        args.nullifiers[0] = changed_nullifier;
    })?;
    instruction.accounts[4].pubkey = changed_nullifier_record;
    cases.push((
        "mutated nullifier",
        instruction,
        [changed_nullifier_record, nullifier_records[1]],
    ));
    cases.push((
        "mutated output commitment",
        mutate_instruction(&prepared.instruction, |args| {
            args.out_commitments[0] = field(903).to_bytes();
        })?,
        nullifier_records,
    ));
    cases.push((
        "mutated public amount",
        mutate_instruction(&prepared.instruction, |args| {
            args.ext_amount = -301;
        })?,
        nullifier_records,
    ));

    // ext_data_hash is recomputed on-chain. Mutate its recipient, ciphertext
    // contents, and encoded length independently while keeping each value valid.
    let mut instruction = mutate_instruction(&prepared.instruction, |args| {
        args.ext_data.recipient = attacker.pubkey();
    })?;
    instruction.accounts[6].pubkey = attacker_ata;
    cases.push(("mutated recipient", instruction, nullifier_records));
    cases.push((
        "mutated encrypted-note byte",
        mutate_instruction(&prepared.instruction, |args| {
            args.ext_data.encrypted_notes[0][0] ^= 1;
        })?,
        nullifier_records,
    ));
    cases.push((
        "mutated encrypted-note length",
        mutate_instruction(&prepared.instruction, |args| {
            args.ext_data.encrypted_notes[1].pop();
        })?,
        nullifier_records,
    ));

    // These remain structurally valid 388-byte and truncated proofs, but no
    // longer verify against the canonical public witness.
    cases.push((
        "mutated proof byte",
        mutate_instruction(&prepared.instruction, |args| {
            args.proof[0] ^= 1;
        })?,
        nullifier_records,
    ));
    cases.push((
        "truncated proof",
        mutate_instruction(&prepared.instruction, |args| {
            args.proof.pop();
        })?,
        nullifier_records,
    ));

    // Independently reproduce the complete external-data binding from the
    // serialized instruction, including both shuffled encrypted outputs.
    let encoded = prepared
        .instruction
        .data
        .get(8..)
        .ok_or("transaction instruction is missing its discriminator")?;
    let canonical_args = pool::instruction::Transact::try_from_slice(encoded)?;
    let canonical_hash = binding_hash(
        Binding {
            domain: &DOMAIN,
            program: &pool::ID,
            pool: &pool.address(),
            mint: &mint,
            verifier: &VERIFIER,
            recipient: &recipient.pubkey(),
        },
        -300,
        &canonical_args.ext_data.encrypted_notes,
    )?;
    assert_eq!(canonical_hash, prepared.proof.public.hash);

    // Preserve the canonical-encoding defenses in the real-verifier path too.
    let non_canonical = add_scalar_modulus(nullifiers[0])?;
    let non_canonical_record = nullifier_address(&pool, &non_canonical);
    let mut instruction = mutate_instruction(&prepared.instruction, |args| {
        args.nullifiers[0] = non_canonical;
    })?;
    instruction.accounts[4].pubkey = non_canonical_record;
    cases.push((
        "non-canonical nullifier",
        instruction,
        [non_canonical_record, nullifier_records[1]],
    ));
    let zero_record = nullifier_address(&pool, &[0; 32]);
    let mut instruction = mutate_instruction(&prepared.instruction, |args| {
        args.nullifiers[0] = [0; 32];
    })?;
    instruction.accounts[4].pubkey = zero_record;
    cases.push((
        "zero nullifier",
        instruction,
        [zero_record, nullifier_records[1]],
    ));

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

    // The production proof is sent as one atomic v1 transaction. Its resource
    // limits live in the message config, leaving the instruction list clean.
    let transaction = v1::build(&client.url(), prepared.instruction.clone(), &payer, nonce)?;
    let transaction_bytes = transaction.wire_size()?;
    eprintln!("v1 transaction bytes: {transaction_bytes}");
    assert!(transaction_bytes <= solana_message_v1::v1::MAX_TRANSACTION_SIZE);

    // The unmodified proof pays exactly 300 and leaves 700 in the vault.
    let signature = v1::send(&client.url(), &transaction)?;
    assert_eq!(token_balance(&client, &recipient_ata)?, 300);
    assert_eq!(token_balance(&client, &pool.vault())?, 700);
    let transaction = confirmed_transaction(&client, &signature)?;
    let meta = transaction
        .transaction
        .meta
        .ok_or("successful transaction has no metadata")?;
    let compute_units = match meta.compute_units_consumed {
        OptionSerializer::Some(units) => units,
        OptionSerializer::None | OptionSerializer::Skip => {
            return Err("successful transaction has no compute measurement".into());
        }
    };
    eprintln!("real verifier compute units: {compute_units}");
    assert!(compute_units <= COMPUTE_CEILING);
    nonce += 1;

    // Replaying the identical instruction must fail on the existing nullifiers
    // and must not pay the recipient a second time.
    assertions.rejects_without_changes(
        nonce,
        prepared.instruction,
        &nullifier_records,
        "spent-nullifier replay",
    )?;
    drop(validator);
    Ok(())
}
