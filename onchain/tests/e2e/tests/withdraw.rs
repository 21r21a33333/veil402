use std::process::Command;

use anchor_lang::{InstructionData, ToAccountMetas};
use light_hasher::{Hasher, Poseidon};
use num_bigint::BigUint;
use pool_e2e::harness::{
    airdrop, create_mint, create_token_account, mint_to, repository, send, token_balance, Result,
    Validator,
};
use serial_test::serial;
use solana_sdk::{
    instruction::Instruction,
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use solana_system_interface::program as system_program;
use spl_associated_token_account::get_associated_token_address;
use veil402_sdk::solana::MAX_ENCRYPTED_NOTE_LEN;
use veil402_sdk::{
    Config, Field, MerklePath, Note, Output, Owner, Pool as VeilPool, Proof, Secret, Spend, Veil,
    Withdrawal, TREE_DEPTH,
};

const VERIFIER: Pubkey = Pubkey::from_str_const("9jpnLceL3ahFfi5JmXdXNT1rZ1zLmfUcBkKbqCvquo19");
const DOMAIN: [u8; 32] = [7; 32];

fn field(value: u64) -> Field {
    Field::from(value)
}

fn secret(value: u64) -> Result<Secret> {
    Ok(Secret::from_bytes(field(value).to_bytes())?)
}

fn withdraw_instruction(
    config: &VeilPool,
    mint: Pubkey,
    payer: Pubkey,
    proof: &Proof,
    nullifier: [u8; 32],
    recipient: Pubkey,
    recipient_ata: Pubkey,
) -> Instruction {
    let (nullifier_record, _) = Pubkey::find_program_address(
        &[b"nullifier", config.address().as_ref(), &nullifier],
        &pool::ID,
    );
    Instruction {
        program_id: pool::ID,
        accounts: pool::accounts::Transact {
            pool: config.address(),
            tree: config.tree(),
            vault: config.vault(),
            mint,
            nullifier_record,
            recipient_ata,
            verifier_program: VERIFIER,
            payer,
            token_program: spl_token::id(),
            system_program: system_program::id(),
        }
        .to_account_metas(None),
        data: pool::instruction::Transact {
            proof: proof.bytes.clone(),
            root: proof.public.root.to_bytes(),
            nullifier,
            out_commitment: proof.public.commitment.to_bytes(),
            ext_amount: -300,
            ext_data: pool::ExtData {
                recipient,
                encrypted_note: vec![2; MAX_ENCRYPTED_NOTE_LEN],
            },
        }
        .data(),
    }
}

fn add_scalar_modulus(value: [u8; 32]) -> Result<[u8; 32]> {
    let modulus = BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .ok_or("BN254 scalar modulus is invalid")?;
    let encoded = (BigUint::from_bytes_be(&value) + modulus).to_bytes_be();
    if encoded.len() > 32 {
        return Err("non-canonical nullifier exceeds 32 bytes".into());
    }
    let mut bytes = [0; 32];
    bytes[32 - encoded.len()..].copy_from_slice(&encoded);
    Ok(bytes)
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn withdrawal_is_bound_and_single_use() -> Result<()> {
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

    // The recipient is part of ext_data_hash. Reusing the proof with an
    // attacker's recipient must fail without changing the tree or balances.
    let tree_before = client.get_account_data(&pool.tree())?;
    let nullifier = prepared.proof.public.nullifier.to_bytes();
    let tampered = withdraw_instruction(
        &pool,
        mint,
        payer.pubkey(),
        &prepared.proof,
        nullifier,
        attacker.pubkey(),
        attacker_ata,
    );
    if send(&client, tampered, &payer, 3).is_ok() {
        return Err("proof accepted a mutated recipient".into());
    }

    // Adding the BN254 modulus preserves the mathematical field value but not
    // its canonical byte encoding; reject it before a nullifier PDA is created.
    let non_canonical = add_scalar_modulus(nullifier)?;
    let non_canonical_record = Pubkey::find_program_address(
        &[b"nullifier", pool.address().as_ref(), &non_canonical],
        &pool::ID,
    )
    .0;
    let altered = withdraw_instruction(
        &pool,
        mint,
        payer.pubkey(),
        &prepared.proof,
        non_canonical,
        recipient.pubkey(),
        recipient_ata,
    );
    if send(&client, altered, &payer, 4).is_ok() {
        return Err("non-canonical nullifier was accepted".into());
    }
    if client.get_account(&non_canonical_record).is_ok() {
        return Err("failed nullifier validation left a PDA behind".into());
    }

    // Zero is canonical as a field element but forbidden as a nullifier because
    // it would collapse every such spend onto one sentinel PDA.
    let zero_record = Pubkey::find_program_address(
        &[b"nullifier", pool.address().as_ref(), &[0; 32]],
        &pool::ID,
    )
    .0;
    let zero = withdraw_instruction(
        &pool,
        mint,
        payer.pubkey(),
        &prepared.proof,
        [0; 32],
        recipient.pubkey(),
        recipient_ata,
    );
    if send(&client, zero, &payer, 5).is_ok() {
        return Err("zero nullifier was accepted".into());
    }
    if client.get_account(&zero_record).is_ok() {
        return Err("failed zero-nullifier validation left a PDA behind".into());
    }

    // All rejected variants must leave both token and Merkle state untouched.
    if token_balance(&client, &pool.vault())? != 1_000
        || client.get_account_data(&pool.tree())? != tree_before
    {
        return Err("failed withdrawal changed pool state".into());
    }

    // The unmodified proof pays exactly 300 and leaves 700 in the vault.
    send(&client, prepared.instruction.clone(), &payer, 6)?;
    assert_eq!(token_balance(&client, &recipient_ata)?, 300);
    assert_eq!(token_balance(&client, &pool.vault())?, 700);

    // Replaying the identical instruction must fail on the existing nullifier
    // and must not pay the recipient a second time.
    if send(&client, prepared.instruction, &payer, 7).is_ok() {
        return Err("spent nullifier was accepted twice".into());
    }
    assert_eq!(token_balance(&client, &recipient_ata)?, 300);
    drop(validator);
    Ok(())
}
