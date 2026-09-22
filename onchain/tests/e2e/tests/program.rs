use light_concurrent_merkle_tree::ConcurrentMerkleTree;
use light_hasher::Poseidon;
use num_bigint::BigUint;
use pool_e2e::{
    harness::{
        airdrop, create_mint, create_token_account, mint_to, repository, send, token_balance,
        tree_state, Result, Validator,
    },
    scenario::{
        field, init_instruction, nullifier_address, shield_instruction, transact_instruction,
        Fixture, Transaction, DOMAIN, MOCK_VERIFIER, PROOF_BYTES,
    },
};
use serial_test::serial;
use solana_sdk::{
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use solana_system_interface::program as system_program;
use veil402_sdk::Pool as VeilPool;

const TREE_BYTES: usize = 8_224;

fn non_canonical(value: [u8; 32]) -> Result<[u8; 32]> {
    let modulus = BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .ok_or("invalid BN254 scalar modulus")?;
    let encoded = (BigUint::from_bytes_be(&value) + modulus).to_bytes_be();
    if encoded.len() > 32 {
        return Err("non-canonical field does not fit in 32 bytes".into());
    }
    let mut bytes = [0; 32];
    bytes[32 - encoded.len()..].copy_from_slice(&encoded);
    Ok(bytes)
}

#[test]
#[serial]
fn initialization_enforces_configuration_and_layout() -> Result<()> {
    let mut fixture = Fixture::start()?;

    // I1/I6: initialization must persist the exact authority, verifier, mint,
    // SDK-derived asset ID, and proof-binding domain supplied by the client.
    let account = fixture.client.get_account(&fixture.config.address())?;
    let state = &account.data[8..];
    assert_eq!(&state[0..32], fixture.payer.pubkey().as_ref());
    assert_eq!(&state[32..64], MOCK_VERIFIER.as_ref());
    assert_eq!(&state[64..96], fixture.mint.as_ref());
    assert_eq!(&state[96..128], &fixture.config.asset().to_bytes());
    assert_eq!(&state[128..160], &DOMAIN);

    // I5: the fixed Anchor allocation must exactly fit Light's configured tree.
    let expected = ConcurrentMerkleTree::<Poseidon, 20>::size_in_account(20, 8, 64, 0);
    assert_eq!(expected, TREE_BYTES);
    assert_eq!(
        fixture
            .client
            .get_account_data(&fixture.config.tree())?
            .len(),
        8 + expected
    );

    // I2: the singleton pool PDAs cannot be initialized a second time.
    let reinitialize = init_instruction(
        &fixture.config,
        fixture.mint,
        MOCK_VERIFIER,
        fixture.payer.pubkey(),
        DOMAIN,
    );
    fixture.assert_rejected(reinitialize, fixture.recipient_ata)?;
    drop(fixture);

    // I3: Anchor's executable constraint rejects a wallet as the verifier and
    // rolls back every account the failed initialization tried to create.
    let repository = repository()?;
    // I4: any executable program can be configured, but a program that does
    // not implement the verifier interface must fail during its CPI.
    let validator = Validator::start(&repository, &[])?;
    let client = validator.client();
    let payer = Keypair::new();
    airdrop(&client, &payer.pubkey(), 100 * LAMPORTS_PER_SOL)?;
    let mint = create_mint(&client, &payer)?;
    let config = VeilPool::new(pool::ID, payer.pubkey(), mint, DOMAIN)?;
    assert!(send(
        &client,
        init_instruction(&config, mint, payer.pubkey(), payer.pubkey(), DOMAIN),
        &payer,
        1,
    )
    .is_err());
    assert!(client.get_account(&config.address()).is_err());
    drop(validator);

    let validator = Validator::start(&repository, &[])?;
    let client = validator.client();
    let payer = Keypair::new();
    airdrop(&client, &payer.pubkey(), 100 * LAMPORTS_PER_SOL)?;
    let mint = create_mint(&client, &payer)?;
    let config = VeilPool::new(pool::ID, system_program::id(), mint, DOMAIN)?;
    send(
        &client,
        init_instruction(&config, mint, system_program::id(), payer.pubkey(), DOMAIN),
        &payer,
        1,
    )?;
    let recipient = Keypair::new().pubkey();
    let recipient_ata = create_token_account(&client, &payer, &recipient, &mint)?;
    let root = tree_state(&client, &config.tree())?.root;
    let tx = Transaction {
        proof: vec![1; PROOF_BYTES],
        root,
        nullifiers: [field(1), field(2)],
        out_commitments: [field(3), field(4)],
        amount: 0,
        recipient,
        encrypted_notes: [Vec::new(), Vec::new()],
        recipient_ata,
        verifier: system_program::id(),
        mint,
        tree: config.tree(),
        vault: config.vault(),
    };
    let before = tree_state(&client, &config.tree())?;
    assert!(send(
        &client,
        transact_instruction(&config, payer.pubkey(), &tx),
        &payer,
        2,
    )
    .is_err());
    assert_eq!(tree_state(&client, &config.tree())?, before);
    for nullifier in tx.nullifiers {
        assert!(client
            .get_account(&nullifier_address(config.address(), &nullifier))
            .is_err());
    }
    Ok(())
}

#[test]
#[serial]
fn shield_boundaries_and_account_constraints_are_atomic() -> Result<()> {
    let mut fixture = Fixture::start()?;
    mint_to(
        &fixture.client,
        &fixture.payer,
        &fixture.mint,
        &fixture.depositor_ata,
        1_000,
    )?;

    // S1/S4-S6: the smallest deposit, empty ciphertext, maximum ciphertext,
    // canonical public key, and zero public key are all valid boundaries.
    fixture.shield(field(1), 1, Vec::new())?;
    fixture.shield([0; 32], 1, vec![1; 128])?;

    // S11: commitments need not be unique; identical leaves occupy distinct
    // Merkle indices because nullifiers, not commitments, prevent replay.
    let before_duplicates = tree_state(&fixture.client, &fixture.config.tree())?;
    fixture.shield(field(2), 1, vec![2])?;
    fixture.shield(field(2), 1, vec![2])?;
    assert_eq!(
        tree_state(&fixture.client, &fixture.config.tree())?.next_index,
        before_duplicates.next_index + 2
    );

    // S2/S4/S7/S9: reject zero value, oversized ciphertext, non-canonical
    // fields, and insufficient funds without moving tokens or appending leaves.
    for (npk, amount, note) in [
        (field(3), 0, Vec::new()),
        (field(4), 1, vec![0; 129]),
        (non_canonical(field(5))?, 1, Vec::new()),
        (field(6), 2_000, Vec::new()),
    ] {
        let instruction = shield_instruction(
            &fixture.config,
            fixture.mint,
            fixture.payer.pubkey(),
            fixture.depositor_ata,
            npk,
            amount,
            note,
        );
        fixture.assert_rejected(instruction, fixture.recipient_ata)?;
    }

    // S8: both the mint and depositor token account are tied to this pool.
    let wrong_mint = create_mint(&fixture.client, &fixture.payer)?;
    let wrong_ata = create_token_account(
        &fixture.client,
        &fixture.payer,
        &fixture.payer.pubkey(),
        &wrong_mint,
    )?;
    let wrong_mint_instruction = shield_instruction(
        &fixture.config,
        wrong_mint,
        fixture.payer.pubkey(),
        wrong_ata,
        field(7),
        1,
        Vec::new(),
    );
    fixture.assert_rejected(wrong_mint_instruction, fixture.recipient_ata)?;

    // S10: replacing the canonical pool vault with another valid token account
    // must fail Anchor's associated-token constraints before the transfer.
    let substituted_vault = shield_instruction(
        &fixture.config,
        fixture.mint,
        fixture.payer.pubkey(),
        fixture.depositor_ata,
        field(8),
        1,
        Vec::new(),
    );
    let mut substituted_vault = substituted_vault;
    substituted_vault.accounts[2].pubkey = fixture.recipient_ata;
    fixture.assert_rejected(substituted_vault, fixture.recipient_ata)?;
    drop(fixture);

    // S3: exercise u64::MAX in an isolated pool so later cases are not blocked
    // by the mint-supply and token-balance maximums.
    let mut fixture = Fixture::start()?;
    mint_to(
        &fixture.client,
        &fixture.payer,
        &fixture.mint,
        &fixture.depositor_ata,
        u64::MAX,
    )?;
    fixture.shield(field(9), u64::MAX, Vec::new())?;
    assert_eq!(
        token_balance(&fixture.client, &fixture.config.vault())?,
        u64::MAX
    );
    assert_eq!(token_balance(&fixture.client, &fixture.depositor_ata)?, 0);
    Ok(())
}

#[test]
#[serial]
fn public_leg_verifier_and_proof_boundaries_are_atomic() -> Result<()> {
    let mut fixture = Fixture::start()?;
    mint_to(
        &fixture.client,
        &fixture.payer,
        &fixture.mint,
        &fixture.depositor_ata,
        100,
    )?;
    fixture.shield(field(1), 100, Vec::new())?;

    // T1: deposits must use shield; transact only permits zero or negative flow.
    let mut positive = fixture.transaction(10)?;
    positive.amount = 1;
    fixture.assert_transaction_rejected(&positive)?;

    // T2: i64::MIN must be handled without overflow or partial state changes.
    let mut minimum = fixture.transaction(11)?;
    minimum.amount = i64::MIN;
    fixture.assert_transaction_rejected(&minimum)?;

    // T7: 128 ciphertext bytes is accepted; 129 is rejected atomically.
    let mut note_128 = fixture.transaction(12)?;
    note_128.encrypted_notes = [vec![1; 128], vec![2; 128]];
    fixture.transact(&note_128)?;

    let mut note_129 = fixture.transaction(13)?;
    note_129.encrypted_notes[1] = vec![1; 129];
    fixture.assert_transaction_rejected(&note_129)?;

    // V1: callers cannot replace the verifier selected during initialization.
    let mut wrong_verifier = fixture.transaction(14)?;
    wrong_verifier.verifier = system_program::id();
    fixture.assert_transaction_rejected(&wrong_verifier)?;

    // V2: the mock's first proof byte deterministically exercises verifier CPI
    // failure while the real pool, token, tree, and PDA logic still executes.
    let mut rejected_proof = fixture.transaction(15)?;
    rejected_proof.proof[0] = 0;
    fixture.assert_transaction_rejected(&rejected_proof)?;

    // V4: only the protocol's exact 388-byte Groth16 encoding is accepted.
    for (unique, length) in [(16, 0), (17, 387), (18, 389)] {
        let mut tx = fixture.transaction(unique)?;
        tx.proof = vec![1; length];
        fixture.assert_transaction_rejected(&tx)?;
    }

    // T3/V3: a valid zero-flow transaction appends both outputs and spends both
    // nullifiers without changing either token balance.
    let before = fixture.snapshot(fixture.recipient_ata)?;
    let exact = fixture.transaction(19)?;
    fixture.transact(&exact)?;
    let after = fixture.snapshot(fixture.recipient_ata)?;
    assert_eq!(after.vault, before.vault);
    assert_eq!(after.recipient, before.recipient);
    assert_eq!(after.tree.next_index, before.tree.next_index + 2);
    Ok(())
}

#[test]
#[serial]
fn root_window_and_encoding_boundaries_are_enforced() -> Result<()> {
    let mut fixture = Fixture::start()?;
    mint_to(
        &fixture.client,
        &fixture.payer,
        &fixture.mint,
        &fixture.depositor_ata,
        65,
    )?;

    // Build 65 successive roots so the 64-entry cyclic history has both a
    // retained age-63 root and roots at ages 64 and 65 that have expired.
    let initial = tree_state(&fixture.client, &fixture.config.tree())?.root;
    let mut roots = Vec::with_capacity(65);
    for value in 1..=65 {
        fixture.shield(field(value), 1, Vec::new())?;
        roots.push(tree_state(&fixture.client, &fixture.config.tree())?.root);
    }

    // R1/R2/R4/R5/R7: reject zero, unseen, expired, and non-canonical roots.
    // Each failed transaction also proves that validation leaves no nullifier.
    for (unique, root) in [
        (100, [0; 32]),
        (101, field(999_999)),
        (102, initial),
        (103, roots[0]),
        (104, non_canonical(roots[64])?),
    ] {
        let mut tx = fixture.transaction(unique)?;
        tx.root = root;
        fixture.assert_transaction_rejected(&tx)?;
    }

    // R6: the pool accepts only its tree PDA, not an account chosen by a caller.
    let mut foreign_tree = fixture.transaction(105)?;
    foreign_tree.tree = system_program::id();
    fixture.assert_transaction_rejected(&foreign_tree)?;

    // R3/R4: the oldest retained root (63 later appends) remains spendable.
    let mut age_63 = fixture.transaction(106)?;
    age_63.root = roots[1];
    fixture.transact(&age_63)?;
    Ok(())
}

#[test]
#[serial]
fn nullifiers_and_withdrawals_are_atomic() -> Result<()> {
    let mut fixture = Fixture::start()?;
    mint_to(
        &fixture.client,
        &fixture.payer,
        &fixture.mint,
        &fixture.depositor_ata,
        100,
    )?;
    fixture.shield(field(1), 100, Vec::new())?;

    // N1-N3: the first spend creates both nullifier PDAs; replay fails even when
    // the attacker changes an output commitment.
    let first = fixture.transaction(200)?;
    fixture.transact(&first)?;
    assert!(fixture
        .client
        .get_account(&nullifier_address(
            fixture.config.address(),
            &first.nullifiers[0]
        ))
        .is_ok());
    assert!(fixture
        .client
        .get_account(&nullifier_address(
            fixture.config.address(),
            &first.nullifiers[1]
        ))
        .is_ok());
    fixture.assert_transaction_rejected(&first)?;
    let mut changed_output = first.clone();
    changed_output.out_commitments[0] = field(9_999);
    fixture.assert_transaction_rejected(&changed_output)?;

    // N6: the pool address is part of nullifier PDA derivation, so the same
    // field value belongs to a different namespace in another deployment.
    let alternate_pool = Pubkey::new_unique();
    assert_ne!(
        nullifier_address(fixture.config.address(), &field(201)),
        nullifier_address(alternate_pool, &field(201))
    );

    // Independent spends remain separate atomic state transitions even though
    // v1 has enough wire capacity to carry more than one proof instruction.
    let tx_a = fixture.transaction(202)?;
    fixture.transact(&tx_a)?;
    let tx_b = fixture.transaction(203)?;
    fixture.transact(&tx_b)?;

    // W1: a valid withdrawal pays the exact public amount and debits the vault.
    let mut payout = fixture.transaction(205)?;
    payout.amount = -10;
    fixture.transact(&payout)?;
    assert_eq!(token_balance(&fixture.client, &fixture.recipient_ata)?, 10);
    assert_eq!(token_balance(&fixture.client, &fixture.config.vault())?, 90);

    // W2: insufficient vault funds fail after proof verification but roll back
    // the provisional nullifier account and all other state.
    let mut insufficient = fixture.transaction(206)?;
    insufficient.amount = -91;
    fixture.assert_transaction_rejected(&insufficient)?;

    // W3: the token account owner must match the recipient declared in ext_data.
    let attacker = Keypair::new().pubkey();
    let attacker_ata =
        create_token_account(&fixture.client, &fixture.payer, &attacker, &fixture.mint)?;
    let mut wrong_owner = fixture.transaction(207)?;
    wrong_owner.amount = -1;
    wrong_owner.recipient_ata = attacker_ata;
    fixture.assert_transaction_rejected(&wrong_owner)?;

    // W4: a valid token account for a different mint cannot receive pool funds.
    let wrong_mint = create_mint(&fixture.client, &fixture.payer)?;
    let wrong_mint_ata = create_token_account(
        &fixture.client,
        &fixture.payer,
        &fixture.recipient,
        &wrong_mint,
    )?;
    let mut wrong_mint_tx = fixture.transaction(208)?;
    wrong_mint_tx.amount = -1;
    wrong_mint_tx.mint = wrong_mint;
    wrong_mint_tx.recipient_ata = wrong_mint_ata;
    fixture.assert_transaction_rejected(&wrong_mint_tx)?;

    // W5: SPL Token transfer failure into a frozen account must also roll back
    // the provisional nullifier and leave the Merkle tree unchanged.
    fixture.submit(spl_token::instruction::freeze_account(
        &spl_token::id(),
        &attacker_ata,
        &fixture.mint,
        &fixture.payer.pubkey(),
        &[],
    )?)?;
    let mut frozen = fixture.transaction(209)?;
    frozen.amount = -1;
    frozen.recipient = attacker;
    frozen.recipient_ata = attacker_ata;
    fixture.assert_transaction_rejected(&frozen)?;

    // W6: the vault cannot be supplied as its own withdrawal destination.
    let mut self_transfer = fixture.transaction(210)?;
    self_transfer.amount = -1;
    self_transfer.recipient = fixture.config.address();
    self_transfer.recipient_ata = fixture.config.vault();
    fixture.assert_transaction_rejected(&self_transfer)?;

    // W7: recipient ownership is irrelevant for zero flow because no token
    // transfer occurs; the supplied account's balance must remain unchanged.
    let attacker_balance = token_balance(&fixture.client, &attacker_ata)?;
    let mut zero_flow = fixture.transaction(211)?;
    zero_flow.recipient = Pubkey::new_unique();
    zero_flow.recipient_ata = attacker_ata;
    fixture.transact(&zero_flow)?;
    assert_eq!(
        token_balance(&fixture.client, &attacker_ata)?,
        attacker_balance
    );

    // W8: withdrawing the exact remaining balance is valid and drains the
    // vault without an off-by-one rejection.
    let vault = token_balance(&fixture.client, &fixture.config.vault())?;
    let recipient_before = token_balance(&fixture.client, &fixture.recipient_ata)?;
    let mut drain = fixture.transaction(212)?;
    drain.amount = -i64::try_from(vault)?;
    fixture.transact(&drain)?;
    assert_eq!(token_balance(&fixture.client, &fixture.config.vault())?, 0);
    assert_eq!(
        token_balance(&fixture.client, &fixture.recipient_ata)?,
        recipient_before + vault
    );
    Ok(())
}
