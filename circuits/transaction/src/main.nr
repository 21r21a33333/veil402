mod merkle;
use poseidon::poseidon::bn254;

global TREE_DEPTH: u32 = 20;

// 1-in / 1-out shielded transaction.
//
// Spend one existing note and create one new note. `public_amount` is the signed public token flow
// (0 = private transfer, negative-in-field = withdrawal); field arithmetic makes the conservation
// check handle both. The proof shows: the spender owns the input note, it is in the tree, its
// nullifier is correct, the output note is well-formed and in range, and value is conserved.
//
// Note layout:  npk = Poseidon(mpk, random);  commitment = Poseidon(npk, asset_id, value)
// Keys:         mpk = Poseidon(Poseidon(spending_key), Poseidon(viewing_key))
// Nullifier:    Poseidon(nullifying_key, leaf_index)   where nullifying_key = Poseidon(viewing_key)
fn main(
    // Public inputs.
    root: pub Field,
    nullifier: pub Field,
    out_commitment: pub Field,
    public_amount: pub Field,
    ext_data_hash: pub Field,
    // Private: input note + the keys that own it.
    in_value: Field,
    asset_id: Field,
    in_random: Field,
    spending_key: Field,
    viewing_key: Field,
    leaf_index: Field,
    siblings: [Field; TREE_DEPTH],
    // Private: output note.
    out_npk: Field,
    out_value: Field,
) {
    // Derive the keys and the input note's owner tag from the spender's secrets.
    let nullifying_key = bn254::hash_1([viewing_key]);
    let mpk = bn254::hash_2([bn254::hash_1([spending_key]), nullifying_key]);
    let in_npk = bn254::hash_2([mpk, in_random]);

    // The input note must be a leaf under the given root.
    let in_commitment = bn254::hash_3([in_npk, asset_id, in_value]);
    assert(
        merkle::compute_root(in_commitment, siblings, leaf_index) == root,
        "input note not in tree",
    );

    // The revealed nullifier must be the one only this owner can produce for this leaf.
    assert(nullifier == bn254::hash_2([nullifying_key, leaf_index]), "wrong nullifier");

    // The output note must be a valid commitment to `out_value` (else conservation is meaningless).
    assert(
        out_commitment == bn254::hash_3([out_npk, asset_id, out_value]),
        "wrong output commitment",
    );
    out_value.assert_max_bit_size::<64>();

    // Value conservation: inputs + public flow == outputs (field math covers signed withdrawals).
    assert(in_value + public_amount == out_value, "value not conserved");

    // Bind the public leg (recipient / relayer / fee / ciphertext) so it can't be swapped post-proof.
    let _ = ext_data_hash;
}

// Table-driven test runner. Builds the standard 1-in/1-out witness (fixed secrets, in_value = 1000,
// a single leaf at index 0) and runs `main`. A case sets `public_amount` / `out_value`; a non-zero
// `*_off` corrupts that one public input to exercise a specific rejection (0 = leave it correct).
fn run_case(
    public_amount: Field,
    out_value: Field,
    root_off: Field,
    nullifier_off: Field,
    out_commitment_off: Field,
) {
    let spending_key = 11;
    let viewing_key = 22;
    let in_random = 33;
    let asset_id = 1;
    let in_value = 1000;
    let out_npk = 4242;
    let leaf_index = 0;
    let siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];

    let nk = bn254::hash_1([viewing_key]);
    let mpk = bn254::hash_2([bn254::hash_1([spending_key]), nk]);
    let in_commitment = bn254::hash_3([bn254::hash_2([mpk, in_random]), asset_id, in_value]);

    main(
        merkle::compute_root(in_commitment, siblings, leaf_index) + root_off,
        bn254::hash_2([nk, leaf_index]) + nullifier_off,
        bn254::hash_3([out_npk, asset_id, out_value]) + out_commitment_off,
        public_amount,
        999,
        in_value,
        asset_id,
        in_random,
        spending_key,
        viewing_key,
        leaf_index,
        siblings,
        out_npk,
        out_value,
    );
}

// Accepted: a private transfer (public_amount 0) and a withdrawal (negative net flow).
#[test]
fn transfer_1in1out() {
    run_case(0, 1000, 0, 0, 0);
}

#[test]
fn withdraw_conserves() {
    run_case(0 - 300, 700, 0, 0, 0);
}

// Rejected: each case corrupts exactly one input; the test name says which.
#[test(should_fail_with = "value not conserved")]
fn rejects_value_inflation() {
    run_case(0, 1001, 0, 0, 0);
}

#[test(should_fail_with = "wrong nullifier")]
fn rejects_wrong_nullifier() {
    run_case(0, 1000, 0, 1, 0);
}

#[test(should_fail_with = "input note not in tree")]
fn rejects_non_membership() {
    run_case(0, 1000, 1, 0, 0);
}

#[test(should_fail_with = "wrong output commitment")]
fn rejects_wrong_output_commitment() {
    run_case(0, 1000, 0, 0, 1);
}

#[test]
fn emit_prover_toml() {
    // Prints the standard transfer's public inputs (for a gitignored Prover.toml).
    let nk = bn254::hash_1([22]);
    let mpk = bn254::hash_2([bn254::hash_1([11]), nk]);
    let in_commitment = bn254::hash_3([bn254::hash_2([mpk, 33]), 1, 1000]);
    let siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    let root = merkle::compute_root(in_commitment, siblings, 0);
    let nullifier = bn254::hash_2([nk, 0]);
    let out_commitment = bn254::hash_3([4242, 1, 1000]);
    println(f"root = {root}");
    println(f"nullifier = {nullifier}");
    println(f"out_commitment = {out_commitment}");
}
