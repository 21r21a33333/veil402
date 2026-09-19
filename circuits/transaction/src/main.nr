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

#[test]
fn transfer_1in1out() {
    // A pure private transfer: public_amount = 0, so out_value == in_value.
    let spending_key = 11;
    let viewing_key = 22;
    let in_random = 33;
    let asset_id = 1;
    let in_value = 1000;

    let nk = bn254::hash_1([viewing_key]);
    let mpk = bn254::hash_2([bn254::hash_1([spending_key]), nk]);
    let in_npk = bn254::hash_2([mpk, in_random]);
    let in_commitment = bn254::hash_3([in_npk, asset_id, in_value]);

    // Self-consistent tree: any siblings work as long as the same ones produce the root we pass in.
    let siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    let leaf_index = 0;
    let root = merkle::compute_root(in_commitment, siblings, leaf_index);
    let nullifier = bn254::hash_2([nk, leaf_index]);

    let out_npk = 4242; // recipient's note public key
    let out_value = in_value;
    let out_commitment = bn254::hash_3([out_npk, asset_id, out_value]);

    main(
        root,
        nullifier,
        out_commitment,
        0,
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

#[test(should_fail_with = "value not conserved")]
fn rejects_value_inflation() {
    // Same as the transfer, but the output is worth more than the input with no public inflow.
    let spending_key = 11;
    let viewing_key = 22;
    let in_random = 33;
    let asset_id = 1;
    let in_value = 1000;

    let nk = bn254::hash_1([viewing_key]);
    let mpk = bn254::hash_2([bn254::hash_1([spending_key]), nk]);
    let in_npk = bn254::hash_2([mpk, in_random]);
    let in_commitment = bn254::hash_3([in_npk, asset_id, in_value]);
    let siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    let leaf_index = 0;
    let root = merkle::compute_root(in_commitment, siblings, leaf_index);
    let nullifier = bn254::hash_2([nk, leaf_index]);

    let out_npk = 4242;
    let out_value = in_value + 1; // minting value from nothing
    let out_commitment = bn254::hash_3([out_npk, asset_id, out_value]);

    main(
        root,
        nullifier,
        out_commitment,
        0,
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

#[test]
fn emit_prover_toml() {
    // Fixed transfer witness -> prints the 3 computed public inputs for Prover.toml.
    let spending_key = 11;
    let viewing_key = 22;
    let in_random = 33;
    let asset_id = 1;
    let in_value = 1000;
    let nk = bn254::hash_1([viewing_key]);
    let mpk = bn254::hash_2([bn254::hash_1([spending_key]), nk]);
    let in_npk = bn254::hash_2([mpk, in_random]);
    let in_commitment = bn254::hash_3([in_npk, asset_id, in_value]);
    let siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    let root = merkle::compute_root(in_commitment, siblings, 0);
    let nullifier = bn254::hash_2([nk, 0]);
    let out_commitment = bn254::hash_3([4242, asset_id, in_value]);
    println(f"root = {root}");
    println(f"nullifier = {nullifier}");
    println(f"out_commitment = {out_commitment}");
}
