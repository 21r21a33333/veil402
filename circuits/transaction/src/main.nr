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
    // Private copy forces the public hash into the constraint system.
    bound_hash: Field,
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

    // Bind the public leg so it cannot be swapped after proving.
    assert(ext_data_hash == bound_hash, "wrong external data hash");
}

struct PrivateInputs {
    in_value: Field,
    asset_id: Field,
    in_random: Field,
    spending_key: Field,
    viewing_key: Field,
    leaf_index: Field,
    siblings: [Field; TREE_DEPTH],
    out_npk: Field,
    out_value: Field,
}

struct PublicInputs {
    root: Field,
    nullifier: Field,
    out_commitment: Field,
    public_amount: Field,
    ext_data_hash: Field,
}

fn standard(
    in_value: Field,
    out_value: Field,
    leaf_index: Field,
    siblings: [Field; TREE_DEPTH],
) -> PrivateInputs {
    PrivateInputs {
        in_value,
        asset_id: 1,
        in_random: 33,
        spending_key: 11,
        viewing_key: 22,
        leaf_index,
        siblings,
        out_npk: 4242,
        out_value,
    }
}

fn derive_public(input: &PrivateInputs, public_amount: Field) -> PublicInputs {
    let nullifying_key = bn254::hash_1([input.viewing_key]);
    let mpk = bn254::hash_2([bn254::hash_1([input.spending_key]), nullifying_key]);
    let in_npk = bn254::hash_2([mpk, input.in_random]);
    let in_commitment = bn254::hash_3([in_npk, input.asset_id, input.in_value]);
    PublicInputs {
        root: merkle::compute_root(in_commitment, input.siblings, input.leaf_index),
        nullifier: bn254::hash_2([nullifying_key, input.leaf_index]),
        out_commitment: bn254::hash_3([input.out_npk, input.asset_id, input.out_value]),
        public_amount,
        ext_data_hash: 999,
    }
}

fn run(input: &PrivateInputs, public: &PublicInputs, bound_hash: Field) {
    main(
        public.root,
        public.nullifier,
        public.out_commitment,
        public.public_amount,
        public.ext_data_hash,
        bound_hash,
        input.in_value,
        input.asset_id,
        input.in_random,
        input.spending_key,
        input.viewing_key,
        input.leaf_index,
        input.siblings,
        input.out_npk,
        input.out_value,
    );
}

fn run_valid(
    in_value: Field,
    public_amount: Field,
    out_value: Field,
    leaf_index: Field,
    siblings: [Field; TREE_DEPTH],
) {
    let input = standard(in_value, out_value, leaf_index, siblings);
    let public = derive_public(&input, public_amount);
    run(&input, &public, 999);
}

// A non-zero offset corrupts exactly one public input.
fn run_case(
    public_amount: Field,
    out_value: Field,
    root_off: Field,
    nullifier_off: Field,
    out_commitment_off: Field,
    ext_data_hash_off: Field,
) {
    let siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    let input = standard(1000, out_value, 0, siblings);
    let mut public = derive_public(&input, public_amount);
    public.root += root_off;
    public.nullifier += nullifier_off;
    public.out_commitment += out_commitment_off;
    public.ext_data_hash += ext_data_hash_off;
    run(&input, &public, 999);
}

// Accepted: a private transfer (public_amount 0) and a withdrawal (negative net flow).
#[test]
fn transfer_1in1out() {
    run_case(0, 1000, 0, 0, 0, 0);
}

#[test]
fn withdraw_conserves() {
    run_case(0 - 300, 700, 0, 0, 0, 0);
}

// Rejected: each case corrupts exactly one input; the test name says which.
#[test(should_fail_with = "value not conserved")]
fn rejects_value_inflation() {
    run_case(0, 1001, 0, 0, 0, 0);
}

#[test(should_fail_with = "value not conserved")]
fn rejects_value_deflation() {
    run_case(0, 999, 0, 0, 0, 0);
}

#[test(should_fail_with = "wrong nullifier")]
fn rejects_wrong_nullifier() {
    run_case(0, 1000, 0, 1, 0, 0);
}

#[test(should_fail_with = "input note not in tree")]
fn rejects_non_membership() {
    run_case(0, 1000, 1, 0, 0, 0);
}

#[test(should_fail_with = "wrong output commitment")]
fn rejects_wrong_output_commitment() {
    run_case(0, 1000, 0, 0, 1, 0);
}

#[test(should_fail_with = "wrong external data hash")]
fn rejects_wrong_external_data_hash() {
    run_case(0, 1000, 0, 0, 0, 1);
}

#[test]
fn accepts_max_u64_value() {
    let siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    run_valid(18446744073709551615, 0, 18446744073709551615, 0, siblings);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_value_at_2_pow_64() {
    let siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    run_valid(18446744073709551616, 0, 18446744073709551616, 0, siblings);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_value_near_the_field_modulus() {
    let siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    run_valid(0 - 1, 0, 0 - 1, 0, siblings);
}

#[test]
fn accepts_synthetic_large_input() {
    let siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    // Reachable pool leaves remain u64 by induction; the circuit alone accepts a synthetic root.
    run_valid(0 - 1, 1, 0, 0, siblings);
}

#[test(should_fail)]
fn rejects_leaf_index_at_2_pow_20() {
    let siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    run_valid(1000, 0, 1000, 1048576, siblings);
}

#[test]
fn accepts_leaf_index_boundaries() {
    let siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    let indices: [Field; 4] = [0, 1, 524288, 1048575];
    let roots: [Field; 4] = [
        0x265d84ab109b9a6a4c1dedc0219829a4c04621d7ceb3d6cd55ecb99f75b687ad,
        0x2d668e1d9f7f441c362635c4321ffc32e416886997abcd04fe98a0febce44df9,
        0x168a9189699777c51dad5935c36dec7c5ac33fd206747c1733397dc6eb269ffc,
        0x23f08697121c787e847a4a91b9d1522f4484d6647427120c14d19157a6c18278,
    ];
    for i in 0..4 {
        let input = standard(1000, 1000, indices[i], siblings);
        let public = derive_public(&input, 0);
        assert(public.root == roots[i]);
        run(&input, &public, 999);
    }
}

#[test(should_fail_with = "input note not in tree")]
fn rejects_wrong_spending_key() {
    let siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    let mut input = standard(1000, 1000, 0, siblings);
    let public = derive_public(&input, 0);
    input.spending_key = 12;
    run(&input, &public, 999);
}

#[test(should_fail_with = "input note not in tree")]
fn rejects_wrong_viewing_key() {
    let siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    let mut input = standard(1000, 1000, 0, siblings);
    let public = derive_public(&input, 0);
    input.viewing_key = 23;
    run(&input, &public, 999);
}

#[test(should_fail_with = "input note not in tree")]
fn rejects_asset_outside_the_tree() {
    let siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    let mut input = standard(1000, 1000, 0, siblings);
    let public = derive_public(&input, 0);
    input.asset_id = 2;
    run(&input, &public, 999);
}

#[test]
fn accepts_distinct_sibling_paths() {
    let empty: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    let mut populated: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    populated[0] = 7;
    let empty_input = standard(1000, 1000, 0, empty);
    let populated_input = standard(1000, 1000, 0, populated);
    let empty_public = derive_public(&empty_input, 0);
    let populated_public = derive_public(&populated_input, 0);
    assert(empty_public.root != populated_public.root);
    run(&empty_input, &empty_public, 999);
    run(&populated_input, &populated_public, 999);
}

#[test]
fn accepts_zero_value_output() {
    let siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    run_valid(300, 0 - 300, 0, 0, siblings);
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
