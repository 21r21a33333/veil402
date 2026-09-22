mod merkle;
use poseidon::poseidon::bn254;

global TREE_DEPTH: u32 = 20;
global INPUTS: u32 = 2;
global OUTPUTS: u32 = 2;

// Hash-role tags are protocol constants. They make values from one role unusable in another.
global SPEND_KEY_DOMAIN: Field = 1;
global NULLIFIER_KEY_DOMAIN: Field = 2;
global OWNER_DOMAIN: Field = 3;
global NOTE_KEY_DOMAIN: Field = 4;
global NOTE_DOMAIN: Field = 5;
global NULLIFIER_DOMAIN: Field = 6;

fn nullifier_key(viewing_key: Field) -> Field {
    bn254::hash_2([NULLIFIER_KEY_DOMAIN, viewing_key])
}

fn owner(spending_key: Field, viewing_key: Field) -> Field {
    let spending_key_hash = bn254::hash_2([SPEND_KEY_DOMAIN, spending_key]);
    bn254::hash_3(
        [OWNER_DOMAIN, spending_key_hash, nullifier_key(viewing_key)],
    )
}

fn note_key(note_owner: Field, random: Field) -> Field {
    bn254::hash_3([NOTE_KEY_DOMAIN, note_owner, random])
}

fn note_commitment(npk: Field, asset_id: Field, value: Field) -> Field {
    bn254::hash_4([NOTE_DOMAIN, npk, asset_id, value])
}

fn nullifier(viewing_key: Field, leaf_index: Field) -> Field {
    bn254::hash_3([NULLIFIER_DOMAIN, nullifier_key(viewing_key), leaf_index])
}

// Fixed 2-in / 2-out JoinSplit. Zero-valued notes pad unused slots without revealing arity.
fn main(
    root: pub Field,
    nullifiers: pub [Field; INPUTS],
    out_commitments: pub [Field; OUTPUTS],
    public_amount: pub Field,
    ext_data_hash: pub Field,
    // A private copy ensures the public hash participates in the constraint system.
    bound_hash: Field,
    in_values: [Field; INPUTS],
    asset_id: Field,
    in_random: [Field; INPUTS],
    spending_keys: [Field; INPUTS],
    viewing_keys: [Field; INPUTS],
    leaf_indices: [Field; INPUTS],
    siblings: [[Field; TREE_DEPTH]; INPUTS],
    out_npks: [Field; OUTPUTS],
    out_values: [Field; OUTPUTS],
) {
    let mut sum_in = 0;
    for i in 0..INPUTS {
        // Range-check inputs as defense in depth instead of relying only on output induction.
        in_values[i].assert_max_bit_size::<64>();

        let npk = note_key(owner(spending_keys[i], viewing_keys[i]), in_random[i]);
        let commitment = note_commitment(npk, asset_id, in_values[i]);
        let computed_root = merkle::compute_root(commitment, siblings[i], leaf_indices[i]);

        // A zero-valued dummy still has normal keys, commitment and nullifier; only membership is
        // bypassed. Any non-zero value forces the computed path to the public root.
        assert(in_values[i] * (computed_root - root) == 0, "input note not in tree");
        assert(nullifiers[i] == nullifier(viewing_keys[i], leaf_indices[i]), "wrong nullifier");
        assert(nullifiers[i] != 0, "zero nullifier");
        sum_in += in_values[i];
    }
    assert(sum_in != 0, "transaction has no real input");
    assert(nullifiers[0] != nullifiers[1], "duplicate nullifier");

    let mut sum_out = 0;
    for i in 0..OUTPUTS {
        out_values[i].assert_max_bit_size::<64>();
        assert(
            out_commitments[i] == note_commitment(out_npks[i], asset_id, out_values[i]),
            "wrong output commitment",
        );
        sum_out += out_values[i];
    }

    assert(sum_in + public_amount == sum_out, "value not conserved");
    assert(ext_data_hash == bound_hash, "wrong external data hash");
}

struct PrivateInputs {
    in_values: [Field; INPUTS],
    asset_id: Field,
    in_random: [Field; INPUTS],
    spending_keys: [Field; INPUTS],
    viewing_keys: [Field; INPUTS],
    leaf_indices: [Field; INPUTS],
    siblings: [[Field; TREE_DEPTH]; INPUTS],
    out_npks: [Field; OUTPUTS],
    out_values: [Field; OUTPUTS],
}

struct PublicInputs {
    root: Field,
    nullifiers: [Field; INPUTS],
    out_commitments: [Field; OUTPUTS],
    public_amount: Field,
    ext_data_hash: Field,
}

fn standard(in_values: [Field; INPUTS], out_values: [Field; OUTPUTS]) -> PrivateInputs {
    let empty_path: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    PrivateInputs {
        in_values,
        asset_id: 7,
        in_random: [33, 66],
        spending_keys: [11, 44],
        viewing_keys: [22, 55],
        leaf_indices: [0, 1],
        siblings: [empty_path, empty_path],
        out_npks: [77, 88],
        out_values,
    }
}

fn input_commitment(input: &PrivateInputs, index: u32) -> Field {
    note_commitment(
        note_key(
            owner(input.spending_keys[index], input.viewing_keys[index]),
            input.in_random[index],
        ),
        input.asset_id,
        input.in_values[index],
    )
}

fn derive_public(input: &PrivateInputs, root: Field, public_amount: Field) -> PublicInputs {
    PublicInputs {
        root,
        nullifiers: [
            nullifier(input.viewing_keys[0], input.leaf_indices[0]),
            nullifier(input.viewing_keys[1], input.leaf_indices[1]),
        ],
        out_commitments: [
            note_commitment(input.out_npks[0], input.asset_id, input.out_values[0]),
            note_commitment(input.out_npks[1], input.asset_id, input.out_values[1]),
        ],
        public_amount,
        ext_data_hash: 999,
    }
}

fn run(input: &PrivateInputs, public: &PublicInputs, bound_hash: Field) {
    main(
        public.root,
        public.nullifiers,
        public.out_commitments,
        public.public_amount,
        public.ext_data_hash,
        bound_hash,
        input.in_values,
        input.asset_id,
        input.in_random,
        input.spending_keys,
        input.viewing_keys,
        input.leaf_indices,
        input.siblings,
        input.out_npks,
        input.out_values,
    );
}

fn one_real_input(public_amount: Field, out_values: [Field; OUTPUTS]) {
    let input = standard([1000, 0], out_values);
    let root = merkle::compute_root(
        input_commitment(&input, 0),
        input.siblings[0],
        input.leaf_indices[0],
    );
    let public = derive_public(&input, root, public_amount);
    run(&input, &public, 999);
}

#[test]
fn accepts_one_input_payment_with_dummy_and_change() {
    // One real 1,000-value note pays 700 privately and returns 300 as change.
    one_real_input(0, [700, 300]);
}

#[test]
fn accepts_two_input_merge() {
    // Both real leaves share one synthetic tree root and merge into a single output.
    let mut input = standard([600, 400], [1000, 0]);
    let first = input_commitment(&input, 0);
    let second = input_commitment(&input, 1);
    input.siblings[0][0] = second;
    input.siblings[1][0] = first;
    let root = merkle::compute_root(first, input.siblings[0], 0);
    assert(root == merkle::compute_root(second, input.siblings[1], 1));
    let public = derive_public(&input, root, 0);
    run(&input, &public, 999);
}

#[test]
fn accepts_full_withdrawal_with_zero_outputs() {
    // Both zero-valued outputs remain committed while all private value leaves the pool.
    one_real_input(0 - 1000, [0, 0]);
}

#[test(should_fail_with = "input note not in tree")]
fn rejects_non_member_real_input() {
    // Membership cannot be bypassed by a non-zero input.
    let input = standard([1000, 0], [1000, 0]);
    let public = derive_public(&input, 123, 0);
    run(&input, &public, 999);
}

#[test(should_fail_with = "duplicate nullifier")]
fn rejects_duplicate_nullifiers() {
    // Reusing the same viewing key and index would otherwise spend one nullifier twice in-slot.
    let mut input = standard([1000, 0], [1000, 0]);
    input.viewing_keys[1] = input.viewing_keys[0];
    input.leaf_indices[1] = input.leaf_indices[0];
    let root = merkle::compute_root(input_commitment(&input, 0), input.siblings[0], 0);
    let public = derive_public(&input, root, 0);
    run(&input, &public, 999);
}

#[test(should_fail_with = "value not conserved")]
fn rejects_value_creation() {
    // Outputs cannot exceed private inputs plus the signed public flow.
    one_real_input(0, [1001, 0]);
}

#[test(should_fail_with = "call to assert_max_bit_size")]
fn rejects_input_outside_u64() {
    // Inputs are range-checked directly, not only assumed valid by tree induction.
    let input = standard([18446744073709551616, 0], [0, 0]);
    let root = merkle::compute_root(input_commitment(&input, 0), input.siblings[0], 0);
    let public = derive_public(&input, root, 0 - 18446744073709551616);
    run(&input, &public, 999);
}

#[test(should_fail_with = "wrong external data hash")]
fn rejects_changed_external_data() {
    // The proof cannot be replayed with different recipient or ciphertext data.
    let input = standard([1000, 0], [1000, 0]);
    let root = merkle::compute_root(input_commitment(&input, 0), input.siblings[0], 0);
    let public = derive_public(&input, root, 0);
    run(&input, &public, 1000);
}

#[test(should_fail)]
fn rejects_leaf_index_at_tree_capacity() {
    // Fixed-width decomposition restricts every real or dummy index to 20 bits.
    let mut input = standard([1000, 0], [1000, 0]);
    input.leaf_indices[0] = 1048576;
    let public = derive_public(&input, 0, 0);
    run(&input, &public, 999);
}
