use poseidon::poseidon::bn254;

// Recompute the Merkle root from a leaf, its sibling path, and the leaf index.
// Bit i of `leaf_index` is the side at level i: 0 = our node is the left child, 1 = the right child.
// Driving the path from `leaf_index` (also used in the nullifier) binds the two together, so a
// spender can't compute a nullifier for a different index than the note's real position.
pub fn compute_root<let DEPTH: u32>(
    leaf: Field,
    siblings: [Field; DEPTH],
    leaf_index: Field,
) -> Field {
    let bits: [bool; DEPTH] = leaf_index.to_le_bits();
    let mut node = leaf;
    for i in 0..DEPTH {
        let (l, r) = if bits[i] {
            (siblings[i], node)
        } else {
            (node, siblings[i])
        };
        node = bn254::hash_2([l, r]);
    }
    node
}
