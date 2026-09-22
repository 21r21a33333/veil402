# Veil transaction v4

Veil v4 uses one fixed two-input, two-output JoinSplit. Callers provide one or two spends and one
or two sends; the SDK creates fresh zero-value notes for missing slots and shuffles both sides before
proving. The fixed shape hides arity while keeping one circuit, artifact bundle and verifier.

## Public statement

The verifier receives, in order:

1. Merkle root
2. Two input nullifiers
3. Two output commitments
4. Signed public amount encoded in BN254
5. External-data hash

All note values are unsigned 64-bit integers. Both inputs use the same private asset identifier.
The circuit enforces ownership, normal nullifier derivation, conditional membership for non-zero
inputs, distinct non-zero nullifiers, output construction, value conservation and external-data
binding. A transaction must contain at least one non-zero input.

## Hash domains

Poseidon calls that serve different protocol roles begin with distinct fixed field tags. The v4
roles are spending-key hash, nullifier-key hash, owner, note key, note commitment, nullifier and
asset identifier. Merkle internal nodes retain Light Protocol's audited two-input Poseidon hash.

## Client boundary

Public `Transaction` values contain one or two `Spend` values and one or two `Send` values. A
`Send` keeps the note opening and its encrypted payload together, so shuffling cannot separate a
commitment from its ciphertext. Padding, random generation, slot order, public-input order and the
Noir witness are SDK implementation details.

`Veil::transfer` and `Veil::withdraw` return `Prepared`, containing the locally verified proof and
the exact Solana instruction that consumes it.

The instruction is submitted in a Solana v1 transaction. Resource limits belong in the v1 message
config, not Compute Budget instructions. The current path requests 700,000 compute units and must
set a non-zero loaded-account-data limit; production clients should simulate, add explicit
headroom, and then write the measured limits into the final message. RPC readers must opt in with
`maxSupportedTransactionVersion: 1`; local tests require Agave 4.2 or newer.

## On-chain transition

The pool checks one known root, two canonical and distinct nullifiers, two canonical commitments,
the pinned verifier, exact proof size, signed public amount and a v4 binding over both ordered
encrypted outputs. It creates both nullifier records and appends both commitments atomically.

v3 state is intentionally incompatible: the pool and tree addresses, hash domains, circuit,
artifacts and public witness are versioned together.
