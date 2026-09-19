# Veil402 pool contract

This records the implemented W3 pool shape. The W4 client and binding extension
is specified in [withdrawal-integration.md](2026-09-19-withdrawal-integration.md).

## Boundary

- One pool per program deployment and one configured SPL mint.
- A PDA-owned associated token account holds shielded tokens.
- A Light Protocol concurrent Poseidon tree stores commitments at depth 20 and
  retains 64 recent roots.
- One pool-scoped PDA per nullifier is the atomic double-spend guard.
- A configured executable Sunspot verifier validates five public inputs:
  `root`, `nullifier`, `out_commitment`, `public_amount`, and
  `ext_data_hash`.

## Instructions

1. `init_pool(domain)` stores authority, verifier, mint, derived asset field,
   deployment domain, and initializes the tree and vault.
2. `shield(npk, amount, encrypted_note)` transfers tokens into the vault,
   derives `Poseidon(npk, asset, amount)`, and appends it.
3. `transact(...)` accepts only non-positive public flow, checks a recent root,
   recomputes the canonical external-data binding, verifies the proof, pays the
   recipient, records the nullifier, and appends the output atomically.

## Limits

- Proof: exactly 388 bytes for the pinned `transaction-v2` artifact.
- Encrypted note: at most 128 bytes so the legacy Solana transaction remains
  below the 1232-byte packet limit.
- Compute: the verifier measures about 456K CU; clients should request about
  650K CU for the full transaction.

Relayer fees, inbound deposits through `transact`, multi-input/multi-output
joins, rollover, and nullifier-rent reclamation are intentionally deferred.
