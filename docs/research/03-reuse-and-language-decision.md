# Reuse strategy + language decision (record)

Decision date: 2026-09-18. Driver: **reuse/copy existing audited infra rather than rebuild**, and
stay on the path proven by production Solana shielded pools — without compromising the idea
(private-by-default agent payments + per-tx, per-verifier provable disclosure + diversified addresses).

## Reassurance (we're on the proven path)
- **Light Protocol's shielded pool = "Zcash in a Solana program"**: UTXO model, **Groth16/BN254,
  Poseidon Merkle tree** — identical architecture to ours.
- Production peers: **Hinkal** (Groth16 + Merkle + stealth addresses + TEE relayers, $400M volume),
  **PrivacyCash** (OFAC-compliant, mainnet 2025).
- **Sunspot** (our circuit compiler, by **Reilabs**) — Reilabs formally verified **Light's** Groth16
  circuits. Same audited orbit.
- Our differentiator vs prior art: **Elusiv** (→ Arcium) had *blanket viewing-key* disclosure; ours
  is **per-tx, per-verifier, nonce-bound** — an improvement, not a reinvention.

## Decision: reuse-first, Rust program + TS wallet
| Layer | Reuse | Language |
|---|---|---|
| On-chain verifier | `Lightprotocol/groth16-solana` (alt_bn128 syscalls) — evaluate **inline verify** vs the Sunspot-generated verifier-program CPI in Phase 2.2 | Rust |
| Shielded-pool program | fork/reference `light-protocol-v1` + `Lightprotocol/private-payments-tutorial` (Merkle tree, nullifier set, UTXO transact) | Rust |
| Circuits | Noir + **Sunspot** (Reilabs); port **Tornado-Nova** `transaction.circom` | Noir |
| Wallet / keys / scanning / note encryption | **RAILGUN engine SDK** + **Light SDK** as the design template; build a thin lib on the shared **`circomlibjs`** primitives (Poseidon + **Baby Jubjub**) | **TypeScript** |
| note-encryption/trial-decrypt shape | Zcash `zcash_note_encryption` `Domain` trait as a reference | (reference) |

## What "reuse" means concretely (important nuance)
RAILGUN's engine and Light's SDK are **not drop-in for a fresh Solana pool** (RAILGUN is EVM-coupled;
Light's SDK is tied to Light's own programs). So reuse here = **reuse the audited primitives and the
proven design patterns**, not a wholesale SDK dependency:
- Reuse the **primitives** everyone shares: `circomlibjs` Poseidon + Baby Jubjub (verified to match the
  Solana syscall and Noir in Phase 1 + the 2.0 pre-flight audit).
- Reuse the **key hierarchy + note layout** template from RAILGUN (`nullifyingKey = Poseidon(viewingKey)`,
  `nullifier = Poseidon(nullifyingKey, leafIndex)`, per-note `random` blinding).
- Reuse the **on-chain building blocks** from Light (`groth16-solana`, Merkle/nullifier account patterns).
- **Build ourselves:** the thin glue (our note/address/encrypt wrappers) and the **novel disclosure layer**.

## Rejected: Rust-core crypto + WASM
Considered (one language, matches Rust strength) but rejected for the wallet layer: the most reusable
shielded-pool wallet SDKs are **TypeScript** (RAILGUN, Light); the Rust option (`librustzcash`) is
audited but **Zcash-curve-bound (Jubjub/Pallas)** — adapting its key-agreement to BN254 is *more*
from-scratch work, cutting against the reuse priority. On-chain stays Rust regardless.

## Rejected: x25519 for note encryption
Considered as a Rust-friendly ECDH shortcut, rejected: it (a) cuts against reuse (no shielded-pool SDK
uses it) and (b) compromises **true per-payer diversified addresses** (a Baby-Jubjub/Jubjub trick).
**Baby Jubjub** stays — it's what the reusable infra uses and it preserves the agent-UX feature.

## Net effect on the plan
The existing `docs/plans/2026-09-18-phase-2.0-crypto-lib.md` already implements this (circomlibjs +
Baby Jubjub, TS, RAILGUN key layout). No rewrite; only this record + a reuse note added to the plan.

## Sources
- Lightprotocol/light-protocol-v1, Lightprotocol/private-payments-tutorial, Lightprotocol/groth16-solana
- Helius "Privacy on Solana with Elusiv and Light"; Light Protocol design writeups (UTXO, height-18 Poseidon Merkle, Groth16/bn254)
- Railgun-Community/engine + /wallet (TS shielded-pool wallet SDK; scanning + POI)
- zcash/librustzcash (zcash_note_encryption Domain trait, zip32, sapling-crypto/orchard)
- Hinkal (Solana institutional privacy), PrivacyCash (OFAC-compliant Solana pool)
