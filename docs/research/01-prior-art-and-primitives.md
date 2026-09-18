# Veil402 — prior-art survey + primitives/math/circuits for the MVP

**Thesis:** a shielded UTXO pool on Solana giving **amount privacy + recipient anonymity by
default**, plus a **per-transaction, per-verifier selective disclosure** so any single payment can be
made *provably auditable on demand* — without a blanket viewing key and without deanonymizing
anything else. "Private by default, provable on demand."

This document fixes the vocabulary, the math, and the exact circuit/primitive set we need, grounded
in what production protocols already do. No design decisions are locked here — those are in §6.

---

## 1. Protocols surveyed & what we take from each

| Protocol | Model | What we borrow | What we leave |
|---|---|---|---|
| **Zcash Sapling/Orchard** | shielded UTXO, Groth16/Halo2 | key hierarchy (spend/nullifier/**ivk**/**ovk**/diversified addrs); **ovk + ZIP-311 payment disclosure** = the exact basis for our per-tx auditability | Halo2/Pallas curves; full diversified-address machinery (trim for MVP) |
| **RAILGUN** | shielded UTXO on EVM, **Groth16** | production key layout: `nullifyingKey=Poseidon(viewingKey)`, `nullifier=Poseidon(nullifyingKey, leafIndex)`; encrypted-UTXO Merkle tree; viewing keys; Proofs-of-Innocence (compliance) | EVM specifics; variable in/out circuits |
| **Tornado Nova** | arbitrary-amount shielded pool, Groth16 (circom) | the **2-in/2-out join-split** shape; `commitment=Poseidon(amount,pubkey,blinding)`; value invariant `sumIn+publicAmount=sumOut`; 248-bit range checks; `nullifier=Poseidon(commitment,path,sig)` | xDAI/L2 bridge |
| **Privacy Pools (0xbow)** | compliant mixer | Association-Set / Proof-of-Innocence pattern for opt-in compliance | fixed-denomination base |
| **Penumbra** | shielded, Halo2 | **FMD** (fuzzy message detection) for scalable note discovery — a *later* upgrade | its own chain |
| **Light Protocol** | ZK-compression on **Solana, mainnet, Groth16 via alt_bn128** every slot | proof that on-chain Groth16 + Poseidon shielded state is viable on Solana today; `groth16-solana` verifier lib | compression-account specifics |
| **Solana Confidential Transfers (Token-2022)** | Twisted-ElGamal amount hiding | the "auditor key" idea (but it's all-or-nothing; our per-tx disclosure is the improvement) | ElGamal amounts; no recipient hiding |

**Where Veil402 is novel:** no surveyed system offers **per-payment, per-verifier, nonce-bound**
disclosure. Zcash's ovk/ZIP-311 discloses a payment to *anyone the sender hands the package to*;
Solana's confidential-transfer auditor sees *everything*; RAILGUN viewing keys reveal a *time
range*. Veil402 scopes a proof to **one output × one verifier**, revealing nothing else.

---

## 2. Core objects & math

Field: BN254 scalar field (so Groth16 + Solana `alt_bn128`/`sol_poseidon` syscalls apply; Poseidon
is circom-compatible = syscall-aligned, as proven in Phase 1).

### 2.1 Note (shielded UTXO)
```
note      = { value, asset_id, owner_pk, blinding }
commitment = Poseidon(value, asset_id, owner_pk, blinding)      // the Merkle leaf
```
- `value` (u64, range-checked < 2^64 to prevent field-overflow on sums)
- `asset_id` (which SPL mint — lets one pool hold USDC/PYUSD/… ; "bring your own stablecoin")
- `owner_pk` = the recipient's public spending/viewing pubkey (see keys)
- `blinding` = random, makes the commitment hiding

### 2.2 Key hierarchy (Zcash/RAILGUN-style, trimmed)
```
spendingKey  (root secret, bearer)
 └─ viewingKey        = KDF(spendingKey)          // detect + decrypt notes to me
     ├─ nullifyingKey = Poseidon(viewingKey)      // derive nullifiers (RAILGUN)
     ├─ incomingVK ivk                            // scan/decrypt incoming notes
     └─ outgoingVK ovk                            // recover notes *I sent* → basis for disclosure
 └─ addr = owner_pk = derive(viewingKey)          // what senders pay to
```

### 2.3 Nullifier (double-spend tag)
```
nullifier = Poseidon(nullifyingKey, leafIndex)      // RAILGUN form
```
Only the owner can compute it; revealed on spend; uniqueness enforced on-chain (a PDA per nullifier
on Solana). Unlinkable to the commitment without the key.

### 2.4 Commitment Merkle tree
Append-only Poseidon tree (depth ~20–26) of all note commitments; recent-root window; identical to
Phase 1's on-chain incremental tree (syscall Poseidon). Output notes are appended; nothing is ever
removed (spends are tracked by nullifiers, not by deleting leaves).

### 2.5 Join-split value conservation (the transaction)
A transaction spends `n` input notes and creates `m` output notes:
```
Σ inputs.value + publicAmount == Σ outputs.value + fee        // per asset_id
```
- `publicAmount` > 0 = a **deposit** (public SOL/SPL entering the shield); < 0 = a **withdrawal**
  (leaving to a transparent address); == 0 = a **pure private transfer** (recipient anonymous).
- All inputs/outputs share one `asset_id` (MVP: single-asset per tx).
- Each input: prove Merkle membership + correct nullifier + ownership (know the spending key).
- Each output: new commitment + 64-bit range check.
- Unused input/output slots are **dummy notes** (value 0), so one fixed circuit shape handles
  deposit, withdraw, transfer, merge (n→1), and split (1→m).

### 2.6 Note encryption & discovery
For each output note, encrypt the plaintext so the **recipient** can find & open it:
```
eph_sk random; eph_pk = eph_sk·G
shared = ECDH(eph_sk, recipient_ivk_pk); k = HKDF(shared)
ct_recipient = AEAD_enc(k, note_plaintext)          // ChaCha20-Poly1305
```
Recipients **trial-decrypt** every tx's ciphertext with their ivk; the ones that open are theirs
(Zcash/RAILGUN model). Scaling fix (later): **FMD** (Penumbra) or OMR. Also encrypt an **outgoing**
ciphertext under a key derived from the sender's **ovk**, so the sender can recover/disclose the
note later (Zcash ovk pattern).

### 2.7 Selective disclosure / per-tx auditability  ← the differentiator
Building on Zcash ovk + ZIP-311 payment disclosure, but scoped and bound:
```
disclosure(output_i, verifier_pk, nonce) = {
  revealed:  { value, asset_id, recipient_addr, memo? } for output_i only
  binding:   a proof that Poseidon(value,asset_id,owner_pk,blinding) == commitment_i  (on-chain leaf)
             AND that this package is bound to (verifier_pk, nonce)  (can't be replayed to others)
}
```
The verifier checks the revealed values hash to the real on-chain commitment — so the disclosure is
**sound** (sender can't lie) and **minimal** (only output_i; other outputs, inputs, and the viewing
key stay secret). Per-verifier + nonce binding is the Veil402 novelty over ZIP-311.

Open question (see §6): is the disclosure **off-chain-verifiable** (auditor runs a checker) or also
**on-chain-verifiable** (a small verifier program), and is the binding a **ZK proof** or a plain
hash-opening + signature.

---

## 3. Circuits required (MVP)

1. **Transaction circuit (join-split, fixed 2-in/2-out proposed).** Public: merkle root, 2
   nullifiers, 2 output commitments, publicAmount, asset_id, fee, extDataHash (binds recipient/relayer
   of the *public* leg). Private: for each input (note fields, spending key, merkle path, leafIndex);
   for each output (note fields). Constraints: membership, nullifier correctness, ownership, value
   conservation, 64-bit range checks, no duplicate input nullifiers.
2. **Disclosure circuit / checker** (shape depends on §6-D): proves a revealed `(value, asset_id,
   recipient)` opens a specific on-chain commitment, bound to `(verifier_pk, nonce)`.

Possibly a separate **deposit** helper (public→shield) if we don't fold it into publicAmount>0.

---

## 4. Solana execution constraints (the real bounds)

- **On-chain Groth16 verify:** `alt_bn128` pairing + `sol_poseidon` syscalls. ~170K–500K CU;
  heavy circuits need `SetComputeUnitLimit`. Proven in Phase 1 (Panagram + mixer). Light Protocol
  runs this on mainnet every slot.
- **Public-input cost:** on-chain input prep computes `L = IC₀ + Σ aᵢ·ICᵢ` — one `alt_bn128` scalar
  mul **per public input** (CU) — and every public input is **32 bytes in the tx**. So `n+m` (more
  nullifiers/commitments) costs both CU and precious tx bytes.
- **Transaction size: 1232 bytes total.** The Groth16 proof is constant (~256 B) but public inputs
  and the encrypted-note ciphertexts compete for space. This is *the* reason to keep the tx shape
  small (2-in/2-out) and possibly move ciphertext blobs to a separate account/instruction or log.
- **Proving stack:** Noir + **Sunspot** (Noir ACIR → gnark Groth16 → Solana verifier program),
  validated end-to-end in Phase 1; Poseidon syscall-aligned. Alternative: circom + `groth16-solana`
  (Light). 
- **State:** commitment tree + nullifier set as PDAs/accounts (tree state like Phase 1; nullifiers as
  one PDA each, `init` = double-spend guard).

**Implication:** MVP transaction shape should be **fixed 2-in/2-out** (Tornado-Nova-proven, fits
Solana). Larger n/m = multiple txs or a future upgrade.

---

## 5. What a payment looks like end-to-end (informative)
1. **Shield (deposit):** publicAmount>0, 0 real inputs, 1 output note to yourself. SPL tokens enter
   the pool vault; a commitment is appended.
2. **Private transfer:** publicAmount=0, spend your note(s), create an output note to the
   recipient's address + a change note to yourself; publish encrypted notes; recipient scans & finds
   theirs. **No address on-chain.**
3. **Unshield (withdraw):** publicAmount<0, spend note(s), send SPL to a transparent address (bound
   in extDataHash to prevent front-running, as in Phase 1).
4. **Disclose (audit):** for any single output you sent, produce a per-verifier disclosure package;
   the auditor verifies it against the on-chain commitment. Nothing else is revealed.

---

## 6. Open design decisions (need sign-off before the spec)
- **A. Transaction schema:** fixed **2-in/2-out** (recommended, Solana-fit) vs a couple of fixed
  shapes vs parameterized n/m.
- **B. Proving stack:** **Noir + Sunspot (Groth16)** (recommended; Phase-1-proven) vs circom +
  groth16-solana.
- **C. Asset model:** single **SPL token, asset_id in the note**, one shared pool multi-asset vs
  per-asset pools; SOL via wrap.
- **D. Disclosure mechanism:** ovk/ZIP-311-style, **per-verifier + nonce-bound**; and whether it's
  **off-chain-verifiable** (cheap, MVP) vs **on-chain-verifiable** (a disclosure verifier program);
  ZK-proof binding vs hash-opening+signature.
- **E. Note discovery for MVP:** plain **trial-decryption** (recommended MVP) vs adding FMD now.

## Sources
- Zcash ZIP-311 (payment disclosures), ZIP-310 (viewing-key security), Zcash protocol spec (Sapling/Orchard key hierarchy)
- RAILGUN docs (notes, nullifiers `Poseidon(nullifyingKey,leafIndex)`, viewing keys), L2BEAT/IPTF writeups
- tornadocash/tornado-nova (transaction.circom, 2-in/2-out, value invariant)
- 0xbow Privacy Pools (association sets); Penumbra (FMD); Light Protocol groth16-solana (on-chain Groth16 on Solana)
- Solana alt_bn128 / sol_poseidon syscalls; Sunspot (Noir→gnark→Solana)
