# Contracts end-to-end (Tornado Nova + RAILGUN) + per-tx disclosure validation

Read from real source: `tornadocash/tornado-nova` (`TornadoPool.sol`, `MerkleTreeWithHistory.sol`)
and `Railgun-Privacy/contract` (`RailgunSmartWallet.sol`, `RailgunLogic.sol`, `Commitments.sol`,
`Verifier.sol`). This is the reference the pool contract + circuit are built against.

## 1. The canonical shielded-pool `transact` (both protocols converge)

Nova `_transact` and RAILGUN `transact`→`validateTransaction`+`accumulateAndNullifyTransaction` do the
**same seven steps**. This is the contract we port to Solana:

1. **Known root.** `require(isKnownRoot(root))` (Nova) / `rootHistory[treeNumber][root]` (RAILGUN).
   Recent-root window (Nova `ROOT_HISTORY_SIZE = 100`).
2. **Nullifiers unspent.** For each input: `require(!isSpent(nullifier))` (Nova `nullifierHashes`
   mapping) / `require(!nullifiers[treeNumber][n])` (RAILGUN). Then mark them spent.
3. **Bind the "external"/"bound" params into the proof.** Nova: `require(extDataHash ==
   keccak256(abi.encode(extData)) % FIELD_SIZE)`. RAILGUN: `boundParamsHash = hashBoundParams(...)`
   is a public input the SNARK is bound to. **This is the anti-front-running mechanism** — the proof
   commits to `(recipient, fee, relayer, ciphertexts, chainID, …)`; the contract recomputes the hash
   from the *actual* submitted data, so nothing can be swapped after proving.
4. **Public amount ties private conservation to public token flow (Nova).**
   `require(publicAmount == calculatePublicAmount(extAmount, fee))` where
   `publicAmount = extAmount − fee`, encoded signed-into-field (`neg → FIELD_SIZE − |x|`). The circuit
   enforces `Σ inValues + publicAmount == Σ outValues`.
5. **Verify the Groth16 proof.** Public inputs (Nova): `[root, publicAmount, extDataHash,
   nullifiers…, outCommitments…]`. (RAILGUN): `[merkleRoot, boundParamsHash, nullifiers…,
   commitments…]`. RAILGUN keeps a **separate verifying key per `(nInputs, nCommitments)` shape**.
6. **Move public tokens.** `extAmount > 0` (shield): pull tokens in. `extAmount < 0` (unshield):
   `token.transfer(recipient, −extAmount)`; pay `fee` to relayer. RAILGUN encodes the unshield as a
   commitment whose preimage must hash-match (`hashCommitment(unshieldPreimage) == last commitment`).
7. **Insert output commitments + emit.** Nova `_insert(c0, c1)` (batch-of-2 incremental tree);
   RAILGUN `Commitments.insertLeaves(commitments)`. Emit `NewCommitment{commitment, index,
   encryptedOutput}` (Nova) / `Transact{..., commitments, ciphertext}` (RAILGUN) **carrying the note
   ciphertext for scanning**, plus `NewNullifier`/`Nullified`.

**Mapping to Solana (our pool program):**
| EVM | Solana (ours, from Phase-1 mixer) |
|---|---|
| `nullifierHashes` / `nullifiers[][]` mapping | one **PDA per nullifier**; `init` = double-spend guard |
| `MerkleTreeWithHistory` (roots ring buffer, `_insert`) | on-chain incremental tree in the Pool PDA (**already built + green in Phase 1**) |
| `extDataHash` / `boundParamsHash` public input | same: bind `extData` hash; program recomputes from the actual accounts/args |
| `verifier.verifyProof(...)` | CPI into Sunspot verifier (Phase-1) **or** `groth16-solana` inline verify |
| `token.transfer` | SPL vault (PDA-owned ATA) transfers |
| events (`NewCommitment` w/ ciphertext) | program logs / `emit!` for the indexer to scan |

## 2. Primitive shaping (confirmed against both)

- **Note commitment (leaf).** RAILGUN: `commitment = Poseidon(npk, tokenID, value)` (`PoseidonT4`,
  3 inputs). Nova: `commitment = Poseidon(amount, pubKey, blinding)`. → **Ours:**
  `commitment = Poseidon(npk, assetId, value)` with `npk = Poseidon(mpk, random)`. (RAILGUN's `npk`
  is exactly a blinded owner tag; Nova's `blinding` is our `random`.)
- **npk (owner tag).** RAILGUN `npk = Poseidon(masterPublicKey, random)`; per-note `random` makes
  two notes to the same wallet unlinkable on-chain. → matches ours.
- **Nullifier.** RAILGUN `nullifier = Poseidon(nullifyingKey, leafIndex)`; Nova
  `nullifier = Poseidon(commitment, merklePath, sign(privKey, commitment, merklePath))`. → **Ours:**
  RAILGUN form `Poseidon(nullifyingKey, leafIndex)` (simpler; nullifyingKey = `Poseidon(viewingKey)`).
- **assetId / tokenID.** RAILGUN `tokenID = keccak(tokenData) % field`. → **Ours:** a registered
  index for the SPL mint (small field element; on-chain index→mint+vault registry).
- **publicAmount.** signed net public flow `= extAmount − fee`, field-encoded; circuit enforces value
  conservation. Keep for shield/unshield; `0` for pure private transfer.
- **extData / boundParams.** the tamper-bound envelope: `{recipient, extAmount, relayer, fee,
  encryptedOutputs, …}` hashed into a public input. Our program recomputes and checks it.

## 3. Public-input interface (ours, matching the canon)
For an `n`-in / `m`-out transaction:
`[ root, publicAmount, extDataHash, nullifier_1..n, outCommitment_1..m ]`
(Nova ordering; we keep `publicAmount` explicit for value conservation.) One verifier per `(n, m)`
shape, exactly like RAILGUN's per-shape keys.

## 4. Per-tx disclosure — validation: **VALID and CONCRETE** ✅

The ask: for a *single* output note, prove to *one* chosen verifier what it was — `(value, asset,
recipient)` — bound to that verifier, revealing nothing about any other note. Validated against the
now-confirmed note structure:

**Why it's sound and minimal (the note commitment IS a binding commitment):**
`commitment = Poseidon(npk, assetId, value)`, `npk = Poseidon(mpk, random)`. Poseidon is
collision-resistant, so a commitment binds exactly one `(mpk, random, assetId, value)`. Therefore
revealing that opening *is* a sound proof of the note's contents — you cannot open a commitment to a
different value/recipient. And it is **minimal**: each note is its own leaf with its own independent
opening; disclosing output_i's opening tells the verifier nothing about output_j (the change note),
the inputs, or amounts (all separate hidden leaves / private witnesses). Value conservation is public
only as `publicAmount`, which does not reveal individual output values.

**Who can disclose:** the **sender** (kept the opening, or recovers it from an `ovk`-encrypted
outgoing blob — Zcash/RAILGUN pattern) *and* the **recipient** (got the opening by `ivk`-decrypting
the note). So both "prove I paid X" and "prove I received Y" work.

**Two concrete constructions (MVP → enhancement):**
- **(A) Opening + binding signature — MVP, no circuit.** Discloser reveals `(mpk, random, assetId,
  value)` + a signature over `H(commitment ‖ mpk ‖ random ‖ assetId ‖ value ‖ verifier_pk ‖ nonce)`.
  Verifier: recompute `commitment` from the opening, confirm it is a real on-chain leaf (query the
  tree/`Transact` events), verify the signature. The `(verifier_pk, nonce)` binding makes the package
  non-replayable/non-transferable. **This is essentially Zcash ZIP-311 payment disclosure**, scoped.
- **(B) ZK disclosure — the differentiator upgrade.** Prove in ZK: "I know `random` such that
  `Poseidon(Poseidon(mpk, random), assetId, value) == commitment`, bound to `(verifier_pk, nonce)`"
  with `commitment, value, assetId, mpk` public and `random` private. Same soundness, and it unlocks
  **predicate disclosures** the plain opening can't: prove `value ≥ threshold` *without revealing the
  exact amount*, or prove `recipient ∈ {my org wallets}` — genuinely "provable on demand" beyond a
  flat reveal. This is the capability no surveyed system (RAILGUN viewing keys = all-or-time-range;
  Solana confidential-transfer auditor = sees everything; ZIP-311 = flat reveal to any holder) offers.

**Verdict:** the per-tx disclosure is concrete and grounded in the exact commitment we're building.
MVP ships (A); (B) is a clean follow-on that reuses the same Poseidon opening inside a small circuit.

## 5. The 1-in / 1-out warm-up we will build (concrete spec)
Smallest real step above the Phase-1 mixer:
- **Note:** `{ value, assetId, mpk, random }`; `npk = Poseidon(mpk, random)`;
  `commitment = Poseidon(npk, assetId, value)`; `nullifier = Poseidon(nullifyingKey, leafIndex)`.
- **Public inputs:** `[ root, publicAmount, extDataHash, nullifier, outCommitment ]`.
- **Circuit (Noir) proves:** input note membership under `root`; correct `nullifier` (owner knows
  `nullifyingKey` s.t. `mpk = Poseidon(spendingPubKey, nullifyingKey)`); output commitment
  well-formed with `value ≤ 2^64`; **conservation** `inValue + publicAmount == outValue`; bind
  `extDataHash` (squared, un-malleable).
- **Contract (Anchor) does:** known-root check → nullifier PDA (unspent→init) → recompute+check
  `extDataHash` and `publicAmount` → CPI verify → move SPL (`publicAmount>0` pull / `<0` pay
  recipient) → insert `outCommitment` into the tree → emit commitment (+ciphertext) & nullifier.
- **Reuses from Phase-1 mixer (already green):** incremental tree, nullifier PDA, verify-by-CPI, SPL
  vault. **New vs mixer:** value-carrying note, `publicAmount` conservation, output-commitment
  insertion, `extData` binding. Grows to 2-in/2-out by adding a second nullifier + output + the sum.

## Sources
- tornado-nova: `TornadoPool.sol` (`_transact`, `calculatePublicAmount`, `verifyProof`),
  `MerkleTreeWithHistory.sol` (`_insert` batch-2, `ROOT_HISTORY_SIZE=100`)
- Railgun-Privacy/contract: `RailgunSmartWallet.sol` (`shield`/`transact`), `RailgunLogic.sol`
  (`hashCommitment=Poseidon(npk,tokenID,value)`, `validateTransaction`, `accumulateAndNullify`),
  `Verifier.sol` (`inputs=[root, boundParamsHash, nullifiers…, commitments…]`), `Commitments.sol`
- Zcash ZIP-311 (payment disclosure) — basis for construction (A)
