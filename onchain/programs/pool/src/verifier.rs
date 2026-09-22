use anchor_lang::prelude::*;
use anchor_lang::solana_program::{instruction::Instruction, program::invoke};

use crate::PoolError;

const FIELD_BYTES: usize = 32;
const GNARK_HEADER_BYTES: usize = 12;
const PUBLIC_INPUT_COUNT: usize = 7;
const PUBLIC_INPUT_COUNT_BE: [u8; 4] = 7u32.to_be_bytes();
const WITNESS_BYTES: usize = GNARK_HEADER_BYTES + PUBLIC_INPUT_COUNT * FIELD_BYTES;

pub(crate) struct PublicInputs {
    root: [u8; 32],
    nullifiers: [[u8; 32]; 2],
    commitments: [[u8; 32]; 2],
    amount: [u8; 32],
    external_data_hash: [u8; 32],
}

impl PublicInputs {
    pub(crate) fn new(
        root: [u8; 32],
        nullifiers: [[u8; 32]; 2],
        commitments: [[u8; 32]; 2],
        amount: [u8; 32],
        external_data_hash: [u8; 32],
    ) -> Self {
        Self {
            root,
            nullifiers,
            commitments,
            amount,
            external_data_hash,
        }
    }

    pub(crate) fn verify(&self, verifier: &AccountInfo, proof: &[u8]) -> Result<()> {
        let witness = self.encode();
        let mut data = Vec::with_capacity(proof.len() + witness.len());
        data.extend_from_slice(proof);
        data.extend_from_slice(&witness);
        invoke(
            &Instruction {
                program_id: *verifier.key,
                accounts: vec![],
                data,
            },
            std::slice::from_ref(verifier),
        )
        .map_err(|_| error!(PoolError::InvalidProof))
    }

    /// gnark encodes vector counts as big-endian u32 values before the field elements.
    fn encode(&self) -> [u8; WITNESS_BYTES] {
        let fields = [
            &self.root,
            &self.nullifiers[0],
            &self.nullifiers[1],
            &self.commitments[0],
            &self.commitments[1],
            &self.amount,
            &self.external_data_hash,
        ];
        let mut witness = [0u8; WITNESS_BYTES];
        witness[0..4].copy_from_slice(&PUBLIC_INPUT_COUNT_BE);
        witness[8..12].copy_from_slice(&PUBLIC_INPUT_COUNT_BE);
        for (destination, field) in witness[GNARK_HEADER_BYTES..]
            .chunks_exact_mut(FIELD_BYTES)
            .zip(fields)
        {
            destination.copy_from_slice(field);
        }
        witness
    }
}
