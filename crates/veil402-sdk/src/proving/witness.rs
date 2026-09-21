use std::{collections::BTreeMap, io};

use acvm::{AcirField, FieldElement};
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use nargo::foreign_calls::DefaultForeignCallBuilder;
use noirc_abi::{InputMap, input_parser::InputValue};
use zeroize::Zeroize;

use super::Artifacts;
use crate::{
    client::Error,
    protocol::{Field, PublicInputs, Transaction, TransactionValues},
};

pub(crate) struct Witness {
    pub(crate) bytes: Vec<u8>,
    pub(crate) public: PublicInputs,
}

impl Drop for Witness {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl Witness {
    pub(crate) fn build(artifacts: &Artifacts, transaction: &Transaction) -> Result<Self, Error> {
        let values = transaction.values()?;
        let input = input_map(transaction, &values);
        let initial = artifacts
            .program
            .abi
            .encode(&input, None)
            .map_err(|_| Error::Witness)?;
        let mut foreign = DefaultForeignCallBuilder::default()
            .with_output(io::sink())
            .with_mocks(false)
            .build();
        let stack = nargo::ops::execute_program(
            &artifacts.program.bytecode,
            initial,
            &Bn254BlackBoxSolver,
            &mut foreign,
        )
        .map_err(|_| Error::Witness)?;
        let bytes = stack.serialize().map_err(|_| Error::Witness)?;
        Ok(Self {
            bytes,
            public: values.public,
        })
    }
}

fn input_map(transaction: &Transaction, values: &TransactionValues) -> InputMap {
    let public = &values.public;
    let mut input = BTreeMap::new();
    input.insert("root".into(), value(public.root));
    input.insert("nullifier".into(), value(public.nullifier));
    input.insert("out_commitment".into(), value(public.commitment));
    input.insert("public_amount".into(), value(public.amount));
    input.insert("ext_data_hash".into(), value(public.hash));
    input.insert("bound_hash".into(), value(public.hash));
    input.insert(
        "in_value".into(),
        value(Field::from(transaction.input.note.value)),
    );
    input.insert("asset_id".into(), value(transaction.input.note.asset));
    input.insert(
        "in_random".into(),
        value(transaction.input.note.random.expose()),
    );
    input.insert(
        "spending_key".into(),
        value(transaction.input.owner.spend.expose()),
    );
    input.insert(
        "viewing_key".into(),
        value(transaction.input.owner.view.expose()),
    );
    input.insert(
        "leaf_index".into(),
        value(Field::from(u64::from(transaction.input.merkle.index))),
    );
    input.insert(
        "siblings".into(),
        InputValue::Vec(
            transaction
                .input
                .merkle
                .siblings
                .iter()
                .copied()
                .map(value)
                .collect(),
        ),
    );
    input.insert("out_npk".into(), value(values.output_key));
    input.insert(
        "out_value".into(),
        value(Field::from(transaction.send.value)),
    );
    input
}

fn value(field: Field) -> InputValue {
    InputValue::Field(FieldElement::from_be_bytes_reduce(field.as_bytes()))
}
