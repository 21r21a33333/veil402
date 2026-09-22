use std::{collections::BTreeMap, io};

use acvm::{AcirField, FieldElement};
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use nargo::foreign_calls::DefaultForeignCallBuilder;
use noirc_abi::{InputMap, input_parser::InputValue};
use zeroize::Zeroize;

use super::Artifacts;
use crate::{
    client::Error,
    protocol::{Field, Plan, Public, PublicInputs, Values},
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
    pub(crate) fn build(
        artifacts: &Artifacts,
        transaction: &Plan,
        public: &Public,
    ) -> Result<Self, Error> {
        let values = transaction.values(public)?;
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

fn input_map(transaction: &Plan, values: &Values) -> InputMap {
    let public = &values.public;
    let mut input = BTreeMap::new();
    input.insert("root".into(), value(public.root));
    input.insert("nullifiers".into(), fields(&public.nullifiers));
    input.insert("out_commitments".into(), fields(&public.commitments));
    input.insert("public_amount".into(), value(public.amount));
    input.insert("ext_data_hash".into(), value(public.hash));
    input.insert("bound_hash".into(), value(public.hash));
    input.insert(
        "in_values".into(),
        fields(
            &transaction
                .spends
                .each_ref()
                .map(|spend| Field::from(spend.note.value)),
        ),
    );
    input.insert("asset_id".into(), value(transaction.asset));
    input.insert(
        "in_random".into(),
        fields(
            &transaction
                .spends
                .each_ref()
                .map(|spend| spend.note.random.expose()),
        ),
    );
    input.insert(
        "spending_keys".into(),
        fields(
            &transaction
                .spends
                .each_ref()
                .map(|spend| spend.owner.spend.expose()),
        ),
    );
    input.insert(
        "viewing_keys".into(),
        fields(
            &transaction
                .spends
                .each_ref()
                .map(|spend| spend.owner.view.expose()),
        ),
    );
    input.insert(
        "leaf_indices".into(),
        fields(
            &transaction
                .spends
                .each_ref()
                .map(|spend| Field::from(u64::from(spend.merkle.index))),
        ),
    );
    input.insert(
        "siblings".into(),
        InputValue::Vec(
            transaction
                .spends
                .iter()
                .map(|spend| fields(&spend.merkle.siblings))
                .collect(),
        ),
    );
    input.insert("out_npks".into(), fields(&values.output_keys));
    input.insert(
        "out_values".into(),
        fields(
            &transaction
                .sends
                .each_ref()
                .map(|send| Field::from(send.value)),
        ),
    );
    input
}

fn fields<const N: usize>(values: &[Field; N]) -> InputValue {
    InputValue::Vec(values.iter().copied().map(value).collect())
}

fn value(field: Field) -> InputValue {
    InputValue::Field(FieldElement::from_be_bytes_reduce(field.as_bytes()))
}
