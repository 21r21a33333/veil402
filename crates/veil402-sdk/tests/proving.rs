use std::{error::Error as StdError, fs, path::Path, process::Command};

use tempfile::tempdir;
use veil402_sdk::{
    Config, Error, Field, MerklePath, Note, Output, Owner, Public, PublicInputs, Secret, Spend,
    TREE_DEPTH, Transaction, Veil,
};

fn field(value: u64) -> Field {
    Field::from(value)
}

fn secret(value: u64) -> Result<Secret, Error> {
    Secret::from_bytes(field(value).to_bytes())
}

fn vector(value: &str) -> Result<Field, Box<dyn StdError>> {
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(value, &mut bytes)?;
    Ok(Field::from_bytes(bytes)?)
}

fn transaction() -> Result<Transaction, Error> {
    Ok(Transaction {
        input: Spend {
            note: Note {
                value: 1_000,
                asset: field(1),
                random: secret(33)?,
            },
            owner: Owner {
                spend: secret(11)?,
                view: secret(22)?,
            },
            merkle: MerklePath {
                index: 0,
                siblings: [Field::ZERO; TREE_DEPTH],
            },
        },
        send: Output {
            owner: field(44),
            value: 700,
            random: secret(55)?,
        },
        public: Public {
            amount: -300,
            hash: field(999),
        },
    })
}

fn root() -> Result<&'static Path, Box<dyn StdError>> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "workspace root is unavailable".into())
}

fn artifacts() -> Result<std::path::PathBuf, Box<dyn StdError>> {
    Ok(root()?.join("prover/veil402-gnark/artifacts/transaction-v3"))
}

#[test]
fn protocol_vector() -> Result<(), Box<dyn StdError>> {
    let inputs = transaction()?.inputs()?;
    let expected = PublicInputs {
        root: vector("265d84ab109b9a6a4c1dedc0219829a4c04621d7ceb3d6cd55ecb99f75b687ad")?,
        nullifier: vector("07def97ce8dc06f71a6a02a00c19586cda8f910b5b75b613b954030e7ce6f471")?,
        commitment: vector("2c00c5ff8637ee41592c4456ae12778790cf3b8357daa7aee945cd2f7036d369")?,
        amount: vector("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffed5")?,
        hash: field(999),
    };
    assert_eq!(inputs, expected);
    assert_eq!(inputs.fields(), expected.fields());
    Ok(())
}

#[test]
fn rejects_corrupt_artifacts() -> Result<(), Box<dyn StdError>> {
    let directory = tempdir()?;
    let source = artifacts()?;
    fs::copy(
        source.join("manifest.json"),
        directory.path().join("manifest.json"),
    )?;
    let mut program = fs::read(source.join("transaction.json"))?;
    let first = program
        .first_mut()
        .ok_or("compiled circuit artifact is empty")?;
    *first ^= 1;
    fs::write(directory.path().join("transaction.json"), program)?;

    let Err(error) = Veil::open(Config::new("unused", directory.path())) else {
        return Err("corrupt artifact was accepted".into());
    };
    assert!(matches!(error, Error::Artifacts(_)));
    Ok(())
}

#[test]
fn rejects_leaf_index_outside_the_tree() -> Result<(), Box<dyn StdError>> {
    let mut transaction = transaction()?;
    transaction.input.merkle.index = 1_u32 << TREE_DEPTH;

    assert!(matches!(
        transaction.inputs(),
        Err(Error::Transaction("leaf index exceeds tree capacity"))
    ));
    Ok(())
}

#[test]
fn merkle_index_vectors_match() -> Result<(), Box<dyn StdError>> {
    let cases = [
        (
            0,
            "265d84ab109b9a6a4c1dedc0219829a4c04621d7ceb3d6cd55ecb99f75b687ad",
        ),
        (
            1,
            "2d668e1d9f7f441c362635c4321ffc32e416886997abcd04fe98a0febce44df9",
        ),
        (
            1 << 19,
            "168a9189699777c51dad5935c36dec7c5ac33fd206747c1733397dc6eb269ffc",
        ),
        (
            (1 << 20) - 1,
            "23f08697121c787e847a4a91b9d1522f4484d6647427120c14d19157a6c18278",
        ),
    ];
    for (index, expected) in cases {
        let mut transaction = transaction()?;
        transaction.input.merkle.index = index;
        assert_eq!(transaction.inputs()?.root, vector(expected)?);
    }
    Ok(())
}

#[tokio::test]
async fn proves_and_verifies_locally() -> Result<(), Box<dyn StdError>> {
    let root = root()?;
    let worker = root.join("target/veil402-gnark-test");
    let status = Command::new("go")
        .args(["build", "-o"])
        .arg(&worker)
        .arg(".")
        .current_dir(root.join("prover/veil402-gnark"))
        .status()?;
    if !status.success() {
        return Err("Go worker build failed".into());
    }

    let veil = Veil::open(Config::new(worker, artifacts()?))?;
    for _ in 0..2 {
        let transaction = transaction()?;
        let expected = transaction.inputs()?;
        let proof = veil.prove(transaction).await?;
        assert_eq!(proof.bytes.len(), 388);
        assert_eq!(proof.public, expected);
        assert_eq!(proof.artifact, "transaction-v3");
    }
    Ok(())
}
