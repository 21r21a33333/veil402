use std::{fs, path::Path};

use noirc_artifacts::program::ProgramArtifact;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::client::Error;

pub(crate) const NOIR_VERSION: &str = "1.0.0-beta.22+c57152f91260ecdb9faad4efc20abb14b6d2ece7";
const PINNED_MANIFEST: &str =
    include_str!("../../../../prover/veil402-gnark/artifacts/transaction-v3/manifest.json");

#[derive(Debug, Deserialize)]
pub(crate) struct Manifest {
    pub(crate) id: String,
    pub(crate) noir: String,
    pub(crate) circuit: String,
    pub(crate) files: Files,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Files {
    pub(crate) acir: String,
    pub(crate) ccs: String,
    pub(crate) pk: String,
    pub(crate) vk: String,
}

pub(crate) struct Artifacts {
    pub(crate) manifest: Manifest,
    pub(crate) program: ProgramArtifact,
}

impl Artifacts {
    pub(crate) fn open(directory: &Path) -> Result<Self, Error> {
        let manifest_bytes = fs::read(directory.join("manifest.json"))
            .map_err(|_| Error::Artifacts("manifest is unavailable"))?;
        if manifest_bytes != PINNED_MANIFEST.as_bytes() {
            return Err(Error::Artifacts("manifest does not match this SDK"));
        }
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|_| Error::Artifacts("manifest is malformed"))?;
        if manifest.noir != NOIR_VERSION {
            return Err(Error::Artifacts("Noir version does not match"));
        }

        let program_bytes = checked_file(directory, "transaction.json", &manifest.files.acir)?;
        let program: ProgramArtifact = serde_json::from_slice(&program_bytes)
            .map_err(|_| Error::Artifacts("ACIR is malformed"))?;
        if program.noir_version != manifest.noir {
            return Err(Error::Artifacts("ACIR Noir version does not match"));
        }
        if program.hash.to_string() != manifest.circuit {
            return Err(Error::Artifacts("circuit hash does not match"));
        }
        checked_file(directory, "transaction.ccs", &manifest.files.ccs)?;
        checked_file(directory, "transaction.pk", &manifest.files.pk)?;
        checked_file(directory, "transaction.vk", &manifest.files.vk)?;

        Ok(Self { manifest, program })
    }
}

fn checked_file(directory: &Path, name: &str, expected: &str) -> Result<Vec<u8>, Error> {
    let bytes =
        fs::read(directory.join(name)).map_err(|_| Error::Artifacts("artifact is unavailable"))?;
    let actual = hex::encode(Sha256::digest(&bytes));
    if actual != expected {
        return Err(Error::Artifacts("artifact checksum does not match"));
    }
    Ok(bytes)
}
