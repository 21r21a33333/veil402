use std::{path::Path, process::Stdio, time::Duration};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::{
    io::AsyncWriteExt,
    process::{Child, ChildStdin, Command},
};
use tokio_util::codec::{FramedRead, LinesCodec};
use zeroize::Zeroize;

use super::Witness;
use crate::client::Error;

const MAX_RESPONSE_BYTES: usize = 64 << 10;
const MAX_REQUEST_BYTES: usize = 2 << 20;

pub(crate) struct Worker {
    child: Child,
    input: ChildStdin,
    output: FramedRead<tokio::process::ChildStdout, LinesCodec>,
    next: u64,
}

#[derive(Serialize)]
struct Request<'a> {
    id: String,
    witness: &'a str,
}

#[derive(Deserialize)]
struct Response {
    id: String,
    #[serde(default)]
    proof: String,
    #[serde(default)]
    public: String,
    #[serde(default)]
    error: String,
}

impl Worker {
    pub(crate) fn start(executable: &Path, artifacts: &Path) -> Result<Self, Error> {
        let mut child = Command::new(executable)
            .arg("-artifacts")
            .arg(artifacts)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| Error::Prover("worker could not start"))?;
        let input = child
            .stdin
            .take()
            .ok_or(Error::Prover("worker input is unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or(Error::Prover("worker output is unavailable"))?;
        let output = FramedRead::new(stdout, LinesCodec::new_with_max_length(MAX_RESPONSE_BYTES));
        Ok(Self {
            child,
            input,
            output,
            next: 0,
        })
    }

    pub(crate) async fn prove(
        &mut self,
        witness: &Witness,
        timeout: Duration,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        self.next = self.next.wrapping_add(1);
        let id = self.next.to_string();
        let mut encoded = STANDARD.encode(&witness.bytes);
        let mut request = serde_json::to_vec(&Request {
            id: id.clone(),
            witness: &encoded,
        })
        .map_err(|_| Error::Prover("request could not be encoded"))?;
        encoded.zeroize();
        request.push(b'\n');
        if request.len() > MAX_REQUEST_BYTES {
            request.zeroize();
            return Err(Error::Prover("witness exceeded its size limit"));
        }

        let result = tokio::time::timeout(timeout, async {
            self.input
                .write_all(&request)
                .await
                .map_err(|_| Error::Prover("worker input failed"))?;
            self.input
                .flush()
                .await
                .map_err(|_| Error::Prover("worker input failed"))?;
            let line = self
                .output
                .next()
                .await
                .ok_or(Error::Prover("worker stopped"))?
                .map_err(|_| Error::Prover("worker response exceeded its limit"))?;
            let response: Response = serde_json::from_str(&line)
                .map_err(|_| Error::Prover("worker response is malformed"))?;
            if response.id != id {
                return Err(Error::Prover("worker response ID does not match"));
            }
            if !response.error.is_empty() {
                return Err(Error::Prover("worker rejected the proof request"));
            }
            let proof = STANDARD
                .decode(response.proof)
                .map_err(|_| Error::Prover("proof is malformed"))?;
            let public = STANDARD
                .decode(response.public)
                .map_err(|_| Error::Prover("public witness is malformed"))?;
            Ok((proof, public))
        })
        .await;
        request.zeroize();

        if let Ok(result) = result {
            result
        } else {
            let _ = self.child.start_kill();
            Err(Error::Timeout)
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}
