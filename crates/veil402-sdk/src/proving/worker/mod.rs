use std::{path::Path, time::Duration};

use protocol::{Failure, Ready, Request, Response};
use zeroize::Zeroize;

use super::Witness;
use crate::client::Error;

#[allow(clippy::doc_markdown, clippy::trivially_copy_pass_by_ref)]
mod generated;
mod process;
mod protocol;

use process::Process;

const VERSION: u32 = 1;

pub(crate) struct Worker {
    process: Process,
    next_request_id: u64,
}

impl Worker {
    pub(crate) async fn start(
        executable: &Path,
        artifacts: &Path,
        artifact: &str,
        timeout: Duration,
    ) -> Result<Self, Error> {
        let mut process = Process::start(executable, artifacts)?;
        let ready = tokio::time::timeout(timeout, process.receive::<Ready>()).await;
        match ready {
            Ok(Ok(ready)) if ready.protocol == VERSION && ready.artifact == artifact => {}
            Ok(Ok(_)) => {
                process.stop().await;
                return Err(Error::Prover("worker identity does not match"));
            }
            Ok(Err(error)) => {
                process.stop().await;
                return Err(error);
            }
            Err(_) => {
                process.stop().await;
                return Err(Error::Timeout);
            }
        }

        Ok(Self {
            process,
            next_request_id: 0,
        })
    }

    pub(crate) async fn prove(
        &mut self,
        witness: &Witness,
        timeout: Duration,
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        self.next_request_id = self.next_request_id.wrapping_add(1);
        if self.next_request_id == 0 {
            self.process.stop().await;
            return Err(Error::Prover("worker request ID was exhausted"));
        }

        let mut request = Request {
            id: self.next_request_id,
            witness: witness.bytes.clone(),
        };
        let result = tokio::time::timeout(timeout, async {
            self.process.send(&request).await?;
            request.witness.zeroize();
            let response = self.process.receive::<Response>().await?;
            self.validate_response(response)
        })
        .await;
        request.witness.zeroize();

        match result {
            Ok(Ok(proof)) => Ok(proof),
            Ok(Err(error)) => {
                self.process.stop().await;
                Err(error)
            }
            Err(_) => {
                self.process.stop().await;
                Err(Error::Timeout)
            }
        }
    }

    fn validate_response(&self, response: Response) -> Result<(Vec<u8>, Vec<u8>), Error> {
        if response.id != self.next_request_id {
            return Err(Error::Prover("worker response ID does not match"));
        }
        let failure = Failure::try_from(response.failure)
            .map_err(|_| Error::Prover("worker response is malformed"))?;
        if failure != Failure::Unspecified {
            return Err(Error::Prover("worker rejected the proof request"));
        }
        if response.proof.is_empty() || response.public.is_empty() {
            return Err(Error::Prover("worker response is incomplete"));
        }
        Ok((response.proof, response.public))
    }
}
