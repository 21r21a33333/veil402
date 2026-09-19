use futures_util::StreamExt;
use prost::Message;
use tokio::{
    io::AsyncWriteExt,
    process::{ChildStdin, ChildStdout},
};
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};
use zeroize::Zeroize;

use crate::client::Error;

pub(super) use super::generated::{Failure, Ready, Request, Response};

const MAX_REQUEST_BYTES: usize = 2 << 20;
const MAX_RESPONSE_BYTES: usize = 64 << 10;

pub(super) struct Channel {
    input: ChildStdin,
    output: FramedRead<ChildStdout, LengthDelimitedCodec>,
}

impl Channel {
    pub(super) fn new(input: ChildStdin, output: ChildStdout) -> Self {
        let codec = LengthDelimitedCodec::builder()
            .length_field_length(4)
            .max_frame_length(MAX_RESPONSE_BYTES)
            .new_codec();
        let output = FramedRead::new(output, codec);
        Self { input, output }
    }

    pub(super) async fn send<M: Message>(&mut self, message: &M) -> Result<(), Error> {
        let mut body = Vec::with_capacity(message.encoded_len());
        message
            .encode(&mut body)
            .map_err(|_| Error::Prover("worker request could not be encoded"))?;
        if body.len() > MAX_REQUEST_BYTES {
            body.zeroize();
            return Err(Error::Prover("witness exceeded its size limit"));
        }
        let length = u32::try_from(body.len())
            .map_err(|_| Error::Prover("witness exceeded its size limit"))?
            .to_be_bytes();
        let result = async {
            self.input
                .write_all(&length)
                .await
                .map_err(|_| Error::Prover("worker input failed"))?;
            self.input
                .write_all(&body)
                .await
                .map_err(|_| Error::Prover("worker input failed"))?;
            self.input
                .flush()
                .await
                .map_err(|_| Error::Prover("worker input failed"))
        }
        .await;
        body.zeroize();
        result
    }

    pub(super) async fn receive<M: Message + Default>(&mut self) -> Result<M, Error> {
        let frame = self
            .output
            .next()
            .await
            .ok_or(Error::Prover("worker stopped"))?
            .map_err(|_| Error::Prover("worker response exceeded its limit"))?;
        M::decode(frame).map_err(|_| Error::Prover("worker response is malformed"))
    }
}
