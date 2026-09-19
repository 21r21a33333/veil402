use std::{path::Path, process::Stdio};

#[cfg(windows)]
use process_wrap::tokio::JobObject;
#[cfg(unix)]
use process_wrap::tokio::ProcessGroup;
use process_wrap::tokio::{KillOnDrop, TokioChildWrapper, TokioCommandWrap};
use prost::Message;

use super::protocol::Channel;
use crate::client::Error;

pub(super) struct Process {
    child: Option<Box<dyn TokioChildWrapper>>,
    channel: Channel,
}

impl Process {
    pub(super) fn start(executable: &Path, artifacts: &Path) -> Result<Self, Error> {
        let executable = executable
            .canonicalize()
            .map_err(|_| Error::Prover("worker executable is unavailable"))?;
        if !executable.is_file() {
            return Err(Error::Prover("worker executable is unavailable"));
        }
        let artifacts = artifacts
            .canonicalize()
            .map_err(|_| Error::Artifacts("artifact directory is unavailable"))?;
        let mut command = TokioCommandWrap::with_new(&executable, |command| {
            command
                .arg("-artifacts")
                .arg(&artifacts)
                .current_dir(&artifacts)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
        });
        command.wrap(KillOnDrop);
        #[cfg(unix)]
        command.wrap(ProcessGroup::leader());
        #[cfg(windows)]
        command.wrap(JobObject);

        let mut child = command
            .spawn()
            .map_err(|_| Error::Prover("worker could not start"))?;
        let input = child
            .stdin()
            .take()
            .ok_or(Error::Prover("worker input is unavailable"))?;
        let output = child
            .stdout()
            .take()
            .ok_or(Error::Prover("worker output is unavailable"))?;

        Ok(Self {
            child: Some(child),
            channel: Channel::new(input, output),
        })
    }

    pub(super) async fn send<M: Message>(&mut self, message: &M) -> Result<(), Error> {
        self.channel.send(message).await
    }

    pub(super) async fn receive<M: Message + Default>(&mut self) -> Result<M, Error> {
        self.channel.receive().await
    }

    pub(super) async fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.start_kill();
        let _ = Box::into_pin(child.wait()).await;
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.start_kill();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = Box::into_pin(child.wait()).await;
            });
        }
    }
}
