//! Output/exit channels shared by the [`VpnProcess`](gp_core::process::VpnProcess)
//! implementations.

use gp_core::process::{ExitStatusInfo, OutputChunk};
use tokio::sync::{mpsc, oneshot};

/// Chunks buffered before the reader applies back-pressure to the child's pipe.
pub(crate) const OUTPUT_CAPACITY: usize = 256;

/// Receiving ends handed out once each through `output()` / `exited()`.
#[derive(Debug)]
pub(crate) struct Channels {
    output: Option<mpsc::Receiver<OutputChunk>>,
    exit: Option<oneshot::Receiver<ExitStatusInfo>>,
}

/// Sending ends owned by the task that reads the process.
#[derive(Debug)]
pub(crate) struct Senders {
    pub(crate) output: mpsc::Sender<OutputChunk>,
    pub(crate) exit: oneshot::Sender<ExitStatusInfo>,
}

impl Channels {
    pub(crate) fn new() -> (Senders, Channels) {
        let (out_tx, out_rx) = mpsc::channel(OUTPUT_CAPACITY);
        let (exit_tx, exit_rx) = oneshot::channel();
        (
            Senders {
                output: out_tx,
                exit: exit_tx,
            },
            Channels {
                output: Some(out_rx),
                exit: Some(exit_rx),
            },
        )
    }

    /// The output receiver; a second call gets an already-closed channel.
    pub(crate) fn take_output(&mut self) -> mpsc::Receiver<OutputChunk> {
        self.output.take().unwrap_or_else(|| mpsc::channel(1).1)
    }

    /// The exit receiver; a second call gets one whose sender is already gone.
    pub(crate) fn take_exit(&mut self) -> oneshot::Receiver<ExitStatusInfo> {
        self.exit.take().unwrap_or_else(|| oneshot::channel().1)
    }
}
