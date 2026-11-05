//! Unix process plumbing (Linux direct/pkexec spawner, macOS osascript wrapper). Safe wrappers
//! from `rustix`; no `unsafe` here.

pub(crate) mod darwin;
pub(crate) mod local;

use std::io;

use rustix::process::{Pid, Signal};

use crate::quote::StopSignal;

/// Effective uid is 0.
pub(crate) fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// Real uid of this process (owner of the FIFOs created by the macOS wrapper).
pub(crate) fn real_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

fn pid_of(pid: u32) -> io::Result<Pid> {
    i32::try_from(pid)
        .ok()
        .filter(|p| *p > 1)
        .and_then(Pid::from_raw)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid pid {pid}")))
}

fn rustix_signal(sig: StopSignal) -> Signal {
    match sig {
        StopSignal::Int => Signal::INT,
        StopSignal::Term => Signal::TERM,
        StopSignal::Kill => Signal::KILL,
    }
}

/// Result of `kill(2)` that callers react to differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KillOutcome {
    Sent,
    /// ESRCH: the process is already gone.
    NoSuchProcess,
    /// EPERM: the process exists but belongs to another user (root).
    NotPermitted,
}

pub(crate) fn send_signal(pid: u32, sig: StopSignal) -> io::Result<KillOutcome> {
    classify(rustix::process::kill_process(pid_of(pid)?, rustix_signal(sig)))
}

/// `kill(pid, 0)`: whether the process exists (owned by us or not).
pub(crate) fn probe_alive(pid: u32) -> io::Result<KillOutcome> {
    classify(rustix::process::test_kill_process(pid_of(pid)?))
}

fn classify(r: rustix::io::Result<()>) -> io::Result<KillOutcome> {
    match r {
        Ok(()) => Ok(KillOutcome::Sent),
        Err(rustix::io::Errno::SRCH) => Ok(KillOutcome::NoSuchProcess),
        Err(rustix::io::Errno::PERM) => Ok(KillOutcome::NotPermitted),
        Err(e) => Err(e.into()),
    }
}

/// Node-style signal name (`SIGINT`) for an exit-by-signal status.
pub(crate) fn signal_name(raw: i32) -> String {
    const NAMES: [(Signal, &str); 9] = [
        (Signal::HUP, "SIGHUP"),
        (Signal::INT, "SIGINT"),
        (Signal::QUIT, "SIGQUIT"),
        (Signal::ABORT, "SIGABRT"),
        (Signal::KILL, "SIGKILL"),
        (Signal::SEGV, "SIGSEGV"),
        (Signal::PIPE, "SIGPIPE"),
        (Signal::TERM, "SIGTERM"),
        (Signal::USR1, "SIGUSR1"),
    ];
    NAMES
        .iter()
        .find(|(s, _)| s.as_raw() == raw)
        .map_or_else(|| format!("SIG{raw}"), |(_, n)| (*n).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_common_signals_like_node() {
        assert_eq!(signal_name(Signal::INT.as_raw()), "SIGINT");
        assert_eq!(signal_name(Signal::KILL.as_raw()), "SIGKILL");
        assert_eq!(signal_name(200), "SIG200");
    }

    #[test]
    fn refuses_to_signal_init_or_groups() {
        assert!(send_signal(0, StopSignal::Int).is_err());
        assert!(send_signal(1, StopSignal::Kill).is_err());
        assert!(send_signal(u32::MAX, StopSignal::Kill).is_err());
    }

    #[test]
    fn classifies_kill_results() {
        // Our own pid exists and is ours.
        assert_eq!(probe_alive(std::process::id()).unwrap(), KillOutcome::Sent);
    }
}
