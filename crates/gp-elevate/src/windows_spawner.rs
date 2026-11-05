//! Windows: openconnect needs administrator rights for the Wintun adapter. The app starts
//! `gp-connect-helper.exe` with UAC (`ShellExecuteExW` verb `runas`) and talks to it over a named
//! pipe (protocol in [`crate::helper_protocol`]). No PowerShell is involved.
#![allow(unsafe_code)] // Win32 FFI: ShellExecuteExW and process handles.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use gp_core::logging::Logger;
use gp_core::openconnect::trust::{TrustOptions, verify_trusted_file};
use gp_core::platform::Platform;
use gp_core::process::{SpawnError, SpawnRequest, VpnProcess};
use gp_core::types::VpnErrorCode;
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::sync::mpsc;
use windows_sys::Win32::Foundation::{ERROR_CANCELLED, GetLastError, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

use crate::helper_client::{START_TIMEOUT, attach};
use crate::helper_protocol::{
    HELLO_TIMEOUT, HelperConfig, MAX_CONNECTIONS, PIPE_PREFIX, exit_code, helper_parameters, pipe_path,
    random_hex, sha256_hex, wait_for_client,
};
use crate::win_security::native::{SecurityAttributes, create_dir_with_sddl, current_user_sid};
use crate::win_security::user_and_admins_sddl;
use crate::windows_acl::native::NativeProbe;

/// After the UAC prompt was accepted: time for the helper to connect back.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
const LOG_SOURCE: &str = "elevate";

fn unknown(msg: impl Into<String>) -> SpawnError {
    SpawnError::new(VpnErrorCode::Unknown, msg)
}

pub(crate) struct UacSpawner {
    pub(crate) helper: Option<PathBuf>,
    pub(crate) logger: Arc<Logger>,
}

/// Launch config in a fresh directory under the user's %TEMP%, created with an explicit
/// protected DACL (the user, SYSTEM, Administrators) so its confidentiality does not depend on
/// where %TEMP% points. Removed on drop.
struct ConfigFile {
    dir: PathBuf,
    path: PathBuf,
}

impl ConfigFile {
    fn create(bytes: &[u8], dir_sddl: &str) -> io::Result<ConfigFile> {
        let dir = std::env::temp_dir().join(format!("gp-connect-{}", random_hex(8)?));
        create_dir_with_sddl(&dir, dir_sddl)?;
        let cf = ConfigFile {
            path: dir.join("helper.json"),
            dir,
        };
        let mut f = OpenOptions::new().write(true).create_new(true).open(&cf.path)?;
        f.write_all(bytes)?;
        Ok(cf)
    }
}

impl Drop for ConfigFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Starts the helper elevated; blocks while the UAC prompt is shown.
/// `dir` becomes the helper's working directory (its own admin-only install folder, never the
/// app's current directory).
fn shell_execute_runas(file: &str, params: &str, dir: &str) -> Result<OwnedHandle, SpawnError> {
    let verb = wide("runas");
    let file_w = wide(file);
    let params_w = wide(params);
    let dir_w = wide(dir);
    // SAFETY: plain C struct, all-zero is a valid initial value.
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = u32::try_from(size_of::<SHELLEXECUTEINFOW>()).unwrap_or(u32::MAX);
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file_w.as_ptr();
    info.lpParameters = params_w.as_ptr();
    info.lpDirectory = dir_w.as_ptr();
    info.nShow = SW_HIDE;
    // SAFETY: `info` and the strings it points to outlive the call.
    if unsafe { ShellExecuteExW(&raw mut info) } == 0 {
        // SAFETY: trivially safe.
        let err = unsafe { GetLastError() };
        return Err(if err == ERROR_CANCELLED {
            SpawnError::new(
                VpnErrorCode::PrivilegesDenied,
                "Administrator rights were not granted (UAC prompt cancelled)",
            )
        } else {
            unknown(format!("Could not start the elevated helper (error {err})"))
        });
    }
    if info.hProcess.is_null() {
        return Err(unknown("Could not start the elevated helper (no process handle)"));
    }
    // SAFETY: SEE_MASK_NOCLOSEPROCESS hands us ownership of the process handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(info.hProcess) })
}

/// Resolves with the helper's exit code once it exits; stops polling when `stop` is set.
async fn helper_exit(process: OwnedHandle, stop: Arc<AtomicBool>) -> Option<u32> {
    tokio::task::spawn_blocking(move || {
        while !stop.load(Ordering::SeqCst) {
            // SAFETY: valid process handle owned by `process`.
            let r = unsafe { WaitForSingleObject(process.as_raw_handle(), 200) };
            if r == WAIT_OBJECT_0 {
                let mut code = 0u32;
                // SAFETY: valid handle and out-pointer.
                let ok = unsafe { GetExitCodeProcess(process.as_raw_handle(), &raw mut code) };
                return (ok != 0).then_some(code);
            }
            if r != WAIT_TIMEOUT {
                return None;
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

/// A pipe instance with an explicit protected DACL (`sddl`: the user, SYSTEM, Administrators),
/// so other principals cannot even open it read-only and use up the instances.
fn new_instance(path: &str, first: bool, sddl: &str) -> io::Result<NamedPipeServer> {
    let mut sa = SecurityAttributes::from_sddl(sddl)?;
    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first)
        .reject_remote_clients(true)
        .max_instances(MAX_CONNECTIONS)
        .pipe_mode(PipeMode::Byte);
    // SAFETY: `sa` is a valid SECURITY_ATTRIBUTES that outlives the call.
    unsafe { opts.create_with_security_attributes_raw(path, sa.as_mut_ptr().cast()) }
}

/// Accepts connections and hands them to [`wait_for_client`] until it is gone.
async fn accept_loop(
    mut server: NamedPipeServer,
    path: String,
    sddl: String,
    tx: mpsc::Sender<NamedPipeServer>,
) {
    loop {
        if tx.is_closed() {
            return;
        }
        if server.connect().await.is_ok() {
            // Create the next instance before handing this one over, so the name never vanishes.
            let next = loop {
                match new_instance(&path, false, &sddl) {
                    Ok(n) => break n,
                    // All instances in use (handshakes pending): they free up within the hello
                    // deadline.
                    Err(_) if !tx.is_closed() => tokio::time::sleep(Duration::from_millis(100)).await,
                    Err(_) => return,
                }
            };
            let connected = std::mem::replace(&mut server, next);
            if tx.send(connected).await.is_err() {
                return;
            }
        } else {
            // The client went away between connect and accept: recycle the instance.
            let _ = server.disconnect();
        }
    }
}

/// Aborts the acceptor and removes the config directory on every exit path.
struct Session {
    acceptor: tokio::task::JoinHandle<()>,
    _config: ConfigFile,
    stop_watch: Arc<AtomicBool>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.acceptor.abort();
        self.stop_watch.store(true, Ordering::SeqCst);
    }
}

impl UacSpawner {
    pub(crate) async fn spawn(&self, req: &SpawnRequest) -> Result<Box<dyn VpnProcess>, SpawnError> {
        let helper = self
            .helper
            .as_deref()
            .ok_or_else(|| unknown("gp-connect-helper.exe was not found next to the app"))?;
        let helper = trusted_helper(helper).await?;
        let binary = req
            .binary
            .to_str()
            .ok_or_else(|| unknown("openconnect path is not valid UTF-8"))?
            .to_string();
        let script = req
            .args
            .iter()
            .find_map(|a| a.strip_prefix("--csd-wrapper="))
            .map(str::to_string);
        // `req.env` is never forwarded: the helper builds a minimal environment itself.
        let user_sid =
            current_user_sid().map_err(|e| unknown(format!("Cannot read the current user: {e}")))?;
        let pipe_sddl = user_and_admins_sddl(&user_sid, false);
        let dir_sddl = user_and_admins_sddl(&user_sid, true);

        let rand = |n| random_hex(n).map_err(|e| unknown(e.to_string()));
        let pipe_name = format!("{PIPE_PREFIX}{}", rand(16)?);
        let token = rand(32)?;
        let path = pipe_path(&pipe_name);
        let first =
            new_instance(&path, true, &pipe_sddl).map_err(|e| unknown(format!("Named pipe error: {e}")))?;
        let (tx, rx) = mpsc::channel(MAX_CONNECTIONS);
        let acceptor = tokio::spawn(accept_loop(first, path, pipe_sddl, tx));

        let config = HelperConfig {
            pipe: pipe_name,
            token: token.clone(),
            binary,
            args: req.args.clone(),
            script,
            server_pid: std::process::id(),
        };
        let bytes = serde_json::to_vec(&config).map_err(|e| unknown(e.to_string()))?;
        let stop_watch = Arc::new(AtomicBool::new(false));
        let config_file = match ConfigFile::create(&bytes, &dir_sddl) {
            Ok(c) => c,
            Err(e) => {
                acceptor.abort();
                return Err(unknown(format!("Could not write the helper configuration: {e}")));
            }
        };
        let params = helper_parameters(&config_file.path.to_string_lossy(), &sha256_hex(&bytes));
        let session = Session {
            acceptor,
            _config: config_file,
            stop_watch: stop_watch.clone(),
        };

        let helper_for_launch = helper.clone();
        let helper_dir = Path::new(&helper)
            .parent()
            .map(|d| d.to_string_lossy().into_owned())
            .ok_or_else(|| unknown("helper path has no directory"))?;
        let process = tokio::task::spawn_blocking(move || {
            shell_execute_runas(&helper_for_launch, &params, &helper_dir)
        })
        .await
        .map_err(|e| unknown(e.to_string()))??;
        self.logger
            .info(LOG_SOURCE, &format!("Started {helper} with administrator rights"));

        let exit = helper_exit(process, stop_watch);
        tokio::pin!(exit);
        let stream = tokio::select! {
            client = tokio::time::timeout(CONNECT_TIMEOUT, wait_for_client(rx, &token, HELLO_TIMEOUT)) => match client {
                Ok(Some(s)) => s,
                Ok(None) => return Err(unknown("The elevated helper could not connect")),
                Err(_) => return Err(SpawnError::new(
                    VpnErrorCode::PrivilegesDenied,
                    "Timed out waiting for the elevated openconnect helper",
                )),
            },
            Some(code) = &mut exit => {
                let code = code.cast_signed();
                return Err(unknown(format!(
                    "The elevated helper exited before connecting: {} (code {code})",
                    exit_code::describe(code)
                )));
            }
        };
        // Stop accepting and remove the config directory; the authenticated pipe stays open.
        drop(session);
        attach(stream, START_TIMEOUT).await
    }
}

/// The helper runs as administrator, so it must itself be admin-controlled (installed
/// per-machine in Program Files). Returns its real path.
async fn trusted_helper(helper: &Path) -> Result<String, SpawnError> {
    let helper = helper
        .to_str()
        .ok_or_else(|| unknown("helper path is not valid UTF-8"))?;
    let trust = TrustOptions::new(Platform::Win32, Some(Arc::new(NativeProbe)));
    verify_trusted_file(helper, &trust)
        .await
        .map_err(|e| SpawnError::new(VpnErrorCode::PrivilegesDenied, e.message))
}

#[cfg(test)]
mod tests {
    use tokio::net::windows::named_pipe::ClientOptions;

    use super::*;
    use crate::helper_protocol::{Frame, write_frame};

    fn sddl(inherit: bool) -> String {
        user_and_admins_sddl(&current_user_sid().unwrap(), inherit)
    }

    #[test]
    fn config_file_is_new_and_removed_on_drop() {
        let cf = ConfigFile::create(b"{}", &sddl(true)).unwrap();
        assert_eq!(std::fs::read(&cf.path).unwrap(), b"{}");
        let dir = cf.dir.clone();
        drop(cf);
        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn accepts_over_a_real_named_pipe_and_refuses_a_second_first_instance() {
        let name = format!("{PIPE_PREFIX}{}", random_hex(16).unwrap());
        let path = pipe_path(&name);
        let first = new_instance(&path, true, &sddl(false)).unwrap();
        // Squatting protection: the name cannot be created twice as a first instance.
        assert!(new_instance(&path, true, &sddl(false)).is_err());
        let (tx, rx) = mpsc::channel(MAX_CONNECTIONS);
        let acceptor = tokio::spawn(accept_loop(first, path.clone(), sddl(false), tx));
        let token = "c".repeat(64);
        let tok = token.clone();
        let waiter = tokio::spawn(async move { wait_for_client(rx, &tok, HELLO_TIMEOUT).await });

        let mut wrong = ClientOptions::new().open(&path).unwrap();
        write_frame(&mut wrong, &Frame::Hello(b"nope".to_vec()))
            .await
            .unwrap();
        let mut client = loop {
            match ClientOptions::new().open(&path) {
                Ok(c) => break c,
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        };
        write_frame(&mut client, &Frame::Hello(token.into_bytes()))
            .await
            .unwrap();
        write_frame(&mut client, &Frame::Pid(99)).await.unwrap();
        let server = waiter.await.unwrap().unwrap();
        acceptor.abort();
        let p = attach(server, START_TIMEOUT).await.unwrap();
        assert_eq!(p.pid(), Some(99));
    }

    #[tokio::test]
    async fn refuses_a_helper_outside_program_files() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("gp-connect-helper.exe");
        std::fs::write(&fake, b"MZ").unwrap();
        let e = trusted_helper(&fake).await.unwrap_err();
        assert_eq!(e.code, VpnErrorCode::PrivilegesDenied);
    }
}
