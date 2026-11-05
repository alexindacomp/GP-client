//! Windows entry of the helper: process hardening → config → pipe (server pid check) → hello →
//! admin-side validation → openconnect in a sanitized environment → relay.
#![allow(unsafe_code)] // Win32 FFI: loader policy, system paths, pipe server pid, console Ctrl+C.

use std::ffi::c_void;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::ptr::null_mut;
use std::time::Duration;

use gp_core::openconnect::trust::TrustOptions;
use gp_core::platform::Platform;
use gp_elevate::helper_protocol::{
    FatalCode, Frame, HelperConfig, exit_code, pipe_path, random_hex, write_frame,
};
use gp_elevate::win_security::admins_only_sddl;
use gp_elevate::win_security::native::create_dir_with_sddl;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::process::Command;
use windows_sys::Win32::Foundation::{ERROR_PIPE_BUSY, TRUE};
use windows_sys::Win32::Globalization::{GetOEMCP, MultiByteToWideChar};
use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Console::{
    AttachConsole, CTRL_C_EVENT, FreeConsole, GenerateConsoleCtrlEvent, GetConsoleOutputCP,
    SetConsoleCtrlHandler,
};
use windows_sys::Win32::System::LibraryLoader::{
    LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
    SetDllDirectoryW,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::SystemInformation::{
    GetNativeSystemInfo, GetSystemDirectoryW, GetSystemWindowsDirectoryW, SYSTEM_INFO,
};
use windows_sys::Win32::System::SystemServices::{
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY, PROCESS_MITIGATION_IMAGE_LOAD_POLICY_0,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, ProcessImageLoadPolicy, SetProcessMitigationPolicy,
};
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

use crate::env::{SystemPaths, minimal_env};
use crate::relay::relay;
use crate::transcode::utf8_lossy;
use crate::validate::validate_request;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Image-load mitigation flags: NoRemoteImages | NoLowMandatoryLabelImages | PreferSystem32Images.
const IMAGE_LOAD_FLAGS: u32 = 0b111;

fn win_string(f: impl Fn(*mut u16, u32) -> u32) -> io::Result<String> {
    let mut buf = vec![0u16; 260];
    loop {
        let cap = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let n = f(buf.as_mut_ptr(), cap) as usize;
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        if n < buf.len() {
            return String::from_utf16(&buf[..n]).map_err(io::Error::other);
        }
        buf.resize(n + 1, 0);
    }
}

/// Runs first: DLLs only from System32 / the (admin-only) install folder, never from the current
/// directory or PATH, the working directory is System32, and remote / low-integrity images are
/// refused. Static imports are covered by the `/DEPENDENTLOADFLAG:0x800` link flag (build.rs).
pub(crate) fn harden_process() -> io::Result<()> {
    // SAFETY: plain Win32 calls; the empty string is NUL-terminated.
    unsafe {
        if SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_APPLICATION_DIR) == 0 {
            return Err(io::Error::last_os_error());
        }
        let empty = [0u16];
        if SetDllDirectoryW(empty.as_ptr()) == 0 {
            return Err(io::Error::last_os_error());
        }
        let policy = PROCESS_MITIGATION_IMAGE_LOAD_POLICY {
            Anonymous: PROCESS_MITIGATION_IMAGE_LOAD_POLICY_0 {
                Flags: IMAGE_LOAD_FLAGS,
            },
        };
        // Best effort: defence in depth on top of the loader settings above; an OS that does not
        // know the policy must not make the helper unusable.
        let _ = SetProcessMitigationPolicy(
            ProcessImageLoadPolicy,
            (&raw const policy).cast::<c_void>(),
            size_of::<PROCESS_MITIGATION_IMAGE_LOAD_POLICY>(),
        );
    }
    // SAFETY: valid buffer of the given capacity.
    let system32 = win_string(|b, n| unsafe { GetSystemDirectoryW(b, n) })?;
    std::env::set_current_dir(system32)
}

/// System locations from APIs, never from the inherited environment.
pub(crate) fn system_paths() -> io::Result<SystemPaths> {
    // SAFETY: valid buffers of the given capacity.
    let system_root = win_string(|b, n| unsafe { GetSystemWindowsDirectoryW(b, n) })?;
    // SAFETY: as above.
    let system32 = win_string(|b, n| unsafe { GetSystemDirectoryW(b, n) })?;
    let mut p: *mut u16 = null_mut();
    // SAFETY: known folder id; `p` receives a CoTaskMemAlloc'ed string (freed below).
    let hr = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, null_mut(), &raw mut p) };
    if hr != 0 || p.is_null() {
        return Err(io::Error::other(format!("cannot locate ProgramData ({hr:#x})")));
    }
    let mut len = 0usize;
    // SAFETY: NUL-terminated string from the API.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` u16s are readable.
    let program_data = String::from_utf16(unsafe { std::slice::from_raw_parts(p, len) });
    // SAFETY: allocated by SHGetKnownFolderPath.
    unsafe { CoTaskMemFree(p.cast::<c_void>().cast_const()) };
    // SAFETY: zeroed POD out-struct.
    let mut si: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: valid out-pointer.
    unsafe { GetNativeSystemInfo(&raw mut si) };
    Ok(SystemPaths {
        system_root,
        system32,
        program_data: program_data.map_err(io::Error::other)?,
        // SAFETY: the struct variant of the union is the documented one.
        processor_architecture: unsafe { si.Anonymous.Anonymous.wProcessorArchitecture },
        number_of_processors: si.dwNumberOfProcessors,
    })
}

/// Fresh temp directory for openconnect and its scripts under ProgramData, readable and writable
/// only by SYSTEM and Administrators (protected DACL; fails if the name exists). Removed on drop.
pub(crate) struct PrivateTemp(PathBuf);

impl PrivateTemp {
    pub(crate) fn create(program_data: &str) -> io::Result<PrivateTemp> {
        let dir = Path::new(program_data).join(format!("GP-Connect-{}", random_hex(16)?));
        create_dir_with_sddl(&dir, &admins_only_sddl())?;
        Ok(PrivateTemp(dir))
    }
}

impl Drop for PrivateTemp {
    fn drop(&mut self) {
        // Best effort: a leftover empty admin-only directory is harmless.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// openconnect with the minimal environment, its own folder as working directory, piped stdio
/// and a hidden console.
pub(crate) fn openconnect_command(binary: &str, args: &[String], sys: &SystemPaths, temp: &Path) -> Command {
    let dir = Path::new(binary)
        .parent()
        .map_or_else(|| sys.system32.clone(), |d| d.to_string_lossy().into_owned());
    let mut cmd = Command::new(binary);
    cmd.args(args)
        .env_clear()
        .envs(minimal_env(sys, &dir, &temp.to_string_lossy()))
        .current_dir(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .kill_on_drop(true);
    cmd
}

/// Ctrl+C for openconnect. It runs in its own hidden console (`CREATE_NO_WINDOW`) — a
/// `CTRL_C_EVENT` cannot target a process group, only the whole console — so the helper (a GUI
/// subsystem process without a console) briefly attaches to that console, ignores Ctrl+C itself
/// and raises it for everyone attached, which is openconnect (and scripts it runs).
fn send_ctrl_c(pid: u32) -> io::Result<()> {
    // SAFETY: plain Win32 calls without pointers.
    unsafe {
        FreeConsole();
        if AttachConsole(pid) == 0 {
            return Err(io::Error::last_os_error());
        }
        SetConsoleCtrlHandler(None, TRUE);
        let ok = GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
        let err = io::Error::last_os_error();
        FreeConsole();
        if ok == 0 { Err(err) } else { Ok(()) }
    }
}

/// Output code page of openconnect's hidden console (the code page its FormatMessage texts are
/// written in), read by attaching to that console briefly; the OEM code page — the default of a
/// new console — when it cannot be read.
fn console_output_codepage(pid: Option<u32>) -> u32 {
    let mut cp = 0;
    // SAFETY: plain Win32 calls without pointers.
    unsafe {
        if let Some(pid) = pid {
            FreeConsole();
            // The helper never reacts to that console's Ctrl+C (same as in `send_ctrl_c`).
            SetConsoleCtrlHandler(None, TRUE);
            if AttachConsole(pid) != 0 {
                cp = GetConsoleOutputCP();
                FreeConsole();
            }
        }
        if cp == 0 { GetOEMCP() } else { cp }
    }
}

/// `bytes` in code page `cp` → String (`MultiByteToWideChar`); lossy UTF-8 if that fails.
pub(crate) fn decode_codepage(cp: u32, bytes: &[u8]) -> String {
    let Ok(len) = i32::try_from(bytes.len()) else {
        return utf8_lossy(bytes);
    };
    if len == 0 {
        return String::new();
    }
    // SAFETY: `bytes` is valid for `len` bytes; the output buffer has exactly the size the first
    // call reported.
    unsafe {
        let needed = MultiByteToWideChar(cp, 0, bytes.as_ptr(), len, std::ptr::null_mut(), 0);
        let Ok(size) = usize::try_from(needed) else {
            return utf8_lossy(bytes);
        };
        if size == 0 {
            return utf8_lossy(bytes);
        }
        let mut wide = vec![0u16; size];
        let written = MultiByteToWideChar(cp, 0, bytes.as_ptr(), len, wide.as_mut_ptr(), needed);
        match usize::try_from(written) {
            Ok(n) if n > 0 => {
                wide.truncate(n);
                String::from_utf16_lossy(&wide)
            }
            _ => utf8_lossy(bytes),
        }
    }
}

async fn connect(name: &str) -> io::Result<NamedPipeClient> {
    let path = pipe_path(name);
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    loop {
        // SECURITY_IDENTIFICATION: the app (pipe server) may identify, never impersonate, the
        // elevated helper.
        match ClientOptions::new()
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(&path)
        {
            Ok(c) => return Ok(c),
            Err(e)
                if e.raw_os_error() == Some(ERROR_PIPE_BUSY.cast_signed())
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Process id of the pipe server.
fn server_pid(pipe: &NamedPipeClient) -> io::Result<u32> {
    let mut pid = 0u32;
    // SAFETY: valid pipe handle and out-pointer.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &raw mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

pub(crate) async fn session(cfg: HelperConfig) -> i32 {
    let Ok(pipe) = connect(&cfg.pipe).await else {
        return exit_code::PIPE;
    };
    // The token only goes to the app that wrote the config.
    if server_pid(&pipe).ok() != Some(cfg.server_pid) {
        return exit_code::PIPE;
    }
    let (reader, mut writer) = tokio::io::split(pipe);
    if write_frame(&mut writer, &Frame::Hello(cfg.token.as_bytes().to_vec()))
        .await
        .is_err()
    {
        return exit_code::PIPE;
    }
    let trust = TrustOptions::new(Platform::Win32, Some(gp_elevate::windows_security_probe()));
    let launch = match validate_request(&cfg, &trust).await {
        Ok(l) => l,
        Err(msg) => {
            let _ = write_frame(&mut writer, &Frame::Fatal(FatalCode::Refused, msg)).await;
            return exit_code::REFUSED;
        }
    };
    let prepared = system_paths().and_then(|sys| PrivateTemp::create(&sys.program_data).map(|t| (sys, t)));
    let (sys, temp) = match prepared {
        Ok(p) => p,
        Err(e) => {
            let msg = format!("Cannot prepare the openconnect environment: {e}");
            let _ = write_frame(&mut writer, &Frame::Fatal(FatalCode::SpawnFailed, msg)).await;
            return exit_code::SPAWN;
        }
    };
    let child = match openconnect_command(&launch.binary, &launch.args, &sys, &temp.0).spawn() {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("Failed to start {}: {e}", launch.binary);
            let _ = write_frame(&mut writer, &Frame::Fatal(FatalCode::SpawnFailed, msg)).await;
            return exit_code::SPAWN;
        }
    };
    // Windows error texts in openconnect's output are in its console's code page, not UTF-8.
    let codepage = console_output_codepage(child.id());
    let fallback = move |bytes: &[u8]| decode_codepage(codepage, bytes);
    let code = match relay(reader, writer, child, &send_ctrl_c, &fallback).await {
        Ok(_) => 0,
        Err(_) => exit_code::INTERNAL,
    };
    drop(temp);
    code
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use gp_elevate::helper_protocol::read_frame;
    use tokio::io::duplex;

    use super::*;

    fn hidden(cmd: &str, args: &[&str]) -> tokio::process::Child {
        Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW)
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    }

    #[tokio::test]
    async fn relays_a_hidden_console_process() {
        let child = hidden(
            "cmd.exe",
            &["/d", "/v:on", "/c", "set /p L=&echo got!L!&exit /b 3"],
        );
        let (mut app, helper) = duplex(64 * 1024);
        let (r, w) = tokio::io::split(helper);
        let task = tokio::spawn(async move { relay(r, w, child, &send_ctrl_c, &utf8_lossy).await });
        assert!(matches!(read_frame(&mut app).await.unwrap(), Some(Frame::Pid(_))));
        write_frame(&mut app, &Frame::Stdin(b"secret\r\n".to_vec()))
            .await
            .unwrap();
        let mut out = Vec::new();
        let exit = loop {
            match read_frame(&mut app).await.unwrap() {
                Some(Frame::Stdout(d)) => out.extend(d),
                Some(Frame::Exit(c)) => break c,
                Some(_) => {}
                None => panic!("no exit frame"),
            }
        };
        assert_eq!(exit, 3);
        assert!(String::from_utf8_lossy(&out).contains("gotsecret"), "{out:?}");
        assert_eq!(task.await.unwrap().unwrap(), Some(3));
    }

    /// "Этот хост неизвестен." in cp866 (how openconnect.exe on Russian Windows prints it).
    const HOST_UNKNOWN_866: &[u8] = &[
        0x9D, 0xE2, 0xAE, 0xE2, 0x20, 0xE5, 0xAE, 0xE1, 0xE2, 0x20, 0xAD, 0xA5, 0xA8, 0xA7, 0xA2, 0xA5, 0xE1,
        0xE2, 0xA5, 0xAD, 0x2E,
    ];

    #[test]
    fn decodes_console_code_pages() {
        assert_eq!(decode_codepage(866, HOST_UNKNOWN_866), "Этот хост неизвестен.");
        assert_eq!(decode_codepage(866, b""), "");
        assert_eq!(
            decode_codepage(1251, &[0xCF, 0xF0, 0xE8, 0xE2, 0xE5, 0xF2]),
            "Привет"
        );
        assert_ne!(console_output_codepage(None), 0);
    }

    /// Raw cp866 bytes written by a hidden-console process reach the app as correct UTF-8.
    #[tokio::test]
    async fn relays_code_page_output_as_utf8() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("out.txt");
        let mut bytes = b"getaddrinfo failed for host 'gp-qa-test.invalid': ".to_vec();
        bytes.extend_from_slice(HOST_UNKNOWN_866);
        bytes.extend_from_slice(b"\r\nPassword:");
        std::fs::write(&file, &bytes).unwrap();
        let child = hidden("cmd.exe", &["/d", "/c", "type", &file.to_string_lossy()]);
        let (mut app, helper) = duplex(64 * 1024);
        let (r, w) = tokio::io::split(helper);
        let task = tokio::spawn(async move {
            relay(r, w, child, &send_ctrl_c, &|b: &[u8]| decode_codepage(866, b)).await
        });
        let mut out = Vec::new();
        loop {
            match read_frame(&mut app).await.unwrap() {
                Some(Frame::Stdout(d)) => out.extend(d),
                Some(Frame::Exit(_)) => break,
                Some(_) => {}
                None => panic!("no exit frame"),
            }
        }
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "getaddrinfo failed for host 'gp-qa-test.invalid': Этот хост неизвестен.\r\nPassword:"
        );
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn closing_the_pipe_kills_the_process() {
        let child = hidden("ping.exe", &["-n", "30", "127.0.0.1"]);
        let (app, helper) = duplex(64 * 1024);
        let (r, w) = tokio::io::split(helper);
        let task = tokio::spawn(async move { relay(r, w, child, &send_ctrl_c, &utf8_lossy).await });
        drop(app);
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    /// Runs in a separate test process (see below): it detaches from its own console.
    #[test]
    #[ignore = "run by ctrl_c_stops_a_hidden_console_child in a child process"]
    fn ctrl_c_child() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut child = hidden("ping.exe", &["-n", "30", "127.0.0.1"]);
            tokio::time::sleep(Duration::from_millis(500)).await;
            send_ctrl_c(child.id().unwrap()).unwrap();
            let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
                .await
                .expect("Ctrl+C did not stop the child")
                .unwrap();
            assert!(status.code().is_some());
        });
    }

    #[test]
    fn reads_system_paths_from_apis() {
        let sys = system_paths().unwrap();
        assert!(
            sys.system32.to_lowercase().ends_with(r"\system32"),
            "{}",
            sys.system32
        );
        assert!(
            sys.system32
                .to_lowercase()
                .starts_with(&sys.system_root.to_lowercase())
        );
        assert!(
            sys.program_data.to_lowercase().ends_with("programdata"),
            "{}",
            sys.program_data
        );
        assert!(sys.number_of_processors > 0);
    }

    #[tokio::test]
    async fn openconnect_sees_only_the_minimal_environment() {
        let sys = system_paths().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let cmd_exe = format!(r"{}\cmd.exe", sys.system32);
        let out = openconnect_command(
            &cmd_exe,
            &["/d".into(), "/c".into(), "set & cd".into()],
            &sys,
            temp.path(),
        )
        .output()
        .await
        .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        let allowed = crate::env::minimal_env_names();
        let mut names = Vec::new();
        for line in text.lines() {
            if let Some((k, _)) = line.split_once('=') {
                names.push(k.to_uppercase());
            }
        }
        for n in &names {
            assert!(
                allowed.contains(n) || n == "PROMPT",
                "unexpected variable {n} in\n{text}"
            );
        }
        assert!(
            names.contains(&"PATH".to_string()) && names.contains(&"TEMP".to_string()),
            "{text}"
        );
        // Working directory = the binary's folder.
        assert!(
            text.to_lowercase().contains(&sys.system32.to_lowercase()),
            "{text}"
        );
    }

    #[test]
    fn checks_the_pipe_server_pid() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let name = format!("gp-connect-{}", random_hex(16).unwrap());
            let path = pipe_path(&name);
            let _server = tokio::net::windows::named_pipe::ServerOptions::new()
                .first_pipe_instance(true)
                .create(&path)
                .unwrap();
            let client = ClientOptions::new().open(&path).unwrap();
            assert_eq!(server_pid(&client).unwrap(), std::process::id());
        });
    }

    #[test]
    fn ctrl_c_stops_a_hidden_console_child() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "win::tests::ctrl_c_child",
                "--ignored",
                "--test-threads=1",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success() && text.contains("1 passed"), "{text}");
    }
}
