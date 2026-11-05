//! Explicit security descriptors for objects the app and helper create (named pipe, launch
//! config directory, the helper's private temp directory), so their confidentiality never
//! depends on where %TEMP% points or on inherited ACLs. The SDDL builder is pure and tested on
//! every OS; [`native`] applies it (Windows only).

use std::fmt::Write;

use gp_core::openconnect::windows_acl::{SID_ADMINISTRATORS, SID_LOCAL_SYSTEM};

/// SDDL for a protected DACL (no inheritance from the parent) granting full access to `sids`
/// only. `inherit` adds object/container inheritance (for directories).
pub fn protected_dacl_sddl(sids: &[&str], inherit: bool) -> String {
    let flags = if inherit { "OICI" } else { "" };
    let aces = sids.iter().fold(String::new(), |mut acc, s| {
        let _ = write!(acc, "(A;{flags};FA;;;{s})");
        acc
    });
    format!("D:P{aces}")
}

/// The user, SYSTEM and Administrators (pipe / launch config).
pub fn user_and_admins_sddl(user_sid: &str, inherit: bool) -> String {
    protected_dacl_sddl(&[user_sid, SID_LOCAL_SYSTEM, SID_ADMINISTRATORS], inherit)
}

/// SYSTEM and Administrators only (the elevated helper's temp directory).
pub fn admins_only_sddl() -> String {
    protected_dacl_sddl(&[SID_LOCAL_SYSTEM, SID_ADMINISTRATORS], true)
}

#[cfg(windows)]
pub mod native {
    #![allow(unsafe_code)] // Win32 FFI: tokens, security descriptors, CreateDirectoryW.

    use std::ffi::c_void;
    use std::io;
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use std::path::Path;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use crate::windows_acl::native::{LocalBox, sid_string};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// String SID of the user this process runs as.
    pub fn current_user_sid() -> io::Result<String> {
        let mut token: HANDLE = null_mut();
        // SAFETY: pseudo handle of the current process; `token` receives a handle we close.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: we own the token handle; OwnedHandle closes it.
        let _close = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut len = 0u32;
        // SAFETY: size query with a null buffer.
        unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &raw mut len) };
        // u64 buffer: TOKEN_USER needs pointer alignment.
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        // SAFETY: `buf` holds at least `len` bytes.
        if unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &raw mut len) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the buffer now starts with a TOKEN_USER whose SID points into the buffer.
        let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        // SAFETY: valid SID inside `buf`.
        unsafe { sid_string(sid) }.map_err(io::Error::other)
    }

    /// `SECURITY_ATTRIBUTES` built from SDDL. Not `Send`: build it right where it is used.
    pub struct SecurityAttributes {
        _sd: LocalBox,
        sa: SECURITY_ATTRIBUTES,
    }

    impl SecurityAttributes {
        pub fn from_sddl(sddl: &str) -> io::Result<SecurityAttributes> {
            let w = wide(sddl);
            let mut sd: *mut c_void = null_mut();
            // SAFETY: NUL-terminated string; `sd` receives a LocalAlloc'ed descriptor.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    w.as_ptr(),
                    SDDL_REVISION_1,
                    &raw mut sd,
                    null_mut(),
                )
            };
            if ok == 0 || sd.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(SecurityAttributes {
                _sd: LocalBox(sd),
                sa: SECURITY_ATTRIBUTES {
                    nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
                    lpSecurityDescriptor: sd,
                    bInheritHandle: 0,
                },
            })
        }

        /// Valid while `self` lives.
        pub fn as_mut_ptr(&mut self) -> *mut SECURITY_ATTRIBUTES {
            &raw mut self.sa
        }
    }

    /// Creates a new directory (fails if it exists) with the security descriptor from `sddl`.
    pub fn create_dir_with_sddl(path: &Path, sddl: &str) -> io::Result<()> {
        let mut sa = SecurityAttributes::from_sddl(sddl)?;
        let w = wide(&path.to_string_lossy());
        // SAFETY: NUL-terminated path, valid attributes.
        if unsafe { CreateDirectoryW(w.as_ptr(), sa.as_mut_ptr()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use gp_core::openconnect::windows_acl::{
            AceType, SID_ADMINISTRATORS, SID_LOCAL_SYSTEM, WindowsSecurityProbe,
        };

        use super::*;
        use crate::win_security::user_and_admins_sddl;
        use crate::windows_acl::native::NativeProbe;

        #[test]
        fn reads_the_current_user_sid() {
            let sid = current_user_sid().unwrap();
            assert!(sid.starts_with("S-1-5-"), "{sid}");
        }

        #[tokio::test]
        async fn creates_a_directory_with_exactly_the_given_dacl() {
            let parent = tempfile::tempdir().unwrap();
            let dir = parent.path().join("private");
            let me = current_user_sid().unwrap();
            create_dir_with_sddl(&dir, &user_and_admins_sddl(&me, true)).unwrap();
            assert!(create_dir_with_sddl(&dir, &user_and_admins_sddl(&me, true)).is_err());
            let r = NativeProbe
                .probe(&[dir.to_string_lossy().into_owned()])
                .await
                .unwrap();
            let mut sids: Vec<&str> = r.items[0]
                .entries
                .iter()
                .filter(|e| e.ace_type == AceType::Allow)
                .map(|e| e.sid.as_str())
                .collect();
            sids.sort_unstable();
            sids.dedup();
            let mut want = vec![me.as_str(), SID_LOCAL_SYSTEM, SID_ADMINISTRATORS];
            want.sort_unstable();
            assert_eq!(sids, want);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_protected_dacls() {
        assert_eq!(
            user_and_admins_sddl("S-1-5-21-1-2-3-1001", false),
            "D:P(A;;FA;;;S-1-5-21-1-2-3-1001)(A;;FA;;;S-1-5-18)(A;;FA;;;S-1-5-32-544)"
        );
        assert_eq!(
            admins_only_sddl(),
            "D:P(A;OICI;FA;;;S-1-5-18)(A;OICI;FA;;;S-1-5-32-544)"
        );
    }
}
