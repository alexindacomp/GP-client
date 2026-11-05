//! Native [`WindowsSecurityProbe`]: Program Files roots from HKLM and owner + DACL of each
//! path via `GetNamedSecurityInfoW`. The mapping from raw ACEs to gp-core's [`AclEntry`] is pure
//! and tested on every OS; the Win32 calls live in [`native`] (Windows only).

use gp_core::openconnect::windows_acl::{AceType, AclEntry};
#[cfg(not(windows))]
use gp_core::openconnect::windows_acl::{WindowsProbeResult, WindowsSecurityProbe};

/// `ACCESS_ALLOWED_ACE_TYPE`.
pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x0;
/// `ACCESS_DENIED_ACE_TYPE`.
pub const ACCESS_DENIED_ACE_TYPE: u8 = 0x1;
/// `ACCESS_ALLOWED_CALLBACK_ACE_TYPE` (conditional allow).
pub const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 0x9;
/// `ACCESS_DENIED_CALLBACK_ACE_TYPE` (conditional deny).
pub const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 0xA;
/// `INHERIT_ONLY_ACE` flag.
pub const INHERIT_ONLY_ACE: u8 = 0x08;
/// Everyone.
pub const SID_EVERYONE: &str = "S-1-1-0";
/// `GENERIC_ALL`.
pub const GENERIC_ALL: u32 = 0x1000_0000;

/// HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion values that name Program Files roots.
pub const PROGRAM_FILES_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion";
pub const PROGRAM_FILES_VALUES: [&str; 3] = ["ProgramFilesDir", "ProgramFilesDir (x86)", "ProgramW6432Dir"];

/// Whether an ACE of this type has the `ACCESS_ALLOWED_ACE` layout (header, mask, SID).
pub fn has_basic_layout(ace_type: u8) -> bool {
    matches!(
        ace_type,
        ACCESS_ALLOWED_ACE_TYPE
            | ACCESS_DENIED_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_ACE_TYPE
    )
}

/// Maps one DACL entry. Conditional (callback) ACEs are treated like their unconditional form:
/// an allow that might apply counts as an allow. Any other ACE type (object ACEs, audit/label
/// entries that do not belong in a file DACL) fails the probe instead of being guessed at.
pub fn map_ace(ace_type: u8, ace_flags: u8, mask: u32, sid: &str) -> Result<AclEntry, String> {
    let kind = match ace_type {
        ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => AceType::Allow,
        ACCESS_DENIED_ACE_TYPE | ACCESS_DENIED_CALLBACK_ACE_TYPE => AceType::Deny,
        other => return Err(format!("unsupported ACE type {other:#04x}")),
    };
    Ok(AclEntry {
        sid: sid.to_string(),
        rights: mask,
        ace_type: kind,
        inherit_only: ace_flags & INHERIT_ONLY_ACE != 0,
    })
}

/// A NULL DACL grants everyone full access.
pub fn null_dacl_entries() -> Vec<AclEntry> {
    vec![AclEntry {
        sid: SID_EVERYONE.into(),
        rights: GENERIC_ALL,
        ace_type: AceType::Allow,
        inherit_only: false,
    }]
}

/// Keeps registry values that are present and non-empty (in registry order, deduplicated
/// case-insensitively).
pub fn collect_program_files(values: impl IntoIterator<Item = Option<String>>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for v in values.into_iter().flatten() {
        let v = v.trim().to_string();
        if !v.is_empty() && !out.iter().any(|o| o.eq_ignore_ascii_case(&v)) {
            out.push(v);
        }
    }
    out
}

/// Probe that is not available on this OS: always fails, so every Windows trust check fails
/// closed.
#[cfg(not(windows))]
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct UnavailableProbe;

#[cfg(not(windows))]
#[async_trait::async_trait]
impl WindowsSecurityProbe for UnavailableProbe {
    async fn probe(&self, _paths: &[String]) -> Result<WindowsProbeResult, String> {
        Err("ACL check is only available on Windows".into())
    }
}

#[cfg(windows)]
pub(crate) mod native {
    #![allow(unsafe_code)] // Win32 FFI: registry and security descriptor APIs.

    use std::ffi::c_void;
    use std::ptr::null_mut;

    use async_trait::async_trait;
    use gp_core::openconnect::windows_acl::{AclEntry, AclItem, WindowsProbeResult, WindowsSecurityProbe};
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, ERROR_UNSUPPORTED_TYPE, HLOCAL, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, OWNER_SECURITY_INFORMATION, PSID,
    };
    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, RRF_NOEXPAND, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY, RegGetValueW,
    };

    use super::{PROGRAM_FILES_KEY, PROGRAM_FILES_VALUES, collect_program_files, has_basic_layout, map_ace};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Frees a `LocalAlloc`ed pointer on drop.
    pub(crate) struct LocalBox(pub(crate) *mut c_void);

    impl Drop for LocalBox {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer was allocated by the API that documents LocalFree.
                unsafe { LocalFree(self.0 as HLOCAL) };
            }
        }
    }

    /// REG_SZ value from the 64-bit view of HKLM; `None` when missing or of another type
    /// (REG_EXPAND_SZ is never expanded: that would trust the environment).
    fn reg_string(subkey: &str, value: &str) -> Result<Option<String>, String> {
        let key = wide(subkey);
        let name = wide(value);
        let flags = RRF_RT_REG_SZ | RRF_NOEXPAND | RRF_SUBKEY_WOW6464KEY;
        let mut size: u32 = 0;
        // SAFETY: valid NUL-terminated strings; a null data pointer queries the size.
        let st = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                name.as_ptr(),
                flags,
                null_mut(),
                null_mut(),
                &raw mut size,
            )
        };
        if st == ERROR_FILE_NOT_FOUND || st == ERROR_UNSUPPORTED_TYPE {
            return Ok(None);
        }
        if st != ERROR_SUCCESS {
            return Err(format!("cannot read HKLM\\{subkey}\\{value} (error {st})"));
        }
        let mut buf = vec![0u16; (size as usize).div_ceil(2) + 1];
        let mut size = u32::try_from(buf.len() * 2).map_err(|_| "registry value too large".to_string())?;
        // SAFETY: `buf` holds `size` bytes.
        let st = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                name.as_ptr(),
                flags,
                null_mut(),
                buf.as_mut_ptr().cast(),
                &raw mut size,
            )
        };
        if st != ERROR_SUCCESS {
            return Err(format!("cannot read HKLM\\{subkey}\\{value} (error {st})"));
        }
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16(&buf[..len])
            .map(Some)
            .map_err(|_| format!("HKLM\\{subkey}\\{value} is not valid UTF-16"))
    }

    /// SAFETY: `sid` must point to a valid SID.
    pub(crate) unsafe fn sid_string(sid: PSID) -> Result<String, String> {
        let mut out: *mut u16 = null_mut();
        // SAFETY: caller guarantees `sid`; `out` receives a LocalAlloc'ed string.
        if unsafe { ConvertSidToStringSidW(sid, &raw mut out) } == 0 || out.is_null() {
            return Err("cannot convert SID".into());
        }
        let guard = LocalBox(out.cast());
        let mut len = 0usize;
        // SAFETY: NUL-terminated string returned by the API.
        while unsafe { *out.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: `len` u16s are readable.
        let s = String::from_utf16(unsafe { std::slice::from_raw_parts(out, len) })
            .map_err(|_| "invalid SID string".to_string());
        drop(guard);
        s
    }

    fn read_item(path: &str) -> Result<AclItem, String> {
        let wpath = wide(path);
        let mut owner: PSID = null_mut();
        let mut dacl: *mut ACL = null_mut();
        let mut sd = null_mut();
        // SAFETY: out-pointers are valid; `sd` is freed by LocalBox.
        let st = unsafe {
            GetNamedSecurityInfoW(
                wpath.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &raw mut owner,
                null_mut(),
                &raw mut dacl,
                null_mut(),
                &raw mut sd,
            )
        };
        if st != ERROR_SUCCESS {
            return Err(format!("cannot read permissions of {path} (error {st})"));
        }
        let _sd = LocalBox(sd);
        if owner.is_null() {
            return Err(format!("{path} has no owner"));
        }
        // SAFETY: `owner` points into the security descriptor kept alive by `_sd`.
        let owner_sid = unsafe { sid_string(owner) }?;
        if dacl.is_null() {
            return Ok(AclItem {
                path: path.to_string(),
                owner_sid,
                entries: super::null_dacl_entries(),
            });
        }
        // SAFETY: zeroed POD out-struct of the documented size.
        let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
        let info_size = u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).unwrap_or(u32::MAX);
        // SAFETY: `dacl` is valid while `_sd` lives.
        if unsafe { GetAclInformation(dacl, (&raw mut info).cast(), info_size, AclSizeInformation) } == 0 {
            return Err(format!("cannot read the ACL of {path}"));
        }
        let mut entries: Vec<AclEntry> = Vec::with_capacity(info.AceCount as usize);
        for i in 0..info.AceCount {
            let mut ace: *mut c_void = null_mut();
            // SAFETY: index below AceCount.
            if unsafe { GetAce(dacl, i, &raw mut ace) } == 0 || ace.is_null() {
                return Err(format!("cannot read the ACL of {path}"));
            }
            // SAFETY: every ACE starts with an ACE_HEADER.
            let header = unsafe { &*(ace as *const ACE_HEADER) };
            if !has_basic_layout(header.AceType) {
                return Err(format!(
                    "{path}: {}",
                    map_ace(header.AceType, header.AceFlags, 0, "")
                        .err()
                        .unwrap_or_default()
                ));
            }
            // SAFETY: allow/deny (callback) ACEs share the ACCESS_ALLOWED_ACE layout; the SID
            // starts at `SidStart`.
            let (mask, sid) = unsafe {
                let a = &*(ace as *const ACCESS_ALLOWED_ACE);
                (a.Mask, sid_string((&raw const a.SidStart).cast_mut().cast())?)
            };
            entries.push(
                map_ace(header.AceType, header.AceFlags, mask, &sid).map_err(|e| format!("{path}: {e}"))?,
            );
        }
        Ok(AclItem {
            path: path.to_string(),
            owner_sid,
            entries,
        })
    }

    fn probe_blocking(paths: &[String]) -> Result<WindowsProbeResult, String> {
        let mut values = Vec::with_capacity(PROGRAM_FILES_VALUES.len());
        for v in PROGRAM_FILES_VALUES {
            values.push(reg_string(PROGRAM_FILES_KEY, v)?);
        }
        let items = paths
            .iter()
            .map(|p| read_item(p))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(WindowsProbeResult {
            program_files: collect_program_files(values),
            items,
        })
    }

    #[derive(Debug, Default, Clone, Copy)]
    pub(crate) struct NativeProbe;

    #[async_trait]
    impl WindowsSecurityProbe for NativeProbe {
        async fn probe(&self, paths: &[String]) -> Result<WindowsProbeResult, String> {
            let paths = paths.to_vec();
            tokio::task::spawn_blocking(move || probe_blocking(&paths))
                .await
                .map_err(|e| format!("ACL check failed: {e}"))?
                .map_err(|e| format!("ACL check failed: {e}"))
        }
    }

    #[cfg(test)]
    mod tests {
        use gp_core::openconnect::windows_acl::{
            SID_ADMINISTRATORS, SID_LOCAL_SYSTEM, SID_TRUSTED_INSTALLER, acl_problem,
        };

        use super::*;

        #[tokio::test]
        async fn reads_program_files_and_a_system_acl() {
            let r = NativeProbe
                .probe(&[r"C:\Windows\System32\kernel32.dll".to_string()])
                .await
                .unwrap();
            assert!(
                r.program_files
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(r"C:\Program Files")),
                "{:?}",
                r.program_files
            );
            let item = &r.items[0];
            assert!(
                [SID_LOCAL_SYSTEM, SID_ADMINISTRATORS, SID_TRUSTED_INSTALLER]
                    .contains(&item.owner_sid.as_str()),
                "{}",
                item.owner_sid
            );
            assert!(!item.entries.is_empty());
            assert_eq!(acl_problem(item), None);
        }

        #[tokio::test]
        async fn a_user_temp_file_is_flagged_and_missing_paths_fail() {
            let dir = tempfile::tempdir().unwrap();
            let f = dir.path().join("x.exe");
            std::fs::write(&f, b"x").unwrap();
            let r = NativeProbe
                .probe(&[f.to_string_lossy().into_owned()])
                .await
                .unwrap();
            assert!(acl_problem(&r.items[0]).is_some());
            assert!(
                NativeProbe
                    .probe(&[r"C:\definitely\missing\x.exe".into()])
                    .await
                    .is_err()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use gp_core::openconnect::windows_acl::{AclItem, SID_ADMINISTRATORS, SID_LOCAL_SYSTEM, acl_problem};

    use super::*;

    fn item(entries: Vec<AclEntry>) -> AclItem {
        AclItem {
            path: r"C:\Program Files\X".into(),
            owner_sid: SID_ADMINISTRATORS.into(),
            entries,
        }
    }

    #[test]
    fn maps_allow_deny_and_inherit_only() {
        let e = map_ace(ACCESS_ALLOWED_ACE_TYPE, 0x03, 0x1f_01ff, SID_LOCAL_SYSTEM).unwrap();
        assert_eq!(
            (e.ace_type, e.inherit_only, e.rights, e.sid.as_str()),
            (AceType::Allow, false, 0x1f_01ff, SID_LOCAL_SYSTEM)
        );
        let e = map_ace(
            ACCESS_ALLOWED_ACE_TYPE,
            INHERIT_ONLY_ACE | 0x03,
            GENERIC_ALL,
            "S-1-3-0",
        )
        .unwrap();
        assert!(e.inherit_only);
        assert_eq!(
            map_ace(ACCESS_DENIED_ACE_TYPE, 0, 0x2, "S-1-5-11")
                .unwrap()
                .ace_type,
            AceType::Deny
        );
        assert_eq!(
            map_ace(ACCESS_ALLOWED_CALLBACK_ACE_TYPE, 0, 0x2, "S-1-5-11")
                .unwrap()
                .ace_type,
            AceType::Allow
        );
        assert_eq!(
            map_ace(ACCESS_DENIED_CALLBACK_ACE_TYPE, 0, 0x2, "S-1-5-11")
                .unwrap()
                .ace_type,
            AceType::Deny
        );
        for unsupported in [0x2, 0x5, 0x6, 0xB, 0x11] {
            assert!(
                map_ace(unsupported, 0, 0x2, "S-1-5-11").is_err(),
                "{unsupported:#x}"
            );
            assert!(!has_basic_layout(unsupported));
        }
    }

    #[test]
    fn mapped_entries_follow_the_windows_acl_ts_semantics() {
        // Users may write → flagged.
        let users_write = map_ace(ACCESS_ALLOWED_ACE_TYPE, 0, 0x2, "S-1-5-32-545").unwrap();
        assert!(
            acl_problem(&item(vec![users_write]))
                .unwrap()
                .contains("writable by S-1-5-32-545")
        );
        // A deny ACE for users never makes anything writable.
        let deny = map_ace(ACCESS_DENIED_ACE_TYPE, 0, 0x2, "S-1-5-32-545").unwrap();
        assert_eq!(acl_problem(&item(vec![deny])), None);
        // CREATOR OWNER inherit-only template does not apply to the object itself.
        let creator = map_ace(
            ACCESS_ALLOWED_ACE_TYPE,
            INHERIT_ONLY_ACE | 0x03,
            GENERIC_ALL,
            "S-1-3-0",
        )
        .unwrap();
        assert_eq!(acl_problem(&item(vec![creator])), None);
        // Conditional allow for a non-admin with write → flagged (fail closed).
        let cond = map_ace(ACCESS_ALLOWED_CALLBACK_ACE_TYPE, 0, 0x4, "S-1-5-11").unwrap();
        assert!(acl_problem(&item(vec![cond])).is_some());
        // NULL DACL = everyone full control.
        assert!(
            acl_problem(&item(null_dacl_entries()))
                .unwrap()
                .contains(SID_EVERYONE)
        );
    }

    #[test]
    fn collects_registered_program_files_roots() {
        assert_eq!(
            collect_program_files([
                Some(r"C:\Program Files".to_string()),
                Some(r"C:\Program Files (x86)".to_string()),
                Some(r"c:\program files".to_string()),
                None,
                Some("  ".to_string()),
            ]),
            [r"C:\Program Files", r"C:\Program Files (x86)"]
        );
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn the_probe_fails_closed_off_windows() {
        assert!(UnavailableProbe.probe(&["C:\\x".into()]).await.is_err());
    }
}
