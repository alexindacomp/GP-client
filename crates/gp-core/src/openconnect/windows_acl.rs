//! Windows security rules for files that will run elevated (the pure part). The probe that reads the registry and ACLs is injected
//! ([`WindowsSecurityProbe`]); its native implementation lives in gp-elevate / gp-helper.
//!
//! Nothing here trusts the process environment (%ProgramFiles%, %SystemRoot%, PATH can all be set
//! by a same-user attacker): Program Files locations must come from HKLM and decisions are made
//! from SIDs (locale-independent), not account names.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::util::win;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AceType {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AclEntry {
    pub sid: String,
    /// Numeric FileSystemRights / ACCESS_MASK.
    pub rights: u32,
    #[serde(rename = "type")]
    pub ace_type: AceType,
    /// Inherit-only ACEs (e.g. CREATOR OWNER templates) do not apply to the object itself.
    pub inherit_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AclItem {
    pub path: String,
    pub owner_sid: String,
    pub entries: Vec<AclEntry>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsProbeResult {
    /// Program Files directories as registered in HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion
    /// (`ProgramFilesDir`, `ProgramFilesDir (x86)`, `ProgramW6432Dir`).
    pub program_files: Vec<String>,
    /// Owner and DACL of each requested path, in request order.
    pub items: Vec<AclItem>,
}

/// Reads the registered Program Files roots and the owner/DACL of `paths`. Must fail (not guess)
/// when anything cannot be read: the caller fails closed.
#[async_trait]
pub trait WindowsSecurityProbe: Send + Sync {
    async fn probe(&self, paths: &[String]) -> Result<WindowsProbeResult, String>;
}

/// LocalSystem.
pub const SID_LOCAL_SYSTEM: &str = "S-1-5-18";
/// BUILTIN\Administrators.
pub const SID_ADMINISTRATORS: &str = "S-1-5-32-544";
/// NT SERVICE\TrustedInstaller.
pub const SID_TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

/// Principals that may legitimately own/modify admin-only install folders.
pub const TRUSTED_SIDS: [&str; 3] = [SID_LOCAL_SYSTEM, SID_ADMINISTRATORS, SID_TRUSTED_INSTALLER];

/// Rights that let a principal change the file/directory or what it contains: WriteData/AddFile,
/// AppendData/AddSubdirectory, WriteExtendedAttributes, DeleteSubdirectoriesAndFiles, Delete,
/// ChangePermissions, TakeOwnership, GENERIC_ALL, GENERIC_WRITE.
pub const WRITE_RIGHTS_MASK: u32 =
    0x2 | 0x4 | 0x10 | 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x1000_0000 | 0x4000_0000;

fn is_trusted_sid(sid: &str) -> bool {
    TRUSTED_SIDS.contains(&sid)
}

/// A reason when `item` can be modified by a non-admin principal, else `None`.
pub fn acl_problem(item: &AclItem) -> Option<String> {
    if !is_trusted_sid(&item.owner_sid) {
        return Some(format!("{} is owned by {}", item.path, item.owner_sid));
    }
    item.entries
        .iter()
        .filter(|e| e.ace_type == AceType::Allow && !e.inherit_only)
        .find(|e| e.rights & WRITE_RIGHTS_MASK != 0 && !is_trusted_sid(&e.sid))
        .map(|e| format!("{} is writable by {}", item.path, e.sid))
}

/// `real` and its parents up to and including `root` (case-insensitive).
pub fn paths_up_to(real: &str, root: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = real.to_string();
    let root_lower = root.to_lowercase();
    loop {
        out.push(cur.clone());
        if cur.to_lowercase() == root_lower {
            break;
        }
        let parent = win::dirname(&cur);
        if parent == cur {
            break;
        }
        cur = parent;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(sid: &str, rights: u32) -> AclEntry {
        AclEntry {
            sid: sid.into(),
            rights,
            ace_type: AceType::Allow,
            inherit_only: false,
        }
    }

    #[test]
    fn accepts_admin_write_and_read_only_for_others() {
        let item = AclItem {
            path: "C:\\Program Files\\X".into(),
            owner_sid: SID_ADMINISTRATORS.into(),
            entries: vec![
                entry(SID_LOCAL_SYSTEM, 0x1f_01ff),
                entry("S-1-5-32-545", 0x12_00a9),
                entry("S-1-15-2-1", 0x12_00a9),
            ],
        };
        assert_eq!(acl_problem(&item), None);
    }

    #[test]
    fn flags_every_write_right_for_a_non_admin_sid() {
        for rights in [
            0x2,
            0x4,
            0x40,
            0x10000,
            0x40000,
            0x80000,
            0x1000_0000,
            0x4000_0000,
        ] {
            let item = AclItem {
                path: "C:\\Program Files\\X".into(),
                owner_sid: SID_ADMINISTRATORS.into(),
                entries: vec![entry("S-1-5-11", rights)],
            };
            assert!(
                acl_problem(&item).unwrap().contains("writable by S-1-5-11"),
                "{rights:#x}"
            );
        }
    }

    #[test]
    fn flags_a_non_admin_owner() {
        let item = AclItem {
            path: "C:\\X".into(),
            owner_sid: "S-1-5-21-9-9-9-1001".into(),
            entries: vec![],
        };
        assert!(acl_problem(&item).unwrap().contains("owned by"));
    }

    #[test]
    fn lists_the_file_and_its_parents_up_to_the_root() {
        assert_eq!(
            paths_up_to("C:\\Program Files\\A\\b.exe", "c:\\program files"),
            [
                "C:\\Program Files\\A\\b.exe",
                "C:\\Program Files\\A",
                "C:\\Program Files"
            ]
        );
    }

    #[test]
    fn probe_result_uses_the_ts_json_shape() {
        let json = r#"{"programFiles":["C:\\Program Files"],"items":[{"path":"C:\\x","ownerSid":"S-1-5-18","entries":[{"sid":"S-1-5-18","rights":2032127,"type":"Allow","inheritOnly":false}]}]}"#;
        let r: WindowsProbeResult = serde_json::from_str(json).unwrap();
        assert_eq!(r.items[0].entries[0].ace_type, AceType::Allow);
    }
}
